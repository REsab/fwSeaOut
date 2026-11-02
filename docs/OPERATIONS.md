# fwSeaOut 运维手册

本文只描述 fwSeaOut（原 `fw_admin.py`）本身的运行机制、操作与排障，不包含任何现网地址或密钥。

## 1. 组件与路径

| 组件 | 路径 | 作用 |
| --- | --- | --- |
| 主程序 | `/opt/fw-admin/fw_admin.py` | Web、规则引擎、自动回滚、自愈线程 |
| 配置 | `/etc/fw-admin/config.json` | 模式、端口范围、白名单、密码哈希 |
| 确认标记 | `/etc/fw-admin/confirmed` | 存在即代表 enforce 已固化 |
| 程序日志 | `/etc/fw-admin/fw_admin.log` | apply / 回滚 / 刷新等事件 |
| CN 名单 | `/etc/f2b/cn-v4.list` | 中国 IPv4 前缀 |
| 恒放行名单 | `/etc/f2b/allow-v4.list` | 不做地域判定的来源 |
| 脚本参数 | `/etc/f2b-geo/env` | 三个 shell 脚本共用 |
| 服务 | `fw-admin.service` | `serve`，开机自启 |
| 定时器 | `f2b-geo-refresh.timer` | 每周刷新名单 |
| 定时器 | `f2b-guard.timer` | 每分钟补 `DOCKER-USER`（可选） |

## 2. 包路径与链顺序

### 2.1 宿主本地端口 → INPUT

`CN_GUARD` 被插入 `INPUT` 第 1 条。范围外的包在 `CN_GUARD` 末尾 `RETURN`，继续走原有规则，因此不会破坏既有的 SSH 放行、fail2ban 或面板规则。

### 2.2 容器发布端口 → FORWARD → DOCKER-USER

Docker 的 `-p` 发布会写 `nat/DNAT`，流量走 `FORWARD`，**不经过 `INPUT`**。所以必须同时挂 `DOCKER-USER`：

- `CN_GUARD` 追加在 `DOCKER-USER` **末尾**（在 `f2b-sip`、`F2B-GEO` 之后）；
- 不 flush、不删除其他链；
- Docker 重启会重建空的 `DOCKER-USER`，由 60 秒自愈补回。

### 2.3 DNAT 后端口（最容易踩的坑）

`iptables` 的 `--dport` 在 DNAT 之后匹配的是**容器内端口**，不是宿主发布端口。

```
宿主 19080 → DNAT → 容器 80
filter 链看到的 --dport 是 80
```

如果 `cn_allowed_range` 是 `2000:50000`，`80` 不在范围内 → `CN_GUARD` 直接 `RETURN` → 海外 IP 仍可访问，规则形同虚设。

处理方式（推荐按顺序尝试）：

1. 让容器监听端口与宿主端口一致，映射写成 `19080:19080`；
2. 或把容器端口纳入 `cn_allowed_range`；
3. 或在自定义链里用 `--ctorigdstport` 匹配 DNAT 前端口（需要 xtables 支持，且规则更复杂）。

### 2.4 规则重建的原子性

- 链重建：`flush` → 逐条 `-A`。flush 的毫秒级窗口是 **fail-open**。
- ipset 更新：先建 `cn_ip_new`，`ipset restore` 成功后 `swap`，再销毁旧集。任何一步失败都保留旧名单。
- 名单少于 1000 条时：不安装地域规则；`enforce` 下 healer 会自动降级为 `monitor`。

## 3. 模式与状态机

```
disabled ──启动/切模式──> monitor ──切 enforce──> enforce(armed)
    ^                        ^                        │
    │                        └──── 120s 未确认 ───────┘
    │                                                 │
    └──────────── 一键关闭 ────────────────────────────┘
                                                      │
                                          点“确认生效” → enforce(confirmed)
```

| 状态 | 页面表现 | 包处理 |
| --- | --- | --- |
| `disabled` | 顶部绿色“已关闭” | `CN_GUARD` 从 `INPUT`/`DOCKER-USER` 摘除 |
| `monitor` | 橙色 `MONITOR` | 范围内非国内来源记 `CNGUARD-WOULD-DROP`，`RETURN` |
| `enforce` armed | 红色倒计时卡片 | 实际 DROP；到期未确认自动降 `monitor` |
| `enforce` confirmed | 绿色“已固化” | 实际 DROP，无自动回滚 |

- `last_mode`：一键关闭前记住的模式，下次“一键启动”恢复。
- `confirmed` 文件：存在时 watchdog 不动作。再次切 `enforce` 会重新布防并删除该文件。
- `healer_loop`：每 60 秒执行一次，负责补挂载、补链、空集降级。

## 4. 日志

内核日志前缀（`journalctl -k`）：

| 前缀 | 含义 | 产生条件 |
| --- | --- | --- |
| `CNGUARD-DROP` | 已丢弃 | `enforce` 命中范围内非国内来源 |
| `CNGUARD-WOULD-DROP` | 将丢弃 | `monitor` 命中 |
| `CNGUARD-ACC` | 访问记录 | 国内 IP 新建连接命中范围，限速 60/min |

```bash
# 最近一小时被拦的来源 Top
journalctl -k --since -1h | grep CNGUARD-DROP | grep -o 'SRC=[0-9.]*' | sort | uniq -c | sort -rn | head -20

# 实时观察
journalctl -k -f | grep CNGUARD
```

程序自身日志：

```bash
tail -f /etc/fw-admin/fw_admin.log
journalctl -u fw-admin -f
```

## 5. 日常操作

### 5.1 模式

```bash
FW="env FW_ADMIN_CONFIG=/etc/fw-admin/config.json FW_ADMIN_STATE=/etc/fw-admin python3 /opt/fw-admin/fw_admin.py"

# 只观察
sudo $FW revert          # -> monitor
# 关闭
sudo $FW disable         # -> disabled
# 按当前配置重放
sudo $FW apply
# 查看将要执行的命令
sudo $FW dry-run
```

切 `enforce` 请走 Web（会自动布防回滚）。如果必须用 CLI，改完 `mode` 后立即手动准备回滚：

```bash
sudo $FW disable         # 先确保有退路
```

### 5.2 刷新 CN 名单

```bash
sudo /usr/local/sbin/f2b-geo-refresh.sh      # 下载 + 合并 + swap
sudo /usr/local/sbin/f2b-geo-load.sh         # 只用本地名单重建 ipset
sudo $FW reload-cn                            # 等价于从 cn_sources 下载（不依赖 shell 脚本）
ipset list cn_ip | grep entries
```

### 5.3 白名单

```bash
# 固定 IP：Web“管理白名单”或直接改 config.json 的 admin_ips
# 网段/合作方：追加到 /etc/f2b/allow-v4.list，然后
sudo /usr/local/sbin/f2b-geo-load.sh
sudo $FW apply
```

`allow-v4.list` 只在安装时自动创建，之后不会被安装器覆盖。

### 5.4 备份与恢复

```bash
iptables-save > /root/iptables-$(date +%F).bak
ipset save > /root/ipset-$(date +%F).bak
cp /etc/fw-admin/config.json /root/config-$(date +%F).json
```

恢复 `iptables` 前先 `disable`，避免把旧规则重复挂回。

### 5.5 改密码

```bash
python3 /opt/fw-admin/fw_admin.py set-password
systemctl restart fw-admin
```

## 6. 变更流程

1. 备份：`iptables-save`、`config.json`。
2. 确认有带外通道（云控制台 VNC / 串口 / 另一个已加白的出口）。
3. 若涉及放行来源：先加 `allow-v4.list` 或 `admin_ips`。
4. 若涉及丢弃：先 `monitor`，观察“将拦记录”至少一个业务高峰。
5. 切 `enforce`，120 秒内验证 SSH、业务、回调、监控。
6. 确认无误后点“确认生效”。
7. 记录变更时间与原因。

## 7. 故障排查

| 症状 | 检查 | 处理 |
| --- | --- | --- |
| 页面打不开 | `systemctl status fw-admin`；来源 IP 是否在 `admin_ips` | 从服务器本机 `curl 127.0.0.1:4443`；加白或走 SSH 隧道 |
| 切 enforce 后业务断 | 页面倒计时是否在跑 | 点“一键关闭”；看“拉黑记录”找出被丢来源 |
| 海外仍能访问某端口 | `iptables -t nat -S` 看 DNAT；`--dport` 是容器端口 | 容器端口与宿主端口对齐（见 2.3） |
| 规则过一会儿消失 | `iptables -S DOCKER-USER` | 等 healer；若 Docker 频繁重启，检查 dockerd 日志 |
| `cn_ip` 条数异常 | `ipset list cn_ip` | 手动跑 `f2b-geo-refresh.sh`，失败会保留旧名单 |
| enforce 被自动降级 | `fw_admin.log` 里找 `healer 防呆` | 补 CN 名单后再评估 |
| 日志为空 | `journalctl -k` 是否有内核日志权限；是否真的命中 | 用 `monitor` 观察；检查 rsyslog 是否吞了 kern |
| 服务起不来 | `journalctl -u fw-admin -n 50` | 常见为 `iptables`/`ipset` 不存在、JSON 损坏 |
| 端口范围改错 | `config.json` 的 `cn_allowed_range` | Web 改回或 CLI 修 JSON 后 `apply` |

## 8. 已知坑清单

1. **空 ipset = 全丢**。地域规则是“不在 CN 集合就 DROP”，集合为空会把所有非私网流量丢掉。所有更新都用 `*_new + swap`，并且低于阈值拒绝安装。
2. **DNAT 改写端口**。`--dport` 看容器端口，不是宿主端口（2.3）。
3. **Docker 重建 `DOCKER-USER`**。任何直接写在 `DOCKER-USER` 的规则都会消失，需要自愈/守卫。
4. **fail2ban 顺序**。封禁 DROP 必须在地域链之前，否则被封 IP 仍会被地域规则先放行。守卫脚本用 `-I` 插到第 1/2 位。
5. **默认策略不要动**。本工具只操作自定义链；改 `INPUT`/`FORWARD` 默认策略极易把人锁在门外。
6. **iptables 后端**。`iptables-nft` 与 `iptables-legacy` 混用会出现“规则存在但不生效”。
7. **cloud-init / 安全组**。实例重启后云厂商可能重置安全组；本工具管不到上游，端口仍可能被上游封禁或放行。
8. **journald 限流**。命中量大时 `journalctl -k` 可能丢日志，`log_accepted` 已限速 60/min，仍建议关注 journald 磁盘配额。
9. **`--purge` 的破坏性**。`cn_ip` 可能被其他组件复用，彻底卸载前确认。

## 9. 巡检清单

每日：

- [ ] Web 顶部模式与预期一致
- [ ] “拉黑记录”Top 来源是否有业务合作方
- [ ] `cn_ip` 条数 > 1000

每周：

- [ ] `f2b-geo-refresh.timer` 最近一次执行成功
- [ ] `iptables -S CN_GUARD` 规则条数与预期一致
- [ ] `systemctl is-active fw-admin f2b-guard.timer`
- [ ] 磁盘 `/var/lib/f2b-geo` 与 journald 占用

变更后：

- [ ] 备份 `iptables-save`
- [ ] 验证 SSH / 业务 / 回调
- [ ] 记录变更
