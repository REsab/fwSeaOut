#!/usr/bin/env python3
# fw_admin.py —— 基于国家/地区 ipset 的动态防火墙（零第三方依赖，纯标准库 + iptables/ipset）
#
# 策略：只动态管理 cn_allowed_range（默认 2000-50000）端口范围 —— 范围内仅放行国内 IP(cn_ip)+白名单，
# 其余（enforce 时）记录 CNGUARD-DROP 并 DROP；范围以下端口（SSH 22 / 管理后台等）交由云安全组/上游防火墙，
# 本工具一律 RETURN 放行、不裁决，故 enforce 不可能锁死 SSH/管理口。国内命中范围内可选记录 CNGUARD-ACC（访问记录）。
# 挂载点：DOCKER-USER（容器发布端口，Docker 走 FORWARD 不经 INPUT）+ INPUT（宿主本地端口）。
# 与 fail2ban 共存：本工具的 CN_GUARD 追加在 DOCKER-USER 末尾，不 flush、不碰第三方链。
#
# 安全设计：
#  - 重建链时先 flush = fail-open（重建的毫秒级空窗里所有包按正常 Docker/INPUT 放行，绝不误锁）。
#  - enforce 模式带自动回滚：armed 后 N 秒内未确认 -> 自动降到 monitor（只记日志不拦）。
#  - DOCKER-USER 挂载每 60s 自愈（docker 重启会把 DOCKER-USER 重建为空链）。
#  - Web 后台仅 admin_ips + localhost 可访问，且需密码；后台端口自身不在管理范围内。
#  - 恒放行私网/关键源；RTP 媒体段可配置为永不按 IP 过滤（媒体源分散，白名单会打断通话）。
#
# CLI:
#   fw_admin.py serve            前台运行 Web（systemd 用），启动先 apply + 起自愈线程
#   fw_admin.py apply            按 config.mode 应用一次（幂等）
#   fw_admin.py dry-run          打印将要执行的 iptables/ipset 命令，不执行
#   fw_admin.py revert           把 mode 降到 monitor 并 apply（自动回滚用）
#   fw_admin.py disable          把 mode 设为 disabled 并 apply（摘掉所有挂载）
#   fw_admin.py reload-cn        从 CN 源刷新 cn_ip（*_new + swap，绝不 flush）
#   fw_admin.py geo <ip>...      查询 IP 地区并写入缓存（页面展示用）
#   fw_admin.py watchdog <epoch> 内部：到点未确认则 revert
#   fw_admin.py set-password     交互式设置后台密码
import json
import os
import sys
import time
import hmac
import hashlib
import secrets
import subprocess
import threading
import ipaddress
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, quote
import html as htmllib

CONFIG_PATH = os.environ.get("FW_ADMIN_CONFIG", "/etc/fw-admin/config.json")
STATE_DIR = os.environ.get("FW_ADMIN_STATE", "/etc/fw-admin")
CONFIRM_FILE = os.path.join(STATE_DIR, "confirmed")
LOG_FILE = os.path.join(STATE_DIR, "fw_admin.log")
GEO_CACHE_FILE = os.path.join(STATE_DIR, "ipgeo.json")

DRY = False
DRY_LOG = []

DEFAULT_CONFIG = {
    "mode": "disabled",                 # disabled | monitor | enforce
    "last_mode": "monitor",             # 总开关“关闭”前记住的模式，下次“启动”恢复到它
    "web_bind": "0.0.0.0",
    "web_port": 4443,
    "admin_ips": [],                    # 管理白名单（全端口放行 + 唯一可访问 Web 的来源），安装时写入
    "cn_allowed_range": [2000, 50000],  # 国内 IP 允许的端口范围（tcp+udp）
    # 恒放行的内网/关键源（不受地域限制）；安装时可用 --always-allow 覆盖
    "always_allow_nets": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "100.64.0.0/10"
    ],
    # RTP 媒体段：永不按 IP 过滤（放这里以便审计，代码里对 udp 这些段直接 RETURN）
    "rtp_udp_ranges": [],
    # 复用现有 ipset（由 f2b-geo-load.sh / f2b-geo-refresh.timer 维护）
    "cn_ipset": "cn_ip",
    "allow_ipset": "f2b_allow",
    "guard_chain": "CN_GUARD",
    "verdict_chain": "CN_VERDICT",
    "rollback_seconds": 120,
    "log_accepted": True,              # 记录国内 IP 在管理范围内的新建访问（访问记录），带限速
    "geo_enabled": True,               # 用公开接口查询命中 IP 的地区并落盘缓存
    "geo_api": "http://ip-api.com/batch?lang=zh-CN&fields=status,country,regionName,city,isp,query",
    "geo_max_per_cycle": 100,          # 每轮最多查询多少个新 IP（接口限速保护）
    "armed_until": 0,
    "password_salt": "",
    "password_hash": "",
    "session_secret": "",
    "cn_sources": [
        "https://www.ipdeny.com/ipblocks/data/countries/cn.zone",
        "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt"
    ]
}


def log(msg):
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line, flush=True)


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH) as f:
            user = json.load(f)
        cfg.update(user)
    except FileNotFoundError:
        pass
    except Exception as e:
        log("config 解析失败，用默认值: %r" % e)
    return cfg


def save_config(cfg):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    os.replace(tmp, CONFIG_PATH)


def sh(argv):
    """执行命令；DRY 模式只记录不执行。返回 (rc, stdout, stderr)。"""
    if DRY:
        DRY_LOG.append(" ".join(argv))
        return 0, "", ""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)


def ipt(*args):
    return sh(["iptables"] + list(args))


def ipt_check(*args):
    """规则是否已存在（-C）。DRY 下假定不存在以便生成命令。"""
    if DRY:
        return False
    rc, _, _ = sh(["iptables", "-C"] + list(args))
    return rc == 0


def chain_exists(name):
    if DRY:
        return False
    rc, _, _ = sh(["iptables", "-L", name, "-n"])
    return rc == 0


def ipset_entries(name):
    rc, out, _ = sh(["ipset", "list", name])
    if rc != 0:
        return 0
    for line in out.splitlines():
        if "Number of entries" in line:
            try:
                return int(line.split(":")[1].strip())
            except Exception:
                return 0
    return 0


# ----------------------------- 规则构建 -----------------------------

def build_cn_guard(cfg):
    """返回 CN_GUARD 链的规则（每条是 iptables 参数列表，不含链名前缀）。

    职责边界：本链只动态管理 cn_allowed_range（配置项，默认 2000-50000）。
    范围以下的端口（SSH 22、管理后台等）一律 RETURN 放行，交给云安全组/上游防火墙处理，
    本工具绝不裁决 —— 这样即使 enforce 也不可能把 SSH/后台锁死。
    """
    lo, hi = cfg["cn_allowed_range"]
    cn = cfg["cn_ipset"]
    allow = cfg["allow_ipset"]
    rng = "%d:%d" % (lo, hi)
    rules = []
    A = rules.append

    # 回环 & 已建立连接：绝不打断现有会话（含进行中的通话）
    A(["-i", "lo", "-j", "RETURN"])
    A(["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"])

    # 现有白名单 ipset（allow-v4.list：私网 / 固定出口 / 境外中继等）
    if ipset_entries(allow) > 0 or DRY:
        A(["-m", "set", "--match-set", allow, "src", "-j", "RETURN"])

    # 管理白名单 IP：全端口放行
    for ip in cfg["admin_ips"]:
        A(["-s", ip, "-j", "RETURN"])

    # 恒放行内网/关键源（容器互访、内部软交换等，误拦会打断业务）
    for net in cfg["always_allow_nets"]:
        A(["-s", net, "-j", "RETURN"])

    # RTP 媒体段：永不按 IP 过滤（媒体来自任意话机/中转，白名单会打断通话）
    for a, b in cfg["rtp_udp_ranges"]:
        A(["-p", "udp", "--dport", "%d:%d" % (a, b), "-j", "RETURN"])

    # 国内 IP：放行管理范围（tcp+udp）；顺带记录「访问记录」（新建连接，限速 60/min 防爆日志）
    if ipset_entries(cn) >= 1000 or DRY:
        if cfg.get("log_accepted", True):
            for proto in ("tcp", "udp"):
                A(["-p", proto, "--dport", rng, "-m", "conntrack", "--ctstate", "NEW",
                   "-m", "set", "--match-set", cn, "src",
                   "-m", "limit", "--limit", "60/min", "--limit-burst", "200",
                   "-j", "LOG", "--log-prefix", "CNGUARD-ACC ", "--log-level", "4"])
        A(["-p", "tcp", "--dport", rng, "-m", "set", "--match-set", cn, "src", "-j", "RETURN"])
        A(["-p", "udp", "--dport", rng, "-m", "set", "--match-set", cn, "src", "-j", "RETURN"])
    # 注意：cn_ip 为空时上面几条不装（防空集语义），此时范围内只剩白名单放行、其余进 verdict。

    # 范围内的非国内流量 → 交裁决链（monitor 记 CNGUARD-WOULD-DROP，enforce 记 CNGUARD-DROP 后 DROP）
    A(["-p", "tcp", "--dport", rng, "-j", cfg["verdict_chain"]])
    A(["-p", "udp", "--dport", rng, "-j", cfg["verdict_chain"]])

    # 范围外一律放行（交回 SG / INPUT 正常处理）—— 本工具只管 cn_allowed_range
    A(["-j", "RETURN"])
    return rules


def build_cn_verdict(cfg):
    """CN_VERDICT：仅对 cn_allowed_range 内的非国内流量做终局裁决。
    enforce=LOG(CNGUARD-DROP)+DROP；monitor=LOG(CNGUARD-WOULD-DROP)+RETURN；disabled=RETURN。"""
    mode = cfg["mode"]
    lim = ["-m", "limit", "--limit", "60/min", "--limit-burst", "200"]
    V = []
    if mode == "enforce":
        V.append(lim + ["-j", "LOG", "--log-prefix", "CNGUARD-DROP ", "--log-level", "4"])
        V.append(["-j", "DROP"])
    elif mode == "monitor":
        V.append(lim + ["-j", "LOG", "--log-prefix", "CNGUARD-WOULD-DROP ", "--log-level", "4"])
        V.append(["-j", "RETURN"])
    else:  # disabled
        V.append(["-j", "RETURN"])
    return V


def flush_and_fill(chain, rules):
    """先建链（若无），flush，再逐条填充。flush 期间链为空 = fail-open，不会误锁。"""
    if not chain_exists(chain):
        ipt("-N", chain)
    ipt("-F", chain)
    for r in rules:
        ipt("-A", chain, *r)


def ensure_hooks(cfg):
    """把 CN_GUARD 挂到 INPUT(首位) 和 DOCKER-USER(末尾)。幂等。"""
    G = cfg["guard_chain"]
    # INPUT：插到第 1 位，RETURN 的包继续走 IN_BT -> 正常放行
    if not ipt_check("INPUT", "-j", G):
        ipt("-I", "INPUT", "1", "-j", G)
    # DOCKER-USER：追加到末尾（在 f2b-sip / F2B-GEO 之后）
    if chain_exists("DOCKER-USER") and not ipt_check("DOCKER-USER", "-j", G):
        ipt("-A", "DOCKER-USER", "-j", G)


def remove_hooks(cfg):
    G = cfg["guard_chain"]
    for chain in ("INPUT", "DOCKER-USER"):
        # 基于 -C 检查的有界删除；DRY 下 ipt_check 恒 False，不会进入循环
        while ipt_check(chain, "-j", G):
            rc, _, _ = ipt("-D", chain, "-j", G)
            if rc != 0:
                break


def apply(cfg):
    """按 cfg.mode 幂等应用。"""
    guard = cfg["guard_chain"]
    verdict = cfg["verdict_chain"]
    log("apply mode=%s cn_ip=%d f2b_allow=%d" % (
        cfg["mode"], ipset_entries(cfg["cn_ipset"]), ipset_entries(cfg["allow_ipset"])))

    # 先建/填裁决链与守卫链（flush=fail-open）
    flush_and_fill(verdict, build_cn_verdict(cfg))
    flush_and_fill(guard, build_cn_guard(cfg))

    if cfg["mode"] == "disabled":
        remove_hooks(cfg)
        log("disabled：已摘除 INPUT/DOCKER-USER 挂载，对现网零影响")
    else:
        ensure_hooks(cfg)
        log("已挂载 CN_GUARD 到 INPUT + DOCKER-USER (mode=%s)" % cfg["mode"])


# ----------------------------- CN 名单刷新 -----------------------------

def reload_cn(cfg):
    """下载 CN 网段，建 cn_ip_new，条目 >=5000 才 swap（防下载残缺导致空集全丢）。"""
    name = cfg["cn_ipset"]
    import urllib.request
    text = None
    for url in cfg["cn_sources"]:
        try:
            log("下载 CN 名单: %s" % url)
            with urllib.request.urlopen(url, timeout=30) as r:
                text = r.read().decode("utf-8", "ignore")
            if text and len(text.split()) > 100:
                break
        except Exception as e:
            log("  失败: %r" % e)
            text = None
    if not text:
        log("所有 CN 源下载失败，保留现有 %s 不动" % name)
        return False
    prefixes = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tok = line.split()[0]
        try:
            ipaddress.ip_network(tok, strict=False)
            prefixes.append(tok)
        except Exception:
            continue
    if len(prefixes) < 5000:
        log("下载到的 CN 前缀仅 %d 条（<5000），疑似残缺，保留现有名单" % len(prefixes))
        return False
    tmp = "/tmp/%s_new.restore" % name
    with open(tmp, "w") as f:
        f.write("create %s_new hash:net family inet maxelem 65536\n" % name)
        for p in prefixes:
            f.write("add %s_new %s\n" % (name, p))
    sh(["ipset", "destroy", "%s_new" % name])
    rc, _, err = sh(["ipset", "restore", "-!", "-f", tmp])
    if rc != 0:
        log("ipset restore 失败: %s" % err)
        return False
    rc, _, _ = sh(["ipset", "list", name])
    if rc != 0:
        # 目标集不存在则先建同类型空集，否则 swap 会失败
        sh(["ipset", "create", name, "hash:net", "family", "inet", "maxelem", "65536"])
    sh(["ipset", "swap", "%s_new" % name, name])
    sh(["ipset", "destroy", "%s_new" % name])
    try:
        os.remove(tmp)
    except Exception:
        pass
    log("cn_ip 刷新完成: %d 条" % ipset_entries(name))
    return True


# ----------------------------- 自动回滚 -----------------------------

def arm_rollback(cfg):
    """enforce 时布防：armed_until = now + rollback_seconds，清除 confirmed，拉起 watchdog。"""
    cfg["armed_until"] = int(time.time()) + int(cfg["rollback_seconds"])
    save_config(cfg)
    try:
        os.remove(CONFIRM_FILE)
    except FileNotFoundError:
        pass
    exe = os.path.abspath(__file__)
    cmd = ["setsid", sys.executable, exe, "watchdog", str(cfg["armed_until"])]
    if not DRY:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL, start_new_session=True)
    log("已布防自动回滚：%d 秒内未确认将自动降为 monitor（armed_until=%d）"
        % (cfg["rollback_seconds"], cfg["armed_until"]))


def confirm(cfg):
    cfg["armed_until"] = 0
    save_config(cfg)
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(CONFIRM_FILE, "w") as f:
        f.write(str(int(time.time())))
    log("已确认 enforce，取消自动回滚")


def watchdog(deadline):
    """到点若未确认（无 CONFIRM_FILE）且仍 enforce，则 revert 到 monitor。"""
    wait = max(0, int(deadline) - int(time.time()))
    time.sleep(wait)
    if os.path.exists(CONFIRM_FILE):
        log("watchdog：已确认，无需回滚")
        return
    cfg = load_config()
    if cfg["mode"] == "enforce" and cfg.get("armed_until", 0) and int(cfg["armed_until"]) <= int(time.time()) + 2:
        log("watchdog：超时未确认，自动回滚 enforce -> monitor")
        cfg["mode"] = "monitor"
        cfg["armed_until"] = 0
        save_config(cfg)
        apply(cfg)


# ----------------------------- 自愈线程 -----------------------------

def healer_loop():
    """每 60s 确保挂载存在（docker 重启会重建空 DOCKER-USER 抹掉我们的 jump）。
    并做防呆：enforce 运行时若 cn_ip 被清空到 <1000 条，自动降级到 monitor（空集=全丢的坑）。"""
    while True:
        try:
            cfg = load_config()
            if cfg["mode"] == "enforce" and ipset_entries(cfg["cn_ipset"]) < 1000:
                log("healer 防呆：enforce 下 cn_ip < 1000 条，自动降级 monitor 以免锁死国内流量")
                cfg["mode"] = "monitor"
                cfg["armed_until"] = 0
                save_config(cfg)
                apply(cfg)
            elif cfg["mode"] != "disabled":
                ensure_hooks(cfg)
                # 若 DOCKER-USER 被重建导致 CN_GUARD 链本身丢失，重填
                if not chain_exists(cfg["guard_chain"]):
                    apply(cfg)
        except Exception as e:
            log("healer 异常: %r" % e)
        time.sleep(60)


# ----------------------------- Web -----------------------------

# iptables LOG 走内核 ring buffer -> journald。类型 -> (前缀, 中文标签, 样式)
LOG_TYPES = [
    ("acc",  "CNGUARD-ACC ",       "访问记录（国内 IP 命中管理范围）", "ok"),
    ("drop", "CNGUARD-DROP ",      "拉黑记录（enforce 实际丢弃）",        "err"),
    ("would", "CNGUARD-WOULD-DROP ", "将拦记录（monitor 只观察未丢）",     "small"),
]


def read_logs(kind="drop", limit=300, since="-24h"):
    """从 journalctl -k 抓 CNGUARD-* 日志，解析成 [{time, src, dst, proto, dpt, sport}]。
    kind: drop | would | acc | all。最新的排最后（页面再倒序显示）。"""
    prefix = {"drop": "CNGUARD-DROP", "would": "CNGUARD-WOULD-DROP",
              "acc": "CNGUARD-ACC", "all": "CNGUARD-"}[kind]
    # -k 只看内核日志；--since 限定时间；抓足够多行再在本地裁剪
    rc, out, err = sh(["journalctl", "-k", "--no-pager", "--since", since,
                       "-o", "short-iso", "--lines", "20000"])
    if rc != 0 and not out:
        return [], "journalctl 读取失败: %s" % (err or "rc=%d" % rc)
    rows = []
    for line in out.splitlines():
        if prefix not in line:
            continue
        ts = line[:19].replace("T", " ")
        rec = {"time": ts}
        if "CNGUARD-DROP " in line:
            rec["kind"] = "drop"
        elif "CNGUARD-WOULD-DROP " in line:
            rec["kind"] = "would"
        elif "CNGUARD-ACC " in line:
            rec["kind"] = "acc"
        for tok in line.split():
            if "=" not in tok:
                continue
            k, v = tok.split("=", 1)
            if k == "SRC":
                rec["src"] = v
            elif k == "DST":
                rec["dst"] = v
            elif k == "PROTO":
                rec["proto"] = v
            elif k == "DPT":
                rec["dpt"] = v
            elif k == "SPT":
                rec["sport"] = v
        if rec.get("src"):
            rows.append(rec)
    return rows[-limit:], ""


# ----------------------------- IP 地区 -----------------------------
# 命中/拉黑的 IP 由后台线程调用公开接口（ip-api.com 批量，失败回落 ipwho.is）查询一次，
# 结果落盘到 STATE_DIR/ipgeo.json。渲染路径只读缓存，绝不阻塞页面或请求外网。

GEO_API_FALLBACK = "https://ipwho.is/%s?lang=zh-CN"
GEO_TTL_OK = 30 * 86400        # 查询成功缓存 30 天
GEO_TTL_FAIL = 1800            # 失败按 30min 起指数退避，最长 24h
GEO_MIN_GAP = 4.5              # ip-api 批量接口限 15 次/分，两批之间至少间隔
GEO_MAX_CACHE = 5000

GEO_LOCK = threading.Lock()
GEO_INFLIGHT = set()
GEO_LAST_CALL = [0.0]
GEO_LAST_KICK = [0.0]


def load_geo_cache():
    try:
        with open(GEO_CACHE_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        log("地区缓存读取失败，忽略: %r" % e)
        return {}


def save_geo_cache(cache):
    now = int(time.time())
    keep = {ip: r for ip, r in cache.items()
            if isinstance(r, dict) and now - int(r.get("ts", 0)) < 90 * 86400}
    if len(keep) > GEO_MAX_CACHE:
        keep = dict(sorted(keep.items(), key=lambda kv: int(kv[1].get("ts", 0)),
                           reverse=True)[:GEO_MAX_CACHE])
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        tmp = GEO_CACHE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(keep, f, ensure_ascii=False, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, GEO_CACHE_FILE)
    except Exception as e:
        log("地区缓存写入失败: %r" % e)


def geo_label(rec):
    """把缓存记录拼成『国家 · 省州 · 城市』；查询失败/无记录返回空串。"""
    if not rec or rec.get("fail"):
        return ""
    parts = []
    for k in ("country", "region", "city"):
        v = (rec.get(k) or "").strip()
        if v and v not in parts:
            parts.append(v)
    return " · ".join(parts)


def _geo_http_json(url, payload=None, timeout=10):
    req = urllib.request.Request(url, data=payload, headers={
        "User-Agent": "fw-admin/1.0", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _geo_rec(item):
    return {"country": (item.get("country") or "").strip(),
            "region": (item.get("regionName") or item.get("region") or "").strip(),
            "city": (item.get("city") or "").strip(),
            "isp": (item.get("isp") or "").strip(),
            "ts": int(time.time()), "fail": 0}


def geo_lookup(ips, cfg):
    """批量查询地区，返回 {ip: rec}；接口失败时回落 HTTPS 单查（最多 5 个）。"""
    out = {}
    while True:
        with GEO_LOCK:
            gap = time.time() - GEO_LAST_CALL[0]
            if gap >= GEO_MIN_GAP:
                GEO_LAST_CALL[0] = time.time()
                break
        time.sleep(GEO_MIN_GAP - gap)
    t0 = time.time()
    try:
        url = cfg.get("geo_api") or DEFAULT_CONFIG["geo_api"]
        data = _geo_http_json(url, json.dumps([{"query": ip} for ip in ips]).encode(), timeout=25)
        if not isinstance(data, list):
            raise ValueError("unexpected response")
        for item in data:
            if not isinstance(item, dict):
                continue
            ip = (item.get("query") or "").strip()
            if not ip:
                continue
            out[ip] = _geo_rec(item) if item.get("status") == "success" else {
                "ts": int(time.time()), "fail": 1}
        return out
    except Exception as e:
        log("地区查询失败（批量接口，%d 个 IP，%.1fs）: %r" % (len(ips), time.time() - t0, e))
    for ip in ips[:5]:
        try:
            time.sleep(1)
            data = _geo_http_json(GEO_API_FALLBACK % quote(ip), timeout=10)
            out[ip] = _geo_rec(data) if data.get("success") else {
                "ts": int(time.time()), "fail": 1}
        except Exception as e:
            log("地区查询失败（%s）: %r" % (ip, e))
    return out


def _geo_needs(rec, now):
    if not rec:
        return True
    if int(rec.get("ts", 0)) > now:
        return False
    if rec.get("fail"):
        ttl = min(86400, GEO_TTL_FAIL * (2 ** min(int(rec.get("fail", 1)), 5)))
    else:
        ttl = GEO_TTL_OK
    return now - int(rec.get("ts", 0)) > ttl


def geo_enrich(ips, cfg=None):
    """补齐一批 IP 的地区缓存；已缓存/正在查询/已关闭的跳过。返回新查询到的个数。"""
    cfg = cfg or load_config()
    if not cfg.get("geo_enabled", True):
        return 0
    now = int(time.time())
    with GEO_LOCK:
        cache = load_geo_cache()
        todo = []
        for ip in dict.fromkeys(str(x) for x in ips if x):
            if ip in GEO_INFLIGHT or not _geo_needs(cache.get(ip), now):
                continue
            todo.append(ip)
        todo = todo[:max(1, int(cfg.get("geo_max_per_cycle", 100) or 100))]
        GEO_INFLIGHT.update(todo)
    if not todo:
        return 0
    try:
        got = geo_lookup(todo, cfg)
        with GEO_LOCK:
            cache = load_geo_cache()
            changed = False
            for ip in todo:
                rec = got.get(ip)
                # 批量超时后只有兜底的少量 IP 真正查过；未尝试的保持原样，下一轮再查
                if not rec:
                    continue
                if rec.get("fail"):
                    rec["fail"] = min(int((cache.get(ip) or {}).get("fail", 0)) + 1, 6)
                    rec["ts"] = now
                cache[ip] = rec
                changed = True
            if changed:
                save_geo_cache(cache)
        return len(got)
    finally:
        with GEO_LOCK:
            GEO_INFLIGHT.difference_update(todo)


def geo_kick(ips):
    """渲染时发现未缓存 IP 就丢给后台补齐（20s 节流，不阻塞响应）。"""
    now = time.time()
    with GEO_LOCK:
        if now - GEO_LAST_KICK[0] < 20:
            return
        GEO_LAST_KICK[0] = now
        pending = [ip for ip in set(ips) if ip not in GEO_INFLIGHT]
    if pending:
        threading.Thread(target=geo_enrich, args=(pending,), daemon=True).start()


def geo_loop():
    """每 60s 扫描近 24h 命中日志，把新出现的来源 IP 地区补进缓存（拉黑即记录）。"""
    while True:
        try:
            cfg = load_config()
            if cfg.get("geo_enabled", True):
                rows, _ = read_logs("all", limit=20000, since="-24h")
                last, blocked = {}, set()
                for i, r in enumerate(rows):
                    ip = r.get("src")
                    if not ip:
                        continue
                    last[ip] = i
                    if r.get("kind") in ("drop", "would"):
                        blocked.add(ip)
                # 拉黑/将拦的来源优先，其次按最近出现时间
                ips = sorted(last, key=lambda ip: (ip in blocked, last[ip]), reverse=True)
                n = geo_enrich(ips, cfg)
                if n:
                    log("地区缓存已更新 %d 个 IP" % n)
        except Exception as e:
            log("geo 线程异常: %r" % e)
        time.sleep(60)


def hash_password(pw, salt):
    return hashlib.sha256((salt + pw).encode()).hexdigest()


def make_session(secret, ttl=43200):
    exp = int(time.time()) + ttl
    mac = hmac.new(secret.encode(), str(exp).encode(), hashlib.sha256).hexdigest()[:32]
    return "%d.%s" % (exp, mac)


def valid_session(secret, cookie):
    try:
        exp, mac = cookie.split(".")
        expect = hmac.new(secret.encode(), exp.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(mac, expect):
            return False
        return int(exp) > int(time.time())
    except Exception:
        return False


PAGE_CSS = """
:root{--bg:#0f172a;--panel:#1e293b;--line:#334155;--text:#e2e8f0;--muted:#94a3b8;
--blue:#2563eb;--red:#b91c1c;--green:#16a34a;--grey:#475569;--chip:#0b1220}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
margin:0;background:var(--bg);color:var(--text);font-size:15px;line-height:1.5}
.wrap{max-width:1040px;margin:0 auto;padding:clamp(12px,3vw,24px);
padding-bottom:calc(clamp(16px,4vw,28px) + env(safe-area-inset-bottom))}
h1{font-size:clamp(17px,4.6vw,21px);line-height:1.3;margin:10px 0 8px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
h2{font-size:clamp(14px,3.8vw,16px);margin:26px 0 4px;border-bottom:1px solid var(--line);padding-bottom:6px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:clamp(12px,3vw,16px);margin:12px 0}
.badge{padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.m-disabled{background:var(--grey)}.m-monitor{background:#b45309}.m-enforce{background:var(--red)}
input,select,button,textarea{font:inherit;font-size:15px;padding:9px 11px;border-radius:8px;
border:1px solid #475569;background:var(--bg);color:var(--text);min-width:0}
button{cursor:pointer;background:var(--blue);border-color:var(--blue);color:#fff;font-weight:600;
min-height:40px;touch-action:manipulation}
button.warn{background:var(--red);border-color:var(--red)}
button.grey{background:var(--grey);border-color:var(--grey)}
button.block{display:block;padding:11px 22px}
code,pre{background:var(--chip);border-radius:6px;font-size:12.5px}
code{padding:2px 6px;word-break:break-all}
pre{padding:12px;border:1px solid var(--line);overflow:auto;max-width:100%}
table{border-collapse:collapse;width:100%}
td,th{border:1px solid var(--line);padding:7px 8px;font-size:13.5px;text-align:left;vertical-align:top;word-break:break-word}
th{background:rgba(148,163,184,.08);white-space:nowrap}
.table-wrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;border-radius:8px}
.table-wrap td code{white-space:nowrap}
.nw{white-space:nowrap}
.geo{display:inline-block;min-width:132px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.row>input,.row>select{flex:1 1 160px}
.row>.num{flex:0 0 110px}
.small{color:var(--muted);font-size:12.5px}
.err{color:#fca5a5}.ok{color:#86efac}
.nav{position:sticky;top:0;z-index:10;display:flex;gap:6px;flex-wrap:wrap;align-items:center;
background:rgba(15,23,42,.94);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);
border-bottom:1px solid var(--line);padding:8px clamp(12px,3vw,24px);
margin:0 calc(-1 * clamp(12px,3vw,24px)) 10px}
.nav a,.nav button{min-height:34px;padding:6px 12px;border-radius:999px;border:1px solid var(--line);
background:transparent;color:#93c5fd;text-decoration:none;font-size:13px;font-weight:500;
display:inline-flex;align-items:center}
.nav a.active{color:#fff;background:rgba(37,99,235,.28);border-color:var(--blue)}
.nav form{margin:0;display:flex}
.nav .live{margin-left:auto;color:var(--muted);font-size:12px;border:1px dashed var(--line);
border-radius:999px;padding:5px 10px;white-space:nowrap}
.nav .live b{color:var(--text)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:10px 0}
.stat{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.stat .k{font-size:12px;color:var(--muted)}
.stat .v{font-size:18px;font-weight:700;margin-top:2px}
.login-card{max-width:400px;margin:clamp(24px,10vh,80px) auto}
@media (max-width:640px){
  .wrap{padding:12px;padding-bottom:calc(20px + env(safe-area-inset-bottom))}
  h1{font-size:18px}
  .nav{padding:8px 12px;margin:0 -12px 10px}
  .nav a,.nav button{font-size:12.5px;padding:6px 10px}
  .nav .live{margin-left:0;order:9;width:100%;text-align:center}
  input,select,button,textarea{font-size:16px}
  .row>input,.row>select,.row>button{flex:1 1 100%}
  .row>.num{flex:1 1 38%}
  td,th{font-size:12.5px;padding:6px 7px}
  table.wide{min-width:640px}
  .stats{grid-template-columns:1fr 1fr}
  .stats .stat:last-child:nth-child(odd){grid-column:1/-1}
  button.block{width:100%}
  pre{font-size:12px}
}
@media (max-width:380px){.stats{grid-template-columns:1fr}}
"""

HEAD_META = ('<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">'
             '<meta name="theme-color" content="#0f172a">'
             '<meta name="format-detection" content="telephone=no">')

AUTO_REFRESH_JS = """
<script>
(function(){
  var box=document.getElementById('live-cd'); if(!box) return;
  var secs=parseInt(box.getAttribute('data-secs')||'30',10), left=secs, dirty=false;
  function busy(){var a=document.activeElement;
    return !!(dirty || (a && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName)));}
  function paint(){box.textContent=(document.hidden||busy())?'暂停':left;}
  document.addEventListener('input',function(e){if(e.target.closest&&e.target.closest('form')){dirty=true;paint();}},true);
  document.addEventListener('change',function(e){if(e.target.closest&&e.target.closest('form')){dirty=true;paint();}},true);
  document.addEventListener('visibilitychange',function(){if(!document.hidden)left=secs;paint();});
  setInterval(function(){
    if(document.hidden||busy()){paint();return;}
    left--; if(left<=0){location.reload();return;} paint();
  },1000);
})();
</script>
"""

ROLLBACK_JS = """
<script>
(function(){
  var el=document.getElementById('rollback-left'); if(!el) return;
  var n=parseInt(el.getAttribute('data-left')||'0',10);
  var note=document.getElementById('rollback-note');
  setInterval(function(){
    if(n>0){n--;el.textContent=n;}
    else if(note){note.textContent='已到期，正在自动降级为 monitor…';}
  },1000);
})();
</script>
"""


def nav_html(live_secs=0, active=""):
    def cls(name):
        return "active" if name == active else ""
    live = ""
    if live_secs:
        live = ('<span class="live">自动刷新 <b id="live-cd" data-secs="%d">%d</b>s</span>'
                % (live_secs, live_secs))
    return ('<div class="nav">'
            '<a href="/" class="%s">仪表盘</a>'
            '<a href="/logs?type=drop" class="%s">记录</a>'
            '<a href="/rules" class="%s">规则</a>'
            '<a href="/backup" class="%s">备份</a>'
            '<form method="post" action="/logout"><button type="submit" class="grey">退出</button></form>'
            '%s</div>') % (cls("dash"), cls("logs"), cls("rules"), cls("backup"), live)


class Handler(BaseHTTPRequestHandler):
    server_version = "fw_admin/1.0"

    def log_message(self, *a):
        pass

    def client_ip(self):
        return self.client_address[0]

    def allowed_source(self, cfg):
        ip = self.client_ip()
        if ip in ("127.0.0.1", "::1"):
            return True
        try:
            for a in cfg["admin_ips"]:
                if "/" in a:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(a, strict=False):
                        return True
                elif ip == a:
                    return True
        except Exception:
            pass
        return False

    def get_cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith(name + "="):
                return part[len(name) + 1:]
        return ""

    def authed(self, cfg):
        return valid_session(cfg["session_secret"], self.get_cookie("fwsess"))

    def send(self, code, body, ctype="text/html; charset=utf-8", extra_headers=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra_headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        cfg = load_config()
        if not self.allowed_source(cfg):
            return self.send(403, "<h1>403</h1><p>来源 IP %s 不在管理白名单内。</p>" % htmllib.escape(self.client_ip()))
        path = urlparse(self.path).path
        if not self.authed(cfg):
            return self.render_login(cfg, "")
        if path == "/":
            return self.render_dash(cfg, "")
        if path == "/rules":
            return self.render_rules(cfg)
        if path == "/logs":
            q = parse_qs(urlparse(self.path).query)
            kind = q.get("type", ["drop"])[0]
            if kind not in ("drop", "would", "acc", "all"):
                kind = "drop"
            return self.render_logs(cfg, kind)
        if path == "/backup":
            rc, out, err = sh(["iptables-save"])
            return self.send(200, out or err, "text/plain; charset=utf-8")
        return self.send(404, "not found")

    def do_POST(self):
        cfg = load_config()
        if not self.allowed_source(cfg):
            return self.send(403, "403 forbidden")
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "ignore") if length else ""
        form = {k: v[0] for k, v in parse_qs(raw).items()}
        path = urlparse(self.path).path

        if path == "/login":
            pw = form.get("password", "")
            if cfg["password_hash"] and hash_password(pw, cfg["password_salt"]) == cfg["password_hash"]:
                sess = make_session(cfg["session_secret"])
                return self.send(302, "", "text/html", [("Location", "/"),
                                                         ("Set-Cookie", "fwsess=%s; Path=/; HttpOnly; SameSite=Strict" % sess)])
            return self.render_login(cfg, "密码错误")

        if not self.authed(cfg):
            return self.send(403, "session expired")

        if path == "/logout":
            return self.send(302, "", "text/html", [("Location", "/"), ("Set-Cookie", "fwsess=; Path=/; Max-Age=0")])

        if path == "/action":
            return self.handle_action(cfg, form)

        return self.send(404, "not found")

    def handle_action(self, cfg, form):
        act = form.get("action", "")
        msg = ""
        if act == "set_mode":
            new = form.get("mode", "disabled")
            if new not in ("disabled", "monitor", "enforce"):
                msg = "非法模式"
            else:
                old = cfg["mode"]
                cfg["mode"] = new
                save_config(cfg)
                apply(cfg)
                if new == "enforce" and old != "enforce":
                    arm_rollback(cfg)
                    cfg = load_config()
                    msg = "已切到 enforce，并布防 %d 秒自动回滚。请新开终端验证 SSH/业务后点『确认生效』。" % cfg["rollback_seconds"]
                else:
                    msg = "模式已设为 %s 并应用" % new
        elif act == "confirm":
            confirm(cfg)
            msg = "已确认，enforce 永久生效（取消自动回滚）"
        elif act == "add_admin":
            ip = form.get("ip", "").strip()
            try:
                ipaddress.ip_address(ip)
                if ip not in cfg["admin_ips"]:
                    cfg["admin_ips"].append(ip)
                    save_config(cfg)
                    if cfg["mode"] != "disabled":
                        apply(cfg)
                    msg = "已加入白名单 %s" % ip
                else:
                    msg = "%s 已在白名单" % ip
            except Exception:
                msg = "非法 IP: %s" % htmllib.escape(ip)
        elif act == "del_admin":
            ip = form.get("ip", "").strip()
            if ip in cfg["admin_ips"]:
                cfg["admin_ips"].remove(ip)
                save_config(cfg)
                if cfg["mode"] != "disabled":
                    apply(cfg)
                msg = "已移除白名单 %s" % ip
        elif act == "reload_cn":
            ok = reload_cn(cfg)
            if cfg["mode"] != "disabled":
                apply(cfg)
            msg = "CN 名单刷新%s，当前 %d 条" % ("成功" if ok else "失败/保留旧名单", ipset_entries(cfg["cn_ipset"]))
        elif act == "set_range":
            try:
                lo = int(form.get("lo")); hi = int(form.get("hi"))
                if 1 <= lo < hi <= 65535:
                    cfg["cn_allowed_range"] = [lo, hi]
                    save_config(cfg)
                    if cfg["mode"] != "disabled":
                        apply(cfg)
                    msg = "端口范围已设为 %d-%d" % (lo, hi)
                else:
                    msg = "范围非法"
            except Exception:
                msg = "范围解析失败"
        elif act == "toggle_logacc":
            cfg["log_accepted"] = not cfg.get("log_accepted", True)
            save_config(cfg)
            if cfg["mode"] != "disabled":
                apply(cfg)
            msg = "访问记录（CNGUARD-ACC）已%s" % ("开启" if cfg["log_accepted"] else "关闭")
        elif act == "toggle_geo":
            cfg["geo_enabled"] = not cfg.get("geo_enabled", True)
            save_config(cfg)
            msg = "IP 地区查询已%s（已缓存地区不受影响）" % ("开启" if cfg["geo_enabled"] else "关闭")
        elif act == "toggle_power":
            if cfg["mode"] == "disabled":
                new = cfg.get("last_mode", "monitor")
                if new not in ("monitor", "enforce"):
                    new = "monitor"
                cfg["mode"] = new
                save_config(cfg)
                apply(cfg)
                if new == "enforce":
                    arm_rollback(cfg)
                    cfg = load_config()
                    msg = "防火墙已启动（enforce），已布防 %d 秒自动回滚，请点『确认生效』固化" % cfg["rollback_seconds"]
                else:
                    msg = "防火墙已启动（monitor：范围内只记录，不丢包）"
            else:
                cfg["last_mode"] = cfg["mode"]
                cfg["mode"] = "disabled"
                cfg["armed_until"] = 0
                save_config(cfg)
                apply(cfg)
                msg = "防火墙已关闭：CN_GUARD 已从 INPUT/DOCKER-USER 摘除（fail2ban 的 f2b-sip/F2B-GEO 不受影响）"
        else:
            msg = "未知动作"
        return self.render_dash(cfg, msg)

    # ---- 渲染 ----
    def render_login(self, cfg, err):
        e = '<p class="err">%s</p>' % htmllib.escape(err) if err else ""
        body = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">%s<style>%s</style></head><body>
<div class="wrap"><div class="card login-card">
<h1>防火墙管理 · 登录</h1>%s
<form method="post" action="/login"><div class="row">
<input type="password" name="password" placeholder="管理密码" autocomplete="current-password" autofocus>
<button type="submit">登录</button></div></form>
<p class="small">仅白名单 IP (%s) 与 localhost 可访问本页。</p>
</div></div></body></html>""" % (HEAD_META, PAGE_CSS, e, ", ".join(cfg["admin_ips"]))
        self.send(200, body)

    def render_rules(self, cfg):
        global DRY, DRY_LOG
        saved = DRY
        DRY = True
        DRY_LOG = []
        try:
            flush_and_fill(cfg["verdict_chain"], build_cn_verdict(cfg))
            flush_and_fill(cfg["guard_chain"], build_cn_guard(cfg))
            if cfg["mode"] == "disabled":
                remove_hooks(cfg)
            else:
                ensure_hooks(cfg)
        finally:
            DRY = saved
        cmds = "\n".join(DRY_LOG)
        body = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">%s<style>%s</style></head><body><div class="wrap">
%s
<h1>将要执行的命令 <span class="badge m-%s">%s</span></h1>
<p class="small">dry-run：只打印不执行，用于核对规则。刷新页面会按当前 config 重新计算。</p>
<pre>%s</pre></div></body></html>""" % (
            HEAD_META, PAGE_CSS, nav_html(active="rules"), cfg["mode"], cfg["mode"], htmllib.escape(cmds))
        self.send(200, body)

    def render_logs(self, cfg, kind):
        rows, err = read_logs(kind)
        tabs = [("drop", "拉黑记录"), ("would", "将拦(monitor)"), ("acc", "访问记录"), ("all", "全部")]
        tab_html = " ".join(
            '<a href="/logs?type=%s" class="badge %s">%s</a>' %
            (t, "m-enforce" if t == kind else "m-disabled", label)
            for t, label in tabs)
        # 统计各来源 IP 命中次数（Top）
        from collections import Counter
        cnt = Counter(r.get("src", "?") for r in rows)
        # 地区：只读本地缓存（拉黑时后台线程已落盘），未命中的丢给后台补查
        geo_on = cfg.get("geo_enabled", True)
        gcache = load_geo_cache()
        missing = [ip for ip in cnt if not geo_label(gcache.get(ip))]
        if geo_on and missing:
            geo_kick(missing)

        def region_html(ip):
            label = geo_label(gcache.get(ip))
            if label:
                return '<span class="geo">%s</span>' % htmllib.escape(label)
            if not geo_on:
                return '<span class="small">已关闭</span>'
            return '<span class="small">查询中…</span>'

        top = "".join("<tr><td><code>%s</code></td><td>%s</td><td>%d</td></tr>" %
                      (htmllib.escape(s), region_html(s), n) for s, n in cnt.most_common(15))
        # 明细倒序（最新在上）
        detail = "".join(
            "<tr><td class=\"nw\">%s</td><td><code>%s</code></td><td>%s</td><td class=\"nw\">%s:%s</td><td class=\"nw\">%s &rarr; %s</td></tr>" %
            (htmllib.escape(r.get("time", "")), htmllib.escape(r.get("src", "")),
             region_html(r.get("src", "")),
             htmllib.escape(r.get("proto", "").upper()), htmllib.escape(r.get("dpt", "")),
             htmllib.escape(r.get("sport", "")), htmllib.escape(r.get("dst", "")))
            for r in reversed(rows[-200:]))
        # 地区分布（次数按命中计，IP 数按去重计）
        regions = {}
        for ip, n in cnt.items():
            label = geo_label(gcache.get(ip)) or ("待查询" if geo_on else "未启用地区查询")
            r = regions.setdefault(label, [0, 0])
            r[0] += 1
            r[1] += n
        region_rows = "".join("<tr><td>%s</td><td>%d</td><td>%d</td></tr>" %
                              (htmllib.escape(k), v[0], v[1])
                              for k, v in sorted(regions.items(), key=lambda kv: (-kv[1][1], kv[0]))[:12])
        err_html = '<p class="err">%s</p>' % htmllib.escape(err) if err else ""
        empty = '<p class="small">该类型近 24h 无记录（日志来自内核 journalctl -k，仅在有命中时产生）。</p>' if not rows and not err else ""
        body = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">%s<style>%s</style></head><body><div class="wrap">
%s
<h1>访问 / 拉黑记录 <span class="small">近 24h · 内核日志</span></h1>
<div class="row">%s</div>
%s%s
<div class="card"><h2>来源 IP Top <span class="small">共 %d 条命中</span></h2>
<div class="table-wrap"><table><tr><th>来源 IP</th><th>地区</th><th>次数</th></tr>%s</table></div>
<p class="small">地区在 IP 首次命中时由公开接口查询并缓存到 <code>%s</code>，之后直接读缓存，不重复外发。</p></div>
<div class="card"><h2>来源地区分布</h2>
<div class="table-wrap"><table><tr><th>地区</th><th>IP 数</th><th>命中次数</th></tr>%s</table></div></div>
<div class="card"><h2>明细 <span class="small">最新 %d 条</span></h2>
<div class="table-wrap"><table class="wide"><tr><th>时间</th><th>来源 IP</th><th>地区</th><th>协议:目的端口</th><th>源端口 &rarr; 目的</th></tr>%s</table></div></div>
</div>%s</body></html>""" % (HEAD_META, PAGE_CSS, nav_html(20, "logs"), tab_html, err_html, empty,
                            len(rows), top or "<tr><td colspan=3 class=small>无</td></tr>",
                            htmllib.escape(GEO_CACHE_FILE),
                            region_rows or "<tr><td colspan=3 class=small>无</td></tr>",
                            min(200, len(rows)), detail or "<tr><td colspan=5 class=small>无</td></tr>",
                            AUTO_REFRESH_JS)
        self.send(200, body)

    def render_dash(self, cfg, msg):
        mode = cfg["mode"]
        cn_n = ipset_entries(cfg["cn_ipset"])
        allow_n = ipset_entries(cfg["allow_ipset"])
        armed = cfg.get("armed_until", 0)
        now = int(time.time())
        armed_html = ""
        if mode == "enforce" and armed and armed > now and not os.path.exists(CONFIRM_FILE):
            armed_html = ('<div class="card" style="border-color:#b91c1c">'
                          '<div class="row"><b class="err">自动回滚已布防：还剩 '
                          '<span id="rollback-left" data-left="%d">%d</span> 秒</b></div>'
                          '<p class="small">请另开终端验证 SSH 与业务是否正常，确认无误后点下方按钮固化；'
                          '超时将自动降为 monitor。<span id="rollback-note"></span></p>'
                          '<form method="post" action="/action">'
                          '<input type="hidden" name="action" value="confirm">'
                          '<button type="submit" class="block">确认生效（取消自动回滚）</button></form></div>'
                          ) % (armed - now, armed - now)
        elif mode == "enforce" and os.path.exists(CONFIRM_FILE):
            armed_html = '<div class="card ok">enforce 已固化生效（自动回滚已取消）。</div>'

        admins = "".join(
            '<tr><td><code>%s</code></td><td><form method="post" action="/action" style="display:inline">'
            '<input type="hidden" name="action" value="del_admin"><input type="hidden" name="ip" value="%s">'
            '<button class="warn" type="submit" onclick="return confirm(\'移除 %s ?\')">移除</button></form></td></tr>'
            % (htmllib.escape(a), htmllib.escape(a), htmllib.escape(a)) for a in cfg["admin_ips"])

        msg_html = '<div class="card ok">%s</div>' % htmllib.escape(msg) if msg else ""
        lo, hi = cfg["cn_allowed_range"]
        if mode == "disabled":
            power_html = (
                '<div class="card" style="border-color:#16a34a">'
                '<div class="row"><b class="ok" style="font-size:18px">防火墙已关闭</b>'
                '<span class="small">CN_GUARD 未挂载：%d-%d 不做任何地域过滤</span></div>'
                '<form method="post" action="/action" style="margin-top:12px">'
                '<input type="hidden" name="action" value="toggle_power">'
                '<button type="submit" class="block" style="background:#16a34a;border-color:#16a34a">'
                '一键启动防火墙（恢复到 %s）</button></form></div>'
            ) % (lo, hi, cfg.get("last_mode", "monitor"))
        else:
            power_html = (
                '<div class="card" style="border-color:#b91c1c">'
                '<div class="row"><b class="err" style="font-size:18px">防火墙运行中（%s）</b>'
                '<span class="small">关闭后记住当前模式，下次启动自动恢复</span></div>'
                '<form method="post" action="/action" style="margin-top:12px">'
                '<input type="hidden" name="action" value="toggle_power">'
                '<button type="submit" class="block" '
                'onclick="return confirm(\'确认关闭地域防火墙？关闭后 %d-%d 不再按国家过滤。\')">'
                '一键关闭防火墙</button></form></div>'
            ) % (mode, lo, hi)
        body = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">%s<style>%s</style></head>
<body><div class="wrap">
%s
<h1>防火墙管理 <span class="badge m-%s">%s</span></h1>
<div class="stats">
<div class="stat"><div class="k">来源 IP</div><div class="v" style="font-size:14px;word-break:break-all">%s</div></div>
<div class="stat"><div class="k">后台端口</div><div class="v">%d</div></div>
<div class="stat"><div class="k">CN 允许范围</div><div class="v">%d-%d</div></div>
</div>
<p class="small">职责边界：本工具只动态管理 <b>%d-%d</b> 端口范围（范围内仅放行国内 IP + 白名单）；<b>%d 以下端口（含 SSH 22 / 后台 %d）交由云安全组或上游防火墙处理，本工具一律放行不裁决</b> —— 因此 enforce 不会锁死 SSH / 后台。</p>
%s
%s
<h2>运行模式</h2>
<div class="card">
<form method="post" action="/action"><input type="hidden" name="action" value="set_mode">
<div class="row">
<select name="mode">
<option value="disabled"%s>disabled — 摘除挂载，对现网零影响</option>
<option value="monitor"%s>monitor — 范围内只记 CNGUARD-WOULD-DROP，不拦截</option>
<option value="enforce"%s>enforce — 范围内非国内 IP 记 CNGUARD-DROP 并丢弃（带自动回滚）</option>
</select>
<button type="submit">应用</button>
</div>
<p class="small" style="margin:8px 0 0">切到 enforce 会布防 %d 秒自动回滚，需手动确认才固化。</p>
</form>
<form method="post" action="/action" style="margin-top:12px"><input type="hidden" name="action" value="toggle_logacc">
<button type="submit" class="grey block">访问记录(CNGUARD-ACC)：当前%s，点击切换</button>
<p class="small" style="margin:8px 0 0">记录国内 IP 在 %d-%d 的<b>新建</b>连接（限速 60/min）。拉黑记录不受此开关影响，始终记录。</p></form>
</div>

<h2>记录查看</h2>
<div class="card"><div class="row">
<a href="/logs?type=drop" class="badge m-enforce" style="text-decoration:none;color:#fff">拉黑记录</a>
<a href="/logs?type=would" class="badge m-monitor" style="text-decoration:none;color:#fff">将拦记录</a>
<a href="/logs?type=acc" class="badge m-disabled" style="text-decoration:none;color:#fff">访问记录</a>
<a href="/logs?type=all" class="badge m-disabled" style="text-decoration:none;color:#fff">全部</a>
</div>
<p class="small" style="margin:10px 0 0">数据源 <code>journalctl -k</code>，默认展示近 24 小时。</p></div>

<h2>数据源</h2>
<div class="card"><div class="table-wrap"><table>
<tr><th>cn_ip（国内网段）</th><td>%d 条 %s</td></tr>
<tr><th>f2b_allow（现有白名单集）</th><td>%d 条</td></tr>
</table></div>
<form method="post" action="/action" style="margin-top:12px"><input type="hidden" name="action" value="reload_cn">
<button type="submit" class="grey block">刷新 CN 名单（*_new + swap，不会空窗）</button></form>
<p class="small">cn_ip 少于 1000 条时不会安装地域规则（防空集=全丢）。刷新失败保留旧名单。</p>
</div>

<h2>CN 允许端口范围</h2>
<div class="card"><form method="post" action="/action"><input type="hidden" name="action" value="set_range">
<div class="row">
<input type="number" name="lo" value="%d" class="num" inputmode="numeric"> <span class="small">—</span>
<input type="number" name="hi" value="%d" class="num" inputmode="numeric">
<button type="submit">保存</button>
</div>
<p class="small" style="margin:8px 0 0">国内 IP 可访问的 tcp/udp 端口范围；范围外（如 SSH 22）仅白名单可达。</p>
</form></div>

<h2>管理白名单（全端口放行）</h2>
<div class="card"><div class="table-wrap"><table><tr><th>IP</th><th>操作</th></tr>%s</table></div>
<form method="post" action="/action" style="margin-top:12px"><input type="hidden" name="action" value="add_admin">
<div class="row"><input type="text" name="ip" placeholder="新增白名单 IP，如 1.2.3.4" inputmode="decimal"><button type="submit">添加</button></div></form>
</div>

<h2>恒放行（不可编辑，来自现网硬约束）</h2>
<div class="card"><p class="small">内网/关键源：%s<br>RTP 媒体段（永不按 IP 过滤）：%s</p></div>

</div>%s%s</body></html>""" % (
            HEAD_META, PAGE_CSS, nav_html(30, "dash"), mode, mode.upper(),
            htmllib.escape(self.client_ip()), cfg["web_port"], lo, hi,
            lo, hi, lo, cfg["web_port"],
            msg_html, armed_html,
            " selected" if mode == "disabled" else "",
            " selected" if mode == "monitor" else "",
            " selected" if mode == "enforce" else "",
            cfg["rollback_seconds"],
            "开启" if cfg.get("log_accepted", True) else "关闭",
            lo, hi,
            cn_n, '<span class="err">（不足 1000，地域规则不会安装！）</span>' if cn_n < 1000 else '<span class="ok">OK</span>',
            allow_n,
            lo, hi, admins,
            ", ".join(cfg["always_allow_nets"]),
            ", ".join("%d-%d/udp" % (a, b) for a, b in cfg["rtp_udp_ranges"]),
            ROLLBACK_JS, AUTO_REFRESH_JS,
        )
        geo_card = (
            '<div class="card"><form method="post" action="/action">'
            '<input type="hidden" name="action" value="toggle_geo">'
            '<button type="submit" class="grey block">IP 地区查询：当前%s，点击切换</button>'
            '<p class="small" style="margin:8px 0 0">命中/拉黑 IP 的地区由公开接口查询一次，'
            '缓存到 <code>%s</code>；关闭后不再外发查询，记录页仍显示已缓存结果。</p></form></div>'
        ) % ("开启" if cfg.get("geo_enabled", True) else "关闭", htmllib.escape(GEO_CACHE_FILE))
        body = body.replace("<h2>运行模式</h2>", power_html + "<h2>运行模式</h2>")
        body = body.replace("<h2>数据源</h2>", geo_card + "<h2>数据源</h2>")
        self.send(200, body)


# ----------------------------- CLI -----------------------------

def set_password(cfg):
    import getpass
    pw = getpass.getpass("设置后台密码: ")
    pw2 = getpass.getpass("再输入一次: ")
    if pw != pw2 or not pw:
        print("两次不一致或为空，未设置")
        return
    salt = secrets.token_hex(8)
    cfg["password_salt"] = salt
    cfg["password_hash"] = hash_password(pw, salt)
    if not cfg.get("session_secret"):
        cfg["session_secret"] = secrets.token_hex(32)
    save_config(cfg)
    print("密码已设置。")


def main():
    global DRY
    args = sys.argv[1:]
    cmd = args[0] if args else "serve"
    cfg = load_config()

    if cmd == "dry-run":
        DRY = True
        apply(cfg)
        print("\n".join(DRY_LOG))
        return
    if cmd == "apply":
        apply(cfg)
        return
    if cmd == "revert":
        cfg["mode"] = "monitor"
        cfg["armed_until"] = 0
        save_config(cfg)
        apply(cfg)
        return
    if cmd == "disable":
        cfg["mode"] = "disabled"
        cfg["armed_until"] = 0
        save_config(cfg)
        apply(cfg)
        return
    if cmd == "reload-cn":
        reload_cn(cfg)
        return
    if cmd == "watchdog":
        watchdog(int(args[1]))
        return
    if cmd == "set-password":
        set_password(cfg)
        return
    if cmd == "geo":
        ips = args[1:]
        if not ips:
            print("用法: fw_admin.py geo <ip> [ip...]")
            return
        geo_enrich(ips, cfg)
        cache = load_geo_cache()
        for ip in ips:
            print("%-16s %s" % (ip, geo_label(cache.get(ip)) or "未知/查询失败"))
        return
    if cmd == "serve":
        if not cfg.get("session_secret"):
            cfg["session_secret"] = secrets.token_hex(32)
            save_config(cfg)
        # 启动即按当前 mode 应用一次，并布防中的回滚若仍有效则重拉 watchdog
        apply(cfg)
        if cfg["mode"] == "enforce" and cfg.get("armed_until", 0) > int(time.time()) and not os.path.exists(CONFIRM_FILE):
            arm_rollback(cfg)
        threading.Thread(target=healer_loop, daemon=True).start()
        threading.Thread(target=geo_loop, daemon=True).start()
        srv = ThreadingHTTPServer((cfg["web_bind"], int(cfg["web_port"])), Handler)
        log("Web 管理后台启动: http://%s:%d (仅白名单+localhost)" % (cfg["web_bind"], cfg["web_port"]))
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return

    print("未知命令: %s" % cmd)
    sys.exit(2)


if __name__ == "__main__":
    main()
