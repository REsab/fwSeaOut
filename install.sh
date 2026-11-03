#!/usr/bin/env bash
# cn-geo-firewall 安装脚本
# 用法：sudo ./install.sh --admin-ip 203.0.113.10
#      sudo ./install.sh --admin-ip 1.2.3.4,5.6.7.8 --range 2000:50000 --mode monitor
set -euo pipefail

REPO_DIR=$(cd "$(dirname "$0")" && pwd)

PREFIX=/opt/fw-admin
STATE_DIR=/etc/fw-admin
LIBEXEC_DIR=/usr/local/sbin
F2B_DIR=/etc/f2b
GEO_CONF_DIR=/etc/f2b-geo
WEB_BIND=0.0.0.0
WEB_PORT=4443
PORT_RANGE=2000:50000
MODE=
ROLLBACK=120
ADMIN_IPS=
ALWAYS_ALLOW=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,100.64.0.0/10
RTP_RANGES=
RANGE_GIVEN=0
WEB_GIVEN=0
ROLLBACK_GIVEN=0
ALWAYS_GIVEN=0
RTP_GIVEN=0
WITH_SIP_GEO=0
WITH_F2B_GUARD=0
JAIL=freeswitch-sip
SIP_PORTS=5060:5091
GEO_RTP_PORTS=10000:10500
CN_IPSET=cn_ip
ALLOW_IPSET=f2b_allow
PASSWORD=
NONINTERACTIVE=0
SKIP_DEPS=0
DRY_RUN=0

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" = 1 ]; then printf '    + %s\n' "$*"; else "$@"; fi; }

usage() {
  cat <<EOF
cn-geo-firewall 安装脚本

必填（非交互时）:
  --admin-ip IP[,IP...]   允许访问 Web 管理页的来源 IP（同时全端口放行）

常用:
  --range LO:HI           国内 IP 允许的端口范围，默认 2000:50000
  --mode MODE             初始模式 disabled|monitor，默认 disabled（enforce 请装好后在 Web 切换）
  --web-port PORT         Web 管理端口，默认 4443
  --web-bind ADDR         监听地址，默认 0.0.0.0
  --rollback SECONDS      enforce 自动回滚窗口，默认 120
  --rtp LO:HI[,LO:HI]     永不按 IP 过滤的 UDP 段（RTP 媒体）
  --always-allow CIDR,..  恒放行网段，默认私网 + 回环 + CGNAT
  --password PW           设置 Web 密码（不推荐，会进 shell history；交互安装会提示输入）
  --non-interactive       不提示任何输入
  --skip-deps             不自动安装缺失依赖
  --dry-run               只打印动作，不落盘

可选组件:
  --with-sip-geo          额外安装 SIP/RTP 地域封禁链 F2B-GEO（Docker 宿主）
  --sip-ports A:B[ C:D]   SIP 端口段，默认 5060:5091
  --geo-rtp-ports A:B..   RTP 端口段，默认 10000:10500
  --with-fail2ban-guard   每分钟把 fail2ban 封禁集重新挂回 DOCKER-USER
  --jail NAME             fail2ban jail 名，默认 freeswitch-sip

示例:
  sudo ./install.sh --admin-ip 203.0.113.10
  sudo ./install.sh --admin-ip 203.0.113.10 --range 1024:65535 --mode monitor
  sudo ./install.sh --admin-ip 203.0.113.10 --with-sip-geo --with-fail2ban-guard
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --admin-ip)            ADMIN_IPS="${ADMIN_IPS:+$ADMIN_IPS,}$2"; shift 2 ;;
    --range)               PORT_RANGE=$2; RANGE_GIVEN=1; shift 2 ;;
    --mode)                MODE=$2; shift 2 ;;
    --web-port)            WEB_PORT=$2; WEB_GIVEN=1; shift 2 ;;
    --web-bind)            WEB_BIND=$2; WEB_GIVEN=1; shift 2 ;;
    --rollback)            ROLLBACK=$2; ROLLBACK_GIVEN=1; shift 2 ;;
    --rtp)                 RTP_RANGES=$2; RTP_GIVEN=1; shift 2 ;;
    --always-allow)        ALWAYS_ALLOW=$2; ALWAYS_GIVEN=1; shift 2 ;;
    --password)            PASSWORD=$2; shift 2 ;;
    --non-interactive)     NONINTERACTIVE=1; shift ;;
    --skip-deps)           SKIP_DEPS=1; shift ;;
    --dry-run)             DRY_RUN=1; shift ;;
    --with-sip-geo)        WITH_SIP_GEO=1; shift ;;
    --sip-ports)           SIP_PORTS=$2; shift 2 ;;
    --geo-rtp-ports)       GEO_RTP_PORTS=$2; shift 2 ;;
    --with-fail2ban-guard) WITH_F2B_GUARD=1; shift ;;
    --jail)                JAIL=$2; shift 2 ;;
    -h|--help)             usage; exit 0 ;;
    *)                     die "未知参数: $1（--help 查看用法）" ;;
  esac
done

case "$PORT_RANGE" in
  *:*:*) die "--range 格式应为 LO:HI" ;;
  *:*)   ;;
  *)     die "--range 格式应为 LO:HI" ;;
esac
if [ -n "$MODE" ] && [ "$MODE" != "disabled" ] && [ "$MODE" != "monitor" ]; then
  die "--mode 只接受 disabled|monitor。enforce 请在安装完成后从 Web 切换（带自动回滚保护）"
fi

if [ "$DRY_RUN" = 0 ] && [ "$(id -u)" -ne 0 ]; then
  die "请用 root 运行（需要 iptables/ipset 与 systemd 写权限）"
fi

if [ "$DRY_RUN" = 0 ] && ! command -v systemctl >/dev/null 2>&1; then
  die "未检测到 systemd，本脚本依赖 systemd 单元"
fi

# ---------- 依赖 ----------
install_pkgs() {
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$@"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$@"
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install "$@"
  else
    die "未识别的包管理器，请手动安装: $*"
  fi
}

MISSING=()
for c in iptables ipset python3 curl; do
  command -v "$c" >/dev/null 2>&1 || MISSING+=("$c")
done
if [ ${#MISSING[@]} -gt 0 ]; then
  if [ "$DRY_RUN" = 1 ]; then
    warn "dry-run：缺少依赖 ${MISSING[*]}（真实安装时会自动安装）"
  elif [ "$SKIP_DEPS" = 1 ]; then
    die "缺少依赖: ${MISSING[*]}（去掉 --skip-deps 可自动安装）"
  else
    PKGS="iptables ipset python3 curl"
    say "安装依赖: $PKGS"
    run install_pkgs $PKGS
  fi
fi

PYTHON=$(command -v python3 || true)
[ -n "$PYTHON" ] || die "python3 不可用"
FLOCK=$(command -v flock || echo /usr/bin/flock)

# ---------- 管理 IP ----------
CONFIG_PATH="$STATE_DIR/config.json"

existing_admins() {
  [ -f "$CONFIG_PATH" ] || return 0
  "$PYTHON" - "$CONFIG_PATH" <<'PY'
import json, sys
try:
    print(",".join(json.load(open(sys.argv[1])).get("admin_ips", [])))
except Exception:
    pass
PY
}

SAVED_ADMINS=$(existing_admins)
if [ -z "$ADMIN_IPS" ] && [ -n "$SAVED_ADMINS" ]; then
  ADMIN_IPS=$SAVED_ADMINS
  warn "未指定 --admin-ip，沿用已有配置: $ADMIN_IPS"
fi
if [ -z "$ADMIN_IPS" ]; then
  ssh_ip="${SSH_CONNECTION%% *}"
  if [ -n "${ssh_ip:-}" ]; then
    ADMIN_IPS=$ssh_ip
    warn "未指定 --admin-ip，使用当前 SSH 来源：$ssh_ip"
  elif [ "$NONINTERACTIVE" = 0 ] && [ -t 0 ]; then
    read -r -p "允许访问 Web 的管理 IP（逗号分隔）: " ADMIN_IPS
  fi
fi
[ -n "$ADMIN_IPS" ] || die "必须用 --admin-ip 指定至少一个管理 IP"
"$PYTHON" - "$ADMIN_IPS" <<'PY' || die "管理 IP 格式错误"
import ipaddress, sys
for item in sys.argv[1].split(","):
    ipaddress.ip_network(item.strip(), strict=False)
PY

# ---------- 密码 ----------
existing_hash() {
  [ -f "$CONFIG_PATH" ] || return 0
  "$PYTHON" - "$CONFIG_PATH" <<'PY'
import json, sys
try:
    print(json.load(open(sys.argv[1])).get("password_hash", ""))
except Exception:
    pass
PY
}

PW=""
PW_GENERATED=0
if [ -n "$PASSWORD" ]; then
  PW=$PASSWORD
elif [ -n "$(existing_hash)" ]; then
  PW=""
elif [ "$NONINTERACTIVE" = 0 ] && [ -t 0 ]; then
  while :; do
    read -r -s -p "设置 Web 管理密码: " p1; echo
    read -r -s -p "再输入一次: " p2; echo
    [ -n "$p1" ] && [ "$p1" = "$p2" ] && break
    warn "两次输入不一致或为空，请重试"
  done
  PW=$p1
else
  PW=$("$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(12))')
  PW_GENERATED=1
fi

# ---------- 落盘 ----------
say "安装文件到 $PREFIX / $LIBEXEC_DIR"
run install -d -m 0755 "$PREFIX" "$STATE_DIR" "$LIBEXEC_DIR" "$F2B_DIR" "$GEO_CONF_DIR" /var/lib/f2b-geo
run install -m 0755 "$REPO_DIR/fw_admin.py" "$PREFIX/fw_admin.py"
run install -m 0755 "$REPO_DIR/scripts/f2b-geo-load.sh" "$LIBEXEC_DIR/f2b-geo-load.sh"
run install -m 0755 "$REPO_DIR/scripts/f2b-geo-refresh.sh" "$LIBEXEC_DIR/f2b-geo-refresh.sh"
run install -m 0755 "$REPO_DIR/scripts/f2b-guard.sh" "$LIBEXEC_DIR/f2b-guard.sh"

say "写入配置 $CONFIG_PATH"
if [ "$DRY_RUN" = 1 ]; then
  echo "    + 生成/合并 JSON 配置（保留已有密码与模式）"
else
  ADMIN_IPS="$ADMIN_IPS" WEB_BIND="$WEB_BIND" WEB_PORT="$WEB_PORT" \
  PORT_RANGE="$PORT_RANGE" MODE="$MODE" ROLLBACK="$ROLLBACK" \
  ALWAYS_ALLOW="$ALWAYS_ALLOW" RTP_RANGES="$RTP_RANGES" \
  RANGE_GIVEN="$RANGE_GIVEN" WEB_GIVEN="$WEB_GIVEN" ROLLBACK_GIVEN="$ROLLBACK_GIVEN" \
  ALWAYS_GIVEN="$ALWAYS_GIVEN" RTP_GIVEN="$RTP_GIVEN" \
  CN_IPSET="$CN_IPSET" ALLOW_IPSET="$ALLOW_IPSET" ADMIN_PASSWORD="$PW" \
  "$PYTHON" - "$CONFIG_PATH" <<'PY'
import hashlib
import json
import os
import secrets
import sys

path = sys.argv[1]
env = os.environ


def split(value):
    return [x.strip() for x in value.split(",") if x.strip()]


try:
    with open(path) as fh:
        cfg = json.load(fh)
except Exception:
    cfg = {}

lo, hi = env["PORT_RANGE"].split(":")[:2]
rtp = []
for part in split(env.get("RTP_RANGES", "")):
    a, b = part.split(":")[:2]
    rtp.append([int(a), int(b)])

cfg["admin_ips"] = split(env["ADMIN_IPS"]) or cfg.get("admin_ips", [])
cfg["cn_ipset"] = env["CN_IPSET"]
cfg["allow_ipset"] = env["ALLOW_IPSET"]
if env.get("WEB_GIVEN") == "1" or "web_bind" not in cfg:
    cfg["web_bind"] = env["WEB_BIND"]
    cfg["web_port"] = int(env["WEB_PORT"])
if env.get("RANGE_GIVEN") == "1" or "cn_allowed_range" not in cfg:
    cfg["cn_allowed_range"] = [int(lo), int(hi)]
if env.get("ROLLBACK_GIVEN") == "1" or "rollback_seconds" not in cfg:
    cfg["rollback_seconds"] = int(env["ROLLBACK"])
if env.get("ALWAYS_GIVEN") == "1" or "always_allow_nets" not in cfg:
    cfg["always_allow_nets"] = split(env["ALWAYS_ALLOW"])
if env.get("RTP_GIVEN") == "1" or "rtp_udp_ranges" not in cfg:
    cfg["rtp_udp_ranges"] = rtp
if env.get("MODE"):
    cfg["mode"] = env["MODE"]
cfg.setdefault("mode", "disabled")
cfg.setdefault("last_mode", "monitor")
cfg.setdefault("armed_until", 0)
cfg.setdefault("guard_chain", "CN_GUARD")
cfg.setdefault("verdict_chain", "CN_VERDICT")
cfg.setdefault("log_accepted", True)
cfg.setdefault("geo_enabled", True)
cfg.setdefault("geo_api", "http://ip-api.com/batch?lang=zh-CN&fields=status,country,regionName,city,isp,query")
cfg.setdefault("geo_max_per_cycle", 100)
cfg.setdefault("cn_sources", [
    "https://www.ipdeny.com/ipblocks/data/countries/cn.zone",
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt",
])
cfg.setdefault("password_salt", "")
cfg.setdefault("password_hash", "")
cfg.setdefault("session_secret", "")

if not cfg["session_secret"]:
    cfg["session_secret"] = secrets.token_hex(32)

pw = env.get("ADMIN_PASSWORD", "")
if pw:
    salt = secrets.token_hex(8)
    cfg["password_salt"] = salt
    cfg["password_hash"] = hashlib.sha256((salt + pw).encode()).hexdigest()

with open(path, "w") as fh:
    json.dump(cfg, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
print("    config written, mode=%s range=%s" % (cfg["mode"], cfg["cn_allowed_range"]))
PY
  chmod 600 "$CONFIG_PATH"
fi

# 允许名单：只在不存在时创建，绝不覆盖用户维护的列表
if [ ! -f "$F2B_DIR/allow-v4.list" ]; then
  say "创建 $F2B_DIR/allow-v4.list"
  if [ "$DRY_RUN" = 1 ]; then
    echo "    + 写入私网/回环/CGNAT 授权网段"
  else
    cat > "$F2B_DIR/allow-v4.list" <<'EOF'
# 必须放行的来源：不做地域判定（私网 / 回环 / 运营商级 NAT）
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
100.64.0.0/10
EOF
    chmod 644 "$F2B_DIR/allow-v4.list"
  fi
fi

# 脚本运行时配置
say "写入 $GEO_CONF_DIR/env"
GUARD_JAIL=""
GUARD_SIP=""
GUARD_RTP=""
if [ "$WITH_F2B_GUARD" = 1 ]; then GUARD_JAIL=$JAIL; fi
if [ "$WITH_SIP_GEO" = 1 ]; then
  GUARD_SIP=$SIP_PORTS
  GUARD_RTP=$GEO_RTP_PORTS
fi
if [ "$DRY_RUN" = 1 ]; then
  echo "    + F2B_DIR=$F2B_DIR CN_IPSET=$CN_IPSET JAIL=$GUARD_JAIL SIP_PORTS=$GUARD_SIP"
else
  cat > "$GEO_CONF_DIR/env" <<EOF
# 由 install.sh 生成；修改后 systemctl restart f2b-geo-refresh.service / f2b-guard.timer
F2B_DIR=$F2B_DIR
LIBEXEC_DIR=$LIBEXEC_DIR
CN_IPSET=$CN_IPSET
ALLOW_IPSET=$ALLOW_IPSET
CN_MIN_ENTRIES=1000
CN_MIN_PREFIXES=5000
JAIL=$GUARD_JAIL
SIP_PORTS=$GUARD_SIP
RTP_PORTS=$GUARD_RTP
EOF
  chmod 644 "$GEO_CONF_DIR/env"
fi

# ---------- CN 名单 ----------
if [ "$DRY_RUN" = 0 ]; then
  ENTRIES=$(ipset list "$CN_IPSET" 2>/dev/null | awk '/Number of entries/{print $4}')
  if [ "${ENTRIES:-0}" -lt 1000 ]; then
    say "初始化 CN 前缀表（需要访问公网）"
    "$LIBEXEC_DIR/f2b-geo-refresh.sh" || warn "CN 名单初始化失败：地域规则在名单就绪前不会启用（可稍后重跑）"
  fi
fi

# ---------- systemd ----------
say "安装 systemd 单元"
render_unit() {
  src=$1
  dst=/etc/systemd/system/$(basename "$src")
  if [ "$DRY_RUN" = 1 ]; then
    echo "    + $dst"
    return 0
  fi
  sed -e "s|@PREFIX@|$PREFIX|g" \
      -e "s|@STATE_DIR@|$STATE_DIR|g" \
      -e "s|@LIBEXEC_DIR@|$LIBEXEC_DIR|g" \
      -e "s|@PYTHON@|$PYTHON|g" \
      -e "s|@FLOCK@|$FLOCK|g" "$src" > "$dst"
  chmod 644 "$dst"
}

render_unit "$REPO_DIR/systemd/fw-admin.service"
render_unit "$REPO_DIR/systemd/f2b-geo-refresh.service"
render_unit "$REPO_DIR/systemd/f2b-geo-refresh.timer"
if [ "$WITH_SIP_GEO" = 1 ] || [ "$WITH_F2B_GUARD" = 1 ]; then
  render_unit "$REPO_DIR/systemd/f2b-guard.service"
  render_unit "$REPO_DIR/systemd/f2b-guard.timer"
fi

run systemctl daemon-reload
run systemctl enable fw-admin.service
run systemctl restart fw-admin.service
run systemctl enable --now f2b-geo-refresh.timer
if [ "$WITH_SIP_GEO" = 1 ] || [ "$WITH_F2B_GUARD" = 1 ]; then
  run systemctl enable --now f2b-guard.timer
else
  run systemctl disable --now f2b-guard.timer 2>/dev/null || true
fi

# ---------- 汇总 ----------
echo
say "安装完成"
echo "  程序目录 : $PREFIX"
echo "  配置文件 : $CONFIG_PATH"
echo "  CN 名单  : $F2B_DIR/cn-v4.list"
echo "  管理地址 : http://<服务器IP>:$WEB_PORT  （仅 admin_ips 与 localhost 可访问）"
echo "  管理 IP  : $ADMIN_IPS"
CURRENT_MODE=$("$PYTHON" -c 'import json,sys;print(json.load(open(sys.argv[1]))["mode"])' "$CONFIG_PATH" 2>/dev/null || echo "disabled")
echo "  当前模式 : $CURRENT_MODE"
if [ "$PW_GENERATED" = 1 ]; then
  echo "  初始密码 : $PW    <-- 仅显示这一次，请立即保存"
elif [ -n "$PW" ]; then
  echo "  密码     : 已按 --password 设置"
else
  echo "  密码     : 沿用已有配置（未修改）"
fi
echo
echo "  下一步：登录 Web → 切到 monitor 观察一到两天 → 再切 enforce（120 秒内确认，否则自动回滚）"
echo "  查看日志：journalctl -u fw-admin -f"
echo
