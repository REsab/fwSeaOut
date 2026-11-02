#!/usr/bin/env bash
# 卸载 cn-geo-firewall / fwSeaOut。默认保留配置和名单，--purge 才彻底清理。
set -euo pipefail

PREFIX=/opt/fw-admin
STATE_DIR=/etc/fw-admin
LIBEXEC_DIR=/usr/local/sbin
F2B_DIR=/etc/f2b
GEO_CONF_DIR=/etc/f2b-geo
PURGE=0
DRY_RUN=0

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" = 1 ]; then printf '    + %s\n' "$*"; else "$@"; fi; }

usage() {
  cat <<EOF
用法: sudo ./uninstall.sh [--purge] [--dry-run]

  默认     停止服务、摘除 CN_GUARD 挂载、删除程序与 systemd 单元，
           保留 $STATE_DIR 配置和 $F2B_DIR 名单
  --purge  连同配置、名单、ipset 一起删除
  --dry-run 只打印动作
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --purge)    PURGE=1; shift ;;
    --dry-run)  DRY_RUN=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *)          die "未知参数: $1" ;;
  esac
done

if [ "$DRY_RUN" = 0 ] && [ "$(id -u)" -ne 0 ]; then
  die "请用 root 运行"
fi

PYTHON=$(command -v python3 || true)

if command -v systemctl >/dev/null 2>&1; then
  say "停止服务"
  if [ -n "$PYTHON" ] && [ -x "$PREFIX/fw_admin.py" ] && [ -f "$STATE_DIR/config.json" ]; then
    run env FW_ADMIN_CONFIG="$STATE_DIR/config.json" FW_ADMIN_STATE="$STATE_DIR" \
        "$PYTHON" "$PREFIX/fw_admin.py" disable || warn "disable 执行失败，请手动检查 iptables"
  fi
  for unit in fw-admin.service f2b-guard.timer f2b-geo-refresh.timer f2b-guard.service f2b-geo-refresh.service; do
    if [ "$DRY_RUN" = 1 ]; then
      echo "    + systemctl disable --now $unit"
    else
      systemctl disable --now "$unit" >/dev/null 2>&1 || true
    fi
  done
  for unit in fw-admin.service f2b-guard.timer f2b-guard.service f2b-geo-refresh.timer f2b-geo-refresh.service; do
    run rm -f "/etc/systemd/system/$unit"
  done
  run systemctl daemon-reload
fi

say "删除程序文件"
run rm -rf "$PREFIX" "$GEO_CONF_DIR"
run rm -f "$LIBEXEC_DIR/f2b-geo-load.sh" "$LIBEXEC_DIR/f2b-geo-refresh.sh" "$LIBEXEC_DIR/f2b-guard.sh"

if [ "$PURGE" = 1 ]; then
  warn "--purge：同时删除配置、名单与 ipset/链"
  run rm -rf "$STATE_DIR" "$F2B_DIR" /var/lib/f2b-geo
  for set in cn_ip f2b_allow f2b-sip; do
    if [ "$DRY_RUN" = 1 ]; then
      echo "    + ipset destroy $set"
    else
      ipset destroy "$set" >/dev/null 2>&1 || true
    fi
  done
  for chain in F2B-GEO CN_VERDICT CN_GUARD; do
    if [ "$DRY_RUN" = 1 ]; then
      echo "    + iptables -F/-X $chain"
    else
      iptables -F "$chain" >/dev/null 2>&1 || true
      iptables -X "$chain" >/dev/null 2>&1 || true
    fi
  done
else
  echo "已保留配置 $STATE_DIR 与名单 $F2B_DIR（需要彻底清理请加 --purge）"
fi

say "卸载完成"
