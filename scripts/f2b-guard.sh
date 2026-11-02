#!/bin/sh
# 可选组件：Docker 宿主的 SIP 地域封禁 + fail2ban 封禁集守卫。
# docker daemon 重启会重建 DOCKER-USER 空链，抹掉第三方规则；这里每分钟补一次。
# 逐条 iptables -C 判定，重复/并发执行都不会插出双份（并发由 systemd flock 保证）。
set -e
[ -r /etc/f2b-geo/env ] && . /etc/f2b-geo/env

LIBEXEC_DIR=${LIBEXEC_DIR:-/usr/local/sbin}
CN_IPSET=${CN_IPSET:-cn_ip}
ALLOW_IPSET=${ALLOW_IPSET:-f2b_allow}
CN_MIN_ENTRIES=${CN_MIN_ENTRIES:-1000}
JAIL=${JAIL:-}
SIP_PORTS=${SIP_PORTS:-}
RTP_PORTS=${RTP_PORTS:-}

command -v iptables >/dev/null 2>&1 || exit 0
iptables -L DOCKER-USER -n >/dev/null 2>&1 || exit 0

add_or_skip() { # chain spec...
  chain=$1
  shift
  iptables -C "$chain" "$@" 2>/dev/null || iptables -A "$chain" "$@"
}

# --- fail2ban 封禁集（仅当 jail 存在）---
if [ -n "$JAIL" ] && command -v fail2ban-client >/dev/null 2>&1 \
   && fail2ban-client status "$JAIL" >/dev/null 2>&1; then
  ipset list f2b-sip >/dev/null 2>&1 || ipset create f2b-sip hash:ip
  if ! iptables -C DOCKER-USER -m set --match-set f2b-sip src -j DROP 2>/dev/null; then
    iptables -I DOCKER-USER 1 -m set --match-set f2b-sip src -j DROP
  fi
  if ! iptables -C DOCKER-USER -m set --match-set f2b-sip dst -j DROP 2>/dev/null; then
    iptables -I DOCKER-USER 2 -m set --match-set f2b-sip dst -j DROP
  fi
fi

# --- geo：CN 表未就绪就完全不装 geo 规则（空集 = 全丢）---
CN=$(ipset list "$CN_IPSET" 2>/dev/null | awk '/Number of entries/{print $4}')
if [ "${CN:-0}" -lt "$CN_MIN_ENTRIES" ]; then
  "$LIBEXEC_DIR/f2b-geo-load.sh" >/dev/null 2>&1 || true
  CN=$(ipset list "$CN_IPSET" 2>/dev/null | awk '/Number of entries/{print $4}')
fi
[ "${CN:-0}" -ge "$CN_MIN_ENTRIES" ] || exit 0
ipset list "$ALLOW_IPSET" >/dev/null 2>&1 || "$LIBEXEC_DIR/f2b-geo-load.sh" >/dev/null 2>&1 || true

# 只有在配置了端口段时才启用该链
[ -n "$SIP_PORTS$RTP_PORTS" ] || exit 0

iptables -N F2B-GEO 2>/dev/null || true
add_or_skip F2B-GEO -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
if ipset list "$ALLOW_IPSET" >/dev/null 2>&1; then
  add_or_skip F2B-GEO -m set --match-set "$ALLOW_IPSET" src -j ACCEPT
fi
for r in $SIP_PORTS; do
  add_or_skip F2B-GEO -p udp -m set ! --match-set "$CN_IPSET" src --dport "$r" -j DROP
  add_or_skip F2B-GEO -p tcp -m set ! --match-set "$CN_IPSET" src --dport "$r" -j DROP
done
for r in $RTP_PORTS; do
  add_or_skip F2B-GEO -p udp -m set ! --match-set "$CN_IPSET" src --dport "$r" -j DROP
done

add_or_skip DOCKER-USER -j F2B-GEO
