#!/bin/sh
# 重建 geo ipset。先建 <name>_new 再 ipset swap：
# 规则语义是 "! --match-set cn_ip src DROP"，集合中途为空 = 丢掉所有非内网流量。
set -e
[ -r /etc/f2b-geo/env ] && . /etc/f2b-geo/env

F2B_DIR=${F2B_DIR:-/etc/f2b}
CN_IPSET=${CN_IPSET:-cn_ip}
ALLOW_IPSET=${ALLOW_IPSET:-f2b_allow}
CN_MAXELEM=${CN_MAXELEM:-65536}
ALLOW_MAXELEM=${ALLOW_MAXELEM:-1024}

build() {
  name=$1
  src=$2
  elem=$3
  if [ ! -s "$src" ]; then
    echo "跳过 $name：$src 不存在或为空" >&2
    return 0
  fi
  tmp=$(mktemp)
  {
    echo "create ${name}_new hash:net maxelem ${elem}"
    awk -v n="${name}_new" 'NF && $1 !~ /^#/ { print "add " n " " $1 }' "$src"
  } > "$tmp"
  ipset destroy "${name}_new" 2>/dev/null || true
  ipset restore -! < "$tmp"
  rm -f "$tmp"
  ipset create "$name" hash:net maxelem "$elem" 2>/dev/null || true
  ipset swap "${name}_new" "$name"
  ipset destroy "${name}_new" 2>/dev/null || true
  echo "$name: $(ipset list "$name" | awk '/Number of entries/{print $4}') 条"
}

build "$CN_IPSET" "$F2B_DIR/cn-v4.list" "$CN_MAXELEM"
build "$ALLOW_IPSET" "$F2B_DIR/allow-v4.list" "$ALLOW_MAXELEM"
