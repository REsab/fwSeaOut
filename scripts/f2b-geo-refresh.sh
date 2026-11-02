#!/bin/sh
# 刷新 CN IPv4 前缀表。原则：宁可过期，不可为空 —— 任何一步校验不通过就保留旧文件。
# 两份来源都要：ipdeny（APNIC 注册体系）会漏掉在 ARIN 等注册的中国云厂商网段，需用运营商表补。
set -e
[ -r /etc/f2b-geo/env ] && . /etc/f2b-geo/env

F2B_DIR=${F2B_DIR:-/etc/f2b}
WORK=${WORK_DIR:-/var/lib/f2b-geo}
LIBEXEC_DIR=${LIBEXEC_DIR:-/usr/local/sbin}
CN_SRC_APNIC=${CN_SRC_APNIC:-https://www.ipdeny.com/ipblocks/data/countries/cn.zone}
CN_SRC_EXTRA=${CN_SRC_EXTRA:-https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt}
CN_MIN_PREFIXES=${CN_MIN_PREFIXES:-5000}

mkdir -p "$WORK" "$F2B_DIR"

fetch() { # url out minlines
  url=$1
  out=$2
  min=$3
  if curl -sSf -m 180 -o "$out.new" "$url" && [ "$(grep -c '^' "$out.new")" -ge "$min" ]; then
    mv -f "$out.new" "$out"
    echo "updated $out"
  else
    rm -f "$out.new"
    echo "KEEP OLD: $url" >&2
  fi
}

fetch "$CN_SRC_APNIC" "$WORK/cn.zone" 5000
fetch "$CN_SRC_EXTRA" "$WORK/china-extra.txt" 4000

CN_MIN_PREFIXES="$CN_MIN_PREFIXES" python3 - "$WORK" "$F2B_DIR" <<'PY'
import ipaddress
import os
import sys

work, out_dir = sys.argv[1], sys.argv[2]
minimum = int(os.environ.get("CN_MIN_PREFIXES", "5000"))


def load(path):
    nets = []
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    continue
                if net.version == 4:
                    nets.append(net)
    except FileNotFoundError:
        pass
    return nets


merged = set(load(os.path.join(work, "cn.zone"))) | set(load(os.path.join(work, "china-extra.txt")))
if len(merged) < minimum:
    sys.exit("合并结果只有 %d 条（<%d），拒绝覆盖" % (len(merged), minimum))

target = os.path.join(out_dir, "cn-v4.list")
with open(target + ".new", "w") as fh:
    for net in ipaddress.collapse_addresses(sorted(merged, key=lambda n: (n.network_address, n.prefixlen))):
        fh.write("%s\n" % net)
os.replace(target + ".new", target)
print("cn-v4.list prefixes:", sum(1 for _ in open(target)))
PY

"$LIBEXEC_DIR/f2b-geo-load.sh"
