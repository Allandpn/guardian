#!/bin/sh
# Manda para o Suricata (fila 0) só o tráfego dos aparelhos que usam este Pi como exit node:
# Tailscale -> internet e a volta. --queue-bypass: se o Suricata cair, o tráfego passa (nada fica sem internet).
# Rode como root, depois que o container guardian-suricata subiu. Idempotente.
set -eu
WAN=${WAN:-eth0}
TS=${TS:-tailscale0}

iptables -C FORWARD -i "$TS" -o "$WAN" -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null \
  || iptables -I FORWARD 1 -i "$TS" -o "$WAN" -j NFQUEUE --queue-num 0 --queue-bypass
iptables -C FORWARD -i "$WAN" -o "$TS" -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null \
  || iptables -I FORWARD 2 -i "$WAN" -o "$TS" -j NFQUEUE --queue-num 0 --queue-bypass
echo "torrent: tráfego $TS <-> $WAN passa pelo Suricata"
