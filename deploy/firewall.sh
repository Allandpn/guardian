#!/bin/sh
# Isola o gateway: o container (rede br-guardian) só pode sair para a internet.
# Bloqueia LAN/RFC1918, link-local, CGNAT/Tailscale do host e o próprio host (INPUT).
# O Docker por padrão deixa containers alcançarem a LAN por NAT: estas regras são OBRIGATÓRIAS.
# Rode como root, depois que o Docker subiu (guardian-firewall.service refaz a cada boot). Idempotente.
set -eu
BR=br-guardian
CH=GUARDIAN_GW

iptables -N "$CH" 2>/dev/null || true
iptables -F "$CH"
iptables -A "$CH" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10 127.0.0.0/8; do
  iptables -A "$CH" -d "$net" -j DROP
done
iptables -A "$CH" -j RETURN
iptables -C DOCKER-USER -i "$BR" -j "$CH" 2>/dev/null || iptables -I DOCKER-USER -i "$BR" -j "$CH"

# Tráfego do container para o próprio host (não passa por DOCKER-USER, passa por INPUT).
iptables -C INPUT -i "$BR" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
  || iptables -I INPUT -i "$BR" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C INPUT -i "$BR" -j DROP 2>/dev/null || iptables -A INPUT -i "$BR" -j DROP

# IPv6: o Docker não habilita por padrão; confirme que a rede não tem IPv6 (docker network inspect guardian_net).
echo "regras aplicadas para $BR"
