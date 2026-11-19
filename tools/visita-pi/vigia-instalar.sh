# Instala o VIGIA do Guardian no Pi. Para colar em PC > Executar agora > Raspberry Pi (o mestre assina; roda como root, uma vez).
# O vigia roda a cada 2 min e conserta sozinho o que já derrubou o site: Docker parado, contêiner do Tailscale parado,
# site sem responder por dentro (recria só o contêiner do site) e publicação do Tailscale recusando (reinicia o contêiner do
# Tailscale, no máximo 1 vez a cada 15 min). Não recria o Tailscale nem mexe nos volumes. Registro: journalctl -t guardian-vigia
set -e
D=/usr/local/lib/guardian-root
mkdir -p "$D" /var/lib/guardian-vigia
cat > "$D/vigia.sh" <<'VIGIA'
#!/bin/sh
TS=deploy-tailscale-1
GW=deploy-gateway-1
S=/var/lib/guardian-vigia
log() { logger -t guardian-vigia "$*"; echo "$*"; }
count() { n=$(( $(cat "$S/$1" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$S/$1"; echo "$n"; }
ok() { echo 0 > "$S/$1"; }
if ! systemctl is-active --quiet docker; then log "Docker parado: ligando"; systemctl start docker; exit 0; fi
st=$(docker inspect -f '{{.State.Status}}' "$TS" 2>/dev/null)
if [ "$st" != running ]; then log "Tailscale do Guardian em '$st': iniciando (mesmo contêiner)"; docker start "$TS" >/dev/null; exit 0; fi
# 1) o site responde por dentro da rede do Tailscale? (é o caminho que a publicação usa)
if docker exec "$TS" wget -q -T 5 -O - http://127.0.0.1:8080/healthz 2>/dev/null | grep -q '"ok"'; then
  ok site
else
  n=$(count site)
  if [ "$n" -ge 2 ]; then
    log "site sem resposta há $n verificações: recriando só o contêiner do site"
    (cd /opt/guardian && docker compose --env-file deploy/gateway.env -f deploy/docker-compose.yml up -d --no-deps --force-recreate gateway) >/dev/null 2>&1 || log "recriar o site falhou"
    ok site
  fi
  exit 0
fi
# 2) a publicação responde pela tailnet? (o mesmo caminho do celular e do PC). Só confere com o Tailscale do próprio Pi no ar.
tailscale status >/dev/null 2>&1 || { log "Tailscale do Pi fora do ar: esperando"; exit 0; }
ORIGIN=$(sed -n 's/^GATEWAY_ORIGIN=//p' /opt/guardian/deploy/gateway.env 2>/dev/null | tr -d '\r" ')
[ -n "$ORIGIN" ] || exit 0
if curl -fsS -m 10 "$ORIGIN/healthz" 2>/dev/null | grep -q '"ok"'; then ok pub; exit 0; fi
n=$(count pub)
last=$(cat "$S/restart" 2>/dev/null || echo 0)
if [ "$n" -ge 3 ] && [ $(( $(date +%s) - last )) -ge 900 ]; then
  log "publicação sem resposta há $n verificações: reiniciando o contêiner do Tailscale do Guardian"
  date +%s > "$S/restart"
  docker restart "$TS" >/dev/null 2>&1 || log "reiniciar o Tailscale falhou"
  ok pub
fi
VIGIA
chmod 0755 "$D/vigia.sh"
cat > /etc/systemd/system/guardian-vigia.service <<'UNIT'
[Unit]
Description=Guardian: vigia do site (conserta sozinho)
After=docker.service network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/lib/guardian-root/vigia.sh
TimeoutStartSec=300
UNIT
cat > /etc/systemd/system/guardian-vigia.timer <<'UNIT'
[Unit]
Description=Guardian: vigia do site a cada 2 min
[Timer]
OnBootSec=3min
OnUnitInactiveSec=2min
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now guardian-vigia.timer
echo "== primeira verificação"
"$D/vigia.sh"; echo "(fim: código $?)"
echo "== timer"; systemctl list-timers guardian-vigia.timer --no-pager | head -3
