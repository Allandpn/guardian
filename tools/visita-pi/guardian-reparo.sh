#!/bin/sh
# Conserto do site do Guardian SEM o site (ele está fora do ar) e sem teclado: vai na partição de boot do SSD e o cmdline.txt o chama uma vez,
# como root (o mesmo jeito do guardian-visita.sh; veja docs/VISITA-PI.md). Ninguém ganha senha nem sudo: faz só o que está aqui e se apaga.
#
# O que faz: anota o estado (contêineres, registros do gateway e do Tailscale, serviços do Guardian) em guardian-reparo.log, na partição de boot,
# e recria SÓ o contêiner do site (gateway). Ele usa a rede do contêiner do Tailscale; quando o do Tailscale reinicia, o do site pode ficar preso
# à rede antiga e o Funnel responde 502. O contêiner do Tailscale e os dados (volumes) não são tocados.

SELF=/usr/local/sbin/guardian-reparo.sh
UNIT=/etc/systemd/system/guardian-reparo.service
ENVF=/etc/guardian-reparo.env
ME=$(readlink -f "$0")
GW=deploy-gateway-1
TS=deploy-tailscale-1

if [ "$ME" != "$SELF" ]; then
  # ------------------------------------------------------------------ fase 1 (antes dos serviços)
  BOOT=$(dirname "$ME")
  LOG="$BOOT/guardian-reparo.log"
  echo "== $(date '+%F %T') fase 1 ($BOOT)" >> "$LOG"
  sed -i -e 's/ systemd\.run=[^ ]*//g' -e 's/ systemd\.run_success_action=[^ ]*//g' -e 's/ systemd\.unit=kernel-command-line\.target//g' "$BOOT/cmdline.txt"
  echo "cmdline.txt de volta ao normal: $(cat "$BOOT/cmdline.txt")" >> "$LOG"
  install -m 0700 -o root -g root "$ME" "$SELF"
  printf 'BOOT=%s\n' "$BOOT" > "$ENVF"
  cat > "$UNIT" <<EOF
[Unit]
Description=Guardian: conserto do site (roda uma vez e se apaga)
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
EnvironmentFile=$ENVF
ExecStart=$SELF
TimeoutStartSec=900

[Install]
WantedBy=multi-user.target
EOF
  mkdir -p /etc/systemd/system/multi-user.target.wants
  ln -sf "$UNIT" /etc/systemd/system/multi-user.target.wants/guardian-reparo.service
  echo "fase 2 instalada; reiniciando" >> "$LOG"
  sync
  exit 0
fi

# -------------------------------------------------------------------- fase 2 (arranque normal, depois do Docker)
BOOT=${BOOT:-/boot/firmware}
LOG="$BOOT/guardian-reparo.log"
exec >> "$LOG" 2>&1
echo "== $(date '+%F %T') fase 2"
section() { echo; echo "---- $1"; }
netns() { p=$(docker inspect -f '{{.State.Pid}}' "$1" 2>/dev/null); [ -n "$p" ] && [ "$p" != 0 ] && readlink "/proc/$p/ns/net"; }
probe() {   # o site responde de dentro da rede do Tailscale? (é o caminho que o Funnel usa)
  docker exec "$TS" wget -q -T 5 -O - http://127.0.0.1:8080/healthz 2>&1 | head -c 200
}

section "Docker";                 systemctl is-active docker; systemctl is-enabled docker
if ! systemctl is-active --quiet docker; then
  echo "o Docker estava parado: ligando"
  systemctl start docker; systemctl enable docker 2>/dev/null
  systemctl --no-pager status docker 2>&1 | tail -15
fi
sleep 30   # o Docker termina de subir os contêineres que reiniciam sozinhos
section "contêineres";            docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}'
section "estado do Tailscale e do site"
for c in "$TS" "$GW"; do
  docker inspect -f "$c: {{.State.Status}} saída={{.State.ExitCode}} OOM={{.State.OOMKilled}} reinícios={{.RestartCount}} erro={{.State.Error}} política={{.HostConfig.RestartPolicy.Name}}" "$c" 2>&1
done
section "versão no ar";           git -C /opt/guardian -c safe.directory=/opt/guardian log -1 --oneline
section "serviços do Guardian";   systemctl --no-pager --plain list-units 'guardian*' 2>&1 | head -20
section "rede: site x Tailscale"; echo "site=$(netns "$GW") tailscale=$(netns "$TS")"
section "site responde (antes)";  probe; echo
section "registro do site (fim)";      docker logs --tail 60 "$GW" 2>&1
section "registro do Tailscale (fim)"; docker logs --tail 40 "$TS" 2>&1 | grep -v -i 'authkey'
section "deployer (fim)";         journalctl -u guardian-deployer -n 25 --no-pager 2>&1
section "executor (fim)";         journalctl -u guardian-executor -n 15 --no-pager 2>&1

section "conserto"
if [ "$(docker inspect -f '{{.State.Status}}' "$TS" 2>/dev/null)" != "running" ]; then
  echo "o contêiner do Tailscale não estava rodando: iniciando o mesmo contêiner (sem recriar, a identidade dele fica no volume)"
  docker start "$TS"
  sleep 20
  docker inspect -f "$TS agora: {{.State.Status}} reinícios={{.RestartCount}}" "$TS" 2>&1
  docker logs --tail 30 "$TS" 2>&1 | grep -v -i 'authkey'
fi
cd /opt/guardian && docker compose --env-file deploy/gateway.env -f deploy/docker-compose.yml up -d --no-deps --force-recreate gateway
sleep 20
section "rede depois";            echo "site=$(netns "$GW") tailscale=$(netns "$TS")"
section "site responde (depois)"
r=$(probe)
echo "$r"
if echo "$r" | grep -q '"ok"'; then RES=OK; else RES=FALHOU; fi

rm -f /etc/systemd/system/multi-user.target.wants/guardian-reparo.service "$UNIT" "$ENVF" "$BOOT/guardian-reparo.sh"
systemctl daemon-reload
echo; echo "== $(date '+%F %T') fim ($RES)"
sync
rm -f "$SELF"
