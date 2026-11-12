#!/bin/sh
# Visita ao Pi SEM teclado, monitor nem senha: este arquivo vai na partição de boot do SSD (a pequena, FAT, que o Windows abre)
# e o cmdline.txt o chama uma vez, como root, no arranque (o mesmo mecanismo que o Raspberry Pi Imager usa para configurar um Pi sem tela).
# Passo a passo: docs/VISITA-PI.md. Ninguém ganha senha nem sudo: o script faz só o que está aqui e se apaga.
#
# Fase 1 (chamada pelo cmdline.txt, antes dos serviços): tira a chamada do cmdline.txt, instala a fase 2 como serviço de uma vez só e reinicia.
# Fase 2 (no arranque normal, depois do Docker e do deployer): confere que /opt/guardian está no commit que o mestre aprovou, troca a entrada
# "guardian" do registro, reinstala o deployer, reinicia o deployer e o executor, e registra o resultado no histórico de Deploys (aparece no site).
# Tudo o que acontece vai para guardian-visita.log, na mesma partição de boot.

# O commit que o mestre colocou no ar (release/14). Se você aprovou outro, escreva o hash completo num arquivo guardian-commit.txt ao lado deste.
EXPECTED=dbb040b1b01ab8c6011da824e47e0f631bee5248

SELF=/usr/local/sbin/guardian-visita.sh
UNIT=/etc/systemd/system/guardian-visita.service
ENVF=/etc/guardian-visita.env
REG=/etc/guardian-deploy/projects.json
STATE=/var/lib/guardian-deploy
ME=$(readlink -f "$0")

if [ "$ME" != "$SELF" ]; then
  # ------------------------------------------------------------------ fase 1
  BOOT=$(dirname "$ME")
  LOG="$BOOT/guardian-visita.log"
  echo "== $(date '+%F %T') fase 1 ($BOOT)" >> "$LOG"
  # Primeiro tira a chamada do cmdline.txt: o próximo arranque é normal, aconteça o que acontecer daqui para frente.
  sed -i -e 's/ systemd\.run=[^ ]*//g' -e 's/ systemd\.run_success_action=[^ ]*//g' -e 's/ systemd\.unit=kernel-command-line\.target//g' "$BOOT/cmdline.txt"
  echo "cmdline.txt de volta ao normal: $(cat "$BOOT/cmdline.txt")" >> "$LOG"
  install -m 0700 -o root -g root "$ME" "$SELF"
  printf 'BOOT=%s\n' "$BOOT" > "$ENVF"
  cat > "$UNIT" <<EOF
[Unit]
Description=Guardian: visita ao Pi (roda uma vez e se apaga)
Wants=network-online.target
After=network-online.target docker.service guardian-deployer.service guardian-executor.service

[Service]
Type=oneshot
EnvironmentFile=$ENVF
ExecStart=$SELF
TimeoutStartSec=900

[Install]
WantedBy=multi-user.target
EOF
  mkdir -p /etc/systemd/system/multi-user.target.wants
  ln -sf "$UNIT" /etc/systemd/system/multi-user.target.wants/guardian-visita.service
  echo "fase 2 instalada; reiniciando" >> "$LOG"
  sync
  exit 0
fi

# -------------------------------------------------------------------- fase 2
BOOT=${BOOT:-/boot/firmware}
LOG="$BOOT/guardian-visita.log"
exec >> "$LOG" 2>&1
echo "== $(date '+%F %T') fase 2"

finish() {   # $1 = 0 deu certo / 1 falhou; $2 = mensagem
  echo "$2"
  # Registra no histórico de Deploys: o site mostra em "Últimos deploys" (o deployer lê o status.json ao reiniciar).
  python3 - "$1" "$2" <<'PY' || echo "não consegui registrar no histórico"
import json, sys, time
p = "/var/lib/guardian-deploy/status.json"
try:
    st = json.load(open(p))
except (OSError, ValueError):
    st = {"history": []}
st["history"] = ([{"ts": int(time.time()), "project": "visita", "commit": "deployer", "ok": sys.argv[1] == "0", "rolled_back": False,
                   "by": "", "msg": sys.argv[2][:200]}] + st.get("history", []))[:20]
json.dump(st, open(p + ".tmp", "w"))
import os
os.chmod(p + ".tmp", 0o644)
os.replace(p + ".tmp", p)
PY
  systemctl restart guardian-deployer || echo "falhou reiniciar o deployer"
  # Roda uma vez só: tira o serviço, o arquivo de ambiente, esta cópia e o script da partição de boot.
  rm -f /etc/systemd/system/multi-user.target.wants/guardian-visita.service "$UNIT" "$ENVF" "$BOOT/guardian-visita.sh"
  systemctl daemon-reload
  echo "== $(date '+%F %T') fim ($([ "$1" = 0 ] && echo OK || echo FALHOU))"
  sync
  rm -f "$SELF"
  exit "$1"
}

if [ -f "$BOOT/guardian-commit.txt" ]; then
  EXPECTED=$(tr -cd '0-9a-f' < "$BOOT/guardian-commit.txt")   # aceita o arquivo com BOM e fim de linha do Windows
fi
echo "$EXPECTED" | grep -Eq '^[0-9a-f]{40}$' || finish 1 "commit esperado inválido ($EXPECTED): use o hash completo de 40 caracteres"

HAVE=$(git -C /opt/guardian -c safe.directory=/opt/guardian rev-parse HEAD 2>/dev/null)
[ "$HAVE" = "$EXPECTED" ] || finish 1 "a versão no ar ($HAVE) não é a esperada ($EXPECTED): coloque a release no ar em Deploys antes. Nada foi mudado."
echo "versão no ar confere: $HAVE"

[ -f "$REG" ] || finish 1 "não achei $REG. Nada foi mudado."
cp -p "$REG" "$REG.antes-da-visita" || finish 1 "não consegui guardar uma cópia de $REG. Nada foi mudado."

python3 - "$REG" /opt/guardian/deploy/deploy-projects.example.json <<'PY' || finish 1 "não consegui atualizar o registro. Nada foi mudado."
import json, os, sys
p, ex = sys.argv[1], sys.argv[2]
reg = json.load(open(p))
new = json.load(open(ex))["guardian"]
old = reg.get("guardian") or {}
keep = {k: old[k] for k in ("repo", "workdir", "tag_prefix", "token_file", "ssh_key", "health", "health_timeout_s") if k in old}
reg["guardian"] = {**new, **keep}
tmp = p + ".tmp"
with open(tmp, "w") as f:
    json.dump(reg, f, indent=2, ensure_ascii=False)
os.chmod(tmp, 0o644)
os.replace(tmp, p)
print("registro atualizado:", json.dumps(reg["guardian"], ensure_ascii=False))
PY

if ! sh /opt/guardian/deploy/install-deployer.sh; then
  cp -p "$REG.antes-da-visita" "$REG"
  finish 1 "install-deployer.sh falhou; o registro voltou ao que era (veja guardian-visita.log)"
fi
systemctl daemon-reload
systemctl restart guardian-executor || echo "falhou reiniciar o executor"
systemctl restart guardian-deployer || echo "falhou reiniciar o deployer"
for i in $(seq 1 30); do   # até 5 min: o deployer regrava o offers.json depois de buscar as etiquetas de todos os projetos
  sleep 10
  if grep -q '"pi_run"' "$STATE/offers.json" 2>/dev/null && systemctl is-active --quiet guardian-deployer; then
    finish 0 "deployer novo instalado (versão $(echo "$HAVE" | cut -c1-8)), registro do guardian atualizado e scripts de root fora do checkout"
  fi
done
finish 1 "o deployer reinstalado não confirmou (offers.json sem pi_run ou serviço parado); veja guardian-visita.log"
