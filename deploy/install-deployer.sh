#!/bin/sh
# Instala (ou reinstala) o deployer do Guardian no Pi. Rode como root, a partir de uma cópia confiável do repositório.
# Não liga nem habilita nada que já exista além do deployer; reinicie o executor depois (o script avisa).
set -eu
[ "$(id -u)" = 0 ] || { echo "rode como root" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
LIB=/usr/local/lib/guardian-deployer
STATE=/var/lib/guardian-deploy
EXEC_UID="$(id -u guardian-exec)"

# O deployer confere ele mesmo a assinatura do mestre (deployer/signed.py): leva uma cópia do protocolo e precisa da biblioteca cryptography.
/usr/bin/python3 -c "import cryptography" 2>/dev/null || { echo "falta a biblioteca cryptography no python do sistema: apt install python3-cryptography" >&2; exit 1; }

install -d -m 0755 -o root -g root "$LIB/guardian_deployer" "$LIB/guardian_deployer/protocol"
install -m 0644 -o root -g root "$SRC/src/guardian/deployer/__init__.py" "$SRC/src/guardian/deployer/core.py" \
  "$SRC/src/guardian/deployer/__main__.py" "$SRC/src/guardian/deployer/policy.py" "$SRC/src/guardian/deployer/apps.py" \
  "$SRC/src/guardian/deployer/signed.py" "$LIB/guardian_deployer/"
install -m 0644 -o root -g root "$SRC/src/guardian/protocol/__init__.py" "$SRC/src/guardian/protocol/commands.py" \
  "$SRC/src/guardian/protocol/webauthn.py" "$SRC/src/guardian/protocol/b64.py" "$SRC/src/guardian/protocol/cbor.py" "$LIB/guardian_deployer/protocol/"

# Scripts que rodam como root no boot (firewall do gateway, bloqueio de torrent): ficam FORA de /opt/guardian, que muda a cada versão.
# Uma versão nova não os altera; para mudá-los, reinstale (este script, como root).
ROOTLIB=/usr/local/lib/guardian-root
install -d -m 0755 -o root -g root "$ROOTLIB" "$ROOTLIB/suricata"
install -m 0755 -o root -g root "$SRC/deploy/firewall.sh" "$SRC/deploy/torrent-firewall.sh" "$ROOTLIB/"
install -m 0644 -o root -g root "$SRC/deploy/suricata/docker-compose.yml" "$SRC/deploy/suricata/torrent.rules" "$ROOTLIB/suricata/"
for u in guardian-firewall guardian-torrent-firewall; do   # só os que já estão instalados neste Pi
  if [ -f "/etc/systemd/system/$u.service" ]; then
    install -m 0644 -o root -g root "$SRC/deploy/$u.service" "/etc/systemd/system/$u.service"
  fi
done

install -d -m 0755 -o root -g root /etc/guardian-deploy
[ -f /etc/guardian-deploy/projects.json ] || install -m 0644 -o root -g root "$SRC/deploy/deploy-projects.example.json" /etc/guardian-deploy/projects.json
[ -f /etc/guardian-deploy/policy.json ] || install -m 0644 -o root -g root "$SRC/deploy/deploy-policy.example.json" /etc/guardian-deploy/policy.json

install -d -m 0755 -o root -g root "$STATE"
install -d -m 0700 -o guardian-exec -g guardian-exec "$STATE/inbox"

# Confiança própria do deployer (guardiões, passkeys, papéis, contadores), copiada UMA vez do executor. Depois só muda por comando assinado.
if [ ! -f "$STATE/trust.json" ]; then
  PYTHONPATH="$LIB" /usr/bin/python3 -m guardian_deployer init-trust --state "$STATE" --from /var/lib/guardian-executor/state.json
  echo "Confira acima: só os guardiões que você reconhece. Se algo estiver errado, apague $STATE/trust.json e corrija o executor antes."
fi

sed "s/@EXEC_UID@/$EXEC_UID/" "$SRC/deploy/guardian-deployer.service" > /etc/systemd/system/guardian-deployer.service
chmod 0644 /etc/systemd/system/guardian-deployer.service

# O executor passa a deixar pedidos na caixa do deployer e a ler as ofertas dele.
install -d -m 0755 /etc/systemd/system/guardian-executor.service.d
cat > /etc/systemd/system/guardian-executor.service.d/deploy.conf <<CONF
[Service]
Environment=DEPLOY_DIR=$STATE
ReadWritePaths=$STATE/inbox
CONF

systemctl daemon-reload
systemctl enable guardian-deployer.service
echo "Pronto. Falta: (1) a chave de leitura do GitHub em /etc/guardian-deploy/ (docs/DEPLOY.md), (2) systemctl restart guardian-executor, (3) systemctl start guardian-deployer."
