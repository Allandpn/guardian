#!/bin/sh
# Instala (ou reinstala) o deployer do Guardian no Pi. Rode como root, a partir de uma cópia confiável do repositório.
# Não liga nem habilita nada que já exista além do deployer; reinicie o executor depois (o script avisa).
set -eu
[ "$(id -u)" = 0 ] || { echo "rode como root" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
LIB=/usr/local/lib/guardian-deployer
STATE=/var/lib/guardian-deploy
EXEC_UID="$(id -u guardian-exec)"

install -d -m 0755 -o root -g root "$LIB/guardian_deployer"
install -m 0644 -o root -g root "$SRC/src/guardian/deployer/__init__.py" "$SRC/src/guardian/deployer/core.py" \
  "$SRC/src/guardian/deployer/__main__.py" "$SRC/src/guardian/deployer/policy.py" "$SRC/src/guardian/deployer/apps.py" "$LIB/guardian_deployer/"

install -d -m 0755 -o root -g root /etc/guardian-deploy
[ -f /etc/guardian-deploy/projects.json ] || install -m 0644 -o root -g root "$SRC/deploy/deploy-projects.example.json" /etc/guardian-deploy/projects.json

install -d -m 0755 -o root -g root "$STATE"
install -d -m 0700 -o guardian-exec -g guardian-exec "$STATE/inbox"

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
