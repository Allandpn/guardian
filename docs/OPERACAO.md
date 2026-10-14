# Operação: instalar e manter

Pré-requisitos: Pi com Docker e Tailscale (nó do Pi na sua tailnet), Pi-hole **v6** funcionando, conta admin da tailnet.

## 1. Tailscale

1. No admin console: ative **MagicDNS** e **HTTPS**. Ajuste a ACL com base em `deploy/tailscale-acl.example.json`
   (tags `tag:gateway`, `tag:pi`, `tag:protegido`; atributo `funnel` **só** em `tag:gateway`; `tag:gateway` sem destinos).
2. Gere uma chave de autenticação: **efêmera**, **pré-autorizada**, **uso único**, com `tag:gateway`.
3. O hostname público será `https://<TS_HOSTNAME>.<tailnet>.ts.net`. Ele é o `rpId` dos passkeys: **não o renomeie depois**.

## 2. Gateway (container isolado)

```sh
sudo mkdir -p /opt/guardian && sudo cp -r . /opt/guardian && cd /opt/guardian
sudo deploy/firewall.sh                                  # obrigatório; instale deploy/guardian-firewall.service para refazer a cada boot
cp deploy/gateway.env.example deploy/gateway.env         # preencha TS_AUTHKEY e GATEWAY_ORIGIN
docker compose --env-file deploy/gateway.env -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml exec gateway python -m guardian.gateway init --name "Nome do 1º guardião"
```

O último comando imprime um link de convite (24 h, uso único). O guardião abre o link, cadastra o passkey e já entra.
Confirme: `curl https://<hostname>/healthz` (de fora da sua rede) e, de dentro do container, que a LAN **não** responde.
Confirme também que `docker network inspect guardian_net` não tem IPv6.

## 3. Executor no Pi

```sh
sudo useradd --system --home /var/lib/guardian-executor --shell /usr/sbin/nologin guardian-exec
sudo python3 -m venv /opt/guardian/.venv && sudo /opt/guardian/.venv/bin/pip install /opt/guardian
# senha de aplicativo do Pi-hole v6 (Settings > Web interface / API > Configure app password):
sudo install -m 0600 -o guardian-exec /dev/stdin /etc/guardian-executor.pihole        # cole a senha, Ctrl-D
sudo install -m 0600 deploy/executor.env.example /etc/guardian-executor.env           # edite PIHOLE_URL, CANARY
```

No site (Guardiões → **Parear executor Pi-hole**) copie a string de pareamento e rode:

```sh
sudo -u guardian-exec env $(cat /etc/guardian-executor.env | xargs) EXECUTOR_STATE=/var/lib/guardian-executor \
  PYTHONPATH=/opt/guardian/src /opt/guardian/.venv/bin/python -m guardian.executor pair --pairing '<string>'
sudo cp deploy/guardian-executor.service /etc/systemd/system/ && sudo systemctl enable --now guardian-executor
```

Confira o fingerprint impresso com o que aparece no site. A API do Pi-hole v6 usa a mesma porta da interface web: se a porta 80/443 colide com
outros serviços seus, mude em `pihole.toml` (`webserver.port`) e ajuste `PIHOLE_URL`.

## 4. Segundo guardião e aparelhos

- Site → Guardiões → **Convidar guardião**: envie o link. Depois que ele cadastrar, use **Propagar** em cada aparelho/executor
  (um toque de passkey por item) para que passem a confiar nele. Peça que cada guardião cadastre um **segundo passkey** (chave física ou outro celular).
- **Parear aparelho**: no site, Guardiões → **Parear aparelho**; no NotToday (tela de PIN) → **Parear com Guardian remoto** e cole a string *antes* do
  `set-device-owner`. O app mostra o **fingerprint**: confira por voz com o que o site mostra para o aparelho. Depois defina o PIN pelo site
  (aparelho → PINs), ajuste o atraso (aparelho → Configuração → `unlock_delay_min`) e só então `adb shell dpm set-device-owner com.allan.nottoday/.AdminReceiver`.
  Detalhes e riscos em `docs/REMOTO.md` e `docs/LOCKOUT.md` (#25) do NotToday.
- **Notificações**: cada guardião abre o site no celular, instala-o na tela inicial (obrigatório no iPhone) e em Guardiões → **Ativar notificações**.
  Defina `GATEWAY_PUSH_SUBJECT=mailto:voce@exemplo.com` (contato do VAPID). Use **Enviar teste** para conferir.

## 5. Manutenção

- **Backups:** o `gateway.db` guarda só chaves públicas, fila e relatórios (nada secreto). Se for perdido, gere novo convite com `init`; aparelhos e executor
  mantêm a confiança fixada e os contadores (o site usa o maior entre o gateway e o relatado).
  Guarde `/var/lib/guardian-executor` (chave e estado do executor) e o volume `ts-state`.
- **Atualizar:** reconstrua a imagem periodicamente (`docker compose build --pull`), fixe a imagem do Tailscale por digest e atualize o Pi-hole.
- **Monitorar:** o site marca "sem sinal" quando um aparelho fica 5 min sem consultar a fila. `docker logs` tem rotação (5 MB × 3).
- **Rotacionar a chave do Tailscale:** chaves efêmeras expiram; o nó guarda o estado em `ts-state`.
- **Se o hostname mudar**, os passkeys deixam de valer e é preciso refazer o cadastro e o pareamento.
