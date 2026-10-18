# Protocolo guardião (v1)

Implementação de referência: `src/guardian/protocol/` (Python). O aparelho (Kotlin) deve passar os mesmos
casos de `protocol/vectors.json` (gerado por `tools/gen_vectors.py`). Convenções: **base64url sem preenchimento**
para todo binário em JSON; chaves públicas em **SPKI/DER**; assinaturas ECDSA em **DER**; JSON UTF-8.

## Implementações

- **Python** (referência): `src/guardian/protocol/`. Gateway e executor usam estas funções.
- **Kotlin** (aparelho): repositório NotToday, pacote `com.allan.nottoday.remote` (`WebAuthn`, `Commands`/`Consumer`, `DevAuth`, `PinBox`).
  `app/src/test/resources/vectors.json` é cópia de `protocol/vectors.json`: ao mudar o protocolo, regenere os vetores e copie o arquivo.
  O vetor `chrome` é um envelope assinado por um passkey real do Chromium (`CHROME_VECTOR_OUT=… python tests/e2e_browser.py` e
  `python tools/add_chrome_vector.py …`).

## Atores

| Ator | Chave | Papel |
|---|---|---|
| Guardião | passkey WebAuthn ES256 (P-256), 2+ por guardião | assina comandos |
| Aparelho (NotToday) | P-256 no Android Keystore, não exportável | autentica requisições, assina relatórios, abre a caixa do PIN |
| Executor (Pi) | P-256 em arquivo 0600 | idem, como um "aparelho" do tipo `executor` |
| Gateway | nenhuma | relé: fila, relatórios, site. **Não é confiável para autorizar nada.** |

**Id do aparelho** = `base32(SHA-256(SPKI))` minúsculo, sem `=`, primeiros 20 caracteres. **Fingerprint** = o id em grupos
de 4 separados por `-` (para conferir por voz).

## Comando

Os bytes do comando são JSON; o envelope carrega esses bytes **exatos** (nunca recanonicalizar):

```json
{ "v":1, "dev":"<id do destino>", "guardian":"<id do autor>", "ctr":7, "type":"approve_app", "args":{"pkg":"com.x"} }
```

Envelope: `{ "payload": b64url(bytes), "sigs": [ {guardian, cred, authenticatorData, clientDataJSON, signature} ] }`.

**Assinatura**: o passkey assina com `challenge = SHA-256(bytes)`. Verificação de cada assinatura (WebAuthn `get`):

1. `clientDataJSON`: `type == "webauthn.get"`, `challenge == b64url(SHA-256(bytes))`, `origin` igual à origem fixada, sem `crossOrigin: true`.
2. `authenticatorData`: tamanho ≥ 37, `rpIdHash == SHA-256(rpId)`, flags **UP e UV** ligadas. `signCount` é ignorado.
3. ES256 sobre `authenticatorData ‖ SHA-256(clientDataJSON)` com a chave do `cred` do `guardian` na lista de confiança.

**Verificação do comando** (`verify_envelope` + `Consumer.accept`), nesta ordem:

1. `payload` ≤ 8 KiB, JSON válido, `v == 1`, campos `dev`, `guardian`, `type` (texto), `args` (objeto), `ctr` (inteiro ≥ 1).
2. 1 a 4 assinaturas; todas válidas; guardiões distintos formam o conjunto de signatários; `guardian` do payload está nele.
3. Papel e quórum: cada guardião na confiança tem `role` (`admin` ou `domains`; sem o campo vale `admin`). Um guardião `domains` só assina `pihole_allow`, `pihole_deny`, `pihole_remove`, `pihole_batch` e `add_credential` para o próprio `id`; qualquer outro comando dele é recusado. `remove_guardian` exige **2 guardiões-mor distintos** quando há 2+ guardiões-mor; os demais tipos exigem 1. Veja docs/PAPEIS.md.
4. `dev` do payload é o id do próprio consumidor.
5. `ctr > último ctr aceito` para aquele `guardian` (contador **por guardião**, persistido, sobrevive a reinício). Aceitar grava o novo contador mesmo que a execução falhe.

Afrouxar passa pelo `Gate` do aparelho (atraso); isso é do consumidor, não do protocolo.

## Catálogo de comandos

Confiança (todo consumidor): `add_guardian {id,name,cred,spki,role}` (`role` obrigatório; só admin) · `add_credential {id,cred,spki}` ·
`remove_guardian {id}` (só admin; nunca remove o último guardião-mor; no aparelho, remover um admin passa pelo atraso e remover um guardião `domains` vale na hora).

Aparelho: `set_config {patch:{chave:valor}}` (passa por `Gate.split`) · `confirm {kind}` · `cancel {kind}`
(`kind` = `SETTINGS|RELEASE|MAINTENANCE`) · `approve_app {pkg}` · `revoke_app {pkg}` · `request_maintenance {}` ·
`set_dev_policy {...}` · `set_pin {box}` · `set_dev_pin {box}` · `activate {}`.

Executor: `pihole_allow {domain, ttl_s?}` · `pihole_deny {domain, ttl_s?}` · `pihole_remove {list:"allow"|"deny", domain}`.
`pihole_batch {items:[{domain, ttl_s?}]}` (1 a 50 itens, só libera): usado para aprovar um pedido de liberação com um único toque.

Veto: o executor recusa `pihole_allow` e `pihole_batch` de domínio que está nas listas de conteúdo adulto do Pi-hole (o domínio, um pai dele ou, com `ALLOW_MODE=regex`, um pai que cobriria um domínio listado) e de site vetado pelo mestre. `pihole_parent_block {action:"add"|"remove", domain}`: só o mestre, uma assinatura; veta o site (o domínio e tudo abaixo dele). Domínios vetados também não viram pedido de liberação (o executor não os envia ao gateway e o gateway apaga os já guardados).
Só domínio **exato** (ASCII, sem curinga/IP); `ttl_s` entre 60 e 2 592 000; o canário configurado é intocável.

## Caixa do PIN (`set_pin`, `set_dev_pin`)

`box = {epk, nonce, ct}`. O navegador gera um par ECDH P-256 efêmero; `shared = ECDH(eph, SPKI do aparelho)`;
`key = HKDF-SHA256(shared, salt = vazio, info = "guardian/pinbox/v1", 32 bytes)`; `ct = AES-256-GCM(key, nonce de 12 bytes,
PIN em UTF-8, aad)` com `aad = "guardian/<type>/<dev>"`. `epk` = ponto não comprimido (65 bytes). O aparelho abre com a chave do Keystore.

## Requisições do aparelho/executor ao gateway

Cabeçalhos: `X-Dev` (id), `X-Ts` (segundos Unix), `X-Nonce` (8–64 caracteres `[A-Za-z0-9_-]`), `X-Sig` =
b64url(ECDSA-SHA256 DER) sobre `METHOD "\n" alvo "\n" ts "\n" nonce "\n" hex(SHA-256(corpo))`, onde `alvo` é a
linha de requisição (caminho + query) exatamente como enviada. O gateway aceita ±300 s e recusa nonce repetido.

| Rota | Uso |
|---|---|
| `POST /v1/devices/register` | corpo `{pairing, pubkey, name, kind}`; assinado com a chave nova (prova de posse); consome o código de pareamento |
| `GET /v1/devices/{dev}/commands?after=<seq>&wait=<s ≤ 25>` | long-poll; devolve `{commands:[{id,seq,envelope}], next}`; guarde `next` como `after` |
| `POST /v1/devices/{dev}/report` | relatório (≤ 64 KiB); `executed:[{type,ok,msg}]` vira auditoria |
| `POST /v1/devices/{dev}/requests` | pedido do usuário `{kind:"domain"|"app"|"other", text}`, ou `{kind:"unblock", domains:[...]}` (1 a 20 domínios que o executor viu bloqueados nas últimas 24 h; sem texto livre) |
| `GET /v1/devices/{dev}/requests` | pedidos de liberação do aparelho, com o estado de cada domínio (`open`, `allowed`, `denied`, `cancelled`) |
| `POST /v1/devices/{dev}/requests/{id}/cancel` | o aparelho cancela um pedido aberto |
| `GET /v1/devices/{dev}/blocked?src=own|list` | (aparelho) o que o Pi-hole bloqueou para ele nas últimas 24 h |
| `POST /v1/devices/{dev}/blocked` | (executor) `{dev, items:[{domain,src:"own"|"list",list,cname,count,first,last}]}`; o gateway soma as contagens e guarda no máximo 1000 domínios por aparelho |

Guardião (sessão): `GET /v1/blocked?dev=&src=` (log), `POST /v1/requests/{id}/resolve {cmd?, deny:[domínios]}`. `cmd` é o id de um
`pihole_batch` já enfileirado pelo mesmo guardião para o executor; o gateway confere o conteúdo e marca os domínios como liberados.
Negar não exige passkey. `src` é `own` (regra própria: `REGEX`, `DENYLIST`) ou `list` (listas de anúncios: `GRAVITY`); nos `*_CNAME`
vale o alvo do CNAME.

**Relatório do aparelho** (campos que o site usa): `kind:"device"`, `ts`, `version`, `owner`, `filterActive`, `filterReason`,
`tailscale`, `tsIps` (endereços do aparelho na Tailscale, até 4; o executor os usa para ligar as consultas do Pi-hole ao aparelho, via `GET /v1/devices/{executor}/clients`), `pinSet`, `pendingApps:[{pkg,label,risks:[...]}]`, `pending:[{kind,state:"waiting|ready",remainingMs,summary}]`,
`windows:{maintenanceMs,devMs,devUsed}`, `snapshot:{chave:valor}` (`Config.snapshot()`), `labels`/`groups`/`hints` (chave → nome em português, grupo e dica: o site monta as Regras só com isto), `approvedApps:[{pkg,label}]`, `activated`, `trust:{guardian:[cred,...]}`,
`ctrs:{guardian:int}`, `executed:[...]`. **Relatório do executor**: `kind:"executor"`, `pihole_ok`, `allow`, `deny`, `temp`,
`allow_by`/`deny_by` ({domínio: guardião} só das entradas criadas pelo guardião), `trust`, `ctrs`, `executed`. Todo texto vindo de relatório é exibido pelo site com `textContent`.

## Pareamento

String de pareamento = `b64url(JSON {v:1, url:<origem do gateway>, rp:<rpId>, token, guardians:{id:{name,creds:{cred:spki},role}}})`,
gerada pelo site do Guardian (token de uso único, 24 h). O aparelho **fixa** `url`, `rp` e os guardiões; só aceita comandos
assinados por eles. Depois de registrar, mostra o **fingerprint** da própria chave; o guardião confere por voz com o que o site mostra.
Novos guardiões/passkeys chegam por `add_guardian`/`add_credential` assinados; o site mostra a divergência (`report.trust`)
e oferece "Propagar".

## Avisos (Web Push)

`GET /v1/push/key` (chave VAPID pública), `POST /v1/push/subscribe {endpoint, keys:{p256dh, auth}}`, `POST /v1/push/unsubscribe {endpoint}`,
`POST /v1/push/test`. O endpoint só é aceito se for de um serviço de push conhecido (FCM, Mozilla, Windows, Apple; HTTPS, porta 443),
senão o gateway viraria um SSRF. Corpo cifrado em `aes128gcm` (RFC 8291) e assinado com VAPID (RFC 8292). Avisos: aparelho sem sinal (5 min) e de volta,
filtro caiu/voltou, app novo pendente, pedido de afrouxar, pedido do usuário, co-assinatura pendente (não avisa o autor), Pi-hole inacessível/de volta.
A 1ª rodada depois de subir o gateway só memoriza o estado (sem avisos).

## API do guardião (site → gateway)

Sessão por cookie (`__Host-gsession`, HttpOnly, SameSite=Strict) obtida com passkey; POSTs exigem `Origin` igual à origem pública.
`POST /v1/register/{options,verify}` (convite) · `POST /v1/auth/{options,verify,logout}` · `GET /v1/me` ·
`POST /v1/invites` · `POST /v1/pairings` · `GET /v1/devices` · `GET /v1/devices/{dev}/ctr` ·
`POST /v1/devices/{dev}/commands` · `GET /v1/commands/awaiting` · `POST /v1/commands/{id}/cosign` ·
`GET /v1/audit` · `GET /v1/requests` · `POST /v1/requests/{id}/dismiss` · `POST /v1/devices/{dev}/forget` · `/v1/push/*`.
O próximo `ctr` é `max(último do gateway, último reportado pelo aparelho) + 1`.
