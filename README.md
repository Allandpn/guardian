# guardian

Sistema guardião do [NotToday](https://github.com/Allandpn/NotToday): permite que pessoas de confiança, em qualquer rede,
aprovem apps, ajustem configurações dos aparelhos protegidos e liberem/bloqueiem domínios no Pi-hole v6 **por um site (PWA)**,
sem instalar nada e sem Tailscale do lado delas.

```
Site (PWA, passkey) ──HTTPS/Funnel──► GATEWAY (container isolado, nó Tailscale próprio)
                                           ▲                       ▲
            NotToday (aparelho) ──long-poll┘                       └── EXECUTOR (Pi) ──► Pi-hole v6 (API local)
```

- **Cada comando é assinado pelo passkey do guardião** (WebAuthn, biometria) e verificado de novo no aparelho e no executor.
  O gateway é só um relé: se for comprometido, não forja comandos e não alcança a sua rede (rede isolada + ACL + firewall).
- O canal remoto **nunca é mais poderoso que o PIN**: afrouxar continua esperando o atraso do aparelho.
- Documentação: [docs/CONTROLE.md](docs/CONTROLE.md) (desenho e ameaças), [protocol/SPEC.md](protocol/SPEC.md) (protocolo),
  [docs/OPERACAO.md](docs/OPERACAO.md) (instalação), [docs/DECISOES.md](docs/DECISOES.md) (decisões e estado), [docs/MIGRACAO.md](docs/MIGRACAO.md)
  (migração do guardião-mor para o computador do trabalho), [docs/PAPEIS.md](docs/PAPEIS.md) e [docs/LIBERACAO.md](docs/LIBERACAO.md).

## Estado

| Parte | Estado |
|---|---|
| `protocol/` + `src/guardian/protocol` | feito, com vetores de teste (`protocol/vectors.json`) |
| Gateway (`src/guardian/gateway`) e site (tema escuro "Mar e terra", celular e computador) | feito; testado, inclusive no Chromium com passkey virtual |
| Executor do Pi-hole v6 | feito; testado contra um Pi-hole falso. **Caminhos `/api/domains/...` ainda não conferidos num Pi-hole v6 real** |
| `deploy/` (Docker, firewall, ACL, systemd) | escrito; compose validado, **não executado** |
| Alertas por Web Push (aparelho sem sinal, filtro caiu, app novo, pedidos, co-assinatura) | feito; criptografia validada com o vetor da RFC 8291; **entrega num navegador real ainda não testada** |
| Lado do aparelho (Kotlin, repositório [NotToday](https://github.com/Allandpn/NotToday), branch `claude/wizardly-goldberg-sxu89c`, `docs/REMOTO.md`) | feito e testado na JVM (vetores, Robolectric, integração com este gateway). **Telas, Keystore (ECDH) e serviço em segundo plano não testados num aparelho** |
| Lote assinado (um toque para vários aparelhos), grupos do Pi-hole por aparelho, consultas bloqueadas recentes | futuro |

## Desenvolvimento

Só `cryptography` como dependência de execução; o gateway usa a biblioteca padrão.

```sh
python3 -m venv .venv && .venv/bin/pip install -e .
PYTHONPATH=src python3 -m unittest discover -s tests -v      # 73 testes
# ponta a ponta no Chromium (precisa de playwright e do Chromium):
PYTHONPATH=src python tests/e2e_browser.py
# simulador de guardião para testes de outras linguagens (o NotToday roda contra ele; veja docs do NotToday):
PYTHONPATH=src:tests python tests/guardian_sim.py serve --dir /tmp/sim
# regenerar os vetores do protocolo:
PYTHONPATH=src:tests python3 tools/gen_vectors.py > protocol/vectors.json
```

Rodar o gateway localmente (sem HTTPS, só para desenvolver):
`GATEWAY_ORIGIN=http://localhost:8080 GATEWAY_RP_ID=localhost GATEWAY_INSECURE_COOKIES=1 GATEWAY_DB=/tmp/g.db python -m guardian.gateway init --name Ana`
e depois `... serve`.

## Estrutura

```
protocol/SPEC.md, vectors.json     especificação e casos fixos (Kotlin e Python)
src/guardian/protocol/             passkeys, comandos, estado de confiança, assinatura do aparelho, caixa do PIN
src/guardian/gateway/              servidor HTTP (stdlib), SQLite, limites, site em static/
src/guardian/executor/             cliente do Pi-hole v6, laço do executor
deploy/                            Dockerfile, compose, firewall, ACL de exemplo, systemd
tests/                             unittest + autenticador de mentira + Pi-hole falso + guardian_sim.py + e2e do navegador
```
