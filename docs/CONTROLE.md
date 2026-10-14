# Controle remoto do NotToday — desenho

Decisões tomadas em conjunto; Pi-hole **v6** é o alvo único. Protocolo: [../protocol/SPEC.md](../protocol/SPEC.md).
Escopo inicial: 2 guardiões, 2 aparelhos, guardiões em outras cidades.

## Modelo de ameaça

| Ameaça | Defesa |
|---|---|
| A. Burla pelo dono do aparelho | O canal remoto **não é mais poderoso que o PIN**: comandos de configuração passam pelo `Gate` do aparelho (afrouxar espera o atraso, contado pelo relógio do aparelho). Aprovar app e endurecer valem na hora, como hoje. |
| B. Hackers e DDoS usando o gateway para entrar na rede doméstica | Gateway num container isolado, com nó Tailscale próprio e sem rota para a LAN (firewall `DOCKER-USER`/`INPUT` + ACL sem destinos). Nada exposto roda no Pi principal. |
| C. Gateway comprometido | Não tem segredos nem acesso ao Pi-hole. Não forja comandos: aparelho e executor verificam a assinatura do passkey. Pode, no máximo, atrasar/descartar mensagens e mostrar um site adulterado (ver riscos). |

> **Atenção ao dono do Pi.** O README do NotToday assume o Pi "em caixa trancada com a pessoa de confiança". Se a pessoa
> protegida também administra o Pi (root), o Pi continua sendo o elo fraco: ela pode mexer no Pi-hole e no executor
> diretamente. Este sistema protege a configuração dos aparelhos e a liberação de domínios *pelos guardiões*, não o Pi contra o seu dono.

## Princípios

1. Cada comando é assinado pelo passkey (WebAuthn, UV obrigatório) com `challenge = SHA-256(comando)`.
2. Remover guardião exige os dois guardiões; qualquer um basta para os demais comandos (afrouxar ainda espera o atraso).
3. Contador anti-replay **por guardião**, dentro do comando, persistido no consumidor. `signCount` do WebAuthn é ignorado (passkeys sincronizados mandam 0).
4. O gateway valida na entrada (barra abuso barato); aparelho e executor revalidam tudo.
5. O PIN local e o PIN de desenvolvedor são definidos pelo site cifrados para a chave do aparelho (ECDH + AES-GCM): nem o gateway nem o usuário os veem. O PIN local também continua definível no app, só presencialmente (aparelho ainda não pareado) ou informando o PIN atual.

## Gateway

- Servidor HTTP/1.0 em biblioteca padrão (uma requisição por conexão), SQLite, limites de taxa (por IP, global, por aparelho, por guardião),
  teto de conexões simultâneas, corpos pequenos, sem upload, sem templates, estáticos em memória, CSP estrita (`default-src 'none'`).
- Sessão do guardião: cookie `__Host-gsession` (HttpOnly, Secure, SameSite=Strict) + checagem de `Origin` nos POSTs.
- Aparelhos autenticam cada requisição com a chave P-256 (timestamp ±300 s + nonce anti-replay).
- Long-poll de até 25 s; uma consulta nova por aparelho substitui a anterior.
- Co-assinatura: comando com quórum 2 fica `awaiting` até outro guardião assinar.
- Funnel: portas 443/8443/10000, atributo `funnel` só no nó do gateway. O hostname `*.ts.net` vira o `rpId` dos passkeys: **precisa ser estável**.

## Executor (Pi-hole v6)

Puxa a fila do gateway (conexão de saída), reverifica e aplica pela API REST local (senha de aplicativo, sessão `X-FTL-SID`).
- Só domínio **exato** (ASCII, sem curinga, regex ou IP); nunca o canário configurado (`CANARY`).
- `pihole_deny` remove o allow do mesmo domínio (a lista de permissão vence a de bloqueio).
- Liberação **temporária** (`ttl_s`): o prazo vai para `state.json` e sobrevive a reinício; se o Pi-hole estiver fora na hora de expirar, tenta de novo.
- Falha ao aplicar (ex.: Pi-hole fora) é **reportada**, e o contador do comando fica consumido: o guardião reenvia.
- Relatório periódico com as listas, as liberações temporárias, a confiança e o resultado dos comandos.

## Site (PWA)

Tema escuro "Mar e terra" (azul-petróleo, verde-água, laranja; contraste 4,5:1). Barra de baixo no celular (Início, Domínios, Pessoas, Histórico) e trilho lateral com painel de detalhe no computador. Toda ação mostra uma folha de confirmação com o que será assinado e o efeito (na hora ou espera). As Regras vêm agrupadas e com nomes em português a partir do relatório do aparelho (`labels`/`groups`/`hints`); várias mudanças viram **um** comando e um toque de passkey. O pareamento é um assistente de 5 passos.

JS puro e sem dependências; todo texto vindo da rede entra por `textContent`. Telas: aparelhos (estado, apps pendentes, pedidos em espera,
configuração, PINs), domínios (listas, liberar/bloquear com duração, pedidos dos usuários), guardiões (convites, propagar confiança,
co-assinaturas, parear aparelho/executor), auditoria. Login e cada comando sensível pedem o passkey.

## Riscos residuais e decisões

1. **JavaScript servido pelo gateway.** Um gateway tomado poderia mostrar uma ação e fazer o passkey assinar outra. Camadas: CSP estrita, JS mínimo,
   o atraso ao afrouxar (o pedido fica visível e qualquer guardião cancela) e a auditoria assinada pelo aparelho.
2. **Passkeys sincronizados** põem a conta Google/Apple do guardião na cadeia de confiança: exigir 2FA nela. Cadastrar 2+ passkeys por guardião.
3. **Perda de passkey:** remover guardião exige os dois; se um sumir, sobra o PIN local presencial.
4. **Container não é fronteira de VM.** Reforços futuros: Docker/Podman rootless; outro hardware em VLAN de convidados.
5. **Pareamento remoto** depende da conferência do fingerprint por voz (veja SPEC). Pareie **antes** do `set-device-owner`.
6. Pendências de validação (?): limite de taxa do Funnel; `TS_SERVE_CONFIG` com `${TS_CERT_DOMAIN}` e `read_only` no container do Tailscale;
   caminhos `/api/domains/{type}/{kind}[/{domain}]` do Pi-hole v6 (confira em `http://<seu-pihole>/api/docs`); ECDH com chave do Keystore na One UI 8.

## Avisos (Web Push)

O gateway avalia o estado a cada 30 s e avisa os guardiões inscritos: aparelho sem sinal (5 min), filtro caiu, app novo pendente,
pedido de afrouxar, pedido do usuário, co-assinatura pendente, Pi-hole inacessível. O corpo vai cifrado até o navegador (RFC 8291) e o
endpoint de push só é aceito de serviços conhecidos (evita SSRF). A chave VAPID fica no `gateway.db`: autoriza só avisos genéricos a quem se inscreveu.

## Estado e próximos passos

Feito: protocolo, gateway, site, executor, avisos e o lado do aparelho (repositório NotToday, `docs/REMOTO.md`).
Falta validar em hardware real: telas e Keystore (ECDH, `PURPOSE_SIGN | PURPOSE_AGREE_KEY`) no aparelho, entrega do push num navegador real,
o Docker/Funnel e a API de domínios do Pi-hole v6. Futuro: lote assinado (um toque para vários aparelhos), grupos do Pi-hole por aparelho,
consultas bloqueadas recentes, `activate` obrigatório antes do `set-device-owner`.
