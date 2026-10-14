# Fluxo de liberação de domínios

Estado: gateway, executor e site implementados e testados. O app (Kotlin) vem em seguida.

Objetivo: quem usa o aparelho tenta acessar algo, vê o que o Pi-hole bloqueou, toca em um botão para pedir a liberação, e o guardião libera com o mínimo de passos. Ninguém digita nome de domínio.

## Decisões já tomadas

- O guardião não recebe notificação. Quem pede avisa o guardião por conta própria (mensagem) e o app oferece um link para compartilhar.
- Entrar no site deve ser sem atrito: abrir o link, tocar na digital, cair direto nos pedidos.
- Maioria das liberações é definitiva, algumas são temporárias, e o guardião pode bloquear de novo.
- Pedido e negação não têm motivo. O campo de digitar domínio fica escondido (só como recurso de emergência).
- O guardião pode consultar o log do que foi bloqueado.
- Pi-hole v6 em Docker, IP do Pi fixo. Todos os aparelhos da casa usam o mesmo Pi-hole, com cerca de 3 mil regras de domínio além das listas.

## Fluxo

1. O aparelho tenta acessar algo e o Pi-hole bloqueia a consulta.
2. O executor (no Pi) lê `GET /api/queries` do Pi-hole a cada 10 a 15 s, só dos IPs dos aparelhos pareados e só consultas bloqueadas.
3. O executor envia ao gateway uma lista deduplicada por domínio: `domain`, `count`, `first`, `last`, `source` (regra própria, lista ou CNAME).
4. No app, a tela **Bloqueado agora** mostra os domínios recentes. A pessoa marca um ou mais e toca em **Pedir liberação**. Em seguida o app abre a folha de compartilhar do Android com um link para o site do guardião.
5. No site, o guardião abre **Pedidos** e vê cada pedido com os domínios, quantas vezes foram bloqueados e a origem. Cada domínio vem marcado como **Liberar sempre**. Ele pode trocar um deles para **Liberar por tempo** (1 h, 1 dia) ou **Negar**. Um toque de passkey assina tudo.
6. O executor aplica no Pi-hole. O app mostra "Liberado", "Liberado por 1 h" ou "Negado".

## Filtro de ruído

O executor reporta todos os bloqueios dos aparelhos pareados, deduplicados por aparelho, domínio e origem, para o guardião poder filtrar como no Pi-hole:

- **Filtro por aparelho** e **filtro por origem** (regras próprias, nome de cada lista, CNAME). A origem vem do próprio log do Pi-hole.
- Padrão da tela: só regras próprias e domínios negados. Listas de anúncios aparecem ao marcar o filtro correspondente.
- No app, a tela **Bloqueado agora** abre com o mesmo padrão (regras próprias) e tem a opção **Mostrar também anúncios**.
- Para `*_CNAME`, o domínio reportado é o alvo do CNAME que causou o bloqueio, porque liberar só o nome original não adianta.
- Cada aparelho guarda no máximo 1000 domínios únicos. Os mais antigos saem primeiro.

## Gateway

- Tabela `blocked(dev, domain, count, first, last, source)`, retenção de 24 horas, 1000 domínios por aparelho.
- `POST /v1/devices/{dev}/blocked`: o executor envia a lista, assinada como o relatório.
- `GET /v1/devices/{dev}/blocked`: o aparelho consulta, com assinatura do aparelho. `GET /v1/blocked`: o guardião consulta, com sessão.
- `POST /v1/devices/{dev}/requests` com `{kind: "unblock", domains: [...]}`. O gateway só aceita domínios que estão na tabela `blocked` daquele aparelho e valida cada um com `domains.normalize`.
- A tabela `requests` ganha `domains` e `status` (`open`, `done`, `denied`) e o resultado de cada domínio. O aparelho consulta o estado dos próprios pedidos.
- Negar não precisa de passkey: apenas fecha o pedido com `denied` e registra na auditoria.

## Comandos assinados

- Liberar usa o `pihole_allow` que já existe, com ou sem `ttl`. Para vários domínios, um pedido vira um comando por domínio dentro da mesma assinatura (mesmo mecanismo do `set_config` com várias mudanças).
- **Bloquear de novo** usa a remoção da lista de permissão (`pihole_remove` com `list: allow`). Isso aperta a regra, então vale na hora, sem espera.
- O executor só gerencia entradas com o comentário `guardian:`. Entradas que o dono do Pi criou à mão não aparecem em **Liberados** e não podem ser removidas pelo site.
- A trava do domínio-canário continua valendo.

## Site

- **Pedidos**: cartão por pedido, como descrito acima.
- **Bloqueios** (novo, dentro de cada aparelho): log das últimas 24 horas, com filtros por aparelho e por origem, contagem e botão **Liberar** direto, sem pedido.
- **Liberados**: ganha o botão **Bloquear de novo** e mostra o tempo restante dos temporários.
- **Entrar**: a passkey é oferecida assim que o site abre, sem digitar nome. Depois do login, o site volta para o link aberto (por exemplo `#/pedidos`). A sessão passa de 12 h para 30 dias (confirmado). O cookie só dá leitura do painel, e cada ação continua exigindo a assinatura da passkey.
- O push para o guardião fica desligado por padrão. Continua existindo como opção.

## App

- **Bloqueado agora** (nova tela), **Pedir liberação**, **Compartilhar link**, estado dos pedidos e notificação local quando o guardião responde.
- Atalho opcional nas configurações rápidas do Android.

## Riscos e limites

- **Liberar vale para a casa toda.** A permissão do Pi-hole fica no grupo padrão, então os aparelhos de casa também deixam de ser bloqueados naquele domínio. Para liberar só um aparelho seria preciso um grupo no Pi-hole para os remotos, com as listas replicadas nele.
- **Origem do cliente no Docker (a confirmar no primeiro uso).** Os aparelhos falam com o Pi-hole pela Tailscale. Se o contêiner usa rede bridge, o Pi-hole pode registrar os pedidos com o IP do gateway do Docker em vez do IP da Tailscale do aparelho. Nesse caso o filtro por aparelho não funciona. Verificação simples: abrir o Query Log do Pi-hole e ver o que aparece na coluna Cliente para o tablet.
- **Mapa aparelho para IP.** O executor recebe os IPs da Tailscale (IPv4 e IPv6) de cada aparelho na configuração. São só dois aparelhos.
- **Nada indica qual app fez a consulta.** O Pi-hole só vê o domínio.
- **Cache.** Depois da liberação, o navegador ou o Android podem guardar o bloqueio por 1 a 2 minutos.
- **Domínios forjados.** Uma página no aparelho pode gerar consultas a nomes arbitrários para encher a lista. O limite de 1000 e o fato de o guardião ver cada domínio antes de assinar contêm o dano. Domínios `xn--` (punycode) aparecem com aviso.
- **Privacidade.** O gateway passa a guardar domínios bloqueados (por regra própria) com horário, por 24 horas. Nada do que foi permitido é guardado.
- **Não validado em Pi-hole real:** formato de `/api/queries` no v6 (campos de status, cliente, lista e `cname`), precedência da lista de permissão sobre regras regex, e os endpoints de domínios.

## Etapas

1. Executor: leitor do log, com Pi-hole falso nos testes, e envio da lista.
2. Gateway: tabela, rotas, pedido de liberação e estado.
3. Site: Pedidos, Bloqueios, Liberados com bloqueio novo, entrada sem atrito e link direto.
4. App: Bloqueado agora, pedido, compartilhar, estado e notificação.
5. Testes de ponta a ponta com o site e o gateway reais, e testes do Kotlin contra o gateway real.
