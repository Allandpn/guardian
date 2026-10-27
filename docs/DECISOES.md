# Decisões e estado do projeto

Registro do que foi definido nas conversas e do ponto em que o trabalho parou, para retomar de qualquer sessão. O desenho técnico está em
[CONTROLE.md](CONTROLE.md) e [../protocol/SPEC.md](../protocol/SPEC.md); aqui ficam as **decisões** e o **estado**.

## Contexto

O NotToday (app Android Device Owner) bloqueia depuração e leva o tráfego de apps escolhidos, pela Tailscale, a um Pi-hole no Raspberry Pi.
O Guardian é o controle remoto: pessoas de confiança (em outras cidades) mudam regras, aprovam apps e liberam ou bloqueiam domínios por
um site (PWA) com passkey. A pessoa protegida é o próprio dono dos aparelhos: o objetivo é que um impulso, à noite, em casa, não consiga
desfazer a proteção.

Nome do sistema: **Guardian** (em inglês, em todos os textos). Papéis: **guardião-mor** (controle total) e **guardião** (só domínios).

## Decisões

### Segurança do canal
1. O canal remoto nunca é mais poderoso que o PIN local.
2. Nada na rede de casa fica exposto: o gateway roda num contêiner isolado, com nó Tailscale próprio, e é publicado por Funnel. O executor só faz conexões de saída.
3. Cada comando é assinado por passkey (WebAuthn ES256, verificação do usuário obrigatória) e verificado por quem o executa (aparelho e executor), nunca só pelo gateway.
4. Afrouxar espera o atraso do aparelho (padrão 24 h); endurecer vale na hora. Remover guardião-mor passa pelo atraso; remover guardião vale na hora.
5. Pareamento inicial à distância, com conferência do fingerprint por voz.
6. Pi-hole v6; o executor fala com a API REST dele. O domínio-canário nunca pode ser alterado.
7. Seja segura, mas sem exagero (sem over-engineering).

### Liberação de domínios
8. Sem digitar domínio: o executor lê o log do Pi-hole, o app mostra o que foi **bloqueado** (padrão: só regras próprias; anúncios atrás de um filtro) e a pessoa marca e pede.
9. O guardião **não é notificado**. Quem pede envia o link (folha de compartilhar do Android). Entrar no site é sem atrito: a passkey abre sozinha e a sessão dura 30 dias.
10. Aprovação: por domínio, "Sempre" (padrão), 1 h, 1 dia ou "Negar"; uma passkey assina o pedido todo (`pihole_batch`). Negar não pede passkey. Pedido e negação não têm motivo.
11. "Bloquear de novo" vale na hora. Só aparecem em Liberados as liberações feitas pelo guardião.
12. O guardião vê o log de bloqueios (24 h, até 1000 domínios por aparelho; só bloqueios são guardados), com filtro por aparelho e por quem bloqueou.
13. O campo de digitar domínio fica escondido (Avançado no site, "Pedido manual" no app).
14. A liberação vale para a casa toda (o Pi-hole é um só). Os aparelhos falam com o Pi-hole pela Tailscale.

### Papéis
15. Um único guardião-mor, com mais de uma passkey (chave de reserva). O site avisa em vermelho enquanto houver uma só.
16. O guardião (só domínios) libera, bloqueia e bloqueia de novo, inclusive sem prazo, e pode cadastrar passkeys extras para si. Não mexe em regras, apps, PIN nem pessoas.
17. O guardião-mor escolhe, por guardião, o que mais ele pode ver (estado dos aparelhos, regras, apps, histórico), só leitura.
18. Não há lista de domínios protegidos além do canário (o guardião é pessoa de confiança). Ficou a ideia de o executor recusar bloquear o domínio do gateway e os da Tailscale; **não foi feita**.
19. Quem aplica as regras de papel é o aparelho e o executor; o gateway só recusa antes, para dar mensagem clara.
20. O primeiro guardião é guardião-mor. Pareamentos antigos (sem papel) continuam funcionando como guardião-mor.

### Passkey e horário (por guardião, definidos na criação, imutáveis)
21. **Só neste aparelho** ou **Pode sincronizar**. Com "só neste aparelho", passkeys com a flag BE (copiáveis, como as do Gerenciador de Senhas do Google) são recusadas por todos. Padrão: guardião-mor "só neste aparelho"; guardião "pode sincronizar".
22. **Horário**: dias e horas, no horário de Brasília (deslocamento fixo −3). Fora dele os comandos do guardião não valem, mesmo com a passkey certa; confere quem consome o comando, com o relógio dele. Co-assinatura não é conferida.
23. O computador do trabalho é gerenciado e **não permite Windows Hello**: sem chave FIDO2 não há passkey "só neste aparelho" ali. Decisão (2026-10-16): por enquanto o guardião-mor do trabalho usa **passkey sincronizável**, cadastrada pelo celular (QR) para não logar a conta Google pessoal no PC; a barreira é o horário. Quando houver chave FIDO2, cria-se outro guardião-mor "só neste aparelho" e remove-se o sincronizável (e a passkey na conta Google).
24. O guardião-mor do trabalho: **terça a quinta, 12:00 às 16:00** (escritório; segunda e sexta são home office), **pode sincronizar** por enquanto.
25. "Remover passkey" existe (guardião-mor; com 2+ guardiões-mor precisa das duas assinaturas; nunca a última).
26. Mudar o horário ou a regra de sincronização = criar outro guardião e remover o antigo. Detalhes e passo a passo em [MIGRACAO.md](MIGRACAO.md).

### Liberação como regex (2026-10-16)
29. O guardião vê e aprova o domínio simples; o executor grava no Pi-hole uma regex gerada por ele, `^([a-zA-Z0-9-]+\.)*dominio\.com$` (o domínio e os subdomínios, como as regras que o dono já usa), em `allow/regex` (e `deny/regex` ao bloquear). Ninguém digita regex; só essa forma exata é reconhecida, listada e removida, então regras escritas à mão ficam intactas. `ALLOW_MODE=exact` volta ao domínio exato. Liberar `x.itau.com.br` cobre `x.itau.com.br` e os subdomínios dele, não `www.itau.com.br`. O executor recusa liberar um domínio que cobriria o canário. **Não validado num Pi-hole v6 real:** rotas `/api/domains/allow/regex/...`.

### Guardião comum e recusas (2026-10-16)
30. O guardião comum também **aprova apps** (`approve_app`, assinatura dele basta; o aparelho e o gateway conferem). Revogar app, regras e PIN continuam só do guardião-mor.
31. **Recusar**: pedido de domínio (por pedido e "Recusar todos") e app pendente. Recusar não precisa de passkey porque não solta nada: o domínio fica negado no pedido; o app fica suspenso no aparelho e sai da lista (tabela `app_refusals` no gateway, "Reconsiderar" desfaz).
32. Regra regex ao liberar `www.dominio.com` grava `^([a-zA-Z0-9-]+\.)*dominio\.com$` (sem o `www.`); regras antigas com o host inteiro continuam reconhecidas e são removidas junto.
33. O site recarrega sozinho quando o gateway passa a servir outra versão (cabeçalho `X-Build`), sem folha aberta nem campo em uso.

34. O guardião comum vê o que **ele** decidiu: domínios liberados (do relatório do executor, `allow_by`), domínios recusados (`GET /v1/my/decisions`, últimos 7 dias, enquanto o pedido existe) e apps aprovados (tabela `app_approvals`, guardada ao enfileirar `approve_app`). Pode bloquear de novo, liberar e revogar (`revoke_app` passou a ser permitido ao guardião; a tela só oferece o que ele aprovou).
35. O relatório do executor põe as entradas do Guardian **antes** das entradas diretas do Pi-hole ao aplicar o corte de 500 (antes o corte alfabético escondia as liberações quando o Pi-hole tem centenas de entradas do dono) e informa `allow_total`/`deny_total`. "Bloqueados pelo guardião" lista só os bloqueios do Guardian.

### Navegação e telas (2026-10-16, noite)
36. **Padrão de UX: separar Domínios e Apps** em toda tela de decisão, cada um com as mesmas abas. Guardião-mor: Início | Domínios | Apps | Guardiões | Dispositivos. Guardião comum: Domínios | Apps | Conta.
37. **Início é só leitura** (aparelhos, Pi-hole e guardiões; no computador, painel de detalhe com o nome do selecionado e valores em MAIÚSCULAS). Botões e configurações ficam em Dispositivos (Parear, Regras e configurações) e Guardiões (convite em passos, passkeys e permissões, confiança, co-assinaturas).
38. **Domínios**: Solicitações (lista com filtro por aparelho, duração global Sempre/1 h/1 dia, Liberar/Recusar por linha, Liberar/Recusar todos) | Bloqueios | Liberados (guardião-mor, com quem liberou) ; guardião comum: Solicitações | Liberados | Recusados (o que ele mesmo decidiu). **Apps**: Solicitações | Aprovados | Recusados, com filtro por aparelho e quem aprovou/recusou.
39. **App Android, tela "Liberações"**: abas Domínios e Apps. Em Apps a pessoa vê os apps suspensos (e quais o guardião recusou) e pede a liberação; isso reabre o app nas solicitações do guardião (`POST /v1/devices/{dev}/apps/request`, `GET .../apps/refused`). O botão de entrada ("Pedir liberação de sites e apps") é primário.

### Interface
27. Paleta "Mar e terra" (dark) no site e no app. O app segue o estilo das Configurações do Android: início com estado e categorias, uma subtela por categoria, rascunho único e barra fixa de "Salvar e aplicar".
28. O site funciona em celular, tablet e computador (barra de baixo no celular, menu lateral a partir de 900 px, conteúdo centralizado).

## Estado

| Parte | Estado |
|---|---|
| Protocolo, gateway, executor, site | feito; 104 testes em Python e teste de navegador (Chromium com passkey virtual, inclusive passkey sincronizada recusada e fora do horário) |
| App Android (repositório NotToday, branch `claude/wizardly-goldberg-sxu89c`) | feito; testes na JVM (Robolectric, vetores, integração com este gateway) |
| Não validado em hardware real | Cadastro da passkey do trabalho pelo celular (QR/Bluetooth) no PC gerenciado, Keystore ECDH e telas no aparelho, serviço em segundo plano, Docker/Funnel, rotas `/api/queries` e `/api/domains/...` do Pi-hole v6 (campos de status, cliente, lista, CNAME), IP dos aparelhos no log (Tailscale) e entrega de push |

O app instalado no aparelho só passa a conferir passkey sincronizável e horário depois de atualizado (o executor e o gateway já conferem).
No aparelho o horário usa o relógio do Android: ligar a restrição "Bloquear mudar data/hora".

## Pendências e ideias

- Executar a migração do guardião-mor ([MIGRACAO.md](MIGRACAO.md)).
- ~~Configurar `CLIENTS` à mão~~: automático (2026-10-16). O app informa `tsIps` no relatório e o executor monta IP → aparelho sozinho; `CLIENTS` ficou só como reserva para app antigo. Falta conferir o Query Log do Pi-hole com um aparelho novo.
- Proteger no executor o domínio do gateway e os da Tailscale contra bloqueio (ideia da conversa; não feita).
- Comando para trocar o horário/regra sem recriar o guardião: descartado de propósito (imutável).
- Telas do app mais próximas dos wireframes (mais cartões e chips): opcional.

## Guardião-mestre e domínio pai (2026-10-17)

40. **Guardião-mestre (`master`)**: inclui e remove guardiões (inclusive outro mestre) sozinho, sem co-assinatura; o guardião-mor passa a fazer tudo menos isso; o guardião comum fica como estava. Motivo: com a regra "dois guardiões-mor removem", um guardião-mor sozinho podia criar um segundo e remover a pessoa de confiança. Primeiro mestre: promoção `set_role` de um guardião-mor, com uma assinatura (só enquanto não existe mestre). Detalhes em `PAPEIS.md`. Protocolo novo nos três lugares (Python, Kotlin, gateway); o relatório dos destinos ganhou `roles`.
41. **Encurtar o domínio no pedido**: no app, `«` tira o rótulo da esquerda de um bloqueio (advertise.cloudlinks.cn -> cloudlinks.cn) e `»` devolve. O gateway aceita o pedido do domínio bloqueado **ou de um pai dele**, nunca de um sufixo público (cn, com.br; heurística sem lista pública em `domains.is_public_suffix`) e nunca de um pai que cubra o canário.
42. **Veto das listas de conteúdo adulto** (2026-10-18): o Pi-hole bloqueia tudo por padrão e só libera o que o Guardian libera; uma liberação vence qualquer lista, então as listas adultas (StevenBlack porn-only, HaGeZi NSFW, paulbrandie) passam a ser um veto. O executor lê o `gravity.db` (somente leitura, índice em memória refeito quando o arquivo muda) e recusa liberar o domínio listado, um pai dele ou, em `ALLOW_MODE=regex`, um pai cuja regra cobriria um domínio listado. Sem conseguir ler o arquivo, recusa tudo (nunca libera às cegas). Domínio vetado não vira pedido: o executor não o manda ao gateway e o gateway apaga o que já tinha. O relatório do executor traz uma auditoria (liberações que o veto não deixaria passar hoje, porque a lista muda todo dia); a tela Domínios > Vetos mostra e deixa bloquear de novo. Falsos positivos das listas ficam para uma feature posterior.
43. **Sites vetados pelo mestre** (`pihole_parent_block`): só o mestre, sozinho, veta um site (como reddit.com, x.com, tumblr.com): ninguém libera o domínio nem nada abaixo dele. Fica no estado do executor e aparece em Domínios > Vetos.
44. **Agente do Windows** (2026-10-18): o computador de quem usa o Guardian é um aparelho com um agente (SYSTEM, tarefa agendada) que executa comandos assinados: instalar programa (winget ou instalador por link com SHA-256) e rodar script do PowerShell como administrador, uma vez, com validade. Aprova guardião-mor ou mestre, uma passkey; o guardião comum fica só com domínios. A conta do dia a dia vira conta comum e a senha de administrador fica com a pessoa de confiança. Pedidos pela tela local em localhost. Veja `docs/AGENTE.md`.
45. **Bloqueados mostram o motivo** (2026-10-23): o que o veto cobre deixou de ser escondido. O executor classifica cada bloqueio em `own` (nada liberou; dá para pedir), `list` (lista do Pi-hole; nome da lista em `list`; só para ver) e `veto` (site vetado pelo mestre; o site vetado vai em `list`; só para ver) e manda todos ao gateway; `sweep_vetoed` e o campo `veto` do POST deixaram de ser usados. O gateway aceita a origem `veto` e recusa o pedido com mensagem própria ("vetado pelo guardião-mor" / "bloqueado por uma lista"). O guardião vê o motivo no cartão do pedido, um aviso quando é lista de conteúdo adulto e o filtro Vetados na tela Bloqueios; o agente do PC também. O app mostra tudo (a chave "anúncios e rastreadores" saiu) e marca "só ver"/"vetado" sem caixa de seleção. Lado do app **não compilado** (sem SDK no Pi).

## Como retomar

- Repositórios: `Allandpn/guardian` (branch `main`) e `Allandpn/NotToday` (branch `claude/wizardly-goldberg-sxu89c`, ainda sem PR para a `main`).
- Guardian: `PYTHONPATH=src python3 -m unittest discover -s tests`. Navegador: `PYTHONPATH=src python tests/e2e_browser.py` num Python com `playwright`
  (`SHOTS=pasta` salva capturas, `WIDE=1` também em tablet e computador, `AUDIT=1` mede largura e alvos de toque no celular).
- NotToday: `ANDROID_HOME=<sdk> GUARDIAN_REPO=../guardian ./gradlew :app:testDebugUnitTest :app:lintDebug`;
  `NOTTODAY_SHOTS=<pasta>` gera capturas das telas.
- Wireframes (privados): telas atuais, fluxo de liberação e papéis, publicados como Artifacts na conta do dono.
46. **Veto de apps** (2026-10-26): o guardião-mor e o mestre veem em Apps > Instalados tudo que o aparelho tem (`report.installedApps` quando o app o envia; senão aprovados, pendentes e recusados) e marcam vários para vetar. Veto é permanente e vive no gateway (`app_vetos`, `POST /v1/devices/{dev}/apps/veto`, sem passkey porque só restringe): o gateway recusa `approve_app` e o pedido do aparelho para um app vetado, e ele sai das solicitações. Para app já aprovado o site também envia `revoke_app` assinado (um passkey por app). Tirar o veto: Apps > Vetados. **Falta no app NotToday** (sessão do IDE): enviar `installedApps:[{pkg,label}]` no relatório assinado e, se quiser, mostrar o veto ao usuário.
47. **App desinstalado e reinstalado pede nova liberação** (2026-10-26, pedido do dono). Quem faz valer é o app NotToday: ao desinstalar de vez um pacote (não numa atualização), ele tira o pacote dos aprovados; ao iniciar, descarta aprovados que não estão instalados. O gateway não consegue revogar sozinho (revogar exige assinatura de guardião). O site avisa em Apps > Instalados: aprovado que sumiu de `installedApps` aparece como "desinstalado, ainda aprovado".
48. **Deploy assinado** (2026-10-27): o código só entra em produção no Pi por um comando `deploy` (projeto + hash do commit) assinado pelo mestre dentro do horário dele. Um deployer root, instalado à mão fora do repositório, busca as etiquetas `release/*`, calcula sozinho se a versão toca arquivos de segurança (lista no Pi), instala, confere a saúde e reverte sozinho se falhar. O mestre vê o mínimo (projeto, versão, resumo, risco); o diff não vai para ele. Desenvolver e testar é livre, em sessões na nuvem. Veja docs/DEPLOY.md. Faltam: cadastro assinado de projetos, isolamento por projeto e a retirada do sudo do desenvolvedor.
49. **Loja própria de apps** (2026-10-27/28): o mestre instala e atualiza apps nos celulares (inclusive o NotToday) sem a janela de dev. O Pi lê as Releases do GitHub (repositório privado com token de leitura guardado como root), baixa o APK, calcula o SHA-256 e o executor o entrega ao gateway; o aparelho nunca fala com o GitHub. Comando `install_app {pkg, sha256, size}` assinado só pelo mestre; o gateway libera o download só ao aparelho que o comando cita; o aparelho confere hash, pacote e certificado e instala em silêncio como Device Owner. Contrato do app em docs/APP-INSTALL.md (**lado do aparelho ainda não feito**). Limite: o mestre aprova um arquivo, não código; para o NotToday, gerar o APK num CI da conta do mestre.

