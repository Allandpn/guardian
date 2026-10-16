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

## Como retomar

- Repositórios: `Allandpn/guardian` (branch `main`) e `Allandpn/NotToday` (branch `claude/wizardly-goldberg-sxu89c`, ainda sem PR para a `main`).
- Guardian: `PYTHONPATH=src python3 -m unittest discover -s tests`. Navegador: `PYTHONPATH=src python tests/e2e_browser.py` num Python com `playwright`
  (`SHOTS=pasta` salva capturas, `WIDE=1` também em tablet e computador, `AUDIT=1` mede largura e alvos de toque no celular).
- NotToday: `ANDROID_HOME=<sdk> GUARDIAN_REPO=../guardian ./gradlew :app:testDebugUnitTest :app:lintDebug`;
  `NOTTODAY_SHOTS=<pasta>` gera capturas das telas.
- Wireframes (privados): telas atuais, fluxo de liberação e papéis, publicados como Artifacts na conta do dono.
