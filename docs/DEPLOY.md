# Deploy assinado

Objetivo: o código do Guardian (e, depois, dos outros projetos do Pi) só muda no Pi com a aprovação do **guardião-mestre**, dentro do
horário dele. Quem desenvolve (você, as sessões do Claude) programa e testa onde quiser, mas não coloca nada no ar.

## Como funciona

1. Quem desenvolve cria uma **etiqueta de versão** no repositório (`release/1.8`). Isso é o pedido de deploy.
2. O **deployer** (root, no Pi) busca as etiquetas, compara com o que está no ar e publica **ofertas** em `/var/lib/guardian-deploy/offers.json`:
   projeto, etiqueta, commit, resumo, autor e a lista de **arquivos de segurança** que a versão toca. Quem calcula isso é o deployer,
   com uma lista que fica no Pi (`/etc/guardian-deploy/projects.json`), não o pipeline nem o repositório.
3. O executor leva as ofertas ao site: tela **Deploys** (só o mestre). O mestre vê o mínimo: projeto, versão, resumo, quem pediu e uma
   linha de risco ("não mexe em segurança" ou "mexe em segurança (N)").
4. O mestre toca em **Colocar no ar** e assina com o passkey (comando `deploy`: projeto + hash do commit; `sensitive_ok` só quando a
   versão mexe em segurança e ele confirmou o aviso em vermelho). O comando só vale dentro do horário dele (relógio do executor).
5. O executor confere assinatura, papel (só mestre) e horário e deixa o pedido em `inbox/`, com o **comando assinado inteiro**. O deployer
   **confere tudo de novo**, inclusive a assinatura da passkey, o papel, o horário (pelo relógio dele) e o contador, contra a **sua própria cópia
   da confiança** (`/var/lib/guardian-deploy/trust.json`, só do root). Vale o que está dentro do comando assinado: projeto, commit e
   `sensitive_ok`. O commit tem que ser a ponta de uma etiqueta, e se a versão toca segurança o comando precisa ter `sensitive_ok`. Um executor
   comprometido não coloca nada no ar sozinho. Passkey nova ou mestre novo chegam ao deployer pelo mesmo caminho: o executor encaminha o
   comando de confiança assinado, e o deployer o confere e aplica.
6. Instala (`git checkout` do commit + passos do projeto), roda a **checagem de saúde** e, se falhar, **volta sozinho** para a versão
   anterior (voltar a uma versão já aprovada não afrouxa nada, então não pede assinatura). O resultado vai para `status.json` e para a tela.

## O que não é atualizado por um deploy

O pacote do deployer (`/usr/local/lib/guardian-deployer`), o serviço (`guardian-deployer.service`) e o registro
(`/etc/guardian-deploy/projects.json`) são de root e instalados à mão por `deploy/install-deployer.sh`. Mudá-los exige root no Pi,
que fica com o guardião. O código do executor e do gateway muda por deploy, mas está na lista de arquivos de segurança: o mestre vê o aviso.

## Instalar (uma vez, como root)

1. `sudo sh deploy/install-deployer.sh` (precisa de `python3-cryptography` no Python do sistema). Na primeira vez, o script copia a confiança
   do executor para o deployer (`init-trust`) e lista os guardiões e quantas passkeys cada um tem: confira que são só os que você reconhece.
2. Repositório público (como o do Guardian): nada a fazer, o Pi lê por https. Repositório privado: gere uma chave só de leitura
   (`ssh-keygen -t ed25519 -N '' -f /etc/guardian-deploy/<projeto>_deploy_key`), cadastre a `.pub` como *deploy key* (sem escrita)
   e aponte `ssh_key` no registro.
3. Confira `/etc/guardian-deploy/projects.json` (repositório, `workdir`, passos, checagens, lista `sensitive`).
4. `systemctl restart guardian-executor` e `systemctl start guardian-deployer`.
5. Crie uma etiqueta `release/…` no repositório: ela aparece em **Deploys** em até 20 s.

## Projetos novos

Cada projeto é uma entrada em `projects.json` (`repo`, `tag_prefix`, `workdir`, `sensitive`, `steps`, `health`). Cadastrar um projeto novo
exige editar esse arquivo como root (ainda não há comando assinado para isso).

## Limites desta primeira versão

- A política do compose (`deployer/policy.py`) recusa: privilégios, rede/PID/IPC do host, dispositivos, pasta do host fora do projeto (inclusive
  por link simbólico da versão ou deixado na pasta de deploy), contexto de build fora do projeto (`context` e `additional_contexts`), `ssh` no
  build, segredo lido do ambiente, volume ou rede com `name:` de outro dono e projeto do compose com o nome de outro serviço (o Guardian é `deploy`).
  Mudar a política exige reinstalar o deployer como root (decisão 53).

- A etiqueta e o commit vêm de quem desenvolve: o mestre aprova **o que o deployer mostra**, e a lista de arquivos de segurança é a defesa.
  Mantenha a lista `sensitive` completa (verificação de assinatura, papéis, janelas, veto, o próprio deploy).
- Os testes automáticos rodam fora do Pi (GitHub Actions ou na sessão); o deployer não os executa. A saúde pós-deploy e a reversão
  automática cobrem uma versão que não sobe.
- Isolamento de cada projeto (usuário próprio, contêiner sem root) e retirada do `sudo` do desenvolvedor são etapas seguintes.

## Primeiro deploy de teste

A versão `release/2` foi criada só para testar o fluxo (mudança apenas de documentação). Ela aparece em Deploys como "não mexe em segurança".

## Script no Pi (`pi_run`), só o mestre

Tela **PC > Executar no Raspberry Pi**: o mestre cola um script bash e assina com a passkey (comando `pi_run`: script, nome opcional e tempo limite de 5 s a 1 h, padrão 10 min).
O executor **não roda nada** (ele não tem poder para isso): deixa o comando assinado na caixa do deployer, que confere a assinatura, o papel (só mestre), a janela de horário e o contador
contra a sua cópia da confiança, e roda o script como root, uma vez, com `bash`, `PATH` fixo e `HOME=/root`. Vale o script que está dentro do comando assinado, não o que o executor escreveu ao lado.
Sem a assinatura conferida pelo deployer, nada roda. O resultado (código, e o fim da saída, 1500 caracteres) vai para o histórico dos deploys; só os 3 mais recentes guardam a saída.

**Atenção:** o deployer é de root e **não é atualizado por deploy**. Esta função só passa a existir no Pi depois de `sudo sh deploy/install-deployer.sh` e `systemctl restart guardian-deployer`
(uma vez, por quem tem root: com o acesso fechado, só com acesso físico ao Pi, veja `docs/OPERACAO-FECHADA.md`). Antes disso o site mantém o botão desligado e o deployer recusaria o pedido.

## Revisão de segurança (2026-11-11): o que ficou combinado

1. **Lista `sensitive` completa no Pi.** O aviso vermelho depende de caminho. O registro do Pi (`/etc/guardian-deploy/projects.json`) tem de listar também o site (`src/guardian/gateway/*`, que inclui
   `static/*.js`: é o JavaScript que monta o que a passkey assina, então uma versão que o troque pode mostrar "liberar um domínio" e assinar outra coisa), o agente do PC (`src/guardian/agent/*`),
   `tools/*`, `.github/*` e `pyproject.toml`. O `deploy/deploy-projects.example.json` já traz a lista nova; **na visita física, copie as linhas `sensitive` do guardian para o arquivo do Pi.**
2. **Renomear não esconde.** O deployer agora compara com `--no-renames`: mover um arquivo sensível para fora da pasta lista o que sumiu e o que surgiu. (Vale depois de reinstalar o deployer.)
3. **Agente do PC só por commit fixo.** `tools/atualizar-agente.ps1` baixava a `main`, que muda: o mestre assinava um texto e o código vinha de fora. Agora o script exige o hash do commit (40 caracteres),
   que fica dentro do texto assinado. Troque `$Commit` pelo hash que você revisou e confira no GitHub antes de assinar.
4. **Ao reinstalar o deployer (acesso físico), confira o que vai instalar:** `git -C /opt/guardian log -1` tem de ser o commit que o mestre aprovou, e `git diff <versão antiga>..HEAD -- src/guardian/deployer src/guardian/protocol deploy/install-deployer.sh`
   é o que passa a rodar como root. O `install-deployer.sh` copia o que estiver na pasta: ele confia na cópia, quem confere é quem instala.
5. **Risco que continua (aceito):** quem tem a passkey do mestre, dentro da janela dele, escreve um script como root no Pi (`pi_run`). A defesa é a passkey (com verificação do usuário), a janela, o CSP sem script inline,
   `SameSite=Strict` e a conferência de origem. Se isso incomodar, a saída é tirar o `pi_run` do deployer.

## Segunda revisão (2026-11-12): o que só vale depois de reinstalar o deployer

1. **Compose: valida o que vai rodar.** Antes, a política conferia o `docker-compose.yml`, mas o passo `docker compose up` (sem `-f`) preferia um `compose.yaml` e juntava os
   `*.override.*` que a versão trouxesse: uma versão "verde" subia um contêiner privilegiado com o disco do Pi montado. Agora todo passo `docker compose ...` de um projeto
   `"type": "compose"` roda com `--project-directory`, `-f` (e `--env-file` e `-p`, se o registro disser) iguais aos da validação; o `.env` usado na validação é o da versão,
   se ela traz um, e só senão o da pasta; e arquivos de compose novos, `.env`, `Dockerfile`, `.pth`, `sitecustomize.py`, `.venv/` e `.github/` são sempre sensíveis.
2. **Política por lista do que é permitido.** Campo do compose que a política não conhece (serviço, `build`, `deploy`, topo) é recusado, em vez de passar.
3. **"Seguro" é a exceção.** Com `"safe"` no registro, tudo é sensível, menos o que a lista diz (`docs/*`, `*.md`). Uma lista do que é sensível sempre esquece algo que roda código.
4. **O gateway também passa pela política.** O projeto `guardian` vira `"type": "compose"`, com o nome do projeto (`deploy`) e a rede fixa (`guardian_net`) declarados no registro.
5. **Scripts de root fora da pasta de deploy.** `firewall.sh`, `torrent-firewall.sh` e o compose do Suricata passam a rodar de `/usr/local/lib/guardian-root/`; uma versão nova não os altera.

### Na visita física, nesta ordem
1. Conferir o commit: `git -C /opt/guardian log -1` tem de ser o que o mestre colocou no ar.
2. Ler o que vai virar root: `git -C /opt/guardian diff <versão antiga>..HEAD -- src/guardian/deployer src/guardian/protocol deploy/install-deployer.sh deploy/*.service`.
3. Em `/etc/guardian-deploy/projects.json`, trocar a entrada `guardian` pela de `deploy/deploy-projects.example.json` (chaves novas: `type`, `compose_file`, `compose_env_file`,
   `compose_project`, `compose_names`, `safe`, e os passos sem `--env-file`/`-f`, que o deployer agora põe sozinho). Nos projetos `estudos` e `imagineer`, nada muda nos passos.
4. `sudo sh deploy/install-deployer.sh` (instala o deployer novo e os scripts de root, e atualiza as unidades do firewall e do torrent que já existirem).
5. `sudo systemctl daemon-reload && sudo systemctl restart guardian-deployer guardian-executor`, e conferir `systemctl is-active guardian-deployer` e
   `grep -o '"features": \[[^]]*\]' /var/lib/guardian-deploy/offers.json`.
6. Fechar de novo o acesso (`docs/OPERACAO-FECHADA.md`).

Fica de fora (baixo risco): a lista de trackers do Pi-hole ainda é lida de `/opt/guardian/deploy/pihole/torrent-trackers.txt`; uma versão pode esvaziá-la (o arquivo é sensível pela lista `safe`).

## Apps Android (loja própria)

Instalar e atualizar apps nos celulares sem a janela de dev. O aparelho **nunca fala com o GitHub**.

1. No registro (`/etc/guardian-deploy/projects.json`) o app é uma entrada `"type": "android_app"`:

   ```json
   "filtro-chamadas": {
     "type": "android_app",
     "github": "Allandpn/FiltroChamadasIndesejadas",
     "pkg": "com.exemplo.filtro",
     "tag_prefix": "v",
     "asset": "\\.apk$",
     "token_file": "/etc/guardian-deploy/github_token",
     "repo": "git@github.com:Allandpn/FiltroChamadasIndesejadas.git",
     "ssh_key": "/etc/guardian-deploy/filtro_deploy_key",
     "sensitive": ["app/src/main/java/*/policy/*", "app/src/main/AndroidManifest.xml"]
   }
   ```

   `token_file` (token do GitHub só de leitura de *Contents*) e `ssh_key` só são necessários em repositório privado. Sem `repo`, o Pi não
   calcula a linha de risco. Cadastrar um app novo exige editar esse arquivo como root.
2. A cada 5 minutos o deployer lê as Releases, baixa o APK (guardado em `/var/lib/guardian-deploy/apks/<sha256>.apk`) e publica `apk-offers.json`
   com pacote, versão, SHA-256, tamanho e quais arquivos de segurança a versão toca (comparada com a Release anterior).
3. O executor envia os APKs novos ao gateway (`POST /v1/devices/{executor}/apks/{sha256}`, em pedaços, conferido contra o hash da URL).
4. O mestre abre **Apps > Catálogo** e toca em **Instalar em <aparelho>**: comando `install_app {pkg, sha256, size}` assinado, só dele e só na janela dele.
5. O gateway só libera o download (`GET /v1/devices/{dev}/apk/{sha256}`) para o aparelho cujo comando assinado citou aquele hash.
6. O aparelho confere o hash e o certificado e instala em silêncio (Device Owner). Contrato completo para o app: `docs/APP-INSTALL.md`.

Limite: o mestre aprova um arquivo, não código. Para o NotToday, o recomendado é gerar o APK num repositório de CI da conta do mestre (sem escrita
para quem desenvolve), que compila a etiqueta e publica a Release.

### Cadastrar um app novo pelo site (sem terminal no Pi)
Deploys > "Cadastrar app novo": nome curto, `dono/repositório` e o pacote (`applicationId`). O mestre assina `project_add`; o executor entrega o pedido ao deployer,
que confere de novo e grava o app em `projects.json`. Regras (todas no deployer, que roda como root):
- só **app Android** lido das Releases: o cadastro nunca cria projeto com diretório e passos a rodar no Pi (esses continuam só por root, direto no registro);
- o dono do repositório tem de estar em `/etc/guardian-deploy/policy.json` (`allowed_owners`); sem esse arquivo ninguém é permitido;
- repositório **público** (lido sem token) ou **privado**: no segundo caso o deployer usa o **token único de leitura** do Pi (`token_file` em `policy.json`, por padrão
  `/etc/guardian-deploy/github_token`, só root lê). Quem decide quais repositórios privados o token enxerga é o dono do token, **no GitHub** (fine-grained token,
  permissão Contents: leitura, lista de repositórios): nenhuma sessão de desenvolvimento mexe nisso. Se o token não enxerga o repositório, o cadastro é recusado com essa
  mensagem. O mesmo token serve à API de Releases e ao git (sem chave SSH);
- o nome, o pacote e o repositório não podem já existir no registro (um app novo não toma o pacote de outro);
- a lista de arquivos sensíveis é a padrão de apps Android (workflows, gradle, manifesto).
Depois de cadastrar, o app aparece em Apps > Catálogo quando houver uma Release. Instalar continua pedindo a passkey do mestre (`install_app`).

**Token de leitura (uma vez):** em GitHub > Settings > Developer settings > Fine-grained tokens: acesso só aos repositórios do app, permissão *Contents: Read-only*, validade
o maior prazo que você aceitar. Gravar no Pi como root: `install -m 0600 /dev/stdin /etc/guardian-deploy/github_token` (cole o token e Ctrl-D) e acrescentar
`"token_file": "/etc/guardian-deploy/github_token"` em `/etc/guardian-deploy/policy.json`. Para liberar um repositório privado novo basta incluí-lo na lista do token no GitHub e
cadastrar o app pelo site. Renovar o token ao vencer exige root no Pi (guarde a data).
