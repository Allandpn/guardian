# Operação do Pi com o acesso fechado

Depois do fechamento (usuários comuns sem `sudo`, sem grupo `docker`, sem SSH por chave, sem senha de administrador na mão de quem desenvolve), **nada muda no Pi sem a
assinatura do mestre (Gandalf), dentro da janela dele**. Este documento diz como fazer cada coisa a partir de então. Princípios e decisões: `docs/DECISOES.md` (45 a 50).

## Quem pode o quê
- **Sessões de desenvolvimento (nuvem):** escrevem código nos repositórios do GitHub, abrem PR, criam tags de versão (com a confirmação do dono). Não têm acesso ao Pi.
- **Mestre (Gandalf):** assina, com a passkey e dentro da janela, tudo que mexe no Pi: deploy de projeto, cadastro e instalação de app, instalação no PC, vetos e liberações.
- **Quem tem o Pi na mão:** só o acesso físico (o Pi fica no cofre, com roteador e modem). O root **não tem senha** (login de root desativado) e a senha dos usuários comuns fica travada: sem o cartão SD na mão, ninguém vira root.
- O que as sessões que rodam no Pi (usuário comum) ainda conseguem: ler logs (`journalctl`, grupo `adm`) e mexer no que é do próprio usuário. Não conseguem mudar nada
  dos serviços, das pastas de deploy, do gateway, do executor, do deployer nem do Pi-hole.

## Fluxos do dia a dia
1. **Código de servidor (Guardian, estudos, imagineer, plano-de-estudos):** merge na `main`, tag `release/N` (N sempre maior), o Pi detecta em ~20 s. Gandalf: site > **Deploys** >
   "Colocar no ar". O Pi confere, instala, testa e volta sozinho para a versão anterior se falhar. Aviso vermelho "mexe em segurança" exige o aceite explícito dele.
   Voltar atrás **não** é "deploy da versão antiga" (downgrade é recusado): corrija e publique `release/N+1`.
2. **App Android novo:** repositório no GitHub (público, ou privado liberado no token do Pi), Release `vX.Y` com um APK assinado (`docs/DEPLOY.md`, "Apps Android"). Gandalf:
   site > Deploys > **Cadastrar app novo** (nome, dono/repositório, pacote). Depois: Apps > **Catálogo** > Instalar no aparelho. App novo ainda pede aprovação em Apps > Solicitações.
3. **Atualizar app Android (inclusive o NotToday):** nova Release com `versionCode` maior; Apps > Catálogo > Instalar/Atualizar. O aparelho confere hash e certificado.
4. **Programa no computador (Windows):** PC > "Instalar pelo winget" ou "Rodar um script", assinado pelo mestre.
5. **Domínios e apps:** como sempre, pelos guardiões. Vetos e o que for só do mestre, pelo mestre.

## Se algo der errado
- **Gateway fora do ar / site em "Carregando…":** corrigir no repositório, tag `release/N+1`, deploy assinado. Se o site não abre para assinar: acesso físico (abaixo).
- **Passkey do mestre perdida:** hoje só há **um** mestre. Cadastrar o segundo mestre (convite assinado pelo primeiro) antes de precisar. Sem ele, só o acesso físico resolve.
- **Acesso físico (emergência):** o Pi não tem login de root por senha. Quem abrir o cofre recupera o acesso pelo cartão SD:
  1. desligar o Pi, tirar o cartão SD e ler no PC (a partição `bootfs`, a pequena, aparece no Windows);
  2. em `cmdline.txt` (uma linha só) acrescentar ao fim ` init=/bin/sh` e salvar; devolver o cartão e ligar o Pi com teclado e tela;
  3. no prompt: `mount -o remount,rw /` e `mount -t proc proc /proc`; então `passwd root` (ou `passwd allan` e `usermod -aG sudo allan`) e o que for preciso;
  4. **desfazer o passo 2** (tirar o ` init=/bin/sh`), reiniciar e, ao terminar, fechar de novo (`gpasswd -d <usuário> sudo`, `gpasswd -d <usuário> docker`, `passwd -l <usuário>`).
  Quem tem a chave do cofre tem, portanto, o Pi: por isso a chave fica com o Gandalf.
- **Pasta de deploy "sem garantia de isolamento":** o deployer só confia em pasta do root que ninguém mais escreve (inclusive o diretório de cima). Se um deploy for
  recusado por isso, alguém mexeu na pasta: ver o dono dos arquivos (`ls -l`) e restaurar para root, no acesso físico.
- **Token de leitura do GitHub:** `/etc/guardian-deploy/github_token` (root, sem validade, só leitura). Para revogar: página do token no GitHub. Para trocar: acesso físico.

## Onde olhar (sem root)
- `journalctl -u guardian-executor`, `-u guardian-deployer` (grupo `adm`), e o site: Deploys (histórico), Início, Histórico.
- Estado do deployer: `/var/lib/guardian-deploy/status.json`, `offers.json`, `apk-offers.json` (legíveis).

## Para mexer no próprio Pi (só root, acesso físico)
Registro dos projetos `/etc/guardian-deploy/projects.json`, política `/etc/guardian-deploy/policy.json` (donos permitidos e token), código do deployer
`/usr/local/lib/guardian-deployer/`, `deploy/install-deployer.sh` (reinstala o deployer, que **não** se atualiza por deploy de propósito).
