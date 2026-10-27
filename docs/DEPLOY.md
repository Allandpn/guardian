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
5. O executor confere assinatura, papel (só mestre) e horário e deixa o pedido em `inbox/`. O deployer **confere tudo de novo**: o commit
   tem que ser a ponta de uma etiqueta, e se a versão toca segurança o pedido precisa ter `sensitive_ok`.
6. Instala (`git checkout` do commit + passos do projeto), roda a **checagem de saúde** e, se falhar, **volta sozinho** para a versão
   anterior (voltar a uma versão já aprovada não afrouxa nada, então não pede assinatura). O resultado vai para `status.json` e para a tela.

## O que não é atualizado por um deploy

O pacote do deployer (`/usr/local/lib/guardian-deployer`), o serviço (`guardian-deployer.service`) e o registro
(`/etc/guardian-deploy/projects.json`) são de root e instalados à mão por `deploy/install-deployer.sh`. Mudá-los exige root no Pi,
que fica com o guardião. O código do executor e do gateway muda por deploy, mas está na lista de arquivos de segurança: o mestre vê o aviso.

## Instalar (uma vez, como root)

1. `sudo sh deploy/install-deployer.sh`
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

- A etiqueta e o commit vêm de quem desenvolve: o mestre aprova **o que o deployer mostra**, e a lista de arquivos de segurança é a defesa.
  Mantenha a lista `sensitive` completa (verificação de assinatura, papéis, janelas, veto, o próprio deploy).
- Os testes automáticos rodam fora do Pi (GitHub Actions ou na sessão); o deployer não os executa. A saúde pós-deploy e a reversão
  automática cobrem uma versão que não sobe.
- Isolamento de cada projeto (usuário próprio, contêiner sem root) e retirada do `sudo` do desenvolvedor são etapas seguintes.
