# Agente do Windows

Estado: implementado e testado (protocolo, gateway, agente, tela local, tela de aprovação, scripts de instalação). Falta validar num Windows de verdade
(winget como SYSTEM, a tarefa agendada, o ícone da bandeja) e fazer a conta comum do dia a dia.

Objetivo: o computador de quem usa o Guardian deixa de ter **uma senha de administrador na mão de quem o usa**. Para liberar um domínio,
instalar um programa ou rodar algo como administrador, a pessoa **pede** e um guardião-mor ou o mestre **aprova com a passkey**.

## Como funciona

```
 PC (conta comum)           PC (SYSTEM)                         Gateway                    Guardião-mor / mestre
 tela local  ──pedido──▶  Guardian Agent ──assinado pela chave do agente──▶  fila de pedidos  ──▶  lê o texto exato
 localhost:47657           (tarefa agendada)                                                       aprova com a passkey
                                ▲                                                                       │
                                └──── comando assinado (win_install / win_run) ◀────────────────────────┘
```

- O agente é um **aparelho** como o celular: chave própria, relatório, pedidos. Os **domínios** bloqueados do PC e os pedidos de liberação usam o fluxo que já existe
  (`docs/LIBERACAO.md`): o IP do PC na Tailscale vai no relatório e o executor do Pi-hole separa o que foi bloqueado para ele.
- **Instalar programa** (`win_install`): um pacote do **winget** (id e versão), um **instalador por link** (`.msi` ou `.exe`) com o **SHA-256** que o guardião conferiu,
  ou um **arquivo que a pessoa já baixou** no computador (caminho em `C:\Users`, SHA-256 e, se tiver, o nome do assinante da assinatura digital).
  O agente baixa por https (redirecionamentos só para https), compara o hash e só então executa. Hash diferente: nada roda.
  No arquivo local ele **copia para a pasta protegida lendo uma vez, confere o hash e a assinatura na cópia e executa a cópia**: trocar o original depois da aprovação não adianta.
- **Rodar comando** (`win_run`): um script do PowerShell, até 6000 bytes, como administrador, **uma vez**, com tempo limite (padrão 10 min, máximo 1 h).
  O que o guardião assina é o texto exato: o gateway recusa a aprovação se o comando assinado não for idêntico ao pedido.
- Quem aprova: **guardião-mor ou mestre, com uma passkey**. O guardião comum só mexe em domínios (nem vê o pedido de instalação).
- **Validade**: todo comando carrega `not_after` (24 h pela tela, no máximo 7 dias). Um comando aprovado e não executado porque o agente estava desligado **vence sozinho**.
- O agente **não confia no gateway**: confere de novo a assinatura, o papel do autor, a janela de horário, o destino, o contador (replay) e a validade.
  O contador é gasto **antes** de executar, então uma queda no meio de uma instalação não repete o comando.
- Resultado e saída (até 3000 caracteres) voltam no relatório e aparecem na tela **PC** do site e na tela local.

## Instalação (uma vez, com a pessoa de confiança)

1. No site: **Dispositivos > Parear aparelho** e copie a string de pareamento (vale por pouco tempo).
2. No PC, num PowerShell **como administrador**, de dentro do repositório:
   ```
   powershell -ExecutionPolicy Bypass -File src\guardian\agent\windows\install.ps1 -Pairing "<string>" -Tray
   ```
   Precisa de **Python 3.11+ instalado para todos os usuários** (em `C:\Program Files`): `winget install --id Python.Python.3.12 --scope machine`, ainda como administrador.
   O instalador recusa um Python dentro de `C:\Users\...` e o atalho da Microsoft Store: o agente roda como SYSTEM e uma conta comum poderia trocar o `python.exe` dela.
   O script copia o agente para `C:\Program Files\GuardianAgent`, cria o estado em `C:\ProgramData\GuardianAgent`
   (só SYSTEM e administradores), pareia, cria a tarefa `GuardianAgent` (SYSTEM, sobe na inicialização, reinicia se cair) e o atalho **NotToday PC** na área de trabalho.
3. Confira o **fingerprint** que o script mostra, por voz, com o guardião.
4. No site, o PC aparece em **Dispositivos** (chip "Windows") e na tela **PC**.

Remover: `uninstall.ps1`, também como administrador (e **Dispositivos > esquecer** no site).

## Conta comum (sem isto a proteção é só de aparência)

Se a conta do dia a dia continuar **administradora**, quem usa o computador para o serviço, apaga a chave, instala o que quiser por fora e muda o DNS.
Para valer:

1. Crie uma conta de **administrador separada**, com uma senha que **só a pessoa de confiança** sabe (veja `docs/OPERACAO.md`).
2. Rebaixe a conta do dia a dia a **usuário padrão**: Configurações > Contas > Outros usuários > alterar tipo de conta, ou `net localgroup Administrators <usuario> /delete`.
3. Confira: numa conta comum, `C:\ProgramData\GuardianAgent` não abre e a tarefa `GuardianAgent` não para.
4. Ative o **BitLocker** com a chave de recuperação com a pessoa de confiança e ponha **senha na BIOS/UEFI** (sem isso dá para iniciar por um pen drive e mexer em tudo).
5. Aplicativos que pedem "executar como administrador" passam a pedir a senha da outra conta: é o momento de **pedir pelo Guardian** em vez de digitar.

## O que ele não impede (honestidade)

- Acesso físico: iniciar por pen drive, modo de recuperação, remover o disco. Só BitLocker e senha de BIOS fecham.
- DNS fora do Pi-hole: o agente não força o DNS do PC. Um navegador com DNS seguro (DoH) ou um programa com DNS próprio contorna o filtro (veja `docs/OPERACAO.md`).
- Quem aprova vê o texto, mas **o que um script faz é de quem assina**: aprove só o que entende. Instalador por link é só tão confiável quanto o arquivo que gerou o hash.
- Programas já instalados continuam rodando: o agente controla o que **entra**, não bloqueia por hash o que já existe (AppLocker/WDAC ficam para uma etapa futura).
- O agente rodando como SYSTEM é uma permissão grande por design: a segurança dele é a assinatura dos guardiões. Proteja as passkeys dos guardiões-mor e do mestre.

## Tela local, o **NotToday PC** (`http://localhost:47657/`)

Só em `127.0.0.1`. Confere o `Host` (contra DNS rebinding) e, nos POST, a origem e o cabeçalho `X-Guardian-Agent` (contra páginas de outros sites).
Abas: **Bloqueados** (marcar e pedir liberação), **Programas** (winget ou link com SHA-256), **Comando** (script) e **Pedidos** (estado, e o que o agente executou, com a saída).
Nada ali executa nada: tudo vira pedido no gateway, assinado com a chave do agente, que a conta comum não lê.

## Tela PC (guardião-mor e mestre)

Pedidos aguardando (com o texto exato), **Revisar e aprovar** (folha com o script ou os dados do instalador, uma passkey), **Negar** (sem passkey),
**Executar agora** (sem pedido) e **O que foi executado** (com a saída).

## Operação e solução de problemas

- O PC fica "Sem sinal" no site se o agente parar (alerta existente): é o aviso de que alguém mexeu.
- `winget` como SYSTEM: o agente usa o `winget.exe` da pasta do App Installer. Se faltar, instale o App Installer ou use instalador por link.
- Um `.exe` precisa de argumentos silenciosos (`/S`, `/quiet`...), senão fica esperando uma janela que o SYSTEM não mostra e vence no tempo limite (10 min por padrão).
  A tela local sugere os argumentos pelo assinante do arquivo (Wireshark: `/S`; DBeaver: `/S /allusers`, e o `/S` sozinho dá o código 666660 = parâmetros inválidos).
- **Instaladores só com janela** (Npcap gratuito, drivers, alguns pacotes): o agente não consegue (o SYSTEM não tem tela, e abrir janela como SYSTEM na área de trabalho de quem usa seria um caminho para virar administrador).
  Esses a pessoa de confiança instala uma vez com a conta de administrador. O resultado do pedido que estoura o tempo diz isso.
- O agente roda um comando do Windows por vez, numa fila própria: um instalador preso não derruba a conversa com o gateway (o site mostra "executando X há N min"), mas os outros esperam até ele terminar ou estourar o tempo.
- Logs: a tarefa `GuardianAgent` no Agendador de Tarefas; o resultado de cada comando também vai para o histórico do site.
- Atualizar o agente: rode `install.ps1` de novo (a chave e o pareamento ficam em `C:\ProgramData\GuardianAgent`).
