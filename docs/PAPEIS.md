# Papéis: guardião-mor e guardião

Nos textos e telas, o papel `admin` é o **guardião-mor** e o papel `domains` é o **guardião**. Os nomes internos (`admin`, `domains`) não mudam.

Estado: implementado e testado (protocolo em Python e Kotlin, gateway, site, executor e app).

Objetivo: o **guardião-mor** controla tudo; os demais **guardiões** só cuidam de **domínios** (liberar, bloquear, bloquear de novo). Assim uma passkey de guardião, se for perdida ou roubada, nunca mexe nas regras, nos apps, no PIN nem nas pessoas.

## Decisões

- Um guardião-mor só, com duas ou mais passkeys (a segunda é a chave de reserva: outro celular ou uma chave física).
- O guardião pode liberar sem prazo.
- Não há lista de domínios protegidos além do canário: o guardião é uma pessoa de confiança.
- O que o guardião vê, além de Domínios, é o guardião-mor quem escolhe, por guardião: estado dos aparelhos, regras (só leitura), apps (só leitura) e histórico completo. Sem nada marcado ele vê Domínios, o histórico das ações de domínio e a própria Conta.
- O convite já vem como "Guardião (só domínios)".
- O guardião-mor remove um guardião sozinho, na hora.
- O guardião pode cadastrar passkeys extras para si mesmo.

## Permissões

| Ação | Guardião-mor | Guardião |
|---|---|---|
| Regras, apps, PIN, janelas, ativar, pedidos do aparelho | sim | não |
| `pihole_allow`, `pihole_deny`, `pihole_remove`, `pihole_batch` | sim | sim |
| Responder pedidos de liberação, ver o log de bloqueios | sim | sim |
| Convidar guardião, parear aparelho ou executor, esquecer aparelho | sim | não |
| `add_guardian`, `remove_guardian` | sim | não |
| `add_credential` | qualquer guardião | só para si mesmo |
| Ver estado dos aparelhos, regras, apps e auditoria completa | sim | se o admin liberar (cada item separado, só leitura) |

## Onde a regra vale

Quem aplica é quem recebe o comando: o aparelho (Kotlin) e o executor (Python), com o mesmo código de referência em `protocol/commands.py`. O gateway também recusa cedo, mas só para dar uma mensagem clara: um gateway invadido não consegue dar poder a ninguém, porque o papel fica fixado em cada consumidor junto com as passkeys.

- A confiança guarda o papel: `guardians: {id: {name, creds, role}}`, com `role` = `admin` ou `domains`. Sem `role` (pareamentos antigos) vale `admin`.
- `add_guardian {id, name, cred, spki, role}`: `role` obrigatório; só um admin assina.
- `add_credential {id, cred, spki}`: um admin assina para qualquer um; um guardião só para o próprio `id`.
- `remove_guardian {id}`: só admin. Nunca remove o último admin. Assinaturas exigidas: duas se houver dois ou mais admins, senão uma. No aparelho, remover um guardião vale na hora; remover um admin continua com a espera.
- Qualquer outro comando de um guardião é recusado pelo aparelho. No executor, ele só pode mandar os quatro comandos de domínio.
- Não há comando para trocar papel: para mudar, o admin remove e convida de novo.

## Gateway e site

- Tabela `guardians` ganha `role`. O primeiro guardião cadastrado é admin. O convite leva o papel escolhido pelo admin.
- `/v1/me` devolve o papel e a visibilidade (`see: {devices, rules, apps, history}`). Rotas de admin respondem 403 para o guardião. `/v1/devices` devolve para ele o executor completo e, dos aparelhos, só o que `see` libera; `/v1/audit` sem `history` traz só as linhas do executor e dos pedidos.
- `POST /v1/guardians/{id}/see` (admin) grava a visibilidade. `POST /v1/guardians/{id}/remove` (admin) tira o guardião do gateway e derruba as sessões dele na hora; nunca o último guardião-mor nem a si mesmo. A visibilidade é regra do gateway (é ele quem guarda os relatórios); as ações continuam sendo conferidas no aparelho e no executor.
- Site do admin: Pessoas mostra o papel de cada um, o convite tem a escolha do papel e um aviso vermelho enquanto o admin tiver só uma passkey. Propagar um guardião só vai para o executor (o aparelho não precisa conhecê-lo).
- Site do guardião: Domínios, Histórico (só domínios) e Conta (as próprias passkeys e "Cadastrar outra passkey").

## Riscos

- **Guardião-mor sem nenhuma passkey.** Ninguém mais administra: sobra só o PIN local no aparelho e, sem ele, o reset de fábrica (LOCKOUT #25). Por isso o aviso até cadastrar a reserva.
- **Guardião mal-intencionado** pode liberar qualquer domínio ou bloquear um domínio de que o sistema precisa (Tailscale, o próprio gateway). Aceito: é uma pessoa de confiança, e o admin desfaz pelo site e o remove na hora.

## Passkey só neste aparelho e horário (por guardião)

Definidos **na criação** do guardião (no convite) e **não mudam**: não existe comando para alterá-los. Para mudar, crie outro guardião.

- **Passkey só neste aparelho** (`allow_sync: false`): o aparelho, o executor e o gateway recusam assinaturas cuja passkey tem a flag BE
  ("backup eligible") ligada, que é a das passkeys copiadas para a nuvem (Gerenciador de Senhas do Google, iCloud). A flag está
  dentro do `authenticatorData`, que é assinado. Windows Hello, Touch ID e chaves de segurança têm BE desligada. O gateway também
  recusa o cadastro de uma passkey sincronizável e não gasta o convite. Passkey extra herda a regra do guardião.
- **Horário** (`window`): `{days: [0..6, segunda = 0], from, to (minutos do dia), utc_offset_min}`, por exemplo seg–sex, 12h às 17h em
  Brasília (`-180`; o Brasil não tem horário de verão). O comando de um guardião com horário só vale se **quem o consome** o recebe
  dentro do horário, pelo relógio dele: o do executor (rede) e o do aparelho. O relógio do navegador não conta. O gateway também
  recusa o login (a sessão acaba no fim do horário) e os comandos fora do horário, só para dar uma mensagem clara.
  No aparelho o relógio é o do Android: ligue a restrição "Bloquear mudar data/hora" para o horário não ser burlado ali.
  Vale para o autor do comando; quem só co-assina não é conferido.
- **Remover passkey** (`remove_credential {id, cred}`): guardião-mor; com dois ou mais guardiões-mor precisa das duas assinaturas; nunca remove a última passkey
  (use remover guardião). Vale na hora, sem espera.

Efeito prático para quem se protege: a passkey do computador do trabalho (Windows Hello, sem sincronizar) só existe naquele computador
e só vale em dia útil das 12h às 17h; em casa, à noite, nem com acesso remoto ao computador do trabalho ela vale.
Uma segunda passkey do mesmo guardião, cadastrada no computador de casa (Windows Hello), tem a mesma regra: serve de reserva sem reabrir o buraco da noite.
