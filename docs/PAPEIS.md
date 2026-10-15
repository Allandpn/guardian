# Papéis dos guardiões (especificação, ainda não implementada)

Objetivo: um guardião **administrador** controla tudo; os outros guardiões só cuidam de **domínios** (liberar, bloquear, bloquear de novo). Assim uma passkey de guardião de domínios, se for perdida ou roubada, nunca mexe nas regras, nos apps, no PIN nem nas pessoas.

## Decisões

- Um administrador só, com duas ou mais passkeys (a segunda é a chave de reserva: outro celular ou uma chave física).
- O guardião de domínios pode liberar sem prazo.
- Não há lista de domínios protegidos além do canário: o guardião de domínios é uma pessoa de confiança.
- O guardião de domínios vê só Domínios e o histórico das ações de domínio.
- O administrador remove um guardião de domínios sozinho, na hora.
- O guardião de domínios pode cadastrar passkeys extras para si mesmo.

## Permissões

| Ação | Admin | Domínios |
|---|---|---|
| Regras, apps, PIN, janelas, ativar, pedidos do aparelho | sim | não |
| `pihole_allow`, `pihole_deny`, `pihole_remove`, `pihole_batch` | sim | sim |
| Responder pedidos de liberação, ver o log de bloqueios | sim | sim |
| Convidar guardião, parear aparelho ou executor, esquecer aparelho | sim | não |
| `add_guardian`, `remove_guardian` | sim | não |
| `add_credential` | qualquer guardião | só para si mesmo |
| Ver regras, apps e estado dos aparelhos; auditoria completa | sim | não |

## Onde a regra vale

Quem aplica é quem recebe o comando: o aparelho (Kotlin) e o executor (Python), com o mesmo código de referência em `protocol/commands.py`. O gateway também recusa cedo, mas só para dar uma mensagem clara: um gateway invadido não consegue dar poder a ninguém, porque o papel fica fixado em cada consumidor junto com as passkeys.

- A confiança guarda o papel: `guardians: {id: {name, creds, role}}`, com `role` = `admin` ou `domains`. Sem `role` (pareamentos antigos) vale `admin`.
- `add_guardian {id, name, cred, spki, role}`: `role` obrigatório; só um admin assina.
- `add_credential {id, cred, spki}`: um admin assina para qualquer um; um guardião de domínios só para o próprio `id`.
- `remove_guardian {id}`: só admin. Nunca remove o último admin. Assinaturas exigidas: duas se houver dois ou mais admins, senão uma. No aparelho, remover um guardião de domínios vale na hora; remover um admin continua com a espera.
- Qualquer outro comando de um guardião de domínios é recusado pelo aparelho. No executor, ele só pode mandar os quatro comandos de domínio.
- Não há comando para trocar papel: para mudar, o admin remove e convida de novo.

## Gateway e site

- Tabela `guardians` ganha `role`. O primeiro guardião cadastrado é admin. O convite leva o papel escolhido pelo admin.
- `/v1/me` devolve o papel. Rotas de admin respondem 403 para o guardião de domínios. `/v1/devices` devolve para ele só o executor completo e o nome dos aparelhos; `/v1/audit` só as linhas do executor e dos pedidos.
- Site do admin: Pessoas mostra o papel de cada um, o convite tem a escolha do papel e um aviso vermelho enquanto o admin tiver só uma passkey. Propagar um guardião de domínios só vai para o executor (o aparelho não precisa conhecê-lo).
- Site do guardião de domínios: Domínios, Histórico (só domínios) e Conta (as próprias passkeys e "Cadastrar outra passkey").

## Riscos

- **Admin sem nenhuma passkey.** Ninguém mais administra: sobra só o PIN local no aparelho e, sem ele, o reset de fábrica (LOCKOUT #25). Por isso o aviso até cadastrar a reserva.
- **Guardião de domínios mal-intencionado** pode liberar qualquer domínio ou bloquear um domínio de que o sistema precisa (Tailscale, o próprio gateway). Aceito: é uma pessoa de confiança, e o admin desfaz pelo site e o remove na hora.
