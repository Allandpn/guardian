# Papéis: guardião-mestre, guardião-mor e guardião

## Guardião-mestre (2026-10-17)

Um terceiro papel, `master`, fecha a brecha de um guardião-mor criar outro (ele mesmo, com outra passkey) para juntar duas assinaturas e remover a pessoa de confiança.

| | Mestre | Guardião-mor | Guardião |
|---|---|---|---|
| Incluir, remover e promover guardiões (`add_guardian`, `remove_guardian`, `remove_credential`, `set_role`, `add_credential` de outro) e convidar | sim, **sozinho** | não | não |
| Tudo o mais (regras, PIN, janelas, domínios, apps, ativar, parear aparelho) | sim | sim | só domínios e apps |
| `add_credential` para si mesmo | sim | sim | sim |

- Com mestre, nenhuma assinatura de guardião-mor ou guardião vale para mexer em guardiões, nem junta de duas.
- Não existe remover ou rebaixar o **último mestre**. O ideal é ter dois (a pessoa de confiança e uma reserva dela), um incluindo o outro.
- No aparelho, remover um guardião-mor ou mestre continua passando pelo atraso (24 h). Remover um guardião comum vale na hora.
- Janela de horário e tipo de passkey (`window`, `allow_sync`) seguem imutáveis por guardião, também para o mestre.

### Migração (como nasce o primeiro mestre)

Enquanto **não existe mestre**, vale o modo antigo: incluir e remover guardiões é do guardião-mor, com duas assinaturas se houver dois. A única mudança de papel possível nesse modo é `set_role {id, role: "master"}` de um guardião-mor, **com uma assinatura** (é a montagem do sistema), enviada a cada aparelho e ao executor. A brecha não reabre: depois do primeiro mestre, só mestre muda papéis. O gateway muda o papel no próprio banco quando o comando fica pronto. Depois da promoção a regra antiga some.

O quórum depende do **autor**: autor mestre = uma assinatura; senão vale o modo antigo (duas assinaturas só para remover guardião ou passkey). Por isso uma promoção que ainda está em andamento em outros destinos continua válida depois de o gateway já ter promovido o alvo.

---

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
| Regras, PIN, janelas, ativar, revogar app, pedidos do aparelho | sim | não |
| `approve_app` (aprovar app novo) e `revoke_app` (revogar app) | sim | **sim** (decisão de 2026-10-16; a assinatura do guardião basta; a tela só oferece revogar o que ele mesmo aprovou) |
| Recusar app pendente (some da lista; o app continua suspenso) | sim | sim (sem passkey, só no gateway) |
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
- Site do guardião (mínimo): **Domínios** com duas abas, *Pedidos* (Recusar, Liberar todos e Confirmar) e *Liberados por mim* (o que liberou, com "Bloquear de novo", e o que recusou, com "Liberar"); **Apps** (aprovar com passkey, recusar, e "Aprovei" com Revogar); **Conta**. Histórico só se o guardião-mor liberar.

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

## Rebaixar (2026-10-17)

O mestre muda o papel de qualquer guardião sozinho (`set_role`): mestre → guardião-mor → guardião, e de volta. Não rebaixa o último mestre. Sem mestre, só existe a promoção de um guardião-mor a mestre (uma assinatura). Na tela Guardiões, os botões "Promover a mestre", "Rebaixar a guardião-mor" e "Rebaixar a guardião" ficam no cartão. O app dos aparelhos já aceita (não precisa reinstalar).
