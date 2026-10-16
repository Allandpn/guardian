# Migração do guardião-mor para o computador do trabalho

Objetivo: o guardião-mor passa a existir **só** no computador do trabalho, com passkey presa ao computador (Windows Hello) e horário
**seg–sex, 12:00 às 17:00**. A passkey antiga (guardião "Handail", sincronizada na conta Google, acessível em casa) é removida de
vez do computador de casa e da conta Google.

## Antes de começar (uma vez)

- [ ] Gateway atualizado e reiniciado (`docker compose up -d --build`). O banco migra sozinho.
- [ ] Executor atualizado e reiniciado (`systemctl restart guardian-executor`).
- [ ] App atualizado em cada aparelho (`adb install -r`; o Device Owner continua). Sem isso o aparelho não confere horário nem passkey sincronizável.
- [ ] Restrição **Bloquear mudar data/hora** ligada em cada aparelho (senão o horário pode ser burlado mudando o relógio).
- [ ] Na tela **Pessoas**, cada aparelho e o executor mostram "confia em todos os passkeys" para o Handail.
- [ ] Ter à mão o PIN local e saber o caminho de reset de fábrica (`NotToday/docs/LOCKOUT.md`) caso algo dê errado.

## Parte 1: criar o guardião-mor do trabalho

Com o Handail, em casa:

1. **Pessoas** → nome "Trabalho" → **Guardião-mor** → passkey **Só neste aparelho** → **Só em um horário**: seg, ter, qua, qui, sex, das 12:00 às 17:00 → **Gerar link de convite**.
2. Enviar o link para o computador do trabalho (o convite vale 24 h e é de uso único).

No computador do trabalho:

3. Abrir o link num **perfil do navegador sem login na conta Google** (perfil novo, ou janela de visitante).
4. **Cadastrar passkey** e, na janela do navegador, escolher **Windows Hello** (PIN ou biometria do Windows).
   Se só aparecer o Gerenciador de Senhas do Google, o cadastro é recusado ("seria sincronizada"): o convite continua válido, é só tentar de novo no perfil certo.
5. Em **Pessoas**, conferir que "Trabalho" aparece como **guardião-mor**, **só neste aparelho**, **seg–sex, 12h às 17h**, e que a passkey está marcada "só neste aparelho". Se aparecer "sincronizada", pare e refaça.

## Parte 2: fazer os aparelhos confiarem nele

Com o Handail (ainda válido, a qualquer hora):

6. Em **Pessoas → Confiança nos aparelhos**, tocar em **Propagar** no executor e em cada aparelho (um toque de passkey por item).
7. Esperar os relatórios e conferir que todos mostram "confia em todos os passkeys". **Não prossiga antes disso.**

Se quiser uma passkey de reserva: no mesmo guardião "Trabalho", **Cadastrar outra passkey** no computador de casa (Windows Hello) e propagar.
Ela tem as mesmas regras (só neste aparelho, seg–sex 12h–17h), então à noite não funciona; mas num dia útil, em casa, entre 12h e 17h, funcionaria.

## Parte 3: remover o Handail

Remover um guardião-mor exige a assinatura de **dois guardiões-mor** (Handail e Trabalho) e, nos aparelhos, passa pelo atraso (24 h).

8. Com o Handail: **Pessoas → Handail → Remover** (assina um `remove_guardian` para o executor e para cada aparelho).
9. No computador do trabalho, **entre 12h e 17h num dia útil**: **Pessoas → Co-assinaturas pendentes → Co-assinar**, um por aparelho.
10. O executor aplica na hora. Cada aparelho entra em espera (24 h): depois, no **Início**, aparece "Pedido pronto para confirmar" → **Confirmar** (agora só o Trabalho consegue assinar, no horário).
11. Conferir em **Pessoas** que só o "Trabalho" restou.

## Parte 4: limpar a passkey antiga

12. Apagar a passkey do Handail em **passwords.google.com/passkeys** (conta Google) e no Windows Hello / gerenciador do computador de casa.
13. Testes finais:
    - Em casa, à noite: tentar abrir o site → não há passkey disponível; com acesso remoto ao computador do trabalho, o site responde **"Fora do horário"**.
    - No trabalho, entre 12h e 17h: abrir o site, liberar um domínio de teste e bloquear de novo.

## Se algo der errado

- Cadastro recusado como "sincronizada": use o perfil sem Google e escolha o Windows Hello; o convite não é gasto.
- Nenhum guardião-mor consegue assinar (horário, computador perdido): sobra o PIN local no aparelho e, sem ele, o reset de fábrica (`LOCKOUT.md`). Por isso o Handail só sai depois de a Parte 2 estar confirmada.
- Erro de horário: o horário usa o relógio de cada aparelho e do executor; relógio errado no Pi ou no Android recusa comandos válidos. Mantenha NTP no Pi e "data/hora automáticas" no Android.

## Migrações futuras

O horário e a regra de sincronização pertencem ao guardião e **não mudam**; só as passkeys dele mudam.

| Situação | O que fazer |
|---|---|
| Trocar de computador, mesmo horário | No computador atual (dentro do horário): **Pessoas → Cadastrar outra passkey**; abrir o link no computador novo (Windows Hello); **Propagar**; **Remover** a passkey antiga. |
| Entre empregos (voltar para o computador de casa) | O mesmo caminho: nova passkey no computador de casa (Windows Hello). Ela só vale no horário do guardião, então não reabre o buraco da noite; se quiser, apague-a de novo ao entrar no novo trabalho. |
| Novo emprego com **horário diferente** | Criar **outro guardião-mor** com o novo horário (Partes 1 e 2), remover o antigo (Parte 3) e limpar a passkey antiga (Parte 4). |
| Computador antigo indisponível antes da troca | Sem passkey utilizável não há como assinar: PIN local ou reset de fábrica. **Faça a troca antes de sair do emprego.** |

Dicas: sempre confirmar "confia em todos os passkeys" antes de remover qualquer coisa; remover a passkey antiga só depois de testar a nova em dia útil, no horário.
