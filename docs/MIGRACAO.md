# Migração do guardião-mor para o computador do trabalho

Objetivo: o guardião-mor passa a existir **só** no trabalho, com horário **terça a quinta, 12:00 às 16:00** (escritório; segunda e sexta são
home office). A passkey antiga (guardião "Heimdall", sincronizada na conta Google, acessível em casa a qualquer hora) é removida de vez.

**Situação do PC do trabalho (2026-10-16):** é gerenciado pela organização e **não tem Windows Hello** (PIN e biometria indisponíveis).
Sem uma chave FIDO2 não há passkey "só neste aparelho" ali. Decisão: **por enquanto** o guardião "Gandalf" usa passkey **sincronizável**
e a barreira é o horário. Quando houver chave FIDO2, troca-se (veja "Troca futura pela chave FIDO2").

## Antes de começar (uma vez)

- [x] Gateway atualizado e reiniciado (`docker compose up -d --build`). O banco migra sozinho. *(Pi em `b7807e3`, 2026-10-16)*
- [x] Executor atualizado e reiniciado (`systemctl restart guardian-executor`).
- [x] App atualizado em cada aparelho (`adb install -r`; o Device Owner continua). *(Tab S8 e A56, 2026-10-16)*
- [x] Restrição **Bloquear mudar data/hora** ligada em cada aparelho (senão o horário pode ser burlado mudando o relógio).
- [x] Na tela **Pessoas**, cada aparelho e o executor mostram "confia em todos os passkeys" para o Heimdall.
- [ ] Ter à mão o PIN local e saber o caminho de reset de fábrica (`NotToday/docs/LOCKOUT.md`) caso algo dê errado.

## Parte 1: criar o guardião-mor do trabalho

Com o Heimdall, em casa:

1. **Pessoas** → nome "Gandalf" → **Guardião-mor** → passkey **Pode sincronizar** → **Só em um horário**: terça, quarta e quinta, das 12:00 às 16:00 →
   **Gerar link de convite**.
2. Enviar o link para o computador do trabalho (o convite vale 24 h e é de uso único).

No computador do trabalho (numa terça, quarta ou quinta, de preferência dentro do horário, para já testar):

3. Abrir o link e tocar em **Cadastrar passkey**. Na janela do navegador, escolher **Usar um telefone ou tablet** (QR code) e salvar a passkey no celular:
   assim a conta Google pessoal não precisa ser logada no PC gerenciado. Exige Bluetooth no PC; se a empresa bloquear, a alternativa é logar a conta
   Google no navegador (menos desejável) ou esperar a chave FIDO2.
4. Em **Pessoas**, conferir que "Gandalf" aparece como **guardião-mor**, **ter–qui, 12h às 16h**.

## Parte 2: fazer os aparelhos confiarem nele

Com o Heimdall (ainda válido, a qualquer hora):

5. Em **Pessoas → Confiança nos aparelhos**, tocar em **Propagar** no executor e em cada aparelho (um toque de passkey por item).
6. Esperar os relatórios e conferir que todos mostram "confia em todos os passkeys". **Não prossiga antes disso.**

## Parte 3: testar e remover o Heimdall

**Atenção:** com as duas passkeys na mesma conta Google, o Chrome lista as duas no login. Escolha **Gandalf** de propósito: se entrar como Heimdall (que não tem horário), o teste não prova nada. O nome do guardião aparece no site depois de entrar.

7. Numa terça, quarta ou quinta, no horário, entrar com o "Gandalf", liberar um domínio de teste e bloquear de novo. **Só continue se funcionar.**

Remover um guardião-mor exige a assinatura de **dois guardiões-mor** (Heimdall e Gandalf) e, nos aparelhos, passa pelo atraso (24 h).

8. Com o Heimdall: **Pessoas → Heimdall → Remover** (assina um `remove_guardian` para o executor e para cada aparelho).
9. Com o Gandalf, **dentro da janela**: **Pessoas → Co-assinaturas pendentes → Co-assinar**, um por aparelho.
10. O executor aplica na hora. Cada aparelho entra em espera (24 h): depois, no **Início**, aparece "Pedido pronto para confirmar" → **Confirmar**
    (agora só o Gandalf consegue assinar, e só no horário; faça isso dentro da próxima janela).
11. Conferir em **Pessoas** que só o "Gandalf" restou.

## Parte 4: limpar a passkey antiga

12. Apagar a passkey do Heimdall em **passwords.google.com/passkeys** (conta Google) e no gerenciador do computador de casa.
13. Teste final: numa segunda ou sexta (home office), o site deve responder **"Fora do horário"** para o guardião-mor.

## Troca futura pela chave FIDO2

O horário e a regra de sincronização são do guardião e **não mudam**. Para sair da passkey sincronizável:

1. Comprar uma chave FIDO2 com chaves residentes (por exemplo, YubiKey 5). Perguntar à TI se USB e chaves de segurança são permitidos.
2. Com o "Gandalf" (no horário): **Pessoas** → novo guardião-mor, p. ex. "Gandalf-chave", passkey **Só neste aparelho**, mesmo horário → convite.
3. No PC do trabalho, abrir o link e cadastrar a passkey **na chave** (PIN da chave + toque).
4. **Propagar** o novo guardião e confirmar "confia em todos os passkeys".
5. Remover o "Gandalf" sincronizável (duas assinaturas: ele e o novo; atraso de 24 h nos aparelhos; tudo dentro da janela).
6. Apagar a passkey do "Gandalf" no celular/Google (passwords.google.com/passkeys).

Onde guardar a chave: o horário só vale ter–qui, 12h–16h, mas com a chave na mão qualquer folga ou feriado nesses dias permite assinar de casa.
Para manter "à prova de mim", deixe a chave no trabalho (gaveta trancada) ou com a pessoa de confiança.

## Se algo der errado

- Cadastro recusado ("seria sincronizada"): só acontece se o guardião foi criado como "Só neste aparelho". Para o sincronizável, crie o convite com "Pode sincronizar".
- Nenhum guardião-mor consegue assinar (horário, celular perdido): sobra o PIN local no aparelho e, sem ele, o reset de fábrica (`LOCKOUT.md`). Por isso o Heimdall
  só sai depois de a Parte 3 (teste) estar confirmada.
- Erro de horário: o horário usa o relógio de cada aparelho e do executor; relógio errado no Pi ou no Android recusa comandos válidos. Mantenha NTP no Pi e
  "data/hora automáticas" no Android.
- Fora da janela **ninguém** assina como guardião-mor (nem emergência): planeje as ações sensíveis para terça a quinta, 12h às 16h.

## Migrações futuras

O horário e a regra de sincronização pertencem ao guardião e **não mudam**; só as passkeys dele mudam.

| Situação | O que fazer |
|---|---|
| Trocar de computador, mesmo horário | No computador atual (dentro do horário): **Pessoas → Cadastrar outra passkey**; abrir o link no computador novo; **Propagar**; **Remover** a passkey antiga. |
| Novo emprego ou **horário diferente** | Criar **outro guardião-mor** com o novo horário (Partes 1 e 2), remover o antigo (Parte 3) e limpar a passkey antiga (Parte 4). |
| Computador ou celular antigo indisponível antes da troca | Sem passkey utilizável não há como assinar: PIN local ou reset de fábrica. **Faça a troca antes de sair do emprego.** |

Dicas: sempre confirmar "confia em todos os passkeys" antes de remover qualquer coisa; remover a passkey antiga só depois de testar a nova no horário.

## Guardião-mestre: promover o Gandalf (2026-10-17)

Sem mestre vale o modo antigo. Para o Gandalf virar o mestre (e só ele incluir e remover guardiões, sozinho, dentro da janela dele):

1. Já com o Pi atualizado e o app novo nos aparelhos, entre como guardião-mor em **Guardiões**.
2. No cartão do Gandalf, **Promover a mestre**. Um toque de passkey por destino (cada aparelho e o executor).
3. O Gandalf (ou outro guardião-mor) abre **Guardiões → Co-assinaturas pendentes** e co-assina cada um. O gateway já passa a tratar o Gandalf como mestre na primeira co-assinatura; cada aparelho e o executor aplicam ao receber o comando (a tela mostra "só o mestre propaga" para quem não é mestre).
4. A partir daí: o mestre convida (inclusive outro mestre, a reserva), propaga e remove, sozinho. A remoção do Heimdall passa a ser do Gandalf, sozinho; cada aparelho ainda espera o atraso antes de aplicar.
5. Convide um segundo mestre (reserva da pessoa de confiança) assim que possível: o último mestre não pode ser removido nem rebaixado, e sem reserva a perda da passkey dele trava a inclusão de guardiões.
