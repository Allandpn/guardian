# Origem e uso neste projeto

Copiada de https://github.com/nextlevelbuilder/ui-ux-pro-max-skill (commit 713eef5, licença MIT, ver LICENSE).
Removidos por tamanho: `scripts/tests`, `scripts/validate_data.py` e os JSON de proveniência (fontes e ícones upstream), que só servem à validação dos dados.

Como usamos:
- Usamos as regras de UX (`--domain ux`, `--domain web`), `references/pro-rules.md` (checklist de entrega para app nativo) e `references/quick-reference.md` (web) para auditar e revisar telas.
- O `--design-system` é voltado a páginas de marketing (landing, depoimentos, paletas de marca). Não usamos para o app nem para o site do Guardian.
- Nenhuma pilha deles bate com a nossa: o NotToday monta Views em Kotlin, e o site do Guardian é HTML/CSS/JS puro. Vale a regra, não o exemplo de código.
- Ação reversível (limpar lista, cancelar pedido) usa "Desfazer" no padrão do Material 3, e não um diálogo de confirmação. A confirmação fica para o que não volta atrás.
