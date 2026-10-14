// Espelho de Gate.classify (app NotToday): diz se mudar uma chave afrouxa a proteção (espera o atraso) ou vale na hora.
// Só informativo: quem decide de verdade é o aparelho. O test_gate_js.py confere os mesmos casos do LogicTest do app.
const NEUTRAL = new Set(['postpone_updates']);
const HIGHER_LOOSENS = new Set(['dev_windows_per_day', 'dev_window_seconds']);
const LOWER_LOOSENS = new Set(['chrome_youtube']);
const csv = (s) => new Set(String(s ?? '').split(',').map((x) => x.trim()).filter(Boolean));
const num = (s) => Number(s) || 0;

export function classify(key, old, neu) {
  if (old === neu) return 'neutral';
  if (NEUTRAL.has(key)) return 'neutral';
  if (key === 'canary') return old == null || String(old).trim() === '' ? 'tighten' : 'loosen';
  if (key === 'unlock_delay_min') return num(neu) < num(old) ? 'loosen' : 'tighten';
  if (HIGHER_LOOSENS.has(key)) return num(neu) > num(old) ? 'loosen' : 'tighten';
  if (LOWER_LOOSENS.has(key)) return num(neu) < num(old) ? 'loosen' : 'tighten';
  if (key === 'protected_pkgs' || key === 'routed_extra' || key === 'store_extra') {
    const o = csv(old); const n = csv(neu);
    return [...o].some((x) => !n.has(x)) ? 'loosen' : 'tighten';
  }
  if (key === 'browsers_exempt') {
    const o = csv(old); const n = csv(neu);
    return [...n].some((x) => !o.has(x)) ? 'loosen' : 'tighten';
  }
  return old === 'true' && neu === 'false' ? 'loosen' : 'tighten';
}
