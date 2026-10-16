// Peças de interface sem innerHTML: todo texto vindo da rede entra por textContent.
export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'style' && v) el.style.cssText = v;  // atributo style inline é barrado pela CSP; o CSSOM não
    else if (v === true) el.setAttribute(k, '');
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : String(kid));
  return el;
}

const NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  home: ['M3 11l9-8 9 8', 'M5 10v10h14V10', 'M10 20v-6h4v6'],
  globe: ['M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18', 'M3 12h18', 'M12 3a14 14 0 0 1 0 18', 'M12 3a14 14 0 0 0 0 18'],
  people: ['M16 20v-1a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v1', 'M9.5 11a3.5 3.5 0 1 0 0-7a3.5 3.5 0 1 0 0 7', 'M21 20v-1a4 4 0 0 0-3-3.9', 'M15 4.1a3.5 3.5 0 0 1 0 6.8'],
  clock: ['M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18', 'M12 7v5l3 2'],
  bell: ['M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9', 'M10 21a2 2 0 0 0 4 0'],
  plus: ['M12 5v14', 'M5 12h14'],
  back: ['M15 5l-7 7 7 7'],
  check: ['M5 13l4 4L19 7'],
  chevron: ['M9 5l7 7-7 7'],
  shield: ['M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z', 'M9 12l2 2 4-4'],
  x: ['M6 6l12 12', 'M18 6L6 18'],
  grid: ['M4 4h6v6H4z', 'M14 4h6v6h-6z', 'M4 14h6v6H4z', 'M14 14h6v6h-6z'],
  device: ['M8 3h8a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z', 'M11 18h2'],
};

export function icon(name, size = 22) {
  const s = document.createElementNS(NS, 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('width', String(size));
  s.setAttribute('height', String(size));
  s.setAttribute('fill', 'none');
  s.setAttribute('stroke', 'currentColor');
  s.setAttribute('stroke-width', '2');
  s.setAttribute('stroke-linecap', 'round');
  s.setAttribute('stroke-linejoin', 'round');
  s.setAttribute('aria-hidden', 'true');
  for (const d of ICONS[name] || []) {
    const p = document.createElementNS(NS, 'path');
    p.setAttribute('d', d);
    s.append(p);
  }
  return s;
}

export const chip = (text, kind) => h('span', { class: 'chip' + (kind ? ' ' + kind : '') }, text);

let toastTimer;
export function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3800);
}

/** Folha de confirmação: mostra em português o que será assinado e o efeito. Resolve true se o guardião confirmar. */
export function sheet({ title, rows = [], effect, effectKind = 'ok', note, noteKind = 'warn', confirm = 'Assinar com passkey', danger = false }) {
  return new Promise((resolve) => {
    const prev = document.activeElement;
    let overlay;
    const onKey = (e) => { if (e.key === 'Escape') close(false); };
    // No Android, o botão/gesto de voltar fecha a folha em vez de sair da tela.
    let pushed = true;
    const onPop = () => { pushed = false; close(false); };
    history.pushState({ sheet: true }, '');
    addEventListener('popstate', onPop);
    const close = (v) => {
      if (!overlay.isConnected) return;
      overlay.remove();
      document.removeEventListener('keydown', onKey);
      removeEventListener('popstate', onPop);
      if (pushed) { pushed = false; history.back(); }
      if (prev && prev.focus) prev.focus();
      resolve(v);
    };
    const ok = h('button', { class: 'btn pri' + (danger ? ' danger' : ''), type: 'button', onclick: () => close(true) }, confirm);
    overlay = h('div', { class: 'overlay', onclick: (e) => { if (e.target === overlay) close(false); } },
      h('div', { class: 'sheet', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
        h('div', { class: 'grab' }),
        h('h2', {}, title),
        rows.length || effect ? h('div', { class: 'kvbox' },
          rows.map(([k, v]) => h('div', { class: 'kv' }, h('span', {}, k), h('span', {}, v))),
          effect ? h('div', { class: 'kv' }, h('span', {}, 'Efeito'), chip(effect, effectKind)) : null) : null,
        note ? h('div', { class: 'note ' + noteKind }, note) : null,
        h('div', { class: 'row gap' }, h('button', { class: 'btn', type: 'button', onclick: () => close(false) }, 'Cancelar'), ok)));
    document.body.append(overlay);
    document.addEventListener('keydown', onKey);
    ok.focus();
  });
}
