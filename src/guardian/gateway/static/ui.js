// Peças de interface sem innerHTML: todo texto vindo da rede entra por textContent.
// Aplica 'a:b;c:d' propriedade por propriedade: o CSSOM por propriedade passa pela CSP 'style-src self'; cssText não.
function setStyle(el, css) {
  for (const decl of css.split(';')) {
    const i = decl.indexOf(':');
    if (i > 0) el.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim());
  }
}

export function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'style') { if (v) setStyle(el, v); }  // atributo style inline (e style.cssText) é barrado pela CSP; setProperty não
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
  key: ['M7 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8', 'M10 12h11', 'M17 12v3', 'M20 12v2'],
  lock: ['M6 11h12v9H6z', 'M8 11V8a4 4 0 0 1 8 0v3'],
  search: ['M11 4a7 7 0 1 0 0 14a7 7 0 1 0 0-14', 'M20 20l-4-4'],
  ban: ['M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18', 'M5.6 5.6l12.8 12.8'],
  list: ['M8 6h12', 'M8 12h12', 'M8 18h12', 'M4 6h.01', 'M4 12h.01', 'M4 18h.01'],
  eyeoff: ['M3 3l18 18', 'M10.6 6.1A9.8 9.8 0 0 1 12 6c5 0 9 6 9 6a15 15 0 0 1-3.2 3.7', 'M6.5 7.6A15 15 0 0 0 3 12s4 6 9 6a9 9 0 0 0 3.6-.8', 'M9.9 9.9a3 3 0 0 0 4.2 4.2'],
  terminal: ['M4 5h16v14H4z', 'M7 10l3 2-3 2', 'M12 15h5'],
  box: ['M21 8l-9-5-9 5v8l9 5 9-5z', 'M3 8l9 5 9-5', 'M12 13v8'],
  inbox: ['M3 13l3-8h12l3 8', 'M3 13v6h18v-6', 'M3 13h5a4 4 0 0 0 8 0h5'],
  send: ['M21 3L10 14', 'M21 3l-7 18-4-7-7-4z'],
  sync: ['M20 12a8 8 0 0 0-14-5', 'M4 4v4h4', 'M4 12a8 8 0 0 0 14 5', 'M20 20v-4h-4'],
};

// Brasões dos guardiões: um escudo comum e a figura de cada papel (mestre: coroa; guardião-mor: espada; guardião: portão do castelo).
const SHIELD = 'M24 2L44 8V28C44 42 35 50 24 54C13 50 4 42 4 28V8Z';
const EMBLEM = {
  master: ['M13 33L11 18L19 24L24 13L29 24L37 18L35 33Z', 'M13 38H35'],
  admin: ['M24 10L26.5 14V32H21.5V14Z', 'M16 32H32', 'M24 32V40', 'M21.5 42H26.5'],
  domains: ['M14 41V22H18V26H21V22H27V26H30V22H34V41Z', 'M21 41V34A3 3 0 0 1 27 34V41'],
  device: ['M17 42V24H31V42Z', 'M15 24V17H19V19H22V17H26V19H29V17H33V24Z', 'M24 29V35'],              // aparelho: atalaia
  executor: ['M12 41V21H36V41Z', 'M18 21V41M24 21V41M30 21V41', 'M12 27H36M12 34H36', 'M12 21V16M24 21V16M36 21V16'],  // Pi-hole: muralha com grade
};

export function insignia(role, size = 52) {
  const s = document.createElementNS(NS, 'svg');
  s.setAttribute('viewBox', '0 0 48 56');
  s.setAttribute('width', String(size));
  s.setAttribute('height', String(Math.round(size * 56 / 48)));
  s.setAttribute('class', 'insignia');
  s.setAttribute('aria-hidden', 'true');
  const add = (d, cls) => {
    const p = document.createElementNS(NS, 'path');
    p.setAttribute('d', d);
    p.setAttribute('class', cls);
    s.append(p);
  };
  add(SHIELD, 'shield');
  for (const d of EMBLEM[role] || EMBLEM.admin) add(d, 'emblem');
  return s;
}

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
export function sheet({ title, rows = [], effect, effectKind = 'ok', note, noteKind = 'warn', confirm = 'Assinar com passkey', danger = false, detail }) {
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
        detail ? h('pre', { class: 'detail', tabindex: '0', 'aria-label': 'O que será executado' }, detail) : null,
        note ? h('div', { class: 'note ' + noteKind }, note) : null,
        h('div', { class: 'row gap' }, h('button', { class: 'btn', type: 'button', onclick: () => close(false) }, 'Cancelar'), ok)));
    document.body.append(overlay);
    document.addEventListener('keydown', onKey);
    ok.focus();
  });
}

/** Domínios pais que dá para liberar no lugar do informado (a.b.exemplo.com -> b.exemplo.com, exemplo.com). Nunca só o sufixo (com, com.br). */
export function parentsOf(domain) {
  const l = domain.split('.');
  const suffix2 = l.length >= 3 && l[l.length - 1].length === 2 && ['com', 'net', 'org', 'gov', 'edu', 'co', 'ac', 'mil'].includes(l[l.length - 2]);
  const min = suffix2 ? 3 : 2;
  const out = [];
  for (let i = 1; l.length - i >= min; i++) out.push(l.slice(i).join('.'));
  return out;
}
