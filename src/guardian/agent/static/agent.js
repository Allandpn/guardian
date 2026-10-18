// Tela local do agente: bloqueados, pedido de liberação, de programa e de comando, e o estado dos pedidos.
import { h, icon, chip, toast, insignia } from '/ui.js';

const main = document.getElementById('main');
let st = null;                 // último estado vindo do agente
let tab = 'bloqueados';
const picked = new Set();      // domínios marcados
let filter = '';

async function api(method, path, body) {
  const r = await fetch(path, { method, headers: method === 'POST' ? { 'Content-Type': 'application/json', 'X-Guardian-Agent': '1' } : {}, body: body ? JSON.stringify(body) : undefined });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `erro ${r.status}`);
  return j;
}
const fail = (e) => toast(String(e.message || e));
const act = (fn) => async () => { try { await fn(); } catch (e) { fail(e); } };
const field = (label, el) => h('label', { style: 'display:block;margin:10px 0 0' }, h('span', { class: 'muted', style: 'display:block;margin-bottom:4px' }, label), el);
const input = (ph, extra = {}) => h('input', { class: 'inp', type: 'text', placeholder: ph, autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', ...extra });

// Formulários que sobrevivem ao redesenho (a pessoa pode estar digitando quando a lista atualiza).
const f = {
  wName: input('Nome do programa (ex.: Git)'), wId: input('Id do winget (ex.: Git.Git)'), wVer: input('Versão (opcional)'),
  uName: input('Nome do programa'), uUrl: input('https://…/instalador.msi'), uSha: input('SHA-256 do arquivo (64 caracteres)'),
  uKind: h('select', { class: 'sel' }, h('option', { value: 'msi' }, 'Instalador .msi'), h('option', { value: 'exe' }, 'Instalador .exe')),
  uArgs: input('Argumentos silenciosos (ex.: /S), se precisar'),
  cName: input('O que o comando faz, em poucas palavras'),
  cScript: h('textarea', { class: 'ta', rows: '8', placeholder: 'Write-Output "olá"', spellcheck: 'false', 'aria-label': 'Script do PowerShell' }),
  cCount: h('div', { class: 'muted', style: 'margin-top:4px' }),
};
f.cScript.addEventListener('input', () => {
  const n = new TextEncoder().encode(f.cScript.value).length;
  f.cCount.textContent = `${n} de 6000 bytes`;
});

const STATE = { open: ['aguardando o guardião', 'warn'], approved: ['aprovado', 'ok'], denied: ['negado', 'bad'], done: ['resolvido', 'ok'] };
const ago = (ts) => { const s = Math.max(0, Math.floor(Date.now() / 1000) - ts); return s < 90 ? 'agora' : s < 5400 ? `há ${Math.round(s / 60)} min` : s < 129600 ? `há ${Math.round(s / 3600)} h` : `há ${Math.round(s / 86400)} d`; };

async function send(body, ok) {
  await api('POST', '/api/request', body);
  toast(ok);
  await refresh();
}

function blockedTab() {
  const rows = (st.blocked || []).filter((b) => !filter || b.domain.includes(filter));
  const q = input('Buscar', { 'aria-label': 'Buscar domínio', value: filter });
  q.addEventListener('input', () => { filter = q.value.trim().toLowerCase(); draw(false); const n = main.querySelector('input[aria-label="Buscar domínio"]'); if (n) { n.focus(); n.setSelectionRange(n.value.length, n.value.length); } });
  return [
    h('div', { class: 'sec' }, `Bloqueado agora · ${(st.blocked || []).length}`),
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0 0 8px' }, 'Marque o que você precisa e peça a liberação. O guardião decide.'), q,
      rows.length ? rows.map((b) => h('label', { class: 'li', style: 'cursor:pointer' },
        h('input', { type: 'checkbox', checked: picked.has(b.domain), 'aria-label': b.domain, onchange: (e) => { e.target.checked ? picked.add(b.domain) : picked.delete(b.domain); draw(false); } }),
        h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, b.domain), h('div', { class: 'muted' }, `${b.count}× · ${ago(b.last)}`)))) :
        h('p', { class: 'muted', style: 'margin:10px 0 0' }, 'Nada bloqueado nas últimas 24 horas.'),
      h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { class: 'btn pri grow', type: 'button', disabled: !picked.size,
        onclick: act(async () => { const d = [...picked].slice(0, 20); await send({ kind: 'unblock', domains: d }, 'Pedido enviado ao guardião.'); d.forEach((x) => picked.delete(x)); }) }, picked.size ? `Pedir liberação (${picked.size})` : 'Pedir liberação'))),
  ];
}

function programsTab() {
  const w = act(async () => {
    const p = { name: f.wName.value.trim(), source: 'winget', id: f.wId.value.trim() };
    if (f.wVer.value.trim()) p.version = f.wVer.value.trim();
    await send({ kind: 'install', payload: p }, 'Pedido de instalação enviado.');
  });
  const u = act(async () => {
    const p = { name: f.uName.value.trim(), source: 'url', url: f.uUrl.value.trim(), sha256: f.uSha.value.trim().toLowerCase(), kind: f.uKind.value };
    if (f.uArgs.value.trim()) p.args = f.uArgs.value.trim();
    await send({ kind: 'install', payload: p }, 'Pedido de instalação enviado.');
  });
  return [
    h('div', { class: 'sec' }, 'Instalar pelo winget'),
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Procure o id no PowerShell com "winget search nome". O guardião aprova e o agente instala como administrador.'),
      field('Nome', f.wName), field('Id', f.wId), field('Versão', f.wVer), h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: w }, 'Pedir instalação'))),
    h('div', { class: 'sec' }, 'Instalar por link'),
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Só https. Baixe o arquivo uma vez, rode "Get-FileHash arquivo" e cole o SHA-256 aqui: o agente só instala se o arquivo for idêntico.'),
      field('Nome', f.uName), field('Endereço', f.uUrl), field('SHA-256', f.uSha), field('Tipo', f.uKind), field('Argumentos silenciosos', f.uArgs),
      h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: u }, 'Pedir instalação'))),
  ];
}

function commandTab() {
  f.cScript.dispatchEvent(new Event('input'));
  const c = act(async () => {
    const p = { script: f.cScript.value, shell: 'powershell', timeout_s: 600 };
    if (f.cName.value.trim()) p.name = f.cName.value.trim();
    await send({ kind: 'command', payload: p }, 'Pedido de comando enviado.');
  });
  return [
    h('div', { class: 'sec' }, 'Comando como administrador'),
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'O guardião lê o script inteiro antes de aprovar e ele roda uma vez, como administrador, com limite de 10 minutos.'),
      field('O que faz', f.cName), field('Script do PowerShell', f.cScript), f.cCount,
      h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: c }, 'Pedir execução'))),
  ];
}

function requestsTab() {
  const open = (st.admin || []).filter((a) => a.status === 'open').length;
  const blocks = [];
  blocks.push(h('div', { class: 'sec' }, `Programas e comandos · ${(st.admin || []).length}`));
  blocks.push((st.admin || []).length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, st.admin.map((a) => {
    const [label, kind] = STATE[a.status] || [a.status, ''];
    return h('div', { class: 'li' }, h('div', { class: 'sp' }, h('strong', {}, a.text), h('div', { class: 'muted' }, ago(a.ts))), chip(label, kind));
  })) : h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum pedido ainda.')));
  blocks.push(h('div', { class: 'sec' }, 'Liberações de domínio'));
  blocks.push((st.requests || []).length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, st.requests.map((q) => h('div', { class: 'li' },
    h('div', { class: 'sp' }, (q.items || []).map((i) => h('div', {}, h('span', { class: 'mono' }, i.domain), ' ', chip(i.state === 'allowed' ? (i.ttl_s ? 'liberado por tempo' : 'liberado') : i.state === 'denied' ? 'negado' : 'aguardando', i.state === 'allowed' ? 'ok' : i.state === 'denied' ? 'bad' : 'warn'))),
      h('div', { class: 'muted' }, ago(q.ts)))))) : h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum pedido ainda.')));
  blocks.push(h('div', { class: 'sec' }, 'O que o agente executou'));
  blocks.push((st.runs || []).length ? [...st.runs].reverse().map((r) => h('details', { class: 'card' }, h('summary', { style: 'cursor:pointer;font-weight:600' }, `${r.name || (r.type === 'win_install' ? 'Instalação' : 'Comando')} `, chip(r.ok ? 'ok' : 'falhou', r.ok ? 'ok' : 'bad'), ` ${ago(r.ts)}`),
    h('pre', { class: 'mono', style: 'white-space:pre-wrap;word-break:break-word;margin:10px 0 0;font-size:12px' }, `código ${r.rc ?? '-'}\n${r.out || ''}`))) :
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nada executado ainda.')));
  return [blocks, open];
}

const TABS = [['bloqueados', 'Bloqueados'], ['programas', 'Programas'], ['comando', 'Comando'], ['pedidos', 'Pedidos']];

function draw(full = true) {
  if (!st) return;
  const [reqNodes, open] = requestsTab();
  const body = tab === 'bloqueados' ? blockedTab() : tab === 'programas' ? programsTab() : tab === 'comando' ? commandTab() : reqNodes;
  main.replaceChildren(
    h('header', { class: 'top' }, h('div', { style: 'margin-left:8px;display:flex;align-items:center;gap:10px' }, insignia('device', 28), h('h1', { style: 'padding-left:0' }, `Guardian · ${st.host}`)),
      h('span', { class: 'sp' }), chip(st.gateway_ok ? 'conectado' : 'sem conexão', st.gateway_ok ? 'ok' : 'bad')),
    h('div', { class: 'wrap' },
      h('nav', { class: 'seg', 'aria-label': 'Seções' }, TABS.map(([k, label]) => h('a', { href: `#${k}`, class: k === tab ? 'on' : '', 'aria-current': k === tab ? 'page' : null }, k === 'pedidos' && open ? `${label} · ${open}` : label))),
      st.gateway_ok ? null : h('div', { class: 'note bad' }, `Sem conexão com o Guardian: ${st.error}`),
      body));
}

async function refresh() {
  try { st = await api('GET', '/api/state'); } catch (e) { st = st || { host: '', gateway_ok: false, error: String(e.message), blocked: [], requests: [], admin: [], runs: [] }; }
  draw();
}

function route() {
  const k = location.hash.slice(1);
  tab = TABS.some(([x]) => x === k) ? k : 'bloqueados';
  draw();
}
window.addEventListener('hashchange', route);
setInterval(() => { if (!document.hidden && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement ? document.activeElement.tagName : '')) refresh(); }, 10000);
refresh().then(route);
