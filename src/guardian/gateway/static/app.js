import { enc, dec, sha256, sealPin, commandBytes, pairingString } from './crypto.js';
import { h, icon, chip, toast, sheet } from './ui.js';
import { classify } from './gate.js';

const main = document.getElementById('main');
const nav = document.getElementById('nav');
const SILENT_S = 300;
let me = null;               // { guardian, trust, rp_id, origin }
let timer = null;
let counts = { apps: 0, reqs: 0, cosign: 0 };
const drafts = new Map();    // aparelho -> { chave: novoValor } (regras ainda não assinadas)
const open = new Set(['Filtro', 'Apps novos', 'Segurança']);  // grupos de regras abertos
let selected = null;         // aparelho aberto no painel (computador)
let pair = null;             // andamento do pareamento
let inviteRole = 'domains';  // papel escolhido no convite
let inviteName = '';         // nome digitado (sobrevive aos redesenhos da tela)
let inviteSync = null;       // passkey sincronizável? null = padrão do papel (guardião-mor: só neste aparelho)
let inviteWin = { on: false, days: [0, 1, 2, 3, 4], from: '12:00', to: '17:00' };  // janela de horário do convidado
const DAY_NAMES = ['seg', 'ter', 'qua', 'qui', 'sex', 'sáb', 'dom'];
const OFFSET_MIN = -180;     // horário de Brasília (o Brasil não tem horário de verão desde 2019)
const toMin = (t) => { const [h, m] = t.split(':').map(Number); return h * 60 + m; };
const fmtHM = (m) => `${Math.floor(m / 60)}h${m % 60 ? String(m % 60).padStart(2, '0') : ''}`;
function describeWindow(w) {
  if (!w) return 'sem horário definido';
  const days = [...w.days].sort(); const runs = []; let start = 0;
  for (let i = 1; i <= days.length; i++) if (i === days.length || days[i] !== days[i - 1] + 1) { runs.push([days[start], days[i - 1]]); start = i; }
  return `${runs.map(([a, b]) => (a === b ? DAY_NAMES[a] : `${DAY_NAMES[a]}–${DAY_NAMES[b]}`)).join(', ')}, ${fmtHM(w.from)} às ${fmtHM(w.to)}`;
}
let domDur = 0;              // duração do formulário manual de domínio (0 = sem prazo)

const fail = (e) => toast(e && e.message ? e.message : String(e));
const show = (...nodes) => { main.replaceChildren(...nodes.flat(Infinity).filter(Boolean)); };
const wide = () => window.matchMedia('(min-width: 900px)').matches;

let BUILD = null;  // versão do site que esta página carregou (cabeçalho X-Build)
function checkBuild(r) {
  const b = r.headers.get('X-Build');
  if (!b) return;
  if (BUILD === null) { BUILD = b; return; }
  // outra versão no servidor: recarrega quando não há folha aberta nem campo em uso (não perde o que está sendo digitado)
  if (b !== BUILD && !document.querySelector('.overlay, .sheet, input:focus, textarea:focus, select:focus')) location.reload();
}

async function api(method, path, body) {
  const r = await fetch(path, {
    method, credentials: 'same-origin', cache: 'no-store',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  checkBuild(r);
  let data = {};
  try { data = await r.json(); } catch (_) { /* corpo vazio */ }
  if (!r.ok) { const e = new Error(data.error || `erro ${r.status}`); e.status = r.status; throw e; }
  return data;
}

// ---------- formatação ----------
function ago(ts, now) {
  if (!ts) return 'nunca';
  const s = Math.max(0, now - ts);
  if (s < 90) return `há ${s} s`;
  if (s < 5400) return `há ${Math.round(s / 60)} min`;
  if (s < 172800) return `há ${Math.round(s / 3600)} h`;
  return `há ${Math.round(s / 86400)} d`;
}
const fp = (id) => id.match(/.{1,4}/g).join('-');
const fmtVal = (v) => (v === 'true' ? 'ligado' : v === 'false' ? 'desligado' : v === '' ? '(vazio)' : v);
const PKG_KEYS = new Set(['routed_extra', 'protected_pkgs', 'store_extra', 'browsers_exempt']);
// Pacote -> "Nome do app (pacote)". O aparelho manda os nomes em pkgNames; apps aprovados/pendentes completam.
const pkgText = (val, r) => {
  const names = new Map([...(r.approvedApps || []), ...(r.pendingApps || [])].filter((a) => a.pkg && a.label).map((a) => [a.pkg, a.label]));
  Object.entries(r.pkgNames || {}).forEach(([p, n]) => names.set(p, n));
  return String(val).split(',').map((x) => x.trim()).filter(Boolean).map((p) => (names.get(p) && names.get(p) !== p ? `${names.get(p)} (${p})` : p)).join(', ');
};
const ruleLabel = (key, labels) => (key === 'unlock_delay_min' ? 'Atraso para afrouxar (horas)' : labels[key] || key);
function dur(ms) {
  const min = Math.max(1, Math.ceil(ms / 60000));
  return min >= 60 ? `${Math.floor(min / 60)} h ${String(min % 60).padStart(2, '0')} min` : `${min} min`;
}
const delayText = (snap) => { const m = Number((snap || {}).unlock_delay_min); return m ? (m % 60 === 0 ? `${m / 60} h` : `${m} min`) : 'sem atraso'; };
const durLabel = (s) => ({ 3600: '1 hora', 86400: '24 horas', 604800: '7 dias', 0: 'permanente' }[s] || `${Math.round(s / 60)} min`);
const gname = (gid) => (me && me.trust[gid] ? me.trust[gid].name : gid);
const TYPE = {
  approve_app: 'aprovar app', revoke_app: 'revogar app', set_config: 'alterar configuração', set_dev_policy: 'ajustar janelas de desenvolvimento',
  confirm: 'confirmar pedido', cancel: 'cancelar pedido', request_maintenance: 'pedir janela de manutenção', set_pin: 'definir o PIN',
  set_dev_pin: 'definir o PIN de desenvolvedor', activate: 'ativar o aparelho', add_guardian: 'incluir guardião', add_credential: 'incluir passkey',
  remove_guardian: 'remover guardião', remove_credential: 'remover passkey', pihole_allow: 'liberar domínio', pihole_deny: 'bloquear domínio', pihole_remove: 'remover domínio', pihole_batch: 'liberar domínios',
};
const KIND = { SETTINGS: 'afrouxar configurações', RELEASE: 'remover o Device Owner', MAINTENANCE: 'janela de manutenção', GUARDIAN: 'remover guardião' };

// ---------- WebAuthn ----------
async function passkeyCreate(opts) {
  const pk = opts.publicKey;
  pk.challenge = dec(pk.challenge);
  pk.user.id = dec(pk.user.id);
  pk.excludeCredentials = (pk.excludeCredentials || []).map((c) => ({ ...c, id: dec(c.id) }));
  const cred = await navigator.credentials.create({ publicKey: pk });
  return { id: cred.id, attestationObject: enc(cred.response.attestationObject), clientDataJSON: enc(cred.response.clientDataJSON) };
}

async function passkeyGet(publicKey) {
  const a = await navigator.credentials.get({ publicKey });
  return { id: a.id, authenticatorData: enc(a.response.authenticatorData), clientDataJSON: enc(a.response.clientDataJSON), signature: enc(a.response.signature) };
}

async function signPayload(bytes) {
  const mine = Object.keys((me.trust[me.guardian.id] || {}).creds || {});
  const a = await passkeyGet({
    challenge: await sha256(bytes), rpId: me.rp_id, userVerification: 'required', timeout: 60000,
    allowCredentials: mine.map((id) => ({ type: 'public-key', id: dec(id) })),
  });
  return { guardian: me.guardian.id, cred: a.id, authenticatorData: a.authenticatorData, clientDataJSON: a.clientDataJSON, signature: a.signature };
}

async function sendCommand(dev, type, args = {}) {
  const { next } = await api('GET', `/v1/devices/${dev}/ctr`);
  const bytes = commandBytes({ v: 1, dev, guardian: me.guardian.id, ctr: next, type, args });
  const sig = await signPayload(bytes);
  const r = await api('POST', `/v1/devices/${dev}/commands`, { payload: enc(bytes), sigs: [sig] });
  toast(r.status === 'awaiting' ? 'Enviado: aguarda a co-assinatura de outro guardião.' : 'Comando enviado ao aparelho.');
  return r;
}

/** Mostra a folha com o que será assinado e, se o guardião confirmar, assina e envia. */
async function confirmSend(dev, type, args, spec) {
  if (!(await sheet(spec))) return false;
  return (await sendCommand(dev, type, args)) || true;
}
const act = (fn) => async () => { try { await fn(); } catch (e) { fail(e); } };
const isAdmin = () => !!me && me.guardian.role === 'admin';
const canSee = (k) => isAdmin() || !!(me && me.guardian.see && me.guardian.see[k]);
const SEE_LABELS = [['devices', 'Estado dos aparelhos'], ['rules', 'Regras (só leitura)'], ['apps', 'Apps (só leitura)'], ['history', 'Histórico completo']];
/** Confiança que vai na string de pareamento: o aparelho só precisa dos guardiões-mor; o executor, de todos. */
const trustFor = (kind) => Object.fromEntries(Object.entries(me.trust).filter(([, g]) => kind === 'executor' || g.role !== 'domains'));

// ---------- dados ----------
async function loadAll() {
  const [d, r, a] = await Promise.all([api('GET', '/v1/devices'), api('GET', '/v1/requests'), api('GET', '/v1/commands/awaiting')]);
  for (const x of d.devices) {  // apps recusados saem das pendências e ficam em refusedApps (dá para reconsiderar)
    const ref = new Set(x.refused || []);
    if (x.report && x.report.pendingApps) {
      x.refusedApps = x.report.pendingApps.filter((a) => ref.has(a.pkg));
      x.report.pendingApps = x.report.pendingApps.filter((a) => !ref.has(a.pkg));
    }
  }
  const apps = d.devices.reduce((n, x) => n + ((x.report && x.report.pendingApps) || []).length, 0);
  counts = { apps, reqs: r.items.length, cosign: a.commands.filter((c) => c.can_cosign).length };
  return { devices: d.devices, now: d.now, reqs: r.items, aw: a.commands };
}

function statusOf(d, now) {
  const r = d.report || {};
  if (now - (d.last_seen || d.created) > SILENT_S) return { word: 'Sem sinal', kind: 'bad', detail: `sem consultar o gateway ${ago(d.last_seen || d.created, now)}` };
  if (!d.report) return { word: 'Novo', kind: '', detail: 'aguardando o primeiro relatório' };
  if (d.kind === 'executor') {
    if (r.pihole_ok === false) return { word: 'Atenção', kind: 'warn', detail: 'Pi-hole inacessível' };
    return { word: 'Ok', kind: 'ok', detail: `${(r.allow || []).length} liberados · ${(r.temp || []).length} temporários · ${(r.deny || []).length} bloqueados` };
  }
  const apps = (r.pendingApps || []).length;
  const pend = (r.pending || []).length;
  if (r.filterActive === false) return { word: 'Atenção', kind: 'warn', detail: 'filtro não confirmado' + (r.filterReason ? `: ${r.filterReason}` : '') };
  if (apps || pend) {
    return { word: 'Atenção', kind: 'warn', detail: [apps ? `${apps} app(s) pendente(s)` : '', pend ? `${pend} pedido(s) em espera` : ''].filter(Boolean).join(' · ') };
  }
  return { word: 'Protegido', kind: 'ok', detail: `filtro confirmado · visto ${ago(d.last_seen, now)}` };
}

// ---------- peças comuns ----------
function top(title, { back, actions } = {}) {
  return h('header', { class: 'top' }, back ? h('a', { class: 'ib', href: back, 'aria-label': 'Voltar' }, icon('back')) : null,
    h('h1', {}, title), actions || null);
}

function renderNav(active) {
  nav.hidden = !me;
  if (!me) return;
  const item = (href, label, ic, key, badge) => h('a', { class: 'navitem' + (active === key ? ' on' : ''), href, 'aria-current': active === key ? 'page' : null },
    icon(ic), label, badge ? h('span', { class: 'badge' }, String(badge)) : null);
  const items = isAdmin() ? [item('#/', 'Início', 'home', 'home', counts.apps), item('#/domains', 'Domínios', 'globe', 'domains', counts.reqs),
    item('#/people', 'Pessoas', 'people', 'people', counts.cosign), item('#/history', 'Histórico', 'clock', 'history', 0)] :
    [canSee('devices') ? item('#/', 'Início', 'home', 'home', 0) : null, item('#/domains', 'Domínios', 'globe', 'domains', counts.reqs),
      item('#/apps', 'Apps', 'grid', 'apps', counts.apps),
      canSee('history') ? item('#/history', 'Histórico', 'clock', 'history', 0) : null, item('#/people', 'Conta', 'people', 'people', 0)];
  nav.replaceChildren(h('div', { class: 'brand' }, 'NotToday Guardian'), ...items.filter(Boolean),
    h('div', { class: 'navfoot' }, h('button', { class: 'btn block', type: 'button', onclick: act(logout) }, 'Sair')));
}

async function logout() {
  autoLogin = false;
  await api('POST', '/v1/auth/logout', {});
  me = null;
  route();
}

/** No celular: abre a folha de compartilhar do sistema (WhatsApp, e-mail…). Some onde não há Web Share. */
function shareBtn(getText, title = 'NotToday Guardian') {
  if (!navigator.share) return null;
  return h('button', { class: 'btn', type: 'button', onclick: async () => {
    try { await navigator.share({ title, text: getText() }); } catch (e) { if (e && e.name !== 'AbortError') toast('Não foi possível compartilhar: copie o texto.'); }
  } }, 'Compartilhar');
}

function copyBtn(getText, label = 'Copiar') {
  return h('button', { class: 'btn', type: 'button', onclick: act(async () => {
    try { await navigator.clipboard.writeText(getText()); toast('Copiado.'); } catch (_) { toast('Não foi possível copiar: selecione o texto.'); }
  }) }, label);
}

// ---------- entrar / convite ----------
let autoLogin = true;
function loginView() {
  if (autoLogin) { autoLogin = false; doLogin().catch(() => {}); }  // abre o passkey sozinho; se o navegador exigir um toque, o botão fica
  show(h('div', { class: 'login' },
    h('div', { class: 'logo' }, icon('shield', 38)),
    h('h1', {}, 'NotToday Guardian'),
    h('p', { class: 'muted' }, 'Entre com o seu passkey (biometria ou chave de segurança). Não existe senha.'),
    h('button', { class: 'btn pri', type: 'button', onclick: act(doLogin) }, 'Entrar com passkey'),
    h('p', { class: 'muted' }, 'Cada ação sensível pede o seu passkey de novo.')));
}

async function doLogin() {
  const o = await api('POST', '/v1/auth/options', {});
  const pk = o.publicKey;
  pk.challenge = dec(pk.challenge);
  const a = await passkeyGet(pk);
  try {
    await api('POST', '/v1/auth/verify', { challengeId: o.challengeId, ...a });
  } catch (e) {
    if (e.status === 403 && /janela de horário/.test(e.message)) { closedView(e.message); return; }
    throw e;
  }
  await boot();
}

/** Fora do horário do guardião: nada abre, nem com a passkey certa. */
function closedView(msg) {
  show(h('div', { class: 'login' }, h('div', { class: 'logo' }, icon('clock', 38)), h('h1', {}, 'Fora do horário'),
    h('p', { class: 'muted' }, 'Este guardião só pode usar o Guardian em um horário definido na criação dele. Volte dentro do horário.'),
    h('p', { class: 'note' }, (msg || '').replace(/^.*\((.*)\).*$/, '$1')),
    h('button', { class: 'btn', type: 'button', onclick: () => { autoLogin = false; route(); } }, 'Tentar de novo')));
}

function inviteView(token) {
  show(h('div', { class: 'login' },
    h('div', { class: 'logo' }, icon('shield', 38)),
    h('h1', {}, 'Cadastrar passkey'),
    h('p', { class: 'muted' }, 'Você foi convidado como guardião. Cadastre uma passkey neste aparelho e, depois, uma segunda (outro celular ou chave física) para não ficar sem acesso.'),
    h('p', { class: 'note ok' }, 'Digital, rosto ou PIN são conferidos só pelo seu aparelho e não saem dele. O Guardian guarda apenas a chave pública, que vale só neste site. Se o seu gerenciador sincronizar (Google, Apple), a chave privada vai criptografada para a sua conta, nunca para o Guardian.'),
    h('button', { class: 'btn pri', type: 'button', onclick: act(async () => {
      const o = await api('POST', '/v1/register/options', { invite: token });
      const reg = await passkeyCreate(o);
      await api('POST', '/v1/register/verify', { challengeId: o.challengeId, ...reg });
      location.hash = '#/';
      await boot();
      toast('Passkey cadastrado.');
    }) }, 'Cadastrar passkey'),
    h('p', { class: 'muted' }, 'O link vale 24 h e só funciona uma vez.')));
}

// ---------- início ----------
function deviceCard(d, now, { sel } = {}) {
  const st = statusOf(d, now);
  return h('a', { class: 'card' + (sel ? ' sel' : '') + (st.kind === 'bad' ? ' badb' : st.kind === 'warn' ? ' warnb' : ''), href: `#/device/${d.id}` },
    h('div', { class: 'row' }, h('span', { class: 'dot ' + st.kind }), h('strong', {}, d.name),
      d.kind === 'executor' ? chip('executor') : null, h('span', { class: 'sp' }), chip(st.word, st.kind)),
    h('div', { class: 'muted', style: 'margin-top:6px' }, st.detail));
}

async function inicioView() {
  const { devices, now, reqs, aw } = await loadAll();
  renderNav('home');
  const todos = [];
  const cos = aw.filter((c) => c.can_cosign);
  if (cos.length) todos.push({ n: cos.length, title: 'Co-assinatura pendente', sub: cos.map((c) => `${TYPE[JSON.parse(new TextDecoder().decode(dec(c.envelope.payload))).type] || 'comando'}`).slice(0, 2).join(' · '), href: '#/people' });
  if (reqs.length) todos.push({ n: reqs.length, title: 'Pedidos dos usuários', sub: reqs.slice(0, 2).map((q) => q.text).join(' · '), href: '#/domains/pedidos' });
  for (const d of isAdmin() ? devices : []) {
    const r = d.report || {};
    const apps = r.pendingApps || [];
    if (apps.length) todos.push({ n: apps.length, title: 'Apps aguardando aprovação', sub: `${d.name}${apps.some((a) => (a.risks || []).length) ? ' · com risco' : ''}`, href: `#/device/${d.id}/apps` });
    const ready = (r.pending || []).filter((p) => p.state === 'ready');
    if (ready.length) todos.push({ n: ready.length, title: 'Pedido pronto para confirmar', sub: `${d.name} · ${ready.map((p) => KIND[p.kind] || p.kind).join(', ')}`, href: `#/device/${d.id}` });
  }
  const phones = devices.filter((d) => d.kind === 'device');
  if (!selected || !devices.some((d) => d.id === selected)) selected = (phones[0] || devices[0] || {}).id || null;
  const sel = devices.find((d) => d.id === selected);

  const list = h('div', { class: 'list' },
    h('div', { class: 'sec' }, 'Precisa de você'),
    todos.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, todos.map((t) => h('a', { class: 'todo', href: t.href },
      h('span', { class: 'cnt' }, String(t.n)), h('div', { class: 'sp' }, h('strong', {}, t.title), h('div', { class: 'muted' }, t.sub)), icon('chevron', 18)))) :
      h('div', { class: 'card' }, h('div', { class: 'row' }, h('span', { style: 'color:var(--green)' }, icon('check')), h('strong', {}, 'Tudo em dia'))),
    h('div', { class: 'sec' }, 'Aparelhos'),
    devices.length ? devices.map((d) => wide() ? h('a', { class: 'card' + (d.id === selected ? ' sel' : ''), href: '#/', onclick: (e) => { e.preventDefault(); selected = d.id; route(); } },
      statusRow(d, now)) : deviceCard(d, now)) :
      h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum aparelho pareado ainda. Toque em “Parear”.')));

  const pane = wide() && sel && sel.kind === 'device' ? h('div', { class: 'pane' }, h('div', { class: 'sec' }, 'Detalhe'), deviceBanner(sel, now),
    h('div', { class: 'row', style: 'margin:12px 14px 0' }, h('a', { class: 'btn grow', href: `#/device/${sel.id}`, style: 'text-align:center;display:flex;align-items:center;justify-content:center;text-decoration:none' }, 'Abrir aparelho completo')),
    resumoNodes(sel, now)) : null;

  show(top('Início'), h('div', { class: 'wrap' }, h('div', { class: 'cols' }, list, pane)),
    isAdmin() ? h('a', { class: 'fab', href: '#/pair' }, icon('plus', 20), 'Parear') : null);
  timer = setTimeout(autoRefresh, 20000);
}

function statusRow(d, now) {
  const st = statusOf(d, now);
  return [h('div', { class: 'row' }, h('span', { class: 'dot ' + st.kind }), h('strong', {}, d.name), d.kind === 'executor' ? chip('executor') : null,
    h('span', { class: 'sp' }), chip(st.word, st.kind)), h('div', { class: 'muted', style: 'margin-top:6px' }, st.detail)];
}

// ---------- aparelho ----------
function deviceBanner(d, now) {
  const st = statusOf(d, now);
  const r = d.report || {};
  const title = d.kind === 'executor' ? 'Executor do Pi-hole' : r.filterActive ? 'Filtro CONFIRMADO' : r.filterActive === false ? 'Filtro NÃO confirmado' : 'Aguardando relatório';
  return h('div', { class: 'banner ' + (st.kind === 'ok' ? '' : st.kind) },
    h('div', { class: 'row' }, h('strong', { style: 'font-size:16px' }, title), h('span', { class: 'sp' }), chip(st.word, st.kind)),
    h('div', { class: 'muted', style: 'margin-top:4px;color:var(--text)' }, `visto ${ago(d.last_seen, now)} · relatório ${ago(d.report_ts, now)}`));
}

function segTabs(items, active) {
  return h('nav', { class: 'seg', 'aria-label': 'Seções' }, items.map(([href, label, key]) => h('a', { href, class: key === active ? 'on' : '', 'aria-current': key === active ? 'page' : null }, label)));
}

async function deviceView(id, tab) {
  const { devices, now } = await loadAll();
  renderNav('home');
  const d = devices.find((x) => x.id === id);
  if (!d) { show(top('Aparelho', { back: '#/' }), h('p', { class: 'empty' }, 'Aparelho não encontrado.')); return; }
  if (!isAdmin()) return deviceReadOnly(d, now);
  const base = `#/device/${id}`;
  const tabs = d.kind === 'executor' ? [[base, 'Resumo', 'resumo'], [`${base}/avancado`, 'Avançado', 'avancado']] :
    [[base, 'Resumo', 'resumo'], [`${base}/regras`, 'Regras', 'regras'], [`${base}/apps`, 'Apps', 'apps'], [`${base}/avancado`, 'Avançado', 'avancado']];
  let body;
  if (tab === 'regras' && d.kind === 'device') body = regrasNodes(d);
  else if (tab === 'apps' && d.kind === 'device') body = appsNodes(d);
  else if (tab === 'avancado') body = avancadoNodes(d, now);
  else { tab = 'resumo'; body = d.kind === 'executor' ? executorNodes(d, now) : resumoNodes(d, now); }
  show(top(d.name, { back: '#/' }), h('div', { class: 'wrap' }, deviceBanner(d, now), segTabs(tabs, tab), body));
  if (tab !== 'regras') timer = setTimeout(autoRefresh, 20000);
}

/** O que um guardião vê de um aparelho: só o que o guardião-mor liberou, sem nenhuma ação. */
function deviceReadOnly(d, now) {
  const r = d.report || {};
  const parts = [];
  if (d.kind === 'executor') parts.push(h('div', { class: 'card' }, h('a', { class: 'btn pri', href: '#/domains', style: 'display:inline-flex;align-items:center;text-decoration:none' }, 'Abrir domínios')));
  if (canSee('devices')) parts.unshift(deviceBanner(d, now));
  if (canSee('rules') && r.snapshot) {
    const labels = r.labels || {};
    const groups = new Map();
    for (const [k, v] of Object.entries(r.snapshot)) {
      const g = (r.groups || {})[k] || 'Outras';
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push([ruleLabel(k, labels), PKG_KEYS.has(k) && v ? pkgText(v, r) : fmtVal(String(v))]);
    }
    for (const [g, rows] of groups) parts.push(h('div', { class: 'sec' }, g), h('div', { class: 'card' }, kvRows(rows)));
  }
  if (canSee('apps')) {
    const pend = r.pendingApps || [];
    const ok = r.approvedApps || [];
    parts.push(h('div', { class: 'sec' }, `Apps aguardando · ${pend.length}`),
      h('div', { class: 'card' }, pend.length ? kvRows(pend.map((a) => [a.label || a.pkg, (a.risks || []).join(', ') || 'sem risco aparente'])) : h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum.')),
      h('div', { class: 'sec' }, `Apps aprovados · ${ok.length}`),
      h('div', { class: 'card' }, ok.length ? kvRows(ok.map((a) => [a.label || a.pkg, a.pkg])) : h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum.')));
  }
  if (!parts.length) parts.push(h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'O guardião-mor não liberou a visualização deste aparelho.')));
  show(top(d.name, { back: '#/' }), h('div', { class: 'wrap' }, parts, h('p', { class: 'muted', style: 'margin:12px 14px' }, 'Somente leitura.')));
  timer = setTimeout(autoRefresh, 20000);
}

function executorNodes(d, now) {
  const r = d.report || {};
  return [h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0 0 10px' }, 'Executor do Pi-hole. Os domínios liberados e bloqueados ficam em Domínios.'),
    h('a', { class: 'btn pri', href: '#/domains', style: 'display:inline-flex;align-items:center;text-decoration:none' }, 'Abrir domínios')),
  h('div', { class: 'card' }, kvRows([['Pi-hole', r.pihole_ok === false ? 'inacessível' : 'ok'], ['Liberados', String((r.allow || []).length)], ['Bloqueados', String((r.deny || []).length)],
    ['Temporários', String((r.temp || []).length)]]))];
}

function kvRows(rows) {
  return h('div', { class: 'kvbox', style: 'margin:0' }, rows.map(([k, v]) => h('div', { class: 'kv' }, h('span', {}, k), h('span', {}, v))));
}

function resumoNodes(d, now) {
  const r = d.report || {};
  const snap = r.snapshot || {};
  const pend = r.pending || [];
  const apps = r.pendingApps || [];
  const nodes = [];
  nodes.push(h('div', { class: 'sec' }, 'Pendências'));
  if (!pend.length && !apps.length) nodes.push(h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nada pendente.')));
  for (const p of pend) {
    const ready = p.state === 'ready';
    nodes.push(h('div', { class: 'card warnb' },
      h('div', { class: 'row' }, h('strong', {}, `Pedido: ${KIND[p.kind] || p.kind}`), h('span', { class: 'sp' }), chip(ready ? 'pronto' : 'em espera', ready ? 'ok' : 'warn')),
      h('div', { class: 'muted', style: 'margin-top:4px' }, p.summary || ''),
      ready ? null : h('div', { class: 'muted', style: 'margin-top:6px' }, 'Libera em ', h('strong', { style: 'color:var(--text)' }, dur(p.remainingMs || 0)), ' (contado pelo relógio do aparelho)'),
      h('div', { class: 'row', style: 'margin-top:10px' },
        h('button', { class: 'btn grow', type: 'button', onclick: act(() => confirmSend(d.id, 'cancel', { kind: p.kind }, { title: `Cancelar o pedido de ${KIND[p.kind] || p.kind}?`,
          rows: [['Aparelho', d.name]], effect: 'vale na hora', effectKind: 'ok' }).then(() => route())) }, 'Cancelar pedido'),
        h('button', { class: 'btn pri grow', type: 'button', disabled: !ready, onclick: act(() => confirmSend(d.id, 'confirm', { kind: p.kind }, { title: `Confirmar: ${KIND[p.kind] || p.kind}?`,
          rows: [['Aparelho', d.name], ['Pedido', p.summary || '']], effect: 'aplica agora', effectKind: 'warn', note: 'Esta mudança afrouxa a proteção.', danger: p.kind === 'RELEASE' }).then(() => route())) }, 'Confirmar'))));
  }
  if (apps.length) {
    nodes.push(h('div', { class: 'card' },
      h('div', { class: 'row' }, h('strong', {}, `${apps.length} app(s) aguardando aprovação`), h('span', { class: 'sp' }),
        apps.some((a) => (a.risks || []).length) ? chip('com risco', 'warn') : null),
      h('div', { class: 'muted', style: 'margin-top:4px' }, apps.slice(0, 3).map((a) => a.label || a.pkg).join(' · ')),
      h('a', { class: 'btn pri block', href: `#/device/${d.id}/apps`, style: 'margin-top:10px;display:flex;align-items:center;justify-content:center;text-decoration:none' }, 'Revisar apps')));
  }
  nodes.push(h('div', { class: 'sec' }, 'Estado'));
  const w = r.windows || {};
  nodes.push(h('div', { class: 'card' }, kvRows([
    ['Device Owner', r.owner ? 'sim' : 'não'], ['Ativado pelo guardião', r.activated ? 'sim' : 'não'], ['PIN local', r.pinSet ? 'definido' : 'não definido'],
    ['Atraso para afrouxar', delayText(snap)], ['Janela de manutenção', w.maintenanceMs ? 'ATIVA' : 'fechada'],
    ['Janela de desenvolvimento', w.devMs ? 'ABERTA' : `fechada · ${w.devUsed ?? '?'} usadas em 24 h`], ['Tailscale', r.tailscale ? 'sim' : 'não'], ['Versão do app', r.version || '?'],
  ])));
  nodes.push(h('div', { class: 'sec' }, 'Atalhos'));
  nodes.push(h('div', { class: 'pad', style: 'display:flex;flex-direction:column;gap:8px' },
    h('button', { class: 'btn', type: 'button', style: 'text-align:left', onclick: act(() => pinDialog(d)) }, 'Definir PIN local ou de desenvolvedor…'),
    h('button', { class: 'btn', type: 'button', style: 'text-align:left', onclick: act(() => confirmSend(d.id, 'request_maintenance', {}, { title: `Pedir janela de manutenção em ${d.name}?`,
      rows: [['Duração', '30 minutos'], ['Libera', 'ADB, instalar apps, USB e lojas']], effect: `espera ${delayText(snap)}`, effectKind: 'warn',
      note: 'Depois da espera, confirme o pedido aqui para abrir a janela.' }).then(() => route())) }, 'Pedir janela de manutenção…')));
  return nodes;
}

/** Janela para digitar um PIN (cifrado no navegador até a chave do aparelho). */
function pinDialog(d) {
  return new Promise((resolve) => {
    const pin = h('input', { class: 'inp', type: 'password', inputmode: 'numeric', autocomplete: 'off', placeholder: 'PIN (6 ou mais dígitos)', 'aria-label': 'PIN' });
    let overlay;
    const close = (v) => { overlay.remove(); resolve(v); };
    const go = (type) => act(async () => {
      if (!/^[0-9]{6,32}$/.test(pin.value)) throw new Error('o PIN precisa ter 6 ou mais dígitos');
      const value = pin.value;
      close(true);
      const box = await sealPin(d.spki, value, `guardian/${type}/${d.id}`);
      await confirmSend(d.id, type, { box }, { title: type === 'set_pin' ? `Definir o PIN local de ${d.name}?` : `Definir o PIN de desenvolvedor de ${d.name}?`,
        rows: [['Aparelho', d.name]], effect: 'vale na hora', effectKind: 'ok', note: 'O PIN viaja cifrado até a chave do aparelho: o gateway e o usuário não o veem.', noteKind: 'ok' });
      route();
    });
    overlay = h('div', { class: 'overlay', onclick: (e) => { if (e.target === overlay) close(false); } },
      h('div', { class: 'sheet', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Definir PIN' }, h('div', { class: 'grab' }), h('h2', {}, 'Definir PIN'),
        h('p', { class: 'muted', style: 'margin:0 0 10px' }, 'O PIN fica só entre você e o aparelho.'), pin,
        h('div', { class: 'row' }, h('button', { class: 'btn pri', type: 'button', onclick: go('set_pin') }, 'PIN local'),
          h('button', { class: 'btn', type: 'button', onclick: go('set_dev_pin') }, 'PIN de desenvolvedor')),
        h('div', { class: 'row' }, h('button', { class: 'btn', type: 'button', onclick: () => close(false) }, 'Cancelar'))));
    document.body.append(overlay);
    pin.focus();
  });
}

// ---------- regras ----------
function regrasNodes(d) {
  const r = d.report || {};
  const snap = r.snapshot || {};
  const labels = r.labels || {};
  const groups = r.groups || {};
  const hints = r.hints || {};
  if (!Object.keys(snap).length) return h('p', { class: 'empty' }, 'O aparelho ainda não enviou a configuração.');
  const dr = drafts.get(d.id) || {};
  const setDraft = (key, value) => {
    const cur = drafts.get(d.id) || {};
    if (String(value) === String(snap[key])) delete cur[key]; else cur[key] = String(value);
    drafts.set(d.id, cur);
    route();
  };
  const effectOf = (key) => {
    const c = classify(key, snap[key], dr[key]);
    return c === 'loosen' ? chip(`espera ${delayText(snap)}`, 'warn') : chip('na hora', 'ok');
  };
  const rowFor = (key) => {
    const v = key in dr ? dr[key] : snap[key];
    const label = ruleLabel(key, labels);
    const chg = key in dr;
    const left = h('div', { class: 't' }, label, hints[key] ? h('div', { class: 'muted' }, hints[key]) : null,
      PKG_KEYS.has(key) && v ? h('div', { class: 'muted' }, pkgText(v, r)) : null,
      chg ? h('div', { class: 'muted', style: 'margin-top:2px' }, key === 'unlock_delay_min' ? `${Number(snap[key]) / 60} h → ${Number(dr[key]) / 60} h` : `${fmtVal(snap[key])} → ${fmtVal(dr[key])}`) : null);
    let ctl;
    if (snap[key] === 'true' || snap[key] === 'false') {
      ctl = h('button', { class: 'tg', type: 'button', role: 'switch', 'aria-checked': String(v === 'true'), 'aria-label': label, onclick: () => setDraft(key, v === 'true' ? 'false' : 'true') });
    } else if (key === 'unlock_delay_min') {
      ctl = h('input', { class: 'inp', type: 'number', min: '0', max: '336', value: String(Number(v) / 60), 'aria-label': `${label} em horas`, style: 'width:90px',
        onchange: (e) => setDraft(key, String(Math.round(Number(e.target.value) * 60))) });
    } else if (key === 'chrome_youtube') {
      ctl = h('select', { class: 'sel', 'aria-label': label, style: 'width:130px', onchange: (e) => setDraft(key, e.target.value) },
        [['0', 'Desligado'], ['1', 'Moderado'], ['2', 'Estrito']].map(([val, t]) => h('option', { value: val, selected: v === val }, t)));
    } else {
      ctl = h('input', { class: 'inp', value: v, 'aria-label': label, onchange: (e) => setDraft(key, e.target.value.trim()) });
    }
    return h('div', { class: 'rw' + (chg ? ' chg' : '') }, left, chg ? effectOf(key) : null, ctl);
  };
  const order = ['Filtro', 'Apps novos', 'Segurança', 'Restrições do sistema', 'Desenvolvimento (ADB curto)', 'Chrome', 'Lojas e apps protegidos', 'Sistema'];
  const keys = Object.keys(snap);
  const byGroup = new Map();
  for (const k of keys) { const g = groups[k] || 'Outros'; (byGroup.get(g) || byGroup.set(g, []).get(g)).push(k); }
  const names = [...order.filter((g) => byGroup.has(g)), ...[...byGroup.keys()].filter((g) => !order.includes(g))];
  const nodes = names.map((g) => {
    const ks = byGroup.get(g);
    const isOpen = open.has(g) || ks.some((k) => k in dr);
    const changed = ks.filter((k) => k in dr).length;
    return h('div', { class: 'group' },
      h('button', { class: 'gh', type: 'button', 'aria-expanded': String(isOpen), onclick: () => { if (open.has(g)) open.delete(g); else open.add(g); route(); } },
        g, h('span', { class: 'sp' }), changed ? chip(`${changed} alterada(s)`, 'warn') : null, h('span', { class: 'muted' }, `${ks.length} ${ks.length === 1 ? 'item' : 'itens'}`)),
      isOpen ? ks.map(rowFor) : null);
  });
  const n = Object.keys(dr).length;
  if (n) {
    nodes.push(h('div', { style: 'height:84px' }));
    const loosen = Object.keys(dr).filter((k) => classify(k, snap[k], dr[k]) === 'loosen').length;
    nodes.push(h('div', { class: 'sticky' }, h('div', { class: 'sp' }, h('strong', {}, `${n} alteraç${n === 1 ? 'ão' : 'ões'}`),
      h('div', { class: 'muted' }, `${n - loosen} valem na hora · ${loosen} esperam ${delayText(snap)}`)),
      h('button', { class: 'btn', type: 'button', onclick: () => { drafts.delete(d.id); route(); } }, 'Descartar'),
      h('button', { class: 'btn pri', type: 'button', onclick: act(async () => {
        const rows = Object.keys(dr).map((k) => [ruleLabel(k, labels), k === 'unlock_delay_min' ? `${Number(snap[k]) / 60} h → ${Number(dr[k]) / 60} h` : `${fmtVal(snap[k])} → ${fmtVal(dr[k])}`]);
        const ok = await confirmSend(d.id, 'set_config', { patch: { ...dr } }, { title: `Alterar ${n} configuraç${n === 1 ? 'ão' : 'ões'} de ${d.name}?`, rows,
          effect: loosen ? `${n - loosen} na hora · ${loosen} espera ${delayText(snap)}` : 'vale na hora', effectKind: loosen ? 'warn' : 'ok',
          note: loosen ? `O que afrouxa a proteção só vale depois de ${delayText(snap)}, e você pode cancelar até lá.` : null });
        if (ok) { drafts.delete(d.id); route(); }
      }) }, 'Revisar e assinar')));
  }
  return nodes;
}

// ---------- apps ----------
const appRisky = (x) => /vpn|shizuku|shell|hail|test dpc/i.test(x);

/** Apps pendentes de um aparelho (Aprovar com passkey ou Recusar) e os já recusados (Reconsiderar). Serve ao guardião-mor e ao guardião. */
function pendingAppNodes(d) {
  const r = d.report || {};
  const pend = r.pendingApps || [];
  const nodes = [h('div', { class: 'sec' }, `Aguardando aprovação · ${pend.length}`)];
  if (!pend.length) nodes.push(h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum app aguardando.')));
  const refuse = (a, undo) => act(async () => {
    if (!undo && !(await sheet({ title: `Recusar “${a.label || a.pkg}” em ${d.name}?`, rows: [['Aparelho', d.name], ['Pacote', a.pkg]],
      note: 'O app continua suspenso no aparelho e sai desta lista. Dá para reconsiderar depois.', confirm: 'Recusar', danger: true }))) return;
    await api('POST', `/v1/devices/${d.id}/apps/refuse`, { pkg: a.pkg, ...(undo ? { undo: true } : {}) });
    route();
  });
  for (const a of pend) {
    const risks = a.risks || [];
    nodes.push(h('div', { class: 'card' + (risks.some(appRisky) ? ' badb' : '') },
      h('div', { class: 'row' }, h('div', { class: 'sp' }, h('strong', {}, a.label || a.pkg), h('div', { class: 'muted mono' }, a.pkg)),
        h('button', { class: 'btn', type: 'button', onclick: refuse(a, false) }, 'Recusar'),
        h('button', { class: 'btn pri', type: 'button', onclick: act(() => confirmSend(d.id, 'approve_app', { pkg: a.pkg }, {
          title: `Aprovar “${a.label || a.pkg}” em ${d.name}?`, rows: [['Ação', 'Aprovar app'], ['Aparelho', d.name], ['Pacote', a.pkg]], effect: 'vale na hora', effectKind: 'ok',
          note: risks.length ? `Risco: ${risks.join(', ')}.` : null, noteKind: 'bad' }).then(() => route())) }, 'Aprovar')),
      risks.length ? h('div', { style: 'margin-top:8px;display:flex;gap:6px;flex-wrap:wrap' }, risks.map((x) => chip(`risco: ${x}`, appRisky(x) ? 'bad' : 'warn'))) : null));
  }
  const ref = d.refusedApps || [];
  if (ref.length) {
    nodes.push(h('div', { class: 'sec' }, `Recusados · ${ref.length}`),
      h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, ref.map((a) => h('div', { class: 'li' },
        h('div', { class: 'sp' }, h('strong', { style: 'font-size:14px' }, a.label || a.pkg), h('div', { class: 'muted mono' }, a.pkg)),
        h('button', { class: 'btn', type: 'button', onclick: refuse(a, true) }, 'Reconsiderar')))));
  }
  return nodes;
}

/** Apps aguardando aprovação, de todos os aparelhos (tela do guardião comum). */
async function appsInboxView() {
  const { devices } = await loadAll();
  renderNav('apps');
  const devs = devices.filter((x) => x.kind === 'device' && (((x.report || {}).pendingApps || []).length || (x.refusedApps || []).length));
  show(top('Apps'), h('div', { class: 'wrap wide' }, devs.length ? devs.map((d) => [h('div', { class: 'sec' }, d.name), pendingAppNodes(d)]) :
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum app aguardando aprovação.'))));
  timer = setTimeout(autoRefresh, 20000);
}

function appsNodes(d) {
  const r = d.report || {};
  const approved = r.approvedApps || [];
  const nodes = pendingAppNodes(d);
  nodes.push(h('div', { class: 'sec' }, `Aprovados · ${approved.length}`));
  const listBox = h('div', {});
  const draw = (q) => {
    const items = approved.filter((a) => `${a.label} ${a.pkg}`.toLowerCase().includes(q.toLowerCase()));
    listBox.replaceChildren(items.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, items.map((a) => h('div', { class: 'li' },
      h('div', { class: 'sp' }, h('strong', { style: 'font-size:14px' }, a.label || a.pkg), h('div', { class: 'muted mono' }, a.pkg)),
      h('button', { class: 'btn', type: 'button', onclick: act(() => confirmSend(d.id, 'revoke_app', { pkg: a.pkg }, { title: `Revogar “${a.label || a.pkg}” em ${d.name}?`,
        rows: [['Ação', 'Revogar aprovação'], ['Pacote', a.pkg]], effect: 'vale na hora', effectKind: 'ok', note: 'O app será suspenso.' }).then(() => route())) }, 'Revogar')))) :
      h('p', { class: 'empty' }, approved.length ? 'Nenhum app com esse nome.' : 'O aparelho ainda não enviou a lista.'));
  };
  draw('');
  nodes.push(h('div', { class: 'pad' }, h('input', { class: 'inp', type: 'search', placeholder: 'Buscar app aprovado', 'aria-label': 'Buscar app aprovado', oninput: (e) => draw(e.target.value) })), listBox);
  return nodes;
}

function avancadoNodes(d, now) {
  return [h('div', { class: 'sec' }, 'Identificação'),
    h('div', { class: 'card' }, kvRows([['Nome', d.name], ['Tipo', d.kind === 'executor' ? 'executor do Pi-hole' : 'aparelho'], ['Fingerprint', fp(d.id)],
      ['Pareado', ago(d.created, now)], ['Comandos na fila', String(d.pending)]])),
    h('div', { class: 'sec' }, 'Gateway'),
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0 0 10px' }, 'Remove este aparelho só da lista do gateway. Não mexe no aparelho.'),
      h('button', { class: 'btn dangero', type: 'button', onclick: act(async () => {
        if (!(await sheet({ title: `Esquecer ${d.name} neste gateway?`, rows: [['Aparelho', d.name], ['Fingerprint', fp(d.id)]], note: 'Ele deixa de aparecer aqui e os comandos na fila são descartados.',
          confirm: 'Esquecer', danger: true }))) return;
        await api('POST', `/v1/devices/${d.id}/forget`, {});
        location.hash = '#/';
      }) }, 'Esquecer neste gateway'))];
}

// ---------- domínios ----------
const reqChoice = new Map(); // `${pedido}|${domínio}` -> 'always' | '3600' | '86400' | 'deny'
let blkDev = '';             // filtro do log: aparelho ('' = todos)
let blkSrc = 'own';          // filtro do log: 'own' (regras próprias) | 'list' (listas) | '' (tudo)
let advOpen = false;         // seção Avançado de Liberados aberta
let blkTtl = 0;              // duração ao liberar direto pelo log (0 = sempre)
const TTL_CHOICES = [['always', 'Sempre', 0], ['3600', '1 h', 3600], ['86400', '1 dia', 86400], ['deny', 'Negar', null]];
const fmtWhen = (ts) => new Date(ts * 1000).toLocaleString('pt-BR', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit', hour12: false });

async function domainsView(tab) {
  const { devices, now, reqs } = await loadAll();
  renderNav('domains');
  const ex = devices.find((x) => x.kind === 'executor');
  if (!ex) { show(top('Domínios'), h('div', { class: 'card' }, h('p', { style: 'margin:0 0 10px' }, 'Nenhum executor do Pi-hole pareado.'), h('a', { class: 'btn pri', href: '#/pair', style: 'display:inline-flex;align-items:center;text-decoration:none' }, 'Parear o executor'))); return; }
  const r = ex.report || {};
  const unb = reqs.filter((q) => q.kind === 'unblock');
  const otherReqs = reqs.filter((q) => q.kind !== 'unblock');
  const minimal = !isAdmin();  // guardião de domínios: só os pedidos de liberação, sem as outras abas
  if (minimal) tab = 'pedidos';
  else if (!tab) tab = reqs.length ? 'pedidos' : 'bloqueios';
  const devName = (id) => (devices.find((x) => x.id === id) || { name: id }).name;
  const protectedDevs = devices.filter((x) => x.kind === 'device');
  const temp = new Map((r.temp || []).map((t) => [`${t.list}:${t.domain}`, t.expires]));
  const covers = (dom) => (r.allow || []).some((a) => dom === a || dom.endsWith('.' + a));  // a regra cobre o domínio e os subdomínios
  const canary = (devices.map((x) => ((x.report || {}).snapshot || {}).canary).find(Boolean)) || '';
  const send = (type, args, spec) => act(() => confirmSend(ex.id, type, args, spec).then((ok) => ok && route()));
  const tabs = minimal ? [] : [['#/domains/pedidos', `Pedidos · ${reqs.length}`, 'pedidos'], ['#/domains/bloqueios', 'Bloqueios', 'bloqueios'],
    ['#/domains/liberados', 'Liberados', 'liberados']];
  const flags = (x) => [x.domain.split('.').some((l) => l.startsWith('xn--')) ? chip('punycode: confira o nome', 'warn') : null,
    x.cname ? chip('via CNAME') : null];
  const batchSpec = (items) => ({ title: `Liberar ${items.length} domínio${items.length > 1 ? 's' : ''}?`,
    rows: items.map((i) => [i.domain, i.ttl_s ? durLabel(i.ttl_s) : 'sem prazo']), effect: 'vale na hora', effectKind: 'ok',
    note: items.some((i) => !i.ttl_s) ? 'Sem prazo: o domínio fica liberado até alguém bloquear de novo. Vale para a casa toda, com os subdomínios.' : 'Vale para a casa toda, com os subdomínios.', noteKind: 'warn' });

  let body;
  if (tab === 'pedidos') {
    const blocked = unb.length ? (await api('GET', '/v1/blocked')).items : [];
    const info = new Map(blocked.map((b) => [`${b.dev}|${b.domain}`, b]));
    // "Liberar todos": um só comando (pihole_batch, até 50 domínios) e um só passkey para todos os pedidos abertos.
    const openReqs = unb.map((q) => ({ q, rows: q.items.filter((i) => i.state === 'open') })).filter((x) => x.rows.length);
    const pick = (q, d) => reqChoice.get(`${q.id}|${d}`) || 'always';
    const merged = new Map();  // domínio -> ttl (0 = sem prazo); o mais curto vence se o mesmo domínio estiver em pedidos diferentes
    for (const { q, rows } of openReqs) for (const i of rows) {
      const v = pick(q, i.domain);
      if (v === 'deny') continue;
      const ttl = v === 'always' ? 0 : Number(v), cur = merged.get(i.domain);
      merged.set(i.domain, cur === undefined ? ttl : cur === 0 ? ttl : ttl === 0 ? cur : Math.min(cur, ttl));
    }
    const allItems = [...merged].slice(0, 50).map(([domain, ttl]) => ({ domain, ...(ttl ? { ttl_s: ttl } : {}) }));
    const total = new Set(openReqs.flatMap((x) => x.rows.map((i) => i.domain))).size;
    const confirmAll = act(async () => {
      let cmd = null;
      if (allItems.length) {
        const sent = await confirmSend(ex.id, 'pihole_batch', { items: allItems }, batchSpec(allItems));
        if (!sent) return;
        cmd = sent.id;
      }
      const sentSet = new Set(allItems.map((x) => x.domain));
      for (const { q, rows } of openReqs) {
        const deny = rows.filter((i) => pick(q, i.domain) === 'deny').map((i) => i.domain);
        if (!deny.length && !(cmd && rows.some((i) => sentSet.has(i.domain)))) continue;  // nada deste pedido entrou no lote
        await api('POST', `/v1/requests/${q.id}/resolve`, { ...(cmd ? { cmd } : {}), deny });
        rows.forEach((i) => reqChoice.delete(`${q.id}|${i.domain}`));
      }
      route();
    });
    const refuseEvery = act(async () => {  // recusar não solta nada: sem passkey
      for (const { q, rows } of openReqs) {
        await api('POST', `/v1/requests/${q.id}/resolve`, { deny: rows.map((i) => i.domain) });
        rows.forEach((i) => reqChoice.delete(`${q.id}|${i.domain}`));
      }
      route();
    });
    body = [openReqs.length > 1 ? h('div', { class: 'card' },
      h('div', { class: 'row', style: 'gap:8px' },
        h('button', { class: 'btn grow', type: 'button', onclick: refuseEvery }, `Recusar todos (${total})`),
        h('button', { class: 'btn pri grow', type: 'button', onclick: confirmAll }, allItems.length ? `Liberar todos (${total}) com um passkey` : 'Negar todos')),
      h('div', { class: 'muted', style: 'margin-top:8px' }, 'Vale a escolha de cada domínio abaixo (Sempre, se você não mudar). A folha mostra tudo antes de assinar.' + (total > 50 ? ' Só os 50 primeiros entram; os outros continuam pedindo.' : ''))) : null,
      unb.length ? h('div', { class: 'grid2' }, unb.map((q) => {
      const rows = q.items.filter((i) => i.state === 'open');
      const key = (d) => `${q.id}|${d}`;
      const val = (d) => reqChoice.get(key(d)) || 'always';
      const refuse = act(async () => {
        await api('POST', `/v1/requests/${q.id}/resolve`, { deny: rows.map((i) => i.domain) });
        rows.forEach((i) => reqChoice.delete(key(i.domain)));
        route();
      });
      const confirm = act(async () => {
        const items = rows.filter((i) => val(i.domain) !== 'deny').map((i) => ({ domain: i.domain, ...(val(i.domain) === 'always' ? {} : { ttl_s: Number(val(i.domain)) }) }));
        const deny = rows.filter((i) => val(i.domain) === 'deny').map((i) => i.domain);
        let cmd = null;
        if (items.length) {
          const sent = await confirmSend(ex.id, 'pihole_batch', { items }, batchSpec(items));
          if (!sent) return;
          cmd = sent.id;
        }
        await api('POST', `/v1/requests/${q.id}/resolve`, { ...(cmd ? { cmd } : {}), deny });
        rows.forEach((i) => reqChoice.delete(key(i.domain)));
        route();
      });
      return h('div', { class: 'card warnb' },
        h('div', { class: 'row' }, h('strong', { class: 'sp' }, devName(q.dev)), chip(`${rows.length} domínio${rows.length > 1 ? 's' : ''}`, 'warn')),
        h('div', { class: 'muted' }, `pedido ${ago(q.ts, now)}`),
        rows.map((i) => {
          const b = info.get(`${q.dev}|${i.domain}`);
          return h('div', { class: 'li', style: 'flex-direction:column;align-items:stretch;gap:2px' },
            h('span', { class: 'mono', style: 'font-weight:600' }, i.domain),
            h('div', { class: 'muted' }, b ? `${b.count} bloqueio${b.count > 1 ? 's' : ''} · ${b.src === 'own' ? 'regra própria' : b.list || 'lista'}` : 'sem bloqueio recente', ' ', flags(b || i)),
            h('div', { class: 'durs', role: 'group', 'aria-label': `Escolha para ${i.domain}`, style: 'margin-top:6px' },
              TTL_CHOICES.map(([k, label]) => h('button', { type: 'button', 'aria-pressed': String(val(i.domain) === k),
                onclick: () => { reqChoice.set(key(i.domain), k); route(); } }, label))));
        }),
        h('div', { class: 'row', style: 'gap:8px;margin-top:12px' },
          h('button', { class: 'btn grow', type: 'button', onclick: refuse }, 'Recusar'),
          h('button', { class: 'btn pri grow', type: 'button', onclick: confirm },
            rows.every((i) => val(i.domain) === 'deny') ? 'Negar' : 'Confirmar com passkey')));
    })) : h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum pedido de liberação.')),
    otherReqs.length ? [h('div', { class: 'sec' }, 'Outros pedidos'), otherReqs.map((q) => h('div', { class: 'card' }, h('div', { class: 'row' },
      h('div', { class: 'sp' }, h('strong', {}, q.text), h('div', { class: 'muted' }, `${q.kind} · ${devName(q.dev)} · ${ago(q.ts, now)}`)),
      h('button', { class: 'btn', type: 'button', onclick: act(async () => { await api('POST', `/v1/requests/${q.id}/dismiss`, {}); route(); }) }, 'Dispensar'))))] : null];
  } else if (tab === 'bloqueios') {
    const qs = new URLSearchParams();
    if (blkDev) qs.set('dev', blkDev);
    if (blkSrc) qs.set('src', blkSrc);
    const items = (await api('GET', '/v1/blocked' + (qs.toString() ? `?${qs}` : ''))).items;
    const pill = (label, on, fn) => h('button', { type: 'button', 'aria-pressed': String(on), onclick: fn }, label);
    body = [h('div', { class: 'sec' }, 'Aparelho'),
      h('div', { class: 'durs', style: 'padding:0 14px', role: 'group', 'aria-label': 'Filtrar por aparelho' },
        [pill('Todos', !blkDev, () => { blkDev = ''; route(); }), ...protectedDevs.map((x) => pill(x.name, blkDev === x.id, () => { blkDev = x.id; route(); }))]),
      h('div', { class: 'sec' }, 'Quem bloqueou'),
      h('div', { class: 'durs', style: 'padding:0 14px', role: 'group', 'aria-label': 'Filtrar por origem' },
        [['own', 'Regras próprias'], ['list', 'Listas'], ['', 'Tudo']].map(([k, label]) => pill(label, blkSrc === k, () => { blkSrc = k; route(); }))),
      h('div', { class: 'sec' }, 'Liberar direto por'),
      h('div', { class: 'durs', style: 'padding:0 14px', role: 'group', 'aria-label': 'Duração da liberação' },
        TTL_CHOICES.filter((c) => c[2] !== null).map(([, label, s]) => pill(label, blkTtl === s, () => { blkTtl = s; route(); }))),
      h('div', { class: 'sec' }, 'Últimas 24 horas'),
      items.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, items.map((x) => h('div', { class: 'li' },
        h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, x.domain),
          h('div', { class: 'muted' }, `${devName(x.dev)} · ${x.count} vez${x.count > 1 ? 'es' : ''} · ${ago(x.last, now)} · ${x.src === 'own' ? 'regra própria' : x.list || 'lista'}`, ' ', flags(x))),
        covers(x.domain) ? chip('liberado', 'ok') : h('button', { class: 'btn', type: 'button', onclick: send('pihole_batch', { items: [{ domain: x.domain, ...(blkTtl ? { ttl_s: blkTtl } : {}) }] },
          batchSpec([{ domain: x.domain, ttl_s: blkTtl }])) }, 'Liberar')))) :
        h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nada bloqueado com esses filtros.'))];
  } else {
    const by = r.allow_by || {};
    const mine = (r.allow || []).filter((d) => by[d] !== undefined);
    const others = (r.allow || []).length - mine.length;
    const listCard = (name, list) => list.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, list.map((x) => h('div', { class: 'li' },
      h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, x),
        h('div', { class: 'muted' }, name === 'allow' && by[x] ? `liberado por ${gname(by[x])}` : '', ' ',
          temp.has(`${name}:${x}`) ? chip(`expira ${fmtWhen(temp.get(`${name}:${x}`))}`, 'warn') : name === 'allow' ? chip('sem prazo') : null)),
      h('button', { class: 'btn', type: 'button', onclick: send('pihole_remove', { list: name, domain: x }, { title: name === 'allow' ? `Bloquear ${x} de novo?` : `Remover ${x} da lista de bloqueados?`,
        rows: [['Ação', name === 'allow' ? 'Bloquear de novo' : 'Remover domínio'], ['Domínio', x]], effect: 'vale na hora', effectKind: 'ok',
        note: name === 'allow' ? 'Volta a valer a regra do Pi-hole para este domínio.' : null }) }, name === 'allow' ? 'Bloquear de novo' : 'Remover')))) :
      h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Vazio.'));
    const dom = h('input', { class: 'inp', type: 'text', inputmode: 'url', placeholder: 'exemplo.com (domínio exato)', autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Domínio' });
    const args = () => ({ domain: dom.value.trim().toLowerCase(), ...(domDur ? { ttl_s: domDur } : {}) });
    const need = (fn) => act(async () => { if (!dom.value.trim()) throw new Error('Digite o domínio.'); await fn(); });
    const durBtns = [3600, 86400, 604800, 0].map((s) => h('button', { type: 'button', 'aria-pressed': String(domDur === s), onclick: () => { domDur = s; route(); } }, durLabel(s)));
    body = [listCard('allow', mine),
      others ? h('p', { class: 'muted', style: 'margin:8px 14px 0' }, `Mais ${others} entrada${others > 1 ? 's' : ''} criada${others > 1 ? 's' : ''} direto no Pi-hole. Elas não aparecem nem são alteradas aqui.`) : null,
      h('details', { class: 'card flat', style: 'margin-top:12px', open: advOpen, ontoggle: (e) => { advOpen = e.target.open; } }, h('summary', { style: 'cursor:pointer;font-weight:600' }, 'Avançado: bloqueados e domínio manual'),
        h('div', { class: 'sec', style: 'padding-left:0' }, `Bloqueados pelo guardião · ${(r.deny || []).length}`), listCard('deny', r.deny || []),
        h('div', { class: 'sec', style: 'padding-left:0' }, 'Liberar ou bloquear um domínio'),
        dom, h('div', { class: 'durs', role: 'group', 'aria-label': 'Duração' }, durBtns),
        h('div', { class: 'row', style: 'margin-top:12px' },
          h('button', { class: 'btn grow', type: 'button', onclick: need(() => confirmSend(ex.id, 'pihole_deny', args(), { title: `Bloquear ${args().domain} ${domDur ? `por ${durLabel(domDur)}` : ''}?`,
            rows: [['Ação', 'Bloquear domínio'], ['Domínio', args().domain], ['Duração', durLabel(domDur)]], effect: 'vale na hora', effectKind: 'ok' }).then((ok) => ok && route())) }, 'Bloquear'),
          h('button', { class: 'btn pri grow', type: 'button', onclick: need(() => confirmSend(ex.id, 'pihole_allow', args(), batchSpec([{ domain: args().domain, ttl_s: domDur }])).then((ok) => ok && route())) }, 'Liberar')),
        h('p', { class: 'muted', style: 'margin:10px 0 0' }, 'Só domínio exato. Curinga e regex ficam de fora desta versão.')),
      canary ? h('div', { class: 'card flat' }, h('div', { class: 'row' }, h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, canary),
        h('div', { class: 'muted' }, 'Domínio-canário · protegido: não pode ser liberado, bloqueado nem removido por aqui')), chip('protegido'))) : null];
  }
  show(top('Domínios', { actions: chip(r.pihole_ok === false ? 'Pi-hole inacessível' : 'Pi-hole ok', r.pihole_ok === false ? 'bad' : 'ok') }),
    h('div', { class: 'wrap wide' }, minimal ? null : segTabs(tabs, tab), body));
  timer = setTimeout(autoRefresh, 20000);
}

// ---------- pessoas ----------
function pushSupported() { return 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window; }

async function pushCard() {
  if (!pushSupported()) return h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Este navegador não suporta notificações push. No iPhone, instale o site na tela inicial primeiro.'));
  const reg = await navigator.serviceWorker.ready.catch(() => null);
  const sub = reg ? await reg.pushManager.getSubscription() : null;
  const on = !!sub && Notification.permission === 'granted';
  return h('div', { class: 'card' },
    h('p', { class: 'muted', style: 'margin:0 0 10px;color:' + (on ? 'var(--green)' : 'var(--muted)') }, on ? 'Avisos ativos neste aparelho: sem sinal, filtro caiu, app novo, pedidos.' :
      Notification.permission === 'denied' ? 'As notificações estão bloqueadas nas configurações do navegador.' : 'Receba um aviso quando algo precisar de você.'),
    on ? h('div', { class: 'row' },
      h('button', { class: 'btn grow', type: 'button', onclick: act(async () => { const r = await api('POST', '/v1/push/test', {}); toast(r.sent ? 'Aviso de teste enviado.' : 'Nenhum aviso enviado.'); }) }, 'Enviar teste'),
      h('button', { class: 'btn grow', type: 'button', onclick: act(async () => { await api('POST', '/v1/push/unsubscribe', { endpoint: sub.endpoint }); await sub.unsubscribe(); toast('Notificações desativadas.'); route(); }) }, 'Desativar')) :
      h('button', { class: 'btn pri', type: 'button', onclick: act(async () => {
        if ((await Notification.requestPermission()) !== 'granted') throw new Error('Permissão de notificação negada.');
        const { key } = await api('GET', '/v1/push/key');
        const s = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: dec(key) });
        const j = s.toJSON();
        await api('POST', '/v1/push/subscribe', { endpoint: j.endpoint, keys: j.keys });
        toast('Notificações ativadas.');
        route();
      }) }, 'Ativar notificações'));
}

function summarize(env) {
  try {
    const c = JSON.parse(new TextDecoder().decode(dec(env.payload)));
    return `${TYPE[c.type] || c.type}${c.args && c.args.id ? ` (${gname(c.args.id)})` : ''}`;
  } catch (_) { return '(ilegível)'; }
}

async function peopleView() {
  me = await api('GET', '/v1/me');
  const { devices, aw } = await loadAll();
  renderNav('people');
  const gs = Object.entries(me.trust);
  const missing = (d) => {
    const have = (d.report && d.report.trust) || {};
    const out = [];
    for (const [gid, g] of gs) {
      if (d.kind !== 'executor' && g.role === 'domains') continue;  // o aparelho não precisa conhecer guardiões
      for (const cred of Object.keys(g.creds)) if (!(have[gid] || []).includes(cred)) out.push({ gid, g, cred });
    }
    return out;
  };
  const propagate = (d) => act(async () => {
    const miss = missing(d);
    const names = [...new Set(miss.map((m) => m.g.name))].join(', ');
    if (!(await sheet({ title: `Fazer ${d.name} confiar em ${names}?`, rows: [['Aparelho', d.name], ['Passkeys novos', String(miss.length)]], effect: 'vale na hora', effectKind: 'ok',
      note: `Serão ${miss.length} toque(s) de passkey, um por item.`, noteKind: 'warn' }))) return;
    const seen = new Set(Object.keys((d.report && d.report.trust) || {}));
    for (const m of miss) {
      if (!seen.has(m.gid)) { await sendCommand(d.id, 'add_guardian', { id: m.gid, name: m.g.name, cred: m.cred, spki: m.g.creds[m.cred], role: m.g.role || 'admin', allow_sync: m.g.allow_sync !== false, window: m.g.window || null }); seen.add(m.gid); }
      else await sendCommand(d.id, 'add_credential', { id: m.gid, cred: m.cred, spki: m.g.creds[m.cred] });
    }
    route();
  });
  const out = h('div', {});
  const link = (kind, name, role, policy) => act(async () => {
    const r = await api('POST', '/v1/invites', { kind, ...(name ? { name } : {}), ...(role ? { role } : {}), ...(policy || {}) });
    const text = `${me.origin}/#invite=${r.token}`;
    out.replaceChildren(h('div', { class: 'card' }, h('p', { style: 'margin:0 0 8px' }, 'Envie este link (vale 24 h, uso único):'), h('textarea', { class: 'ta', readonly: true }, text),
      h('div', { class: 'row', style: 'margin-top:8px' }, copyBtn(() => text), shareBtn(() => text))));
    if (out.scrollIntoView) out.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });
  const nm = h('input', { class: 'inp', placeholder: 'nome do guardião', autocapitalize: 'words', autocomplete: 'off', enterkeyhint: 'done', 'aria-label': 'Nome do guardião', value: inviteName, oninput: (e) => { inviteName = e.target.value; } });
  const myCreds = Object.keys((me.trust[me.guardian.id] || { creds: {} }).creds).length;
  const syncOn = inviteSync === null ? inviteRole === 'domains' : inviteSync;  // guardião-mor: só neste aparelho, a menos que se escolha o contrário
  const cos = aw.filter((c) => c.can_cosign);
  show(top('Pessoas'), h('div', { class: 'wrap' },
    h('div', { class: 'sec' }, 'Guardiões'),
    myCreds < 2 ? h('div', { class: 'card badb' }, h('strong', {}, 'Cadastre uma chave de reserva'),
      h('p', { class: 'muted', style: 'margin:6px 0 10px' }, 'Você é o guardião-mor e tem só 1 passkey. Se perder este celular, ninguém mais administra os aparelhos: cadastre outro celular ou uma chave física.'),
      h('button', { class: 'btn pri', type: 'button', onclick: link('add_passkey') }, 'Cadastrar outra passkey')) : null,
    h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, gs.map(([gid, g]) => {
      const n = Object.keys(g.creds).length;
      const dom = g.role === 'domains';
      const see = (me.see_of || {})[gid] || {};
      const removeCred = (gid2, g2, cred, num) => act(async () => {
        const on = devices.filter((d) => ((d.report && d.report.trust) || {})[gid2] && d.report.trust[gid2].includes(cred));
        if (!(await sheet({ title: `Remover a passkey ${num} de ${g2.name}?`, rows: [['Guardião', g2.name], ['Passkey', String(num)], ['Aparelhos que confiam nela', String(on.length)]],
          effect: 'vale na hora', effectKind: 'ok', note: `${on.length ? `Um toque de passkey por aparelho (${on.length}). ` : ''}Depois apague essa passkey também no gerenciador (conta Google, Windows Hello…) onde ela estiver.`,
          confirm: on.length ? 'Assinar e remover' : 'Remover', danger: true }))) return;
        for (const d of on) await sendCommand(d.id, 'remove_credential', { id: gid2, cred });
        await api('POST', `/v1/guardians/${gid2}/credentials/remove`, { cred });
        toast('Passkey removida.');
        route();
      });
      const removeDomain = act(async () => {
        const on = devices.filter((d) => ((d.report && d.report.trust) || {})[gid]);
        if (!(await sheet({ title: `Remover ${g.name}?`, rows: [['Guardião', g.name], ['Papel', 'guardião'], ['Aparelhos que confiam', String(on.length)]], effect: 'vale na hora', effectKind: 'ok',
          note: on.length ? `Um toque de passkey por aparelho (${on.length}). O acesso ao site acaba na hora.` : 'O acesso ao site acaba na hora.', confirm: 'Remover', danger: true }))) return;
        for (const d of on) await sendCommand(d.id, 'remove_guardian', { id: gid });
        await api('POST', `/v1/guardians/${gid}/remove`, {});
        toast(`${g.name} removido.`);
        route();
      });
      return h('div', { class: 'li', style: 'flex-wrap:wrap' }, h('div', { class: 'av' }, g.name.slice(0, 1).toUpperCase()),
        h('div', { class: 'sp' }, h('strong', {}, g.name), ' ', gid === me.guardian.id ? chip('você') : null, ' ', chip(dom ? 'guardião' : 'guardião-mor', dom ? '' : 'ok'),
          h('div', { class: 'muted', style: n < 2 ? 'color:var(--orange)' : '' }, `${n} passkey${n === 1 ? '' : 's'}`),
          h('div', { style: 'margin-top:4px;display:flex;gap:6px;flex-wrap:wrap' }, chip(g.allow_sync === false ? 'só neste aparelho' : 'pode sincronizar', g.allow_sync === false ? 'ok' : ''),
            g.window ? chip(describeWindow(g.window), 'warn') : null)),
        gid === me.guardian.id ? null : dom ? h('button', { class: 'btn dangero', type: 'button', onclick: removeDomain }, 'Remover') :
          h('button', { class: 'btn dangero', type: 'button', onclick: act(async () => {
            if (!(await sheet({ title: `Pedir a remoção de ${g.name}?`, rows: [['Ação', 'Remover guardião-mor'], ['Guardião', g.name], ['Aparelhos', String(devices.length)]], effect: 'dois guardiões-mor + espera', effectKind: 'warn',
              note: 'Exige a co-assinatura do outro guardião-mor e passa pelo atraso de cada aparelho.', confirm: 'Assinar e pedir', danger: true }))) return;
            for (const d of devices) await sendCommand(d.id, 'remove_guardian', { id: gid });
            route();
          }) }, 'Remover'),
        dom ? h('div', { style: 'flex-basis:100%;padding:4px 0 6px 46px' }, h('div', { class: 'muted', style: 'margin-bottom:6px' }, 'Pode ver, além de domínios:'),
          h('div', { class: 'durs', role: 'group', 'aria-label': `O que ${g.name} pode ver` }, SEE_LABELS.map(([k, label]) => h('button', { type: 'button', 'aria-pressed': String(!!see[k]),
            onclick: act(async () => { await api('POST', `/v1/guardians/${gid}/see`, { ...see, [k]: !see[k] }); route(); }) }, label)))) : null,
        gid === me.guardian.id ? h('div', { style: 'flex-basis:100%;padding:0 0 6px 46px' }, h('button', { class: 'btn' + (n < 2 ? ' pri' : ''), type: 'button', onclick: link('add_passkey') }, 'Cadastrar outra passkey')) : null,
        n > 0 ? h('div', { style: 'flex-basis:100%;padding:2px 0 6px 46px' }, Object.entries(g.creds).map(([cred], i) => {
          const info = (me.cred_info || {})[cred] || {};
          return h('div', { class: 'row', style: 'min-height:40px;gap:8px' },
            h('div', { class: 'sp muted' }, `Passkey ${i + 1}${info.created ? ` · cadastrada ${ago(info.created, me.now)}` : ''}`),
            chip(info.be ? 'sincronizada' : 'só neste aparelho', info.be ? 'warn' : 'ok'),
            n > 1 ? h('button', { class: 'btn dangero', type: 'button', onclick: removeCred(gid, g, cred, i + 1) }, 'Remover') : null);
        })) : null);
    })),
    h('div', { class: 'sec' }, 'Convidar guardião'),
    h('div', { class: 'card' }, nm,
      h('div', { class: 'durs', role: 'group', 'aria-label': 'Papel do convidado' },
        [['domains', 'Guardião (só domínios)'], ['admin', 'Guardião-mor']].map(([k, label]) => h('button', { type: 'button', 'aria-pressed': String(inviteRole === k), onclick: () => { inviteRole = k; route(); } }, label))),
      h('p', { class: 'muted', style: 'margin:8px 0 0' }, inviteRole === 'admin' ? 'Controle completo. Use só para uma chave de reserva sua ou alguém que divide a administração com você.' :
        'Libera e bloqueia sites e responde aos pedidos. Não mexe em regras, apps, PIN nem pessoas. O que mais ele pode ver você escolhe depois.'),
      h('div', { class: 'sec', style: 'padding-left:0' }, 'Passkey'),
      h('div', { class: 'durs', role: 'group', 'aria-label': 'Passkey sincronizável' },
        [[false, 'Só neste aparelho'], [true, 'Pode sincronizar']].map(([k, label]) => h('button', { type: 'button', 'aria-pressed': String(syncOn === k), onclick: () => { inviteSync = k; route(); } }, label))),
      h('p', { class: 'muted', style: 'margin:8px 0 0' }, syncOn ? 'A passkey pode ir para a conta Google ou Apple da pessoa e aparecer em outros aparelhos dela.' :
        'Só vale passkey presa ao aparelho (Windows Hello, Touch ID, chave de segurança). Uma passkey da conta Google é recusada. Não dá para mudar depois.'),
      h('div', { class: 'sec', style: 'padding-left:0' }, 'Horário'),
      h('div', { class: 'durs', role: 'group', 'aria-label': 'Limitar a um horário' },
        [[false, 'A qualquer hora'], [true, 'Só em um horário']].map(([k, label]) => h('button', { type: 'button', 'aria-pressed': String(inviteWin.on === k), onclick: () => { inviteWin.on = k; route(); } }, label))),
      inviteWin.on ? [h('div', { class: 'durs', role: 'group', 'aria-label': 'Dias da semana' },
        DAY_NAMES.map((d, i) => h('button', { type: 'button', 'aria-pressed': String(inviteWin.days.includes(i)), onclick: () => {
          inviteWin.days = inviteWin.days.includes(i) ? inviteWin.days.filter((x) => x !== i) : [...inviteWin.days, i]; route(); } }, d))),
        h('div', { class: 'row', style: 'margin-top:10px;gap:8px;align-items:center' }, 'Das',
          h('input', { class: 'inp', type: 'time', value: inviteWin.from, 'aria-label': 'Início', style: 'width:130px', onchange: (e) => { inviteWin.from = e.target.value; } }), 'às',
          h('input', { class: 'inp', type: 'time', value: inviteWin.to, 'aria-label': 'Fim', style: 'width:130px', onchange: (e) => { inviteWin.to = e.target.value; } })),
        h('p', { class: 'muted', style: 'margin:8px 0 0' }, 'Horário de Brasília. Fora dele os comandos dessa pessoa não valem, mesmo com a passkey certa; quem confere é o aparelho e o executor, com o relógio deles. Não dá para mudar depois.')] : null,
      h('div', { class: 'row', style: 'margin-top:10px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: act(async () => {
        if (!nm.value.trim()) throw new Error('Digite o nome.');
        let window = null;
        if (inviteWin.on) {
          if (!inviteWin.days.length) throw new Error('Escolha pelo menos um dia.');
          if (!inviteWin.from || !inviteWin.to || toMin(inviteWin.from) >= toMin(inviteWin.to)) throw new Error('O horário final precisa ser depois do inicial.');
          window = { days: [...inviteWin.days].sort(), from: toMin(inviteWin.from), to: toMin(inviteWin.to), utc_offset_min: OFFSET_MIN };
        }
        await link('new_guardian', nm.value.trim(), inviteRole, { allow_sync: syncOn, window })();
      }) }, 'Gerar link de convite')),
      ),
    out,
    h('div', { class: 'sec' }, 'Confiança nos aparelhos'),
    h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, devices.length ? devices.map((d) => {
      const m = missing(d);
      return h('div', { class: 'li' }, h('div', { class: 'sp' }, h('strong', {}, d.name), d.kind === 'executor' ? ' ' : null, d.kind === 'executor' ? chip('executor') : null,
        h('div', { class: 'muted', style: m.length ? 'color:var(--orange)' : '' }, m.length ? `ainda não confia em ${[...new Set(m.map((x) => x.g.name))].join(', ')}` : 'confia em todos os passkeys')),
        m.length ? h('button', { class: 'btn pri', type: 'button', onclick: propagate(d) }, 'Propagar') : chip('ok', 'ok'));
    }) : h('p', { class: 'muted' }, 'Nenhum aparelho pareado.')),
    h('div', { class: 'sec' }, 'Co-assinaturas pendentes'),
    h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, aw.length ? aw.map((c) => h('div', { class: 'li' }, h('div', { class: 'sp' }, h('strong', {}, (devices.find((x) => x.id === c.dev) || { name: c.dev }).name),
      h('div', { class: 'muted' }, `${summarize(c.envelope)} · pedido de ${gname(c.guardian)}`)),
      c.can_cosign ? h('button', { class: 'btn pri', type: 'button', onclick: act(async () => {
        if (!(await sheet({ title: `Co-assinar: ${summarize(c.envelope)}?`, rows: [['Pedido de', gname(c.guardian)], ['Aparelho', (devices.find((x) => x.id === c.dev) || { name: c.dev }).name]],
          effect: 'dois guardiões + espera', effectKind: 'warn', note: 'Remover um guardião exige a assinatura dos dois.', confirm: 'Co-assinar' }))) return;
        const sig = await signPayload(dec(c.envelope.payload));
        await api('POST', `/v1/commands/${c.id}/cosign`, { sig });
        toast('Co-assinado.');
        route();
      }) }, 'Co-assinar') : chip('aguardando o outro guardião'))) : h('p', { class: 'muted', style: 'margin:10px 0' }, cos.length ? '' : 'Nenhuma.')),
    h('div', { class: 'sec' }, 'Notificações neste aparelho'), await pushCard(),
    h('div', { class: 'pad', style: 'margin-top:14px' }, h('button', { class: 'btn block', type: 'button', onclick: act(logout) }, 'Sair'))));
}

// ---------- conta (guardião) ----------
async function contaView() {
  me = await api('GET', '/v1/me');
  const { devices } = await loadAll();
  renderNav('people');
  const gid = me.guardian.id;
  const creds = me.trust[gid] ? me.trust[gid].creds : {};
  const n = Object.keys(creds).length;
  const ex = devices.find((x) => x.kind === 'executor');
  const exHave = ex ? (((ex.report || {}).trust || {})[gid] || null) : null;
  const miss = exHave ? Object.keys(creds).filter((c) => !exHave.includes(c)) : [];
  const out = h('div', {});
  const invite = act(async () => {
    const r = await api('POST', '/v1/invites', { kind: 'add_passkey' });
    const text = `${me.origin}/#invite=${r.token}`;
    out.replaceChildren(h('div', { class: 'card' }, h('p', { style: 'margin:0 0 8px' }, 'Abra este link no outro celular ou com a chave física (vale 24 h, uso único):'),
      h('textarea', { class: 'ta', readonly: true }, text), h('div', { class: 'row', style: 'margin-top:8px' }, copyBtn(() => text), shareBtn(() => text))));
  });
  const seen = SEE_LABELS.filter(([k]) => canSee(k)).map(([, label]) => label);
  show(top('Conta'), h('div', { class: 'wrap' },
    h('div', { class: 'card' }, h('div', { class: 'row' }, h('div', { class: 'av' }, me.guardian.name.slice(0, 1).toUpperCase()),
      h('div', { class: 'sp' }, h('strong', {}, me.guardian.name), h('div', { class: 'muted' }, 'guardião')), chip('guardião'))),
    h('div', { class: 'sec' }, 'Minhas passkeys'),
    h('div', { class: 'card' + (n < 2 ? ' warnb' : '') }, h('p', { style: 'margin:0 0 10px' }, `${n} passkey${n === 1 ? '' : 's'} cadastrada${n === 1 ? '' : 's'}.` + (n < 2 ? ' Cadastre outra para não perder o acesso se trocar de celular.' : '')),
      h('button', { class: 'btn' + (n < 2 ? ' pri' : ''), type: 'button', onclick: invite }, 'Cadastrar outra passkey')),
    out,
    ex && miss.length ? h('div', { class: 'card warnb' }, h('p', { style: 'margin:0 0 10px' }, `O executor ainda não conhece ${miss.length} passkey${miss.length > 1 ? 's' : ''} sua${miss.length > 1 ? 's' : ''}.`),
      h('button', { class: 'btn pri', type: 'button', onclick: act(async () => {
        for (const c of miss) await sendCommand(ex.id, 'add_credential', { id: gid, cred: c, spki: creds[c] });
        route();
      }) }, 'Propagar ao executor')) : null,
    ex && !exHave ? h('div', { class: 'card warnb' }, h('p', { style: 'margin:0' }, 'O executor ainda não confia em você. Peça ao guardião-mor para abrir Pessoas e tocar em Propagar.')) : null,
    h('div', { class: 'sec' }, 'O que você pode ver'),
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, ['Domínios', ...seen].join(' · ') + '. Quem define é o guardião-mor.')),
    h('div', { class: 'sec' }, 'Notificações neste aparelho'), await pushCard(),
    h('div', { class: 'pad', style: 'margin-top:14px' }, h('button', { class: 'btn block', type: 'button', onclick: act(logout) }, 'Sair'))));
}

// ---------- histórico ----------
const AUDIT_FILTERS = [['#/history', 'Tudo', 'tudo'], ['#/history/comandos', 'Comandos', 'comandos'], ['#/history/acessos', 'Acessos e pareamento', 'acessos']];

function describeAudit(i, devices) {
  const dev = devices.find((d) => d.id === i.dev);
  const dn = dev ? dev.name : '';
  const t = i.text || '';
  if (i.kind === 'executed') {
    const ok = / ok:/.test(t);
    const type = t.split(' ')[0];
    return { title: `${TYPE[type] || type}${dn ? ` · ${dn}` : ''}`, sub: t.replace(/^\S+ (ok|FALHOU): ?/, '') || '', chip: ok ? [dev && dev.kind === 'executor' ? 'executado pelo executor' : 'executado pelo aparelho', 'ok'] : ['falhou', 'bad'] };
  }
  if (i.kind === 'queued') {
    const m = t.match(/^(\S+?)(?::| co-assinou) (.+)$/);
    const who = m ? gname(m[1]) : '';
    const rest = m ? m[2].replace(/ \(aguarda 2º guardião\)/, '') : t;
    return { title: `${who} ${/co-assinou/.test(t) ? 'co-assinou' : 'pediu'}: ${TYPE[rest] || rest}${dn ? ` · ${dn}` : ''}`, sub: '', chip: /aguarda/.test(t) ? ['aguarda co-assinatura', 'warn'] : null };
  }
  if (i.kind === 'login') return { title: `${gname(t)} entrou`, sub: '', chip: null };
  if (i.kind === 'guardian') return { title: 'Cadastro de guardião ou passkey', sub: t, chip: null };
  if (i.kind === 'paired') return { title: `${dn || 'Aparelho'} pareado`, sub: t, chip: null };
  if (i.kind === 'forget') return { title: `${dn || 'Aparelho'} removido do gateway`, sub: '', chip: null };
  return { title: t, sub: i.kind, chip: null };
}

async function historyView(filter) {
  const [{ devices }, { items }] = await Promise.all([loadAll(), api('GET', '/v1/audit?limit=200')]);
  renderNav('history');
  const keep = { comandos: ['queued', 'executed'], acessos: ['login', 'guardian', 'paired', 'forget'] }[filter];
  const rows = items.filter((i) => !keep || keep.includes(i.kind));
  const dayOf = (ts) => {
    const d = new Date(ts * 1000);
    const t = new Date();
    const y = new Date(Date.now() - 864e5);
    return d.toDateString() === t.toDateString() ? 'Hoje' : d.toDateString() === y.toDateString() ? 'Ontem' : d.toLocaleDateString('pt-BR');
  };
  const groups = [];
  for (const i of rows) { const g = dayOf(i.ts); if (!groups.length || groups[groups.length - 1][0] !== g) groups.push([g, []]); groups[groups.length - 1][1].push(i); }
  show(top('Histórico'), h('div', { class: 'wrap' }, segLinks(AUDIT_FILTERS, filter || 'tudo'),
    groups.length ? groups.map(([g, list]) => [h('div', { class: 'day' }, g), h('div', { class: 'card', style: 'padding-top:2px;padding-bottom:2px' }, list.map((i) => {
      const e = describeAudit(i, devices);
      return h('div', { class: 'ev' }, h('span', { class: 'tm' }, new Date(i.ts * 1000).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', hour12: false })),
        h('div', { class: 't' }, h('strong', {}, e.title), e.sub ? h('div', { class: 'muted' }, e.sub) : null, e.chip ? h('div', { style: 'margin-top:6px' }, chip(e.chip[0], e.chip[1])) : null));
    }))]) : h('p', { class: 'empty' }, 'Nada por aqui ainda.'),
    h('p', { class: 'muted pad', style: 'margin-top:10px' }, 'O “executado” vem do aparelho (relatório), não do site: se algo for adulterado no caminho, aparece aqui.')));
}

function segLinks(items, active) {
  return h('nav', { class: 'filters', 'aria-label': 'Filtros' }, items.map(([href, label, key]) => h('a', { href, class: key === active ? 'on' : '' }, label)));
}

// ---------- parear ----------
const STEPS = { device: ['Gerar o código', 'Colar no NotToday', 'Conferir por voz', 'PIN e atraso', 'Ativar'], executor: ['Gerar o código', 'Rodar no Pi', 'Conferir por voz'] };

async function pairView() {
  me = await api('GET', '/v1/me');
  const { devices } = await loadAll();
  renderNav('home');
  if (!pair) pair = { step: 1, kind: 'device' };
  const names = Object.values(trustFor(pair.kind)).map((g) => `${g.name} (${Object.keys(g.creds).length} passkey${Object.keys(g.creds).length === 1 ? '' : 's'})`).join(', ');
  const steps = STEPS[pair.kind];
  const card = (n, title, detail, body) => {
    const state = n < pair.step ? 'done' : n === pair.step ? 'cur' : 'lock';
    return h('div', { class: `card ${state}` }, h('div', { class: 'stepcard' }, h('span', { class: 'st ' + (state === 'done' ? 'ok' : state === 'cur' ? 'cur' : '') }, state === 'done' ? icon('check', 16) : String(n)),
      h('div', { class: 'sp' }, h('strong', { style: n === pair.step ? 'font-size:16px' : '' }, title), state === 'cur' ? null : h('div', { class: 'muted' }, detail), state === 'cur' ? body : null)));
  };
  const reset = () => { pair = null; location.hash = '#/'; };
  const cmd = 'adb shell dpm set-device-owner com.allan.nottoday/.AdminReceiver';
  const dev = pair.deviceId ? devices.find((d) => d.id === pair.deviceId) : null;
  const body = [];

  body.push(card(1, steps[0], `O aparelho vai confiar em: ${names}`, [
    h('div', { class: 'seg', style: 'margin:10px 0' }, [['device', 'Aparelho'], ['executor', 'Executor do Pi-hole']].map(([k, t]) => h('a', { href: '#/pair', class: pair.kind === k ? 'on' : '', onclick: (e) => { e.preventDefault(); pair.kind = k; pair.step = 1; route(); } }, t))),
    h('p', { class: 'muted', style: 'margin:0 0 10px' }, 'O código vale 24 h e só funciona uma vez.'),
    h('button', { class: 'btn pri', type: 'button', onclick: act(async () => {
      const before = devices.map((d) => d.id);
      const r = await api('POST', '/v1/pairings', { kind: pair.kind });
      pair = { ...pair, step: 2, before, string: pairingString(me.origin, me.rp_id, r.token, trustFor(pair.kind)) };
      route();
    }) }, 'Gerar código')]));

  body.push(card(2, steps[1], pair.kind === 'executor' ? 'Enviado ao Pi' : 'Enviado por mensagem; vale 24 h, uso único', [
    h('div', { class: 'note' }, `O ${pair.kind === 'executor' ? 'executor' : 'aparelho'} passará a confiar em: ${names}. ${pair.kind === 'executor' ? 'Ele' : 'O aparelho'} mostra esta lista antes de parear: se algum nome não for o esperado, NÃO prossiga.`),
    h('textarea', { class: 'ta', readonly: true, 'aria-label': 'String de pareamento' }, pair.string || ''),
    h('div', { class: 'row', style: 'margin-top:8px' }, copyBtn(() => pair.string), shareBtn(() => pair.string)),
    h('p', { class: 'muted', style: 'margin:10px 0 0' }, pair.kind === 'executor' ?
      'No Pi: python -m guardian.executor pair --pairing "<string>". Aguardando o executor aparecer aqui…' :
      'No NotToday: tela de PIN → “Parear com Guardian remoto” → cole a string. Aguardando o aparelho aparecer aqui…')]));

  body.push(card(3, steps[2], 'Compare o código que a pessoa lê', [
    h('p', { class: 'muted', style: 'margin:0' }, 'O aparelho apareceu aqui. Peça para ler o que a tela dele mostra e compare:'),
    h('div', { class: 'fpb', 'aria-label': 'Fingerprint' }, pair.deviceId ? fp(pair.deviceId) : ''),
    h('div', { class: 'note bad' }, 'Se a pessoa leu um código diferente, ou o aparelho não apareceu aqui, não continue: o código pode ter sido usado com outro gateway.'),
    h('div', { class: 'row', style: 'margin-top:10px' },
      h('button', { class: 'btn grow', type: 'button', onclick: act(async () => { if (pair.deviceId) await api('POST', `/v1/devices/${pair.deviceId}/forget`, {}); reset(); toast('Pareamento descartado.'); }) }, 'Não confere'),
      h('button', { class: 'btn pri grow', type: 'button', onclick: () => { pair.step = pair.kind === 'executor' ? 9 : 4; route(); } }, 'Confere, continuar'))]));

  if (pair.kind === 'device') {
    const pin = h('input', { class: 'inp', type: 'password', inputmode: 'numeric', autocomplete: 'off', placeholder: 'PIN local (6 ou mais dígitos)', 'aria-label': 'PIN local' });
    const hours = h('select', { class: 'sel', 'aria-label': 'Atraso para afrouxar' }, [[0, 'sem atraso (só para testes)'], [24, '24 horas (padrão)'], [48, '48 horas'], [72, '72 horas']].map(([v, t]) => h('option', { value: v, selected: v === 24 }, t)));
    body.push(card(4, steps[3], 'Você define o PIN local e o atraso para afrouxar', [
      h('p', { class: 'muted', style: 'margin:0 0 8px' }, 'Chega cifrado até o aparelho: o gateway e o usuário não o veem.'), pin,
      h('label', { class: 'muted', style: 'display:block;margin:10px 0 4px' }, 'Atraso para afrouxar a proteção'), hours,
      h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: act(async () => {
        if (!/^[0-9]{6,32}$/.test(pin.value)) throw new Error('o PIN precisa ter 6 ou mais dígitos');
        const value = pin.value;
        const box = await sealPin(dev.spki, value, `guardian/set_pin/${dev.id}`);
        const delayMin = Number(hours.value) * 60;
        if (!(await sheet({ title: `Definir o PIN e o atraso de ${dev.name}?`, rows: [['PIN local', 'definido por você (cifrado)'], ['Atraso para afrouxar', delayMin ? `${Number(hours.value)} h` : 'sem atraso']],
          effect: 'vale na hora', effectKind: 'ok', note: delayMin ? 'Serão 2 toques de passkey: o PIN e o atraso.' : 'Será 1 toque de passkey.', noteKind: 'ok' }))) return;
        await sendCommand(dev.id, 'set_pin', { box });
        if (delayMin !== Number(((dev.report || {}).snapshot || {}).unlock_delay_min || 1440)) await sendCommand(dev.id, 'set_config', { patch: { unlock_delay_min: String(delayMin) } });
        pair.step = 5;
        route();
      }) }, 'Definir PIN e atraso'))]));
    body.push(card(5, steps[4], 'Só depois disto o set-device-owner', [
      h('p', { class: 'muted', style: 'margin:0 0 8px' }, 'Envie a ativação. Depois, no computador da pessoa:'),
      h('div', { class: 'note ok mono', style: 'word-break:break-all' }, cmd),
      h('div', { class: 'row', style: 'margin-top:8px' }, copyBtn(() => cmd, 'Copiar comando')),
      h('div', { class: 'row', style: 'margin-top:10px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: act(async () => {
        if (await confirmSend(dev.id, 'activate', {}, { title: `Ativar ${dev.name}?`, rows: [['Aparelho', dev.name], ['Fingerprint', fp(dev.id)]], effect: 'vale na hora', effectKind: 'ok',
          note: 'Confirma que você conferiu o fingerprint e definiu o PIN.', noteKind: 'ok' })) { pair.step = 9; route(); }
      }) }, 'Ativar aparelho'))]));
  }

  const done = pair.step === 9;
  const title = pair.kind === 'executor' ? 'Parear executor' : 'Parear aparelho';
  show(top(title, { back: '#/' }), h('div', { class: 'wrap pad' },
    h('p', { class: 'muted', style: 'margin:12px 0 0' }, done ? 'Pronto.' : `passo ${Math.min(pair.step, steps.length)} de ${steps.length}`),
    done ? h('div', { class: 'card' }, h('div', { class: 'row' }, h('span', { style: 'color:var(--green)' }, icon('check')), h('strong', {}, pair.kind === 'executor' ? 'Executor pareado' : 'Aparelho pareado e ativado')),
      pair.kind === 'device' ? h('p', { class: 'muted' }, 'Agora a pessoa pode rodar o set-device-owner. Você recebe o aviso quando o aparelho confirmar.') : null,
      h('button', { class: 'btn pri', type: 'button', style: 'margin-top:10px', onclick: reset }, 'Concluir')) : body,
    done ? null : h('div', { class: 'note' }, 'Por que nesta ordem? Antes do Device Owner o aparelho ainda não está protegido. Pareie, defina o PIN e ative primeiro; senão, sem PIN e sem você, só o reset de fábrica resolve.'),
    done ? null : h('button', { class: 'btn block', type: 'button', style: 'margin-top:10px', onclick: reset }, 'Cancelar')));

  // espera o aparelho/executor aparecer
  if (pair.step === 2) {
    const poll = async () => {
      try {
        const d = await api('GET', '/v1/devices');
        const fresh = d.devices.find((x) => !pair.before.includes(x.id) && x.kind === pair.kind);
        if (fresh) { pair.deviceId = fresh.id; pair.step = 3; route(); return; }
      } catch (_) { /* tenta de novo */ }
      timer = setTimeout(poll, 3000);
    };
    timer = setTimeout(poll, 3000);
  }
}

// ---------- roteamento ----------
/** Atualização periódica que não atropela quem está digitando (no celular se digita devagar) nem uma folha aberta. */
function autoRefresh() {
  const a = document.activeElement;
  const typing = a && a.matches && a.matches('input, textarea, select');
  const dirty = [...document.querySelectorAll('#main input.inp, #main textarea:not([readonly])')].some((e) => e.value.trim());
  if (typing || dirty || document.querySelector('.overlay') || document.hidden) { timer = setTimeout(autoRefresh, 20000); return; }
  route();
}

async function route() {
  clearTimeout(timer);
  const hash = location.hash || '#/';
  const inv = hash.match(/^#invite=([\w-]+)$/);
  if (inv) { nav.hidden = true; return inviteView(inv[1]); }
  if (!me) { nav.hidden = true; return loginView(); }
  try {
    const dm = hash.match(/^#\/device\/([a-z2-7]{20})(?:\/(regras|apps|avancado))?$/);
    const dom = hash.match(/^#\/(?:domains\/)?(pedidos|bloqueios|liberados)$/) || hash.match(/^#\/(domains)$/);
    const his = hash.match(/^#\/history(?:\/(comandos|acessos))?$/);
    if (dm) await deviceView(dm[1], dm[2] || 'resumo');
    else if (dom) await domainsView(dom[1] === 'domains' ? undefined : dom[1]);
    else if (hash === '#/people') await (isAdmin() ? peopleView() : contaView());
    else if (his) await (isAdmin() || canSee('history') ? historyView(his[1]) : domainsView());
    else if (hash === '#/pair' && isAdmin()) await pairView();
    else if (hash === '#/apps') await appsInboxView();
    else if (isAdmin() || canSee('devices')) await inicioView();
    else await domainsView();
  } catch (e) {
    if (e.status === 401) { me = null; nav.hidden = true; return loginView(); }
    if (e.status === 403 && /janela de horário/.test(e.message)) { me = null; nav.hidden = true; return closedView(e.message); }
    show(top('Erro'), h('div', { class: 'card badb' }, e.message));
  }
}

async function boot() {
  try { me = await api('GET', '/v1/me'); } catch (_) { me = null; }
  await route();
}

addEventListener('hashchange', route);
// No celular o navegador congela a aba em segundo plano: ao voltar, recarrega os dados (se ninguém estiver digitando).
document.addEventListener('visibilitychange', () => { if (!document.hidden && me) { clearTimeout(timer); autoRefresh(); } });
window.matchMedia('(min-width: 900px)').addEventListener('change', () => route());
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
boot();
