import { enc, dec, sha256, sealPin, commandBytes, pairingString } from './crypto.js';
import { h, icon, chip, toast, sheet, insignia, parentsOf } from './ui.js';
import { classify } from './gate.js';

const main = document.getElementById('main');
const nav = document.getElementById('nav');
const SILENT_S = 300;
let me = null;               // { guardian, trust, rp_id, origin }
let timer = null;
let counts = { apps: 0, reqs: 0, cosign: 0, pc: 0 };
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
  remove_guardian: 'remover guardião', set_role: 'mudar o papel', remove_credential: 'remover passkey', pihole_allow: 'liberar domínio', pihole_deny: 'bloquear domínio', pihole_remove: 'remover domínio', pihole_batch: 'liberar domínios', pihole_parent_block: 'vetar site', win_install: 'instalar programa no computador', win_run: 'rodar comando no computador',
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

async function signPayload(bytes, only) {
  let mine = Object.keys((me.trust[me.guardian.id] || {}).creds || {});
  if (only && only.length) mine = mine.filter((c) => only.includes(c));   // só as passkeys que o destino já conhece
  const a = await passkeyGet({
    challenge: await sha256(bytes), rpId: me.rp_id, userVerification: 'required', timeout: 60000,
    allowCredentials: mine.map((id) => ({ type: 'public-key', id: dec(id) })),
  });
  return { guardian: me.guardian.id, cred: a.id, authenticatorData: a.authenticatorData, clientDataJSON: a.clientDataJSON, signature: a.signature };
}

async function sendCommand(dev, type, args = {}) {
  const { next } = await api('GET', `/v1/devices/${dev}/ctr`);
  const bytes = commandBytes({ v: 1, dev, guardian: me.guardian.id, ctr: next, type, args });
  // Passkey nova ainda não é conhecida pelo destino: assinar a propagação com ela seria recusado. Oferece só as que o destino já confia.
  let known;
  if (type === 'add_credential' || type === 'add_guardian') {
    const d = ((await api('GET', '/v1/devices')).devices || []).find((x) => x.id === dev);
    known = ((d && d.report && d.report.trust) || {})[me.guardian.id];
  }
  const sig = await signPayload(bytes, known);
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
const isAdmin = () => !!me && (me.guardian.role === 'admin' || me.guardian.role === 'master');   // guardião-mor ou mestre
const isMaster = () => !!me && me.guardian.role === 'master';
const hasMaster = () => !!me && Object.values(me.trust || {}).some((g) => g.role === 'master');
/** Incluir, remover e promover guardiões: só o mestre. Enquanto não existe mestre, vale o modo antigo (guardião-mor, com duas assinaturas). */
const canManage = () => isMaster() || (isAdmin() && !hasMaster());
const roleLabel = (r) => (r === 'master' ? 'mestre' : r === 'domains' ? 'guardião' : 'guardião-mor');
const deviceKey = (d) => (d.kind === 'executor' ? 'executor' : 'device');
const roleKey = (r) => (r === 'master' || r === 'domains' ? r : 'admin');
const EPITHET = { master: 'Senhor das chaves', admin: 'Capitão da guarda', domains: 'Sentinela dos portões' };
/** Metadado do guardião: texto gravado, sem borda nem fundo (só botão e cartão-link parecem clicáveis). */
const inscr = (ic, text, kind) => h('span', { class: 'insc-i' + (kind ? ' ' + kind : '') }, icon(ic, 14), text);
/** Brasão + nome + título: o topo de todo cartão de guardião. */
const guardianHead = (g, mine) => [insignia(roleKey(g.role)),
  h('div', { class: 'sp' }, h('div', { class: 'gname' }, g.name, mine ? h('small', {}, ' (você)') : null),
    h('div', { class: 'gtitle' }, `${roleLabel(g.role)} · ${EPITHET[roleKey(g.role)]}`))];
const guardianInscr = (g, n) => h('div', { class: 'insc' }, inscr('key', `${n} passkey${n === 1 ? '' : 's'}`, n < 2 ? 'warn' : ''),
  inscr(g.allow_sync === false ? 'lock' : 'sync', g.allow_sync === false ? 'só neste aparelho' : 'pode sincronizar'),
  inscr('clock', g.window ? describeWindow(g.window) : 'a qualquer hora', g.window ? 'warn' : ''));
const canSee = (k) => isAdmin() || !!(me && me.guardian.see && me.guardian.see[k]);
const SEE_LABELS = [['devices', 'Estado dos aparelhos'], ['rules', 'Regras (só leitura)'], ['apps', 'Apps (só leitura)'], ['history', 'Histórico completo']];
/** Confiança que vai na string de pareamento: aparelho e executor conhecem todos os guardiões (o comum aprova apps, o aparelho confere a assinatura). */
const trustFor = (_kind) => ({ ...me.trust });

// ---------- dados ----------
async function loadAll() {
  const [d, r, a] = await Promise.all([api('GET', '/v1/devices'), api('GET', '/v1/requests'), api('GET', '/v1/commands/awaiting')]);
  for (const x of d.devices) {  // apps recusados saem das pendências e ficam em refusedApps (dá para reconsiderar)
    const ref = new Set(x.refused || []);
    if (x.report && x.report.pendingApps) {
      x.refusedApps = x.report.pendingApps.filter((a) => ref.has(a.pkg) && !(x.vetoed || {})[a.pkg]);
      x.report.pendingApps = x.report.pendingApps.filter((a) => !ref.has(a.pkg) && !(x.vetoed || {})[a.pkg]);  // vetados saem das solicitações
    }
  }
  const apps = d.devices.reduce((n, x) => n + ((x.report && x.report.pendingApps) || []).length, 0);
  const pcReqs = r.items.filter((q) => q.kind === 'install' || q.kind === 'command');   // pedidos do computador: tela PC
  const reqs = r.items.filter((q) => q.kind !== 'install' && q.kind !== 'command');
  counts = { apps, reqs: reqs.length, cosign: a.commands.filter((c) => c.can_cosign).length, pc: pcReqs.length };
  return { devices: d.devices, now: d.now, reqs, pcReqs, aw: a.commands };
}

function statusOf(d, now) {
  const r = d.report || {};
  if (now - (d.last_seen || d.created) > SILENT_S) return { word: 'Sem sinal', kind: 'bad', detail: `sem consultar o gateway ${ago(d.last_seen || d.created, now)}` };
  if (!d.report) return { word: 'Novo', kind: '', detail: 'aguardando o primeiro relatório' };
  if (d.kind === 'executor') {
    if (r.pihole_ok === false) return { word: 'Atenção', kind: 'warn', detail: 'Pi-hole inacessível' };
    return { word: 'Ok', kind: 'ok', detail: `${Object.keys(r.allow_by || {}).length} liberados pelo Guardian · ${(r.temp || []).length} temporários · ${Object.keys(r.deny_by || {}).length} bloqueados pelo Guardian` };
  }
  if (r.platform === 'windows') return { word: 'Ok', kind: 'ok', detail: (r.busy ? `executando ${r.busy.name || (r.busy.type === 'win_install' ? 'uma instalação' : 'um comando')} há ${dur((now - r.busy.since) * 1000)} · ` : '') + `agente ${r.version || ''} · visto ${ago(d.last_seen, now)}${r.tailscale ? '' : ' · sem Tailscale'}` };
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
    h('h1', {}, title), whoami(), actions || null);
}

/** Quem está logado e com que força: brasão do papel + nome + título, em todas as telas (só leitura, não é botão). */
function whoami() {
  if (!me || !me.guardian) return null;
  const r = roleKey(me.guardian.role);
  return h('div', { class: 'who r-' + r, role: 'img', 'aria-label': `Você: ${me.guardian.name}, ${roleLabel(me.guardian.role)}` },
    insignia(r, 28), h('div', { class: 'wt' }, h('div', { class: 'wn' }, me.guardian.name), h('div', { class: 'wr' }, roleLabel(me.guardian.role))));
}

function renderNav(active) {
  nav.hidden = !me;
  if (!me) return;
  const item = (href, label, ic, key, badge) => h('a', { class: 'navitem' + (active === key ? ' on' : ''), href, 'aria-current': active === key ? 'page' : null },
    icon(ic), label, badge ? h('span', { class: 'badge' }, String(badge)) : null);
  const items = isAdmin() ? [item('#/', 'Início', 'home', 'home', 0), item('#/domains', 'Domínios', 'globe', 'domains', counts.reqs),
    item('#/apps', 'Apps', 'grid', 'apps', counts.apps), item('#/guardians', 'Guardiões', 'people', 'guardians', counts.cosign),
    item('#/devices', 'Dispositivos', 'device', 'devices', 0), item('#/pc', 'PC', 'terminal', 'pc', counts.pc), item('#/history', 'Histórico', 'clock', 'history', 0)] :
    [canSee('devices') ? item('#/', 'Início', 'home', 'home', 0) : null, item('#/domains', 'Domínios', 'globe', 'domains', counts.reqs),
      item('#/apps', 'Apps', 'grid', 'apps', counts.apps),
      canSee('history') ? item('#/history', 'Histórico', 'clock', 'history', 0) : null, item('#/people', 'Conta', 'people', 'people', 0)];
  nav.replaceChildren(h('div', { class: 'brand' }, insignia('master', 28), 'NotToday Guardian'), ...items.filter(Boolean),
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
    h('div', { class: 'logo' }, insignia('master', 72)),
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
    h('div', { class: 'logo' }, insignia('master', 72)),
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
function deviceCard(d, now, { sel, href, onclick } = {}) {
  const st = statusOf(d, now);
  return h('a', { class: 'card gcard r-' + deviceKey(d) + (sel ? ' sel' : '') + (st.kind === 'bad' ? ' badb' : st.kind === 'warn' ? ' warnb' : ''), href: href || `#/device/${d.id}`, onclick },
    h('div', { class: 'row', style: 'gap:12px' }, insignia(deviceKey(d), 40), h('strong', {}, d.name),
      d.kind === 'executor' ? chip('Pi-hole') : (d.report || {}).platform === 'windows' ? chip('Windows') : null, h('span', { class: 'sp' }), chip(st.word, st.kind)),
    h('div', { class: 'muted', style: 'margin-top:8px' }, st.detail));
}

function guardianCard(id, g, { sel, href, onclick } = {}) {
  const n = Object.keys(g.creds || {}).length;
  return h('a', { class: 'card gcard r-' + roleKey(g.role) + (sel ? ' sel' : ''), href: href || '#/guardians', onclick },
    h('div', { class: 'row', style: 'align-items:flex-start;gap:14px' }, guardianHead(g, id === me.guardian.id)),
    guardianInscr(g, n));
}

const canaryOf = (devices) => (devices.map((x) => ((x.report || {}).snapshot || {}).canary).find(Boolean)) || '';

/** Leitura de um aparelho (sem nenhum botão): estado, pendências e o que o aparelho informou. */
function deviceInfoNodes(d, now) {
  const r = d.report || {};
  const snap = r.snapshot || {};
  const w = r.windows || {};
  const pend = r.pending || [];
  const apps = r.pendingApps || [];
  const nodes = [deviceBanner(d, now)];
  if (pend.length || apps.length) {
    nodes.push(h('div', { class: 'sec' }, 'Pendências'), h('div', { class: 'card' }, kvRows([
      ...pend.map((p) => [`Pedido: ${KIND[p.kind] || p.kind}`, p.state === 'ready' ? 'pronto' : `em espera · ${dur(p.remainingMs || 0)}`]),
      ...(apps.length ? [['Apps aguardando aprovação', String(apps.length)]] : []),
    ], true)));
  }
  nodes.push(h('div', { class: 'sec' }, 'Estado'), h('div', { class: 'card' }, kvRows([
    ['Device Owner', r.owner ? 'sim' : 'não'], ['Ativado pelo guardião', r.activated ? 'sim' : 'não'], ['PIN local', r.pinSet ? 'definido' : 'não definido'],
    ['Atraso para afrouxar', delayText(snap)], ['Janela de manutenção', w.maintenanceMs ? 'ativa' : 'fechada'],
    ['Janela de desenvolvimento', w.devMs ? 'aberta' : `fechada · ${w.devUsed ?? '?'} usadas em 24 h`], ['Tailscale', r.tailscale ? 'sim' : 'não'], ['Versão do app', r.version || '?'],
  ], true)));
  return nodes;
}

function executorInfoNodes(d, now, devices) {
  const r = d.report || {};
  const mineAllow = Object.keys(r.allow_by || {}).length;
  const mineDeny = Object.keys(r.deny_by || {}).length;
  const direct = Math.max(0, (r.allow_total ?? (r.allow || []).length) - mineAllow) + Math.max(0, (r.deny_total ?? (r.deny || []).length) - mineDeny);
  return [deviceBanner(d, now), h('div', { class: 'sec' }, 'Pi-hole'), h('div', { class: 'card' }, kvRows([
    ['Pi-hole', r.pihole_ok === false ? 'inacessível' : 'ok'], ['Liberados pelo Guardian', String(mineAllow)], ['Bloqueados pelo Guardian', String(mineDeny)],
    ['Temporários', String((r.temp || []).length)], ['Entradas criadas direto no Pi-hole', String(direct)], ['Domínio-canário', canaryOf(devices || []) || 'não definido'],
  ], true))];
}

function guardianInfoNodes(id, g) {
  const creds = Object.keys(g.creds || {});
  const see = (me.see_of || {})[id] || {};
  const dom = g.role === 'domains';
  const seen = SEE_LABELS.filter(([k]) => see[k]).map(([, label]) => label);
  return [h('div', { class: 'sec' }, 'Perfil'), h('div', { class: 'card' }, kvRows([
    ['Papel', roleLabel(g.role)], ['Passkeys', String(creds.length)], ['Sincronização', g.allow_sync === false ? 'só neste aparelho' : 'pode sincronizar'],
    ['Horário', describeWindow(g.window)], ...(dom ? [['Pode ver além de domínios', seen.length ? seen.join(', ') : 'nada']] : []),
  ], true)),
  h('div', { class: 'sec' }, 'Passkeys'), h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, creds.map((cred, i) => {
    const info = (me.cred_info || {})[cred] || {};
    return h('div', { class: 'li' }, h('div', { class: 'sp muted' }, `Passkey ${i + 1}${info.created ? ` · cadastrada ${ago(info.created, me.now)}` : ''}`),
      chip(info.be ? 'sincronizada' : 'só neste aparelho', info.be ? 'warn' : 'ok'));
  }))];
}

const paneHead = (name, kindLabel) => h('div', { class: 'panehead' }, h('h2', {}, name), chip(kindLabel));

/** Início: só leitura. Aparelhos, Pi-hole e guardiões; tudo que se configura fica em Dispositivos, Guardiões, Domínios e Apps. */
async function inicioView() {
  me = await api('GET', '/v1/me');
  const { devices, now, reqs, aw } = await loadAll();
  renderNav('home');
  const todos = [];
  const cos = aw.filter((c) => c.can_cosign);
  if (cos.length) todos.push({ n: cos.length, title: 'Co-assinatura pendente', sub: cos.map((c) => `${TYPE[JSON.parse(new TextDecoder().decode(dec(c.envelope.payload))).type] || 'comando'}`).slice(0, 2).join(' · '), href: '#/guardians' });
  if (reqs.length) todos.push({ n: reqs.length, title: 'Solicitações dos usuários', sub: reqs.slice(0, 2).map((q) => q.text).join(' · '), href: '#/domains/solicitacoes' });
  for (const d of isAdmin() ? devices : []) {
    const r = d.report || {};
    const apps = r.pendingApps || [];
    if (apps.length) todos.push({ n: apps.length, title: 'Apps aguardando aprovação', sub: `${d.name}${apps.some((a) => (a.risks || []).length) ? ' · com risco' : ''}`, href: '#/apps/solicitacoes' });
    const ready = (r.pending || []).filter((p) => p.state === 'ready');
    if (ready.length) todos.push({ n: ready.length, title: 'Pedido pronto para confirmar', sub: `${d.name} · ${ready.map((p) => KIND[p.kind] || p.kind).join(', ')}`, href: `#/device/${d.id}` });
  }
  const execs = devices.filter((d) => d.kind === 'executor');
  const phones = devices.filter((d) => d.kind === 'device');
  const gs = isAdmin() ? Object.entries(me.trust) : [];
  const ids = [...execs, ...phones].map((d) => d.id).concat(gs.map(([id]) => id));
  if (!selected || !ids.includes(selected)) selected = (phones[0] || execs[0] || {}).id || (gs[0] || [])[0] || null;
  const pick = (id) => (wide() ? { sel: id === selected, href: '#/', onclick: (e) => { e.preventDefault(); selected = id; route(); } } : {});

  const list = h('div', { class: 'list' },
    h('div', { class: 'sec' }, 'Precisa de você'),
    todos.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, todos.map((t) => h('a', { class: 'todo', href: t.href },
      h('span', { class: 'cnt' }, String(t.n)), h('div', { class: 'sp' }, h('strong', {}, t.title), h('div', { class: 'muted' }, t.sub)), icon('chevron', 18)))) :
      h('div', { class: 'card' }, h('div', { class: 'row' }, h('span', { style: 'color:var(--green)' }, icon('check')), h('strong', {}, 'Tudo em dia'))),
    execs.length ? [h('div', { class: 'sec' }, 'Pi-hole'), execs.map((d) => deviceCard(d, now, pick(d.id)))] : null,
    h('div', { class: 'sec' }, 'Aparelhos'),
    phones.length ? phones.map((d) => deviceCard(d, now, pick(d.id))) :
      h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum aparelho pareado ainda. Use Dispositivos → Parear.')),
    gs.length ? [h('div', { class: 'sec' }, 'Guardiões'), gs.map(([id, g]) => guardianCard(id, g, wide() ? pick(id) : {}))] : null,
    null);

  let pane = null;
  if (wide() && selected) {
    const d = devices.find((x) => x.id === selected);
    const ge = gs.find(([id]) => id === selected);
    if (d) pane = h('div', { class: 'pane' }, paneHead(d.name, d.kind === 'executor' ? 'Pi-hole' : 'Aparelho'), d.kind === 'executor' ? executorInfoNodes(d, now, devices) : deviceInfoNodes(d, now));
    else if (ge) pane = h('div', { class: 'pane' }, paneHead(ge[1].name, roleLabel(ge[1].role).replace(/^./, (c) => c.toUpperCase())), guardianInfoNodes(ge[0], ge[1]));
  }
  show(top('Início'), h('div', { class: 'wrap' }, h('div', { class: 'cols' }, list, pane)));
  timer = setTimeout(autoRefresh, 20000);
}

/** Dispositivos: o Pi-hole e os aparelhos, com os botões e configurações de cada um. */
let selectedDev = null;
async function devicesView() {
  const { devices, now } = await loadAll();
  renderNav('devices');
  const execs = devices.filter((d) => d.kind === 'executor');
  const phones = devices.filter((d) => d.kind === 'device');
  if (!selectedDev || !devices.some((d) => d.id === selectedDev)) selectedDev = (phones[0] || execs[0] || {}).id || null;
  const pick = (id) => (wide() ? { sel: id === selectedDev, href: '#/devices', onclick: (e) => { e.preventDefault(); selectedDev = id; route(); } } : {});
  const list = h('div', { class: 'list' },
    execs.length ? [h('div', { class: 'sec' }, 'Pi-hole'), execs.map((d) => deviceCard(d, now, pick(d.id)))] : null,
    h('div', { class: 'sec' }, 'Aparelhos'),
    phones.length ? phones.map((d) => deviceCard(d, now, pick(d.id))) : h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum aparelho pareado ainda. Toque em Parear.')));
  const sel = devices.find((d) => d.id === selectedDev);
  const pane = wide() && sel ? h('div', { class: 'pane' }, paneHead(sel.name, sel.kind === 'executor' ? 'Pi-hole' : 'Aparelho'),
    sel.kind === 'executor' ? executorNodes(sel, now) : [resumoNodes(sel, now),
      h('div', { class: 'pad', style: 'margin-top:12px' }, h('a', { class: 'btn pri block', href: `#/device/${sel.id}/regras`, style: 'display:flex;align-items:center;justify-content:center;text-decoration:none' }, 'Regras e configurações'))]) : null;
  show(top('Dispositivos', { actions: h('a', { class: 'btn pri', href: '#/pair', style: 'min-height:40px;display:inline-flex;align-items:center;text-decoration:none' }, 'Parear') }),
    h('div', { class: 'wrap' }, h('div', { class: 'cols' }, list, pane)));
  timer = setTimeout(autoRefresh, 20000);
}

function statusRow(d, now) {
  const st = statusOf(d, now);
  return [h('div', { class: 'row', style: 'gap:12px' }, insignia(deviceKey(d), 36), h('strong', {}, d.name), d.kind === 'executor' ? chip('executor') : null,
    h('span', { class: 'sp' }), chip(st.word, st.kind)), h('div', { class: 'muted', style: 'margin-top:6px' }, st.detail)];
}

// ---------- aparelho ----------
function deviceBanner(d, now) {
  const st = statusOf(d, now);
  const r = d.report || {};
  const title = d.kind === 'executor' ? 'Executor do Pi-hole' : r.filterActive ? 'Filtro CONFIRMADO' : r.filterActive === false ? 'Filtro NÃO confirmado' : 'Aguardando relatório';
  return h('div', { class: 'banner gcard r-' + deviceKey(d) + ' ' + (st.kind === 'ok' ? '' : st.kind) },
    h('div', { class: 'row', style: 'gap:12px' }, insignia(deviceKey(d), 40), h('strong', { style: 'font-size:16px' }, title), h('span', { class: 'sp' }), chip(st.word, st.kind)),
    h('div', { class: 'muted', style: 'margin-top:4px;color:var(--text)' }, `visto ${ago(d.last_seen, now)} · relatório ${ago(d.report_ts, now)}`));
}

function segTabs(items, active) {
  return h('nav', { class: 'seg', 'aria-label': 'Seções' }, items.map(([href, label, key]) => h('a', { href, class: key === active ? 'on' : '', 'aria-current': key === active ? 'page' : null }, label)));
}

async function deviceView(id, tab) {
  const { devices, now } = await loadAll();
  renderNav(isAdmin() ? 'devices' : 'home');
  const d = devices.find((x) => x.id === id);
  if (!d) { show(top('Aparelho', { back: isAdmin() ? '#/devices' : '#/' }), h('p', { class: 'empty' }, 'Aparelho não encontrado.')); return; }
  if (!isAdmin()) return deviceReadOnly(d, now);
  if (tab === 'apps') { appDev = d.kind === 'device' ? id : ''; location.hash = '#/apps/solicitacoes'; return; }  // endereço antigo
  const base = `#/device/${id}`;
  const tabs = d.kind === 'executor' ? [[base, 'Resumo', 'resumo'], [`${base}/avancado`, 'Avançado', 'avancado']] :
    [[base, 'Resumo', 'resumo'], [`${base}/regras`, 'Regras', 'regras'], [`${base}/avancado`, 'Avançado', 'avancado']];
  let body;
  if (tab === 'regras' && d.kind === 'device') body = regrasNodes(d);
  else if (tab === 'avancado') body = avancadoNodes(d, now);
  else { tab = 'resumo'; body = d.kind === 'executor' ? executorNodes(d, now) : resumoNodes(d, now); }
  show(top(d.name, { back: '#/devices' }), h('div', { class: 'wrap' }, deviceBanner(d, now), segTabs(tabs, tab), body));
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
    ['Temporários', String((r.temp || []).length)]], true))];
}

/** Linhas rótulo/valor. Com `upper`, o valor vai em MAIÚSCULAS e em destaque (estado e configuração). */
function kvRows(rows, upper = false) {
  return h('div', { class: 'kvbox', style: 'margin:0' }, rows.map(([k, v]) => h('div', { class: 'kv' + (upper ? ' up' : '') }, h('span', {}, k), h('span', {}, v))));
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
      h('a', { class: 'btn pri block', href: '#/apps/solicitacoes', style: 'margin-top:10px;display:flex;align-items:center;justify-content:center;text-decoration:none' }, 'Revisar apps')));
  }
  nodes.push(h('div', { class: 'sec' }, 'Estado'));
  const w = r.windows || {};
  nodes.push(h('div', { class: 'card' }, kvRows([
    ['Device Owner', r.owner ? 'sim' : 'não'], ['Ativado pelo guardião', r.activated ? 'sim' : 'não'], ['PIN local', r.pinSet ? 'definido' : 'não definido'],
    ['Atraso para afrouxar', delayText(snap)], ['Janela de manutenção', w.maintenanceMs ? 'ativa' : 'fechada'],
    ['Janela de desenvolvimento', w.devMs ? 'aberta' : `fechada · ${w.devUsed ?? '?'} usadas em 24 h`], ['Tailscale', r.tailscale ? 'sim' : 'não'], ['Versão do app', r.version || '?'],
  ], true)));
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
// ---------- apps ----------
let appDev = '';             // filtro das telas de Apps: aparelho ('' = todos)
const appRisky = (x) => /vpn|shizuku|shell|hail|test dpc/i.test(x);

/** Grupo de botões de escolha única (mesmo desenho dos filtros de Bloqueios). */
function pillGroup(label, options, current, onPick) {
  return h('div', { class: 'durs', style: 'padding:0 14px', role: 'group', 'aria-label': label },
    options.map(([k, text]) => h('button', { type: 'button', 'aria-pressed': String(current === k), onclick: () => onPick(k) }, text)));
}

/** Apps: Solicitações | Aprovados | Recusados, com filtro por aparelho. Serve ao guardião-mor e ao guardião. */
async function appsView(tab) {
  const { devices } = await loadAll();
  renderNav('apps');
  const phones = devices.filter((x) => x.kind === 'device');
  if (appDev && !phones.some((x) => x.id === appDev)) appDev = '';
  const shown = appDev ? phones.filter((x) => x.id === appDev) : phones;
  tab = ['solicitacoes', 'aprovados', 'recusados', ...(isAdmin() ? ['instalados', 'vetados'] : [])].includes(tab) ? tab : 'solicitacoes';
  const pendingOf = (d) => ((d.report || {}).pendingApps || []);
  const nPend = shown.reduce((n, d) => n + pendingOf(d).length, 0);
  const nRef = shown.reduce((n, d) => n + (d.refusedApps || []).length, 0);
  const tabs = [['#/apps/solicitacoes', `Solicitações · ${nPend}`, 'solicitacoes'], ['#/apps/aprovados', 'Aprovados', 'aprovados'], ['#/apps/recusados', `Recusados · ${nRef}`, 'recusados'],
    ...(isAdmin() ? [['#/apps/instalados', 'Instalados', 'instalados'], ['#/apps/vetados', `Vetados · ${shown.reduce((n, d) => n + Object.keys(d.vetoed || {}).length, 0)}`, 'vetados']] : [])];
  const filters = phones.length > 1 ? [h('div', { class: 'sec' }, 'Aparelho'),
    pillGroup('Filtrar por aparelho', [['', 'Todos'], ...phones.map((x) => [x.id, x.name])], appDev, (k) => { appDev = k; route(); })] : null;
  const refuse = (d, a, undo) => act(async () => {
    if (!undo && !(await sheet({ title: `Recusar “${a.label || a.pkg}” em ${d.name}?`, rows: [['Aparelho', d.name], ['Pacote', a.pkg]],
      note: 'O app continua suspenso no aparelho e sai das solicitações. Dá para reconsiderar depois, em Recusados.', confirm: 'Recusar', danger: true }))) return;
    await api('POST', `/v1/devices/${d.id}/apps/refuse`, { pkg: a.pkg, ...(undo ? { undo: true } : {}) });
    route();
  });
  const approve = (d, a) => act(() => confirmSend(d.id, 'approve_app', { pkg: a.pkg }, {
    title: `Aprovar “${a.label || a.pkg}” em ${d.name}?`, rows: [['Ação', 'Aprovar app'], ['Aparelho', d.name], ['Pacote', a.pkg]], effect: 'vale na hora', effectKind: 'ok',
    note: (a.risks || []).length ? `Risco: ${a.risks.join(', ')}.` : null, noteKind: 'bad' }).then(() => route()));
  const nameRow = (a, d, extra) => h('div', { class: 'sp' }, h('strong', { style: 'font-size:14px' }, a.label || a.pkg), h('div', { class: 'muted mono' }, a.pkg),
    h('div', { class: 'muted' }, d.name, extra ? ` · ${extra}` : ''));
  const empty = (text) => h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, text));

  let body;
  if (tab === 'solicitacoes') {
    const rows = shown.flatMap((d) => pendingOf(d).map((a) => ({ d, a })));
    body = rows.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, rows.map(({ d, a }) => h('div', { class: 'li', style: 'flex-wrap:wrap' },
      nameRow(a, d, a.asked ? 'pedido do usuário' : ''),
      h('div', { class: 'acts' }, h('button', { class: 'btn', type: 'button', onclick: refuse(d, a, false) }, 'Recusar'),
        h('button', { class: 'btn pri', type: 'button', onclick: approve(d, a) }, 'Aprovar')),
      (a.risks || []).length ? h('div', { style: 'flex-basis:100%;display:flex;gap:6px;flex-wrap:wrap' }, a.risks.map((x) => chip(`risco: ${x}`, appRisky(x) ? 'bad' : 'warn'))) : null))) :
      empty('Nenhum app aguardando aprovação.');
  } else if (tab === 'aprovados') {
    let rows;
    if (isAdmin()) {
      rows = shown.flatMap((d) => ((d.report || {}).approvedApps || []).map((a) => ({ d, a, by: (d.approved_by || {})[a.pkg] })));
    } else {
      const dec = await api('GET', '/v1/my/decisions');
      rows = dec.apps.filter((x) => shown.some((d) => d.id === x.dev)).map((x) => {
        const d = phones.find((p) => p.id === x.dev);
        const f = ((d.report || {}).approvedApps || []).find((y) => y.pkg === x.pkg);
        return { d, a: { pkg: x.pkg, label: (f && f.label) || x.pkg }, by: me.guardian.id };
      });
    }
    const listBox = h('div', {});
    const draw = (q) => {
      const items = rows.filter(({ a }) => `${a.label} ${a.pkg}`.toLowerCase().includes(q.toLowerCase()));
      const cut = items.slice(0, 150);
      listBox.replaceChildren(cut.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, cut.map(({ d, a, by }) => h('div', { class: 'li' },
        nameRow(a, d, by ? `aprovado por ${gname(by)}` : ''),
        h('button', { class: 'btn', type: 'button', onclick: act(() => confirmSend(d.id, 'revoke_app', { pkg: a.pkg }, { title: `Revogar “${a.label || a.pkg}” em ${d.name}?`,
          rows: [['Ação', 'Revogar aprovação'], ['Pacote', a.pkg]], effect: 'vale na hora', effectKind: 'ok', note: 'O app será suspenso.' }).then(() => route())) }, 'Revogar'))),
        items.length > cut.length ? h('p', { class: 'muted', style: 'margin:8px 0' }, `Mostrando ${cut.length} de ${items.length}. Use a busca.`) : null) :
        h('p', { class: 'empty' }, rows.length ? 'Nenhum app com esse nome.' : isAdmin() ? 'O aparelho ainda não enviou a lista.' : 'Você ainda não aprovou nenhum app.'));
    };
    draw('');
    body = [h('div', { class: 'pad', style: 'margin-top:12px' }, h('input', { class: 'inp', type: 'search', placeholder: 'Buscar app aprovado', 'aria-label': 'Buscar app aprovado', oninput: (e) => draw(e.target.value) })), listBox];
  } else if (tab === 'instalados') {
    // Tudo que se sabe de cada aparelho: a lista completa de instalados (quando o app a envia) mais aprovados, pendentes, recusados e vetados.
    // Aprovado, mas o aparelho já informa a lista completa e o pacote não está nela: foi desinstalado e a aprovação continua valendo.
    const gone = (d, pkg) => Array.isArray((d.report || {}).installedApps) && !d.report.installedApps.some((a) => a.pkg === pkg);
    const stateOf = (d, pkg) => ((d.vetoed || {})[pkg] ? (((d.report || {}).approvedApps || []).some((a) => a.pkg === pkg) ? 'vetoact' : 'veto')
      : ((d.report || {}).approvedApps || []).some((a) => a.pkg === pkg) ? (gone(d, pkg) ? 'gone' : 'ok') : (d.refusedApps || []).some((a) => a.pkg === pkg) ? 'refused'
      : ((d.report || {}).pendingApps || []).some((a) => a.pkg === pkg) ? 'pending' : 'inst');
    const rows = shown.flatMap((d) => {
      const m = new Map(), put = (a) => { if (a && a.pkg && !m.has(a.pkg)) m.set(a.pkg, { pkg: a.pkg, label: a.label || a.pkg }); };
      const rep = d.report || {};
      (rep.installedApps || []).forEach(put); (rep.approvedApps || []).forEach(put); (rep.pendingApps || []).forEach(put); (d.refusedApps || []).forEach(put);
      Object.entries(d.vetoed || {}).forEach(([pkg, v]) => put({ pkg, label: v.label }));
      return [...m.values()].map((a) => ({ d, a, st: stateOf(d, a.pkg) }));
    }).sort((x, y) => x.a.label.localeCompare(y.a.label, 'pt-BR') || x.d.name.localeCompare(y.d.name));
    const hasFull = shown.some((d) => Array.isArray((d.report || {}).installedApps));
    const STATES = { ok: ['aprovado', 'ok'], gone: ['desinstalado, ainda aprovado', 'warn'], pending: ['pendente', 'warn'], refused: ['recusado', ''], veto: ['vetado', 'bad'], vetoact: ['vetado, ainda ativo', 'bad'], inst: ['instalado', ''] };
    const keyOf = ({ d, a }) => `${d.id}|${a.pkg}`;
    const canVeto = (x) => x.st !== 'veto';
    const vis = () => { const q = appSearch.trim().toLowerCase();
      return rows.filter((x) => (!appState || x.st === appState || (appState === 'veto' && x.st === 'vetoact') || (appState === 'ok' && x.st === 'gone')) && (!q || `${x.a.label} ${x.a.pkg}`.toLowerCase().includes(q))); };
    const boxes = new Map(), allBox = h('input', { type: 'checkbox', class: 'chk', 'aria-label': 'Marcar todos' });
    const goBtn = h('button', { class: 'btn pri danger', type: 'button' }), list = h('div');
    const sync = () => {
      for (const [k, e] of boxes) e.checked = appSel.has(k);
      const pick = vis().filter(canVeto).map(keyOf);
      allBox.checked = pick.length > 0 && pick.every((k) => appSel.has(k));
      goBtn.textContent = appSel.size ? `Vetar ${appSel.size} marcado${appSel.size > 1 ? 's' : ''}` : 'Vetar marcados';
      goBtn.disabled = appSel.size === 0;
    };
    const draw = () => {
      boxes.clear();
      const v = vis(), cut = v.slice(0, 300);
      list.replaceChildren(cut.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, cut.map((x) => {
        const k = keyOf(x), [word, kind] = STATES[x.st];
        let e = h('span', { class: 'chk' });
        if (canVeto(x)) { e = h('input', { type: 'checkbox', class: 'chk', 'aria-label': `Marcar ${x.a.label}`, onchange: (ev) => { if (ev.target.checked) appSel.add(k); else appSel.delete(k); sync(); } }); boxes.set(k, e); }
        return h('div', { class: 'li' }, e, nameRow(x.a, x.d, ''), chip(word, kind));
      }), v.length > cut.length ? h('p', { class: 'muted', style: 'margin:8px 0' }, `Mostrando ${cut.length} de ${v.length}. Use a busca.`) : null) :
        h('p', { class: 'empty' }, rows.length ? 'Nenhum app com esses filtros.' : 'O aparelho ainda não enviou a lista.'));
      sync();
    };
    allBox.addEventListener('change', () => { const pick = vis().filter(canVeto).map(keyOf); if (allBox.checked) pick.forEach((k) => appSel.add(k)); else pick.forEach((k) => appSel.delete(k)); sync(); });
    goBtn.addEventListener('click', act(async () => {
      const chosen = rows.filter((x) => appSel.has(keyOf(x)));
      if (!chosen.length) return;
      const live = chosen.filter((x) => x.st === 'ok' || x.st === 'gone' || x.st === 'vetoact');  // aprovados: precisam da revogação assinada para suspender
      if (!(await sheet({ title: `Vetar ${chosen.length} app${chosen.length > 1 ? 's' : ''}?`,
        rows: chosen.slice(0, 8).map((x) => [x.d.name, x.a.label]).concat(chosen.length > 8 ? [['…', `mais ${chosen.length - 8}`]] : []),
        note: `Veto permanente: o app fica suspenso e ninguém o aprova nem o pede até você tirar o veto.${live.length ? ` ${live.length} já aprovado${live.length > 1 ? 's' : ''}: serão pedidos ${live.length} passkey${live.length > 1 ? 's' : ''} para revogar.` : ''}`,
        noteKind: 'warn', confirm: 'Vetar', danger: true }))) return;
      for (const dev of [...new Set(chosen.map((x) => x.d.id))]) {
        await api('POST', `/v1/devices/${dev}/apps/veto`, { apps: chosen.filter((x) => x.d.id === dev).map((x) => ({ pkg: x.a.pkg, label: x.a.label })) });
      }
      let failed = 0;
      for (const x of live) {
        try { await sendCommand(x.d.id, 'revoke_app', { pkg: x.a.pkg }); } catch (e) { failed += 1; }
      }
      appSel.clear();
      if (failed) toast(`${failed} revogaç${failed > 1 ? 'ões não foram' : 'ão não foi'} enviada${failed > 1 ? 's' : ''}: o app segue ativo no aparelho. Vete de novo para tentar outra vez.`);
      route();
    }));
    draw();
    body = [h('div', { class: 'pad', style: 'margin-top:12px' }, h('input', { class: 'inp', type: 'search', placeholder: 'Buscar app', 'aria-label': 'Buscar app', value: appSearch,
        autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', autocomplete: 'off', oninput: (e) => { appSearch = e.target.value; draw(); } })),
      pillGroup('Filtrar por situação', [['', 'Todos'], ['ok', 'Aprovados'], ['pending', 'Pendentes'], ['refused', 'Recusados'], ['veto', 'Vetados'], ['inst', 'Só instalados']], appState, (k) => { appState = k; route(); }),
      hasFull ? null : h('div', { class: 'note warn', style: 'margin:12px 0' }, 'O app do aparelho ainda não envia a lista completa de instalados: aparecem só os apps aprovados, pendentes, recusados e vetados.'),
      h('div', { class: 'card', style: 'margin:12px 0' }, h('div', { class: 'row', style: 'gap:10px' },
        h('label', { class: 'row grow', style: 'gap:10px;cursor:pointer' }, allBox, h('span', {}, 'Marcar todos os mostrados')), goBtn)), list];
  } else if (tab === 'vetados') {
    const rows = shown.flatMap((d) => Object.entries(d.vetoed || {}).map(([pkg, v]) => ({ d, a: { pkg, label: v.label || pkg }, by: v.by })));
    body = rows.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, rows.map(({ d, a, by }) => h('div', { class: 'li' },
      nameRow(a, d, by ? `vetado por ${gname(by)}` : ''),
      h('button', { class: 'btn', type: 'button', onclick: act(async () => {
        if (!(await sheet({ title: `Tirar o veto de “${a.label}” em ${d.name}?`, rows: [['Aparelho', d.name], ['Pacote', a.pkg]],
          note: 'O app continua suspenso, mas volta a poder ser pedido e aprovado.', confirm: 'Tirar veto' }))) return;
        await api('POST', `/v1/devices/${d.id}/apps/veto`, { apps: [{ pkg: a.pkg }], undo: true });
        route();
      }) }, 'Tirar veto')))) : empty('Nenhum app vetado.');
  } else {
    const rows = shown.flatMap((d) => (d.refusedApps || []).map((a) => ({ d, a, by: (d.refused_by || {})[a.pkg] })));
    body = rows.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, rows.map(({ d, a, by }) => h('div', { class: 'li' },
      nameRow(a, d, by ? `recusado por ${gname(by)}` : ''),
      h('button', { class: 'btn', type: 'button', onclick: refuse(d, a, true) }, 'Reconsiderar')))) : empty('Nenhum app recusado.');
  }
  show(top('Apps'), h('div', { class: 'wrap wide' }, segTabs(tabs, tab), filters, body));
  timer = setTimeout(autoRefresh, 20000);
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
        location.hash = '#/devices';
      }) }, 'Esquecer neste gateway'))];
}

// ---------- domínios ----------
let reqDev = '';             // filtro das solicitações: aparelho ('' = todos)
let domGuardian = '';        // filtro de Bloqueios e Liberados: guardião que liberou/bloqueou ('' = todos)
const reqLvl = new Map();   // Solicitações: quanto cada domínio foi encurtado («)
let reqTtl = 0;              // duração ao liberar pelas solicitações (0 = sempre)
let qryDev = '', qryState = '', qrySearch = '';   // Consultas: aparelho, resultado ('' tudo | 'ok' | 'blk') e pesquisa
const qrySel = new Set(), qryLvl = new Map();
let appState = '', appSearch = '';   // Apps > Instalados: situação e busca
const appSel = new Set();
let blkDev = '';             // filtro do log: aparelho ('' = todos)
let blkSrc = 'own';          // filtro do log: 'own' (regras próprias) | 'list' (listas) | '' (tudo)
let advOpen = false;         // seção Avançado de Liberados aberta
const blkSel = new Set(), blkLvl = new Map();    // domínios marcados na lista de bloqueios para liberar de uma vez
let blkTtl = 0;              // duração ao liberar direto pelo log (0 = sempre)
const TTL_CHOICES = [['always', 'Sempre', 0], ['3600', '1 h', 3600], ['86400', '1 dia', 86400], ['deny', 'Negar', null]];
const REQ_TTLS = [[0, 'Sempre'], [3600, '1 h'], [86400, '1 dia']];
const fmtWhen = (ts) => new Date(ts * 1000).toLocaleString('pt-BR', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit', hour12: false });

/** Domínios. Guardião-mor: Solicitações | Bloqueios | Liberados. Guardião: Solicitações | Liberados | Recusados (o que ele mesmo decidiu). */
async function domainsView(tab) {
  const { devices, now, reqs } = await loadAll();
  renderNav('domains');
  const ex = devices.find((x) => x.kind === 'executor');
  if (!ex) { show(top('Domínios'), h('div', { class: 'card' }, h('p', { style: 'margin:0 0 10px' }, 'Nenhum executor do Pi-hole pareado.'), h('a', { class: 'btn pri', href: '#/pair', style: 'display:inline-flex;align-items:center;text-decoration:none' }, 'Parear o executor'))); return; }
  const r = ex.report || {};
  const admin = isAdmin();
  const unb = reqs.filter((q) => q.kind === 'unblock');
  const otherReqs = reqs.filter((q) => q.kind !== 'unblock');
  tab = tab === 'pedidos' ? 'solicitacoes' : tab === 'meus' ? 'liberados' : tab;  // endereços antigos
  if (!(admin ? ['solicitacoes', 'bloqueios', 'consultas', 'liberados', 'vetos'] : ['solicitacoes', 'bloqueios', 'consultas', 'liberados', 'recusados']).includes(tab)) tab = admin && !reqs.length ? 'bloqueios' : 'solicitacoes';
  const devName = (id) => (devices.find((x) => x.id === id) || { name: id }).name;
  const protectedDevs = devices.filter((x) => x.kind === 'device');
  const temp = new Map((r.temp || []).map((t) => [`${t.list}:${t.domain}`, t.expires]));
  const entryOf = (dom) => (r.allow || []).find((a) => dom === a || dom.endsWith('.' + a));  // a regra cobre o domínio e os subdomínios
  const covers = (dom) => entryOf(dom) !== undefined;
  const coverBy = (dom) => { const e = entryOf(dom); return e !== undefined ? (r.allow_by || {})[e] : undefined; };
  const canary = canaryOf(devices);
  const guardianPills = Object.entries(me.trust || {}).length > 1 && admin ? [h('div', { class: 'sec' }, 'Guardião'),
    pillGroup('Filtrar por guardião', [['', 'Todos'], ...Object.entries(me.trust).map(([id, g]) => [id, g.name])], domGuardian, (k) => { domGuardian = k; route(); })] : null;
  if (domGuardian && !(me.trust || {})[domGuardian]) domGuardian = '';
  const send = (type, args, spec) => act(() => confirmSend(ex.id, type, args, spec).then((ok) => ok && route()));
  const veto = r.veto || {};
  const tabs = admin ? [['#/domains/solicitacoes', `Solicitações · ${reqs.length}`, 'solicitacoes'], ['#/domains/bloqueios', 'Bloqueios', 'bloqueios'], ['#/domains/consultas', 'Consultas', 'consultas'], ['#/domains/liberados', 'Liberados', 'liberados'],
    ['#/domains/vetos', veto.audit_total ? `Vetos · ${veto.audit_total}` : 'Vetos', 'vetos']] :
    [['#/domains/solicitacoes', `Solicitações · ${reqs.length}`, 'solicitacoes'], ['#/domains/bloqueios', 'Bloqueios', 'bloqueios'], ['#/domains/consultas', 'Consultas', 'consultas'], ['#/domains/liberados', 'Liberados', 'liberados'], ['#/domains/recusados', 'Recusados', 'recusados']];
  const flags = (x) => [x.domain.split('.').some((l) => l.startsWith('xn--')) ? chip('punycode: confira o nome', 'warn') : null,
    x.cname ? chip('via CNAME') : null,
    x.src === 'list' ? chip('lista de conteúdo adulto: confira antes de liberar', 'warn') : null,
    x.src === 'veto' ? chip('site vetado pelo mestre', 'bad') : null];
  const srcLabel = (b) => (b.src === 'own' ? 'regra própria' : b.src === 'veto' ? `vetado (${b.list})` : b.list || 'lista');
  const batchSpec = (items) => ({ title: `Liberar ${items.length} domínio${items.length > 1 ? 's' : ''}?`,
    rows: items.map((i) => [i.domain, i.ttl_s ? durLabel(i.ttl_s) : 'sem prazo']), effect: 'vale na hora', effectKind: 'ok',
    note: items.some((i) => !i.ttl_s) ? 'Sem prazo: o domínio fica liberado até alguém bloquear de novo. Vale para a casa toda, com os subdomínios.' : 'Vale para a casa toda, com os subdomínios.', noteKind: 'warn' });
  const empty = (text) => h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, text));
  const removeSpec = (name, x) => ({ title: name === 'allow' ? `Bloquear ${x} de novo?` : `Remover ${x} da lista de bloqueados?`,
    rows: [['Ação', name === 'allow' ? 'Bloquear de novo' : 'Remover domínio'], ['Domínio', x]], effect: 'vale na hora', effectKind: 'ok',
    note: name === 'allow' ? 'Volta a valer a regra do Pi-hole para este domínio.' : null });

  const atOf = (d) => (r.allow_at || {})[d] || 0;  // quando a liberação foi criada no Pi-hole (0 = sem data)
  // Lista de liberados: mais recentes primeiro, com data e hora, e uma pesquisa por domínio (também acha o pai que cobre o domínio digitado).
  const allowCard = (list, emptyText, withBy) => {
    const sorted = [...list].sort((a, b) => atOf(b) - atOf(a) || a.localeCompare(b));
    const by = r.allow_by || {};
    const box = h('div');
    const draw = () => {
      const q = search.value.trim().toLowerCase().replace(/^\.+/, '');
      const shown = q ? sorted.filter((x) => x.includes(q) || q.endsWith(`.${x}`)) : sorted;
      box.replaceChildren(shown.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, shown.map((x) => h('div', { class: 'li' },
        h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, x),
          h('div', { class: 'muted' }, atOf(x) ? `${fmtWhen(atOf(x))} · ${ago(atOf(x), now)}` : 'sem data', withBy && by[x] ? ` · liberado por ${gname(by[x])}` : '', ' ',
            temp.has(`allow:${x}`) ? chip(`expira ${fmtWhen(temp.get(`allow:${x}`))}`, 'warn') : chip('sem prazo'))),
        h('button', { class: 'btn', type: 'button', onclick: send('pihole_remove', { list: 'allow', domain: x }, removeSpec('allow', x)) }, 'Bloquear de novo')))) :
        empty(q ? 'Nenhum liberado combina com a pesquisa.' : emptyText));
    };
    const search = h('input', { class: 'inp', type: 'search', placeholder: 'Pesquisar domínio liberado', 'aria-label': 'Pesquisar domínio liberado', autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', autocomplete: 'off', oninput: draw });
    draw();
    return [h('div', { class: 'pad', style: 'margin:12px 0' }, search), box];
  };
  // Domínio de lista de conteúdo adulto: pede uma segunda confirmação do mesmo guardião, antes da folha de assinatura (individual ou em lote).
  const confirmAdult = async (domains, blockedItems) => {
    const adult = [...new Set(domains.filter((d) => blockedItems.some((b) => b.src === 'list' && (b.domain === d || b.domain.endsWith(`.${d}`)))))];
    if (!adult.length) return true;
    return sheet({ title: adult.length > 1 ? `${adult.length} domínios de lista de conteúdo adulto` : 'Domínio de lista de conteúdo adulto',
      rows: adult.slice(0, 8).map((d) => ['Domínio', d]).concat(adult.length > 8 ? [['…', `mais ${adult.length - 8}`]] : []),
      note: 'Estes domínios estão em lista de conteúdo adulto. Confirme de novo que quer liberar.', noteKind: 'warn', confirm: 'Sim, liberar mesmo', danger: true });
  };
  // Limpar o histórico que a tela mostra (Bloqueios ou Consultas), do aparelho filtrado ou de todos. Só o guardião-mor; não mexe no Pi-hole.
  const clearHist = (what, dev, devName_) => (admin ? h('div', { class: 'pad', style: 'margin:8px 0' }, h('button', { class: 'btn', type: 'button', onclick: act(async () => {
    if (!(await sheet({ title: what === 'blocked' ? 'Limpar o histórico de bloqueios?' : 'Limpar o histórico de consultas?',
      rows: [['O que', what === 'blocked' ? 'Bloqueios das últimas 24 h' : 'Consultas das últimas 24 h'], ['Aparelho', dev ? devName_ : 'todos']],
      note: 'Só zera o que esta tela mostra; não mexe em nenhuma regra do Pi-hole. A lista volta a encher com as próximas consultas.' + (what === 'blocked' ? ' Um aparelho só consegue pedir liberação de um domínio depois que ele for bloqueado de novo.' : ''),
      noteKind: 'warn', confirm: 'Limpar', danger: true }))) return;
    const r2 = await api('POST', '/v1/history/clear', { what, ...(dev ? { dev } : {}) });
    toast(`${r2.removed} linha${r2.removed === 1 ? '' : 's'} removida${r2.removed === 1 ? '' : 's'}.`);
    route();
  }) }, dev ? `Limpar histórico de ${devName_}` : 'Limpar histórico de todos')) : null);
  let body;
  if (tab === 'solicitacoes') {
    const blocked = unb.length ? (await api('GET', '/v1/blocked')).items : [];
    const info = new Map(blocked.map((b) => [`${b.dev}|${b.domain}`, b]));
    const all = unb.flatMap((q) => q.items.filter((i) => i.state === 'open').map((i) => ({ q, i })));
    if (reqDev && !protectedDevs.some((x) => x.id === reqDev)) reqDev = '';
    const shown = reqDev ? all.filter((x) => x.q.dev === reqDev) : all;
    const ttl = reqTtl ? { ttl_s: reqTtl } : {};
    const resolveAll = async (domains, cmd) => {  // fecha todas as solicitações abertas desses domínios (a liberação vale para a casa toda)
      const set = new Set(domains);
      for (const q of new Set(all.filter((x) => set.has(x.i.domain)).map((x) => x.q))) {
        await api('POST', `/v1/requests/${q.id}/resolve`, cmd ? { cmd, deny: [] } : { deny: all.filter((x) => x.q.id === q.id && set.has(x.i.domain)).map((x) => x.i.domain) });
      }
    };
    const optsOf = (d) => [d, ...parentsOf(d)];
    const eff = (d) => { const o = optsOf(d); return o[Math.min(reqLvl.get(d) || 0, o.length - 1)]; };  // o domínio como está encurtado na tela
    const nameEls = new Map();
    const syncNames = () => {
      for (const [d, r] of nameEls) {
        const o = optsOf(d), at = Math.min(reqLvl.get(d) || 0, o.length - 1);
        r.name.forEach((e) => { e.textContent = o[at]; });
        r.less.forEach((e) => { e.disabled = at >= o.length - 1; });
        r.more.forEach((e) => { e.disabled = at === 0; });
      }
    };
    const stepReq = (d, delta) => { reqLvl.set(d, Math.max(0, Math.min(optsOf(d).length - 1, (reqLvl.get(d) || 0) + delta))); syncNames(); };
    const stepBtn = (label, aria, fn) => h('button', { class: 'btn', type: 'button', 'aria-label': aria, style: 'padding:0 10px;min-width:40px', onclick: fn }, label);
    const releaseOne = (x) => act(async () => {
      const items = [{ domain: eff(x.i.domain), ...ttl }];
      if (!(await confirmAdult([items[0].domain], blocked))) return;
      const sent = await confirmSend(ex.id, 'pihole_batch', { items }, batchSpec(items));
      if (!sent) return;
      await resolveAll([x.i.domain], sent.id);
      route();
    });
    const refuseOne = (x) => act(async () => {
      await api('POST', `/v1/requests/${x.q.id}/resolve`, { deny: [x.i.domain] });  // recusar não solta nada: sem passkey
      route();
    });
    const doms = [...new Set(shown.map((x) => x.i.domain))];
    const releaseAll = act(async () => {  // um só comando (até 50 domínios) e um só passkey
      const first = doms.slice(0, 50);
      const items50 = [...new Set(first.map(eff))].map((domain) => ({ domain, ...ttl }));
      if (!(await confirmAdult(items50.map((x) => x.domain), blocked))) return;
      const sent = await confirmSend(ex.id, 'pihole_batch', { items: items50 }, batchSpec(items50));
      if (!sent) return;
      await resolveAll(first, sent.id);
      reqLvl.clear();
      route();
    });
    const refuseAll = act(async () => { await resolveAll(doms, null); route(); });
    setTimeout(syncNames, 0);  // as setas começam desativadas até o desenho terminar
    body = [phonesFilter(protectedDevs, reqDev, (k) => { reqDev = k; route(); }),
      h('div', { class: 'sec' }, 'Liberar por'), pillGroup('Duração da liberação', REQ_TTLS, reqTtl, (k) => { reqTtl = k; route(); }),
      doms.length > 1 ? h('div', { class: 'card', style: 'margin-top:12px' }, h('div', { class: 'row', style: 'gap:8px' },
        h('button', { class: 'btn grow', type: 'button', onclick: refuseAll }, `Recusar todos (${doms.length})`),
        h('button', { class: 'btn pri grow', type: 'button', onclick: releaseAll }, `Liberar todos (${doms.length}) com um passkey`)),
        h('div', { class: 'muted', style: 'margin-top:8px' }, 'A folha mostra tudo antes de assinar.' + (doms.length > 50 ? ' Só os 50 primeiros entram; os outros continuam pedindo.' : ''))) : null,
      h('div', { class: 'sec' }, `Solicitações · ${shown.length}`),
      shown.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, shown.map((x) => {
        const b = info.get(`${x.q.dev}|${x.i.domain}`);
        const d0 = x.i.domain, nm = h('span', { class: 'mono', style: 'font-weight:600' }, d0);
        const less = stepBtn('«', 'Encurtar um nível', () => stepReq(d0, 1)), more = stepBtn('»', 'Voltar um nível', () => stepReq(d0, -1));
        const nr = nameEls.get(d0) || { name: [], less: [], more: [] };
        nr.name.push(nm); nr.less.push(less); nr.more.push(more);
        nameEls.set(d0, nr);
        return h('div', { class: 'li', style: 'flex-wrap:wrap' },
          h('div', { class: 'sp' }, nm,
            h('div', { class: 'muted' }, `${devName(x.q.dev)} · ${b ? `${b.count} bloqueio${b.count > 1 ? 's' : ''} · ${srcLabel(b)}` : 'sem bloqueio recente'} · ${ago(x.q.ts, now)}`, ' ', flags(b || x.i))),
          h('div', { class: 'acts' }, h('button', { class: 'btn', type: 'button', onclick: refuseOne(x) }, 'Recusar'),
            parentsOf(d0).length ? [less, more] : null,
            h('button', { class: 'btn pri', type: 'button', onclick: releaseOne(x) }, 'Liberar')));
      })) : empty('Nenhuma solicitação de liberação.'),
      otherReqs.length ? [h('div', { class: 'sec' }, 'Outros pedidos'), otherReqs.map((q) => h('div', { class: 'card' }, h('div', { class: 'row' },
        h('div', { class: 'sp' }, h('strong', {}, q.text), h('div', { class: 'muted' }, `${q.kind} · ${devName(q.dev)} · ${ago(q.ts, now)}`)),
        h('button', { class: 'btn', type: 'button', onclick: act(async () => { await api('POST', `/v1/requests/${q.id}/dismiss`, {}); route(); }) }, 'Dispensar'))))] : null];
  } else if (tab === 'bloqueios') {
    const qs = new URLSearchParams();
    if (blkSrc) qs.set('src', blkSrc);
    const resp = await api('GET', '/v1/blocked' + (qs.toString() ? `?${qs}` : ''));
    const everyone = resp.items.filter((x) => !domGuardian || coverBy(x.domain) === domGuardian);  // com guardião escolhido: só o que ele liberou
    const netDevs = resp.net || [];  // clientes da rede que o Pi-hole vê e não são aparelhos protegidos: só para ver
    const nameOf = (id) => (netDevs.find((x) => x.id === id) || {}).name || devName(id);
    const perDev = new Map();  // quantos bloqueios cada aparelho tem com os filtros de origem e de guardião (o número ao lado do nome)
    everyone.forEach((x) => perDev.set(x.dev, (perDev.get(x.dev) || 0) + 1));
    if (blkDev && !protectedDevs.some((x) => x.id === blkDev) && !netDevs.some((x) => x.id === blkDev)) blkDev = '';
    const items = blkDev ? everyone.filter((x) => x.dev === blkDev) : everyone;
    const netPills = netDevs.filter((x) => perDev.get(x.id)).sort((a, b) => perDev.get(b.id) - perDev.get(a.id));  // os sem bloqueio aqui não entram na lista
    const pill = (label, on, fn) => h('button', { type: 'button', 'aria-pressed': String(on), onclick: fn }, label);
    const optsOf = (d) => [d, ...parentsOf(d)];
    const eff = (d) => { const o = optsOf(d); return o[Math.min(blkLvl.get(d) || 0, o.length - 1)]; };  // o domínio como está encurtado na tela
    const pickable = (d) => !covers(d) && !items.some((x) => x.domain === d && x.src === 'veto');  // o que já está liberado ou é vetado não se marca
    const origs = [...new Set(items.map((x) => x.domain).filter(pickable))];
    const pickNow = () => [...new Set(origs.map(eff))];
    [...blkSel].forEach((d) => { if (!pickNow().includes(d)) blkSel.delete(d); });
    const rowEls = [], allBox = h('input', { type: 'checkbox', class: 'chk', 'aria-label': 'Marcar todos' });
    const goBtn = h('button', { class: 'btn pri', type: 'button' });
    const sync = () => {  // atualiza as caixas, os nomes e o botão sem redesenhar a tela (a rolagem fica onde está)
      for (const r of rowEls) {
        const o = optsOf(r.d), at = Math.min(blkLvl.get(r.d) || 0, o.length - 1);
        r.name.textContent = o[at];
        if (r.box) r.box.checked = blkSel.has(o[at]);
        r.less.disabled = at >= o.length - 1;
        r.more.disabled = at === 0;
      }
      const pick = pickNow();
      allBox.checked = pick.length > 0 && pick.every((d) => blkSel.has(d));
      goBtn.textContent = blkSel.size ? `Liberar ${blkSel.size} marcado${blkSel.size > 1 ? 's' : ''}` : 'Liberar marcados';
      goBtn.disabled = blkSel.size === 0;
    };
    const step = (d, delta) => {  // « encurta um nível, » devolve um; a marcação acompanha o nome
      const old = eff(d), was = blkSel.has(old);
      blkLvl.set(d, Math.max(0, Math.min(optsOf(d).length - 1, (blkLvl.get(d) || 0) + delta)));
      if (was) { blkSel.delete(old); blkSel.add(eff(d)); }
      sync();
    };
    const checkFor = (d) => h('input', { type: 'checkbox', class: 'chk', 'aria-label': `Marcar ${d}`, onchange: (ev) => { const e = eff(d); if (ev.target.checked) blkSel.add(e); else blkSel.delete(e); sync(); } });
    allBox.addEventListener('change', () => { if (allBox.checked) pickNow().forEach((d) => blkSel.add(d)); else pickNow().forEach((d) => blkSel.delete(d)); sync(); });
    goBtn.addEventListener('click', act(async () => {  // um só comando (até 50 domínios) e um só passkey
      const its = [...blkSel].slice(0, 50).map((domain) => ({ domain, ...(blkTtl ? { ttl_s: blkTtl } : {}) }));
      if (!its.length) return;
      if (!(await confirmAdult(its.map((x) => x.domain), everyone))) return;
      const sent = await confirmSend(ex.id, 'pihole_batch', { items: its }, batchSpec(its));
      if (!sent) return;
      blkSel.clear();
      blkLvl.clear();
      route();
    }));
    const stepBtn = (label, aria, fn) => h('button', { class: 'btn', type: 'button', 'aria-label': aria, style: 'padding:0 10px;min-width:40px', onclick: fn }, label);
    const blockRow = (x) => {
      const ok = pickable(x.domain);
      const r = { d: x.domain, box: ok ? checkFor(x.domain) : null, name: h('span', { class: 'mono', style: 'font-weight:600' }, x.domain) };
      r.less = stepBtn('«', 'Encurtar um nível', () => step(x.domain, 1));
      r.more = stepBtn('»', 'Voltar um nível', () => step(x.domain, -1));
      rowEls.push(r);
      return h('div', { class: 'li' }, r.box || h('span', { class: 'chk' }),
        h('div', { class: 'sp' }, r.name,
          h('div', { class: 'muted' }, `${nameOf(x.dev)} · ${x.count} vez${x.count > 1 ? 'es' : ''} · ${ago(x.last, now)} · ${srcLabel(x)}`, ' ', flags(x))),
        covers(x.domain) ? chip(coverBy(x.domain) ? `liberado por ${gname(coverBy(x.domain))}` : 'liberado', 'ok') : x.src === 'veto' ? null : h('div', { class: 'acts' },
          parentsOf(x.domain).length ? [r.less, r.more] : null,
          h('button', { class: 'btn', type: 'button', onclick: act(async () => {
            const its = [{ domain: eff(x.domain), ...(blkTtl ? { ttl_s: blkTtl } : {}) }];
            if (!(await confirmAdult([its[0].domain], everyone))) return;
            if (await confirmSend(ex.id, 'pihole_batch', { items: its }, batchSpec(its))) { blkLvl.delete(x.domain); route(); }
          }) }, 'Liberar')));
    };
    const selectBar = origs.length ? h('div', { class: 'card', style: 'margin-bottom:12px' }, h('div', { class: 'row', style: 'gap:10px' },
      h('label', { class: 'row grow', style: 'gap:10px;cursor:pointer' }, allBox, h('span', {}, `Marcar todos (${pickNow().length})`)), goBtn),
      pickNow().length > 50 ? h('div', { class: 'muted', style: 'margin-top:8px' }, 'Cada liberação leva até 50 domínios; os outros continuam marcados para a próxima.') : null) : null;
    setTimeout(sync, 0);
    body = [h('div', { class: 'sec' }, 'Aparelho'),
      pillGroup('Filtrar por aparelho', [['', `Todos · ${everyone.length}`], ...protectedDevs.map((x) => [x.id, `${x.name} · ${perDev.get(x.id) || 0}`])], blkDev, (k) => { blkDev = k; route(); }),
      netPills.length ? [h('div', { class: 'sec' }, 'Outros da rede'),
        pillGroup('Filtrar por cliente da rede', netPills.map((x) => [x.id, `${x.name === x.ip ? x.ip : `${x.name} (${x.ip})`} · ${perDev.get(x.id)}`]), blkDev, (k) => { blkDev = k; route(); })] : null,
      h('div', { class: 'sec' }, 'Quem bloqueou'),
      pillGroup('Filtrar por origem', [['own', 'Regras próprias'], ['list', 'Listas'], ['veto', 'Vetados'], ['', 'Tudo']], blkSrc, (k) => { blkSrc = k; route(); }),
      guardianPills,
      h('div', { class: 'sec' }, 'Liberar direto por'),
      h('div', { class: 'durs', style: 'padding:0 14px', role: 'group', 'aria-label': 'Duração da liberação' },
        TTL_CHOICES.filter((c) => c[2] !== null).map(([, label, s]) => pill(label, blkTtl === s, () => { blkTtl = s; route(); }))),
      h('div', { class: 'sec' }, 'Últimas 24 horas'),
      clearHist('blocked', blkDev, nameOf(blkDev)),
      selectBar, items.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, items.map(blockRow)) : empty('Nada bloqueado com esses filtros.')];
  } else if (tab === 'consultas') {
    const resp = await api('GET', '/v1/queried');
    const netDevs = resp.net || [];
    const nameOf = (id) => (netDevs.find((x) => x.id === id) || {}).name || devName(id);
    const all = resp.items;
    if (qryDev && !protectedDevs.some((x) => x.id === qryDev) && !netDevs.some((x) => x.id === qryDev)) qryDev = '';
    const perDev = new Map();
    all.forEach((x) => perDev.set(x.dev, (perDev.get(x.dev) || 0) + 1));
    const netPills = netDevs.filter((x) => perDev.get(x.id)).sort((a, b) => perDev.get(b.id) - perDev.get(a.id));
    const denyBy = r.deny_by || {};
    const stateOf = (x) => (x.blocked === 0 ? 'ok' : x.blocked >= x.count ? 'blk' : 'mix');
    const visible = () => {
      const q = qrySearch.trim().toLowerCase();
      return all.filter((x) => (!qryDev || x.dev === qryDev) && (!qryState || stateOf(x) === qryState || (qryState === 'blk' && stateOf(x) === 'mix')) && (!q || x.domain.includes(q)));
    };
    const optsOf = (d) => [d, ...parentsOf(d)];
    const eff = (d) => { const o = optsOf(d); return o[Math.min(qryLvl.get(d) || 0, o.length - 1)]; };  // o domínio como está encurtado na tela
    const boxes = new Map(), names = new Map(), allBox = h('input', { type: 'checkbox', class: 'chk', 'aria-label': 'Marcar todos' });
    const relBtn = h('button', { class: 'btn pri', type: 'button' }), blkBtn = h('button', { class: 'btn', type: 'button' });
    const box = h('div');
    const shownDomains = () => [...new Set(visible().map((x) => eff(x.domain)))];
    const sync = () => {
      for (const [d, r] of names) {
        const o = optsOf(d), at = Math.min(qryLvl.get(d) || 0, o.length - 1);
        r.name.forEach((e) => { e.textContent = o[at]; });
        r.box.forEach((e) => { e.checked = qrySel.has(o[at]); });
        r.less.forEach((e) => { e.disabled = at >= o.length - 1; });
        r.more.forEach((e) => { e.disabled = at === 0; });
      }
      const sh = shownDomains();
      allBox.checked = sh.length > 0 && sh.every((d) => qrySel.has(d));
      relBtn.textContent = qrySel.size ? `Liberar ${qrySel.size}` : 'Liberar marcados';
      blkBtn.textContent = qrySel.size ? `Bloquear ${qrySel.size}` : 'Bloquear marcados';
      relBtn.disabled = blkBtn.disabled = qrySel.size === 0;
    };
    const step = (d, delta) => {  // « encurta um nível, » devolve um; a marcação acompanha o nome
      const old = eff(d), was = qrySel.has(old);
      qryLvl.set(d, Math.max(0, Math.min(optsOf(d).length - 1, (qryLvl.get(d) || 0) + delta)));
      if (was) { qrySel.delete(old); qrySel.add(eff(d)); }
      sync();
    };
    const stepBtn = (label, aria, fn) => h('button', { class: 'btn', type: 'button', 'aria-label': aria, style: 'padding:0 10px;min-width:40px', onclick: fn }, label);
    const draw = () => {
      names.clear();
      const rows = visible();
      box.replaceChildren(rows.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, rows.slice(0, 400).map((x) => {
        const st = stateOf(x), d = x.domain;
        const e = h('input', { type: 'checkbox', class: 'chk', 'aria-label': `Marcar ${d}`, onchange: (ev) => { const n = eff(d); if (ev.target.checked) qrySel.add(n); else qrySel.delete(n); sync(); } });
        const nm = h('span', { class: 'mono', style: 'font-weight:600' }, d);
        const less = stepBtn('«', 'Encurtar um nível', () => step(d, 1)), more = stepBtn('»', 'Voltar um nível', () => step(d, -1));
        const r = names.get(d) || { name: [], box: [], less: [], more: [] };
        r.name.push(nm); r.box.push(e); r.less.push(less); r.more.push(more);
        names.set(d, r);
        return h('div', { class: 'li' }, e,
          h('div', { class: 'sp' }, nm,
            h('div', { class: 'muted' }, `${nameOf(x.dev)} · ${x.count} vez${x.count > 1 ? 'es' : ''} · ${ago(x.last, now)}`, ' ',
              st === 'ok' ? chip('permitido', 'ok') : st === 'blk' ? chip('bloqueado', 'bad') : chip(`${x.blocked} de ${x.count} bloqueadas`, 'warn'),
              covers(d) ? chip(coverBy(d) ? `liberado por ${gname(coverBy(d))}` : 'liberado', 'ok') : null,
              denyBy[d] ? chip(`bloqueado por ${gname(denyBy[d])}`, 'bad') : null)),
          parentsOf(d).length ? h('div', { class: 'acts' }, less, more) : null);
      })) : empty('Nenhuma consulta com esses filtros.'));
      if (rows.length > 400) box.append(h('div', { class: 'muted pad' }, `Mostrando 400 de ${rows.length}. Use a pesquisa para achar o resto.`));
      sync();
    };
    allBox.addEventListener('change', () => { const sh = shownDomains(); if (allBox.checked) sh.forEach((d) => qrySel.add(d)); else sh.forEach((d) => qrySel.delete(d)); sync(); });
    const denySpec = (its) => ({ title: `Bloquear ${its.length} domínio${its.length > 1 ? 's' : ''}?`, rows: its.map((i) => [i.domain, 'bloquear']),
      effect: 'vale na hora', effectKind: 'ok', note: 'Vale para a casa toda, com os subdomínios. Tira da lista de liberados, se estiver lá.', noteKind: 'warn', danger: true, confirm: 'Bloquear com passkey' });
    const doBatch = (deny) => act(async () => {  // um só comando (até 50 domínios) e um só passkey
      const its = [...qrySel].slice(0, 50).map((domain) => (deny ? { domain, deny: true } : { domain, ...(blkTtl ? { ttl_s: blkTtl } : {}) }));
      if (!its.length) return;
      if (!deny) {
        const listed = (await api('GET', '/v1/blocked?src=list')).items;
        if (!(await confirmAdult(its.map((x) => x.domain), listed))) return;
      }
      const sent = await confirmSend(ex.id, 'pihole_batch', { items: its }, deny ? denySpec(its) : batchSpec(its));
      if (!sent) return;
      qrySel.clear();
      qryLvl.clear();
      route();
    });
    relBtn.addEventListener('click', doBatch(false));
    blkBtn.addEventListener('click', doBatch(true));
    const search = h('input', { class: 'inp', type: 'search', placeholder: 'Pesquisar domínio consultado', 'aria-label': 'Pesquisar domínio consultado', value: qrySearch,
      autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', autocomplete: 'off', oninput: () => { qrySearch = search.value; draw(); } });
    draw();
    body = [h('div', { class: 'sec' }, 'Aparelho'),
      pillGroup('Filtrar por aparelho', [['', `Todos · ${all.length}`], ...protectedDevs.map((x) => [x.id, `${x.name} · ${perDev.get(x.id) || 0}`])], qryDev, (k) => { qryDev = k; route(); }),
      netPills.length ? [h('div', { class: 'sec' }, 'Outros da rede'),
        pillGroup('Filtrar por cliente da rede', netPills.map((x) => [x.id, `${x.name === x.ip ? x.ip : `${x.name} (${x.ip})`} · ${perDev.get(x.id)}`]), qryDev, (k) => { qryDev = k; route(); })] : null,
      h('div', { class: 'sec' }, 'Resultado'),
      pillGroup('Filtrar por resultado', [['', 'Tudo'], ['ok', 'Permitidos'], ['blk', 'Bloqueados']], qryState, (k) => { qryState = k; route(); }),
      h('div', { class: 'sec' }, 'Liberar por'),
      h('div', { class: 'durs', style: 'padding:0 14px', role: 'group', 'aria-label': 'Duração da liberação' },
        TTL_CHOICES.filter((c) => c[2] !== null).map(([, label, sec]) => h('button', { type: 'button', 'aria-pressed': String(blkTtl === sec), onclick: () => { blkTtl = sec; route(); } }, label))),
      h('div', { class: 'sec' }, 'Últimas 24 horas'),
      clearHist('queried', qryDev, nameOf(qryDev)),
      h('div', { class: 'pad', style: 'margin:12px 0' }, search),
      h('div', { class: 'card', style: 'margin-bottom:12px' }, h('div', { class: 'row', style: 'gap:10px' },
        h('label', { class: 'row grow', style: 'gap:10px;cursor:pointer' }, allBox, h('span', {}, 'Marcar todos os mostrados')), relBtn, blkBtn),
        h('div', { class: 'muted', style: 'margin-top:8px' }, 'Cada ação leva até 50 domínios e um só passkey. Vale para a casa toda.')),
      box];
  } else if (tab === 'liberados' && !admin) {
    const myId = me.guardian.id;
    const by = r.allow_by || {};
    const mine = (r.allow || []).filter((d) => by[d] === myId);
    body = [h('div', { class: 'sec' }, `Liberei · ${mine.length}`), allowCard(mine, 'Você ainda não liberou nada.', false)];
  } else if (tab === 'recusados') {
    const dec = await api('GET', '/v1/my/decisions');
    const openDomains = new Set(unb.flatMap((q) => q.items.filter((i) => i.state === 'open').map((i) => i.domain)));
    const denied = dec.denied.filter((x) => !covers(x.domain) && !openDomains.has(x.domain));
    body = [h('div', { class: 'sec' }, `Recusei · ${denied.length}`),
      denied.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, denied.map((x) => h('div', { class: 'li' },
        h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, x.domain), h('div', { class: 'muted' }, `${devName(x.dev)} · ${ago(x.ts, now)}`)),
        h('button', { class: 'btn pri', type: 'button', onclick: act(async () => {
          if (!(await confirmAdult([x.domain], (await api('GET', '/v1/blocked?src=list')).items))) return;
          if (await confirmSend(ex.id, 'pihole_batch', { items: [{ domain: x.domain }] }, batchSpec([{ domain: x.domain }]))) route();
        }) }, 'Liberar')))) : empty('Nada recusado nos últimos dias.')];
  } else if (tab === 'vetos') {
    const parents = veto.parents || [], audit = veto.audit || [], master = isMaster();
    const pdom = h('textarea', { class: 'ta', rows: '3', placeholder: 'reddit.com, x.com, discord.com (um ou vários, separados por espaço, vírgula ou linha)', autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Sites para vetar' });
    const parentSpec = (add, list) => {
      const one = list.length === 1 ? list[0] : '';
      return { title: add ? (one ? `Vetar ${one}?` : `Vetar ${list.length} sites?`) : (one ? `Tirar o veto de ${one}?` : `Tirar o veto de ${list.length} sites?`),
        rows: list.length > 6 ? [['Sites', String(list.length)], ['Primeiros', list.slice(0, 6).join(', ') + '…'], ['Ação', add ? 'Vetar os sites' : 'Tirar o veto']] : [...list.map((p) => ['Site', p]), ['Ação', add ? 'Vetar os sites' : 'Tirar o veto']],
        effect: 'vale na hora', effectKind: add ? 'warn' : 'ok',
        note: add ? 'Ninguém libera estes sites nem o que está abaixo deles (como www. e outros subdomínios). Liberações que já existem continuam até você bloquear de novo.' : 'Os guardiões voltam a poder liberar.' };
    };
    body = [
      veto.on === false ? h('div', { class: 'note bad' }, 'O veto das listas de conteúdo adulto está desligado: o executor não lê o gravity.db do Pi-hole.') : null,
      // O campo para vetar fica no topo; a lista de vetados e o histórico (liberações em conflito) ficam embaixo.
      master ? [h('div', { class: 'sec' }, 'Vetar sites'),
        h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0 0 8px' }, 'Sites grandes e abertos, como reddit.com, x.com e tumblr.com, que ninguém pode liberar nem pelo pai nem por subdomínio. Vale para todos os guardiões.'),
          pdom, h('div', { class: 'row', style: 'margin-top:10px' }, h('button', { class: 'btn pri', type: 'button', onclick: act(async () => {
            const list = [...new Set(pdom.value.toLowerCase().split(/[\s,;]+/).filter(Boolean))];
            if (!list.length) throw new Error('Digite o site.');
            if (list.length > 80) throw new Error('No máximo 80 sites por vez.');
            if (await confirmSend(ex.id, 'pihole_parent_block', { action: 'add', domains: list }, parentSpec(true, list))) route();
          }) }, 'Vetar')))] :
        [h('div', { class: 'sec' }, 'Vetar sites'), h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Só o guardião-mestre veta ou tira o veto de um site.'))],
      h('div', { class: 'sec' }, `Sites vetados · ${parents.length}`),
      parents.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, parents.map((p) => h('div', { class: 'li' }, h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, p)),
        master ? h('button', { class: 'btn', type: 'button', onclick: send('pihole_parent_block', { action: 'remove', domains: [p] }, parentSpec(false, [p])) }, 'Tirar veto') : null))) :
        empty('Nenhum site vetado.'),
      h('div', { class: 'sec' }, `Liberações vetadas hoje · ${veto.audit_total || 0}`),
      audit.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, audit.map((x) => h('div', { class: 'li' },
        h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, x.domain), h('div', { class: 'muted' }, x.why, x.by ? ` · liberado por ${gname(x.by)}` : '')),
        h('button', { class: 'btn', type: 'button', onclick: send('pihole_remove', { list: 'allow', domain: x.domain }, removeSpec('allow', x.domain)) }, 'Bloquear de novo')))) :
        empty('Nenhuma liberação em conflito com as listas de conteúdo adulto.'),
      h('p', { class: 'muted', style: 'margin:8px 14px 0' }, `As listas de conteúdo adulto têm ${veto.listed || 0} domínios. Uma liberação que passa a cair nelas (a lista muda todo dia) aparece aqui e continua valendo até você bloquear de novo. Regras escritas à mão no Pi-hole não entram nesta conferência.`)];
  } else {
    const by = r.allow_by || {};
    const mine = (r.allow || []).filter((d) => by[d] !== undefined && (!domGuardian || by[d] === domGuardian));
    const others = (r.allow_total || (r.allow || []).length) - (r.allow || []).filter((d) => by[d] !== undefined).length;
    const denyBy = r.deny_by || {};
    const denyMine = (r.deny || []).filter((d) => denyBy[d] !== undefined && (!domGuardian || denyBy[d] === domGuardian));
    const denyOthers = (r.deny_total || (r.deny || []).length) - denyMine.length;
    const listCard = (name, list) => list.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, list.map((x) => h('div', { class: 'li' },
      h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, x),
        h('div', { class: 'muted' }, name === 'allow' && by[x] ? `liberado por ${gname(by[x])}` : name === 'deny' && denyBy[x] ? `bloqueado por ${gname(denyBy[x])}` : '', ' ',
          temp.has(`${name}:${x}`) ? chip(`expira ${fmtWhen(temp.get(`${name}:${x}`))}`, 'warn') : name === 'allow' ? chip('sem prazo') : null)),
      h('button', { class: 'btn', type: 'button', onclick: send('pihole_remove', { list: name, domain: x }, removeSpec(name, x)) }, name === 'allow' ? 'Bloquear de novo' : 'Remover')))) :
      empty('Vazio.');
    const dom = h('input', { class: 'inp', type: 'text', inputmode: 'url', placeholder: 'exemplo.com (domínio exato)', autocapitalize: 'none', autocorrect: 'off', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Domínio' });
    const args = () => ({ domain: dom.value.trim().toLowerCase(), ...(domDur ? { ttl_s: domDur } : {}) });
    const need = (fn) => act(async () => { if (!dom.value.trim()) throw new Error('Digite o domínio.'); await fn(); });
    const durBtns = [3600, 86400, 604800, 0].map((s) => h('button', { type: 'button', 'aria-pressed': String(domDur === s), onclick: () => { domDur = s; route(); } }, durLabel(s)));
    body = [guardianPills, allowCard(mine, 'Vazio.', true),
      others ? h('p', { class: 'muted', style: 'margin:8px 14px 0' }, `Mais ${others} entrada${others > 1 ? 's' : ''} criada${others > 1 ? 's' : ''} direto no Pi-hole. Elas não aparecem nem são alteradas aqui.`) : null,
      // Corrigir um bloqueio indevido (inclusive de lista): digitar o domínio e liberar, sem esperar pedido. Fica à vista, não escondido.
      h('div', { class: 'sec' }, 'Liberar ou bloquear um domínio à mão'),
      h('div', { class: 'card' },
        h('p', { class: 'muted', style: 'margin:0 0 8px' }, 'Para corrigir um bloqueio indevido, inclusive de listas de bloqueio, que ninguém consegue pedir: digite o domínio e libere. Só domínio exato.'),
        h('div', { class: 'row', style: 'gap:8px' }, h('span', { class: 'ib', style: 'width:24px;height:24px;color:var(--muted)' }, icon('search', 20)), h('div', { style: 'flex:1' }, dom)),
        h('div', { class: 'durs', role: 'group', 'aria-label': 'Duração' }, durBtns),
        h('div', { class: 'row', style: 'margin-top:12px' },
          h('button', { class: 'btn grow', type: 'button', onclick: need(() => confirmSend(ex.id, 'pihole_deny', args(), { title: `Bloquear ${args().domain} ${domDur ? `por ${durLabel(domDur)}` : ''}?`,
            rows: [['Ação', 'Bloquear domínio'], ['Domínio', args().domain], ['Duração', durLabel(domDur)]], effect: 'vale na hora', effectKind: 'ok' }).then((ok) => ok && route())) }, 'Bloquear'),
          h('button', { class: 'btn pri grow', type: 'button', onclick: need(async () => {
            if (!(await confirmAdult([args().domain], (await api('GET', '/v1/blocked?src=list')).items))) return;
            if (await confirmSend(ex.id, 'pihole_allow', args(), batchSpec([{ domain: args().domain, ttl_s: domDur }]))) route();
          }) }, 'Liberar')),
        h('p', { class: 'muted', style: 'margin:10px 0 0' }, 'Curinga e regex ficam de fora desta versão.')),
      h('details', { class: 'card flat', style: 'margin-top:12px', open: advOpen, ontoggle: (e) => { advOpen = e.target.open; } }, h('summary', { style: 'cursor:pointer;font-weight:600' }, 'Avançado: bloqueados pelo guardião'),
        h('div', { class: 'sec', style: 'padding-left:0' }, `Bloqueados pelo guardião · ${denyMine.length}`), listCard('deny', denyMine),
        denyOthers ? h('p', { class: 'muted', style: 'margin:8px 0 0' }, `Mais ${denyOthers} bloqueio${denyOthers > 1 ? 's' : ''} criado${denyOthers > 1 ? 's' : ''} direto no Pi-hole.`) : null),
      canary ? h('div', { class: 'card flat' }, h('div', { class: 'row' }, h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, canary),
        h('div', { class: 'muted' }, 'Domínio-canário · protegido: não pode ser liberado, bloqueado nem removido por aqui')), chip('protegido'))) : null];
  }
  show(top('Domínios', { actions: chip(r.pihole_ok === false ? 'Pi-hole inacessível' : 'Pi-hole ok', r.pihole_ok === false ? 'bad' : 'ok') }),
    h('div', { class: 'wrap wide' }, segTabs(tabs, tab), body));
  timer = setTimeout(autoRefresh, 20000);
}

/** Filtro por aparelho (some quando há um só). */
function phonesFilter(phones, current, onPick) {
  if (phones.length < 2) return null;
  return [h('div', { class: 'sec' }, 'Aparelho'), pillGroup('Filtrar por aparelho', [['', 'Todos'], ...phones.map((x) => [x.id, x.name])], current, onPick)];
}

// ---------- computador (agente do Windows) ----------
// Padrões das aprovações do computador: ficam neste navegador (só o aprovador usa) e o que vale é o que vai assinado no comando.
const WIN_DEFAULTS = { hours: 24, install_s: 600, idle_s: 120, run_s: 600 };
const WIN_CHOICES = {
  hours: ['Vale por', [[1, '1 h'], [6, '6 h'], [24, '24 h'], [72, '3 dias'], [168, '7 dias']]],
  install_s: ['Tempo limite da instalação', [[300, '5 min'], [600, '10 min'], [1200, '20 min'], [1800, '30 min'], [3600, '1 h']]],
  idle_s: ['Desistir se parar', [[60, '1 min'], [120, '2 min'], [300, '5 min'], [600, '10 min'], [0, 'nunca']]],
  run_s: ['Tempo limite de scripts', [[60, '1 min'], [300, '5 min'], [600, '10 min'], [1800, '30 min'], [3600, '1 h']]],
};
const winCfg = () => {
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem('winCfg') || '{}'); } catch (e) { /* sem armazenamento: usa os padrões */ }
  return Object.fromEntries(Object.keys(WIN_DEFAULTS).map((k) => [k, WIN_CHOICES[k][1].some((c) => c[0] === saved[k]) ? saved[k] : WIN_DEFAULTS[k]]));
};
const setWinCfg = (k, v) => { try { localStorage.setItem('winCfg', JSON.stringify({ ...winCfg(), [k]: v })); } catch (e) { /* sem armazenamento */ } };
const hoursLabel = (hrs) => (hrs % 24 === 0 && hrs >= 48 ? `${hrs / 24} dias` : `${hrs} h`);
// o que o pedido não traz, o aprovador completa com os padrões; o gateway só exige que o comando assinado contenha o pedido
function winArgs(p) {
  const c = winCfg();
  const extra = isRun(p) ? { timeout_s: p.timeout_s || c.run_s } : { timeout_s: p.timeout_s || c.install_s, ...(p.source !== 'winget' && p.kind !== 'msi' ? { idle_s: p.idle_s ?? c.idle_s } : {}) };
  return { ...p, ...extra, not_after: Math.floor(Date.now() / 1000) + c.hours * 3600 };   // o comando deixa de valer sozinho
}
const winType = (kind) => (kind === 'install' ? 'win_install' : 'win_run');
const isRun = (p) => p.script !== undefined;
const winDetail = (p) => (isRun(p) ? p.script : p.source === 'file' ? `Arquivo no computador: ${p.path}\nSHA-256: ${p.sha256}\nAssinatura digital exigida: ${p.publisher || '(nenhuma: só o hash vale)'}\nTipo: ${p.kind}${p.args ? `\nArgumentos: ${p.args}` : ''}` : p.source === 'url' ? `Endereço: ${p.url}\nSHA-256: ${p.sha256}\nTipo: ${p.kind}${p.args ? `\nArgumentos: ${p.args}` : ''}` :
  `winget install --id ${p.id}${p.version ? ` --version ${p.version}` : ''} --exact --silent`);
function winSpec(pcName, p) {
  return { title: isRun(p) ? `Rodar este script em ${pcName}?` : `Instalar ${p.name} em ${pcName}?`,
    rows: [['Computador', pcName], ['Ação', isRun(p) ? 'Rodar como administrador' : 'Instalar como administrador'],
      ['Tempo limite', `${winArgs(p).timeout_s / 60} min`],
      ...(isRun(p) ? [] : [['Origem', p.source === 'winget' ? 'winget' : p.source === 'file' ? 'arquivo já baixado no computador' : 'instalador por link']]),
      ...(winArgs(p).idle_s !== undefined ? [['Desiste se parar', winArgs(p).idle_s ? `${winArgs(p).idle_s / 60} min` : 'nunca']] : [])],
    effect: `executa em até ${hoursLabel(winCfg().hours)}, senão vence`, effectKind: 'warn', detail: winDetail(p), confirm: 'Assinar e aprovar', danger: true,
    note: 'Roda como administrador no computador, uma vez. Leia o texto acima por inteiro: o que você assina é exatamente isto.' };
}

async function pcView() {
  me = await api('GET', '/v1/me');
  const { devices, now, pcReqs } = await loadAll();
  renderNav('pc');
  const ai = new Map(((await api('GET', '/v1/analyses').catch(() => ({ items: [] }))).items || []).map((x) => [`${x.dev}|${x.ctr}`, x]));   // análises por IA (só leitura)
  const pcs = devices.filter((d) => d.kind === 'device' && d.report && d.report.platform === 'windows');
  const nameOf = (id) => (devices.find((x) => x.id === id) || { name: id }).name;
  const approve = (q) => act(async () => {
    if (!(await sheet(winSpec(nameOf(q.dev), q.payload)))) return;
    const res = await sendCommand(q.dev, winType(q.kind), winArgs(q.payload));   // o gateway confere que o comando assinado é exatamente o pedido
    await api('POST', `/v1/requests/${q.id}/resolve`, { cmd: res.id });
    toast('Aprovado. O computador executa em instantes.');
    route();
  });
  const deny = (q) => act(async () => { await api('POST', `/v1/requests/${q.id}/dismiss`, {}); toast('Pedido negado.'); route(); });
  const direct = (dev, p) => act(async () => {
    if (!dev) throw new Error('Escolha o computador.');
    if (!(await sheet(winSpec(nameOf(dev), p)))) return;
    await sendCommand(dev, isRun(p) ? 'win_run' : 'win_install', winArgs(p));
    route();
  });
  const mk = (ph, label) => h('input', { class: 'inp', type: 'text', placeholder: ph, 'aria-label': label, autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' });
  const sel = h('select', { class: 'sel', 'aria-label': 'Computador' }, pcs.map((d) => h('option', { value: d.id }, d.name)));
  const wName = mk('Nome (ex.: Git)', 'Nome do programa'), wId = mk('Id do winget (ex.: Git.Git)', 'Id do winget'), wVer = mk('Versão (opcional)', 'Versão');
  const sName = mk('O que o script faz', 'Descrição'), sBody = h('textarea', { class: 'ta', rows: '6', placeholder: 'Write-Output "olá"', spellcheck: 'false', 'aria-label': 'Script do PowerShell' });
  const reqCard = (q) => h('div', { class: 'card warnb' },
    h('div', { class: 'row', style: 'align-items:flex-start;gap:12px' }, insignia('device', 40), h('div', { class: 'sp' }, h('strong', {}, q.text), h('div', { class: 'muted' }, `${nameOf(q.dev)} · ${ago(q.ts, now)}`))),
    h('pre', { class: 'detail inline' }, winDetail(q.payload)),
    h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { class: 'btn dangero', type: 'button', onclick: deny(q) }, 'Negar'), h('button', { class: 'btn pri grow', type: 'button', onclick: approve(q) }, 'Revisar e aprovar')));
  const runs = pcs.flatMap((d) => ((d.report || {}).runs || []).map((r) => ({ ...r, pc: d.name, dev: d.id }))).sort((a, b) => b.ts - a.ts).slice(0, 12);
  const ACT = { retry_with_args: 'Argumentos para tentar', release_domain: 'Domínio para liberar', admin_manual: 'Precisa da conta de administrador', other: 'Sugestão' };
  const aiBlock = (r) => {
    const a = r.needs_help ? ai.get(`${r.dev}|${r.ctr}`) : null;
    if (!a) return null;
    const res = a.result || {};
    return h('div', { class: 'note', style: 'margin:10px 0 0' }, h('strong', {}, 'Análise por IA (não verificada)'), a.status === 'pending' ? ' · analisando…' : '',
      res.summary ? h('p', { style: 'margin:6px 0 0' }, res.summary) : null, res.cause && a.status === 'done' ? h('p', { class: 'muted', style: 'margin:4px 0 0' }, `Causa provável: ${res.cause}`) : null,
      (res.actions || []).map((x) => h('div', { class: 'muted', style: 'margin-top:4px' }, `${ACT[x.kind] || 'Sugestão'}: `, h('span', { class: 'mono' }, x.args || (x.domains || []).join(', ') || x.text || x.why || ''))),
      h('p', { class: 'muted', style: 'margin:6px 0 0' }, 'O solicitante recebe a mesma análise. Qualquer ação sugerida vira um pedido novo que você aprova.'));
  };

  show(top('PC'), h('div', { class: 'wrap' },
    h('div', { class: 'sec royal' }, `Pedidos do computador · ${pcReqs.length}`),
    pcReqs.length ? pcReqs.map(reqCard) : h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, pcs.length ? 'Nenhum pedido aguardando.' :
      'Nenhum computador com o agente ainda. Instale o agente no Windows (docs/AGENTE.md) e pareie em Dispositivos.')),
    pcs.length ? [
      h('div', { class: 'sec' }, 'Computadores'),
      h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, pcs.map((d) => { const st = statusOf(d, now); return h('div', { class: 'li' }, insignia('device', 34), h('div', { class: 'sp' }, h('strong', {}, d.name), h('div', { class: 'muted' }, st.detail)), chip(st.word, st.kind)); })),
      h('div', { class: 'sec' }, 'Padrões das aprovações'),
      h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0 0 8px' }, 'Se o computador estiver desligado, o comando aprovado espera no servidor e roda quando ele ligar, dentro do prazo "Vale por". Depois disso vence e precisa ser aprovado de novo. Vale para as próximas aprovações, neste navegador.'),
        Object.keys(WIN_CHOICES).map((k) => [h('div', { class: 'sec', style: 'padding-left:0' }, WIN_CHOICES[k][0]),
          pillGroup(WIN_CHOICES[k][0], WIN_CHOICES[k][1], winCfg()[k], (v) => { setWinCfg(k, v); route(); })])),
      h('div', { class: 'sec' }, 'Executar agora'),
      h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0 0 8px' }, 'Sem pedido: você mesmo manda, com a sua passkey.'), sel,
        h('div', { class: 'sec', style: 'padding-left:0' }, 'Instalar pelo winget'), wName, h('div', { style: 'height:8px' }), wId, h('div', { style: 'height:8px' }), wVer,
        h('div', { class: 'row', style: 'margin-top:10px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: act(async () => {
          const p = { name: wName.value.trim(), source: 'winget', id: wId.value.trim() };
          if (wVer.value.trim()) p.version = wVer.value.trim();
          await direct(sel.value, p)();
        }) }, 'Revisar e assinar')),
        h('div', { class: 'sec', style: 'padding-left:0' }, 'Rodar um script'), sName, h('div', { style: 'height:8px' }), sBody,
        h('div', { class: 'row', style: 'margin-top:10px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: act(async () => {
          const p = { shell: 'powershell', script: sBody.value };
          if (sName.value.trim()) p.name = sName.value.trim();
          await direct(sel.value, p)();
        }) }, 'Revisar e assinar'))),
      h('div', { class: 'sec' }, 'O que foi executado'),
      runs.length ? runs.map((r) => h('details', { class: 'card' }, h('summary', { style: 'cursor:pointer;font-weight:600' }, `${r.name || (r.type === 'win_install' ? 'Instalação' : 'Comando')} `, chip(r.ok ? 'ok' : 'falhou', r.ok ? 'ok' : 'bad'),
        h('span', { class: 'muted' }, ` ${r.pc} · ${ago(r.ts, now)} · ${gname(r.by)}`), r.verified === true ? [' ', chip('conferido', 'ok')] : r.verified === false && r.ok ? [' ', chip('não confirmou', 'warn')] : null),
        r.installed && r.installed.length ? h('div', { class: 'muted', style: 'margin-top:8px' }, `Apareceu: ${r.installed.join(', ')}`) : null,
        h('pre', { class: 'detail inline' }, `código ${r.rc ?? '-'}\n${r.out || ''}`), aiBlock(r))) :
        h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nada executado ainda.'))] : null));
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

/** Cria o link de convite e o mostra em `out`. */
function makeInviteLink(out, kind, name, role, policy) {
  return act(async () => {
    const r = await api('POST', '/v1/invites', { kind, ...(name ? { name } : {}), ...(role ? { role } : {}), ...(policy || {}) });
    const text = `${me.origin}/#invite=${r.token}`;
    out.replaceChildren(h('div', { class: 'card' }, h('p', { style: 'margin:0 0 8px' }, 'Envie este link (vale 24 h, uso único):'), h('textarea', { class: 'ta', readonly: true }, text),
      h('div', { class: 'row', style: 'margin-top:8px' }, copyBtn(() => text), shareBtn(() => text))));
    if (out.scrollIntoView) out.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });
}

const gOpen = new Set();     // guardiões com "Passkeys e permissões" aberto (sobrevive aos redesenhos)

/** Guardiões: quem são, passkeys e permissões, convite, confiança dos aparelhos e co-assinaturas. */
async function guardiansView() {
  me = await api('GET', '/v1/me');
  const { devices, aw } = await loadAll();
  renderNav('guardians');
  const gs = Object.entries(me.trust);
  const missing = (d) => {
    const have = (d.report && d.report.trust) || {};
    const out = [];
    for (const [gid, g] of gs) {
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
  const myCreds = Object.keys((me.trust[me.guardian.id] || { creds: {} }).creds).length;
  const cos = aw.filter((c) => c.can_cosign);

  const guardianCardFull = ([gid, g]) => {
    const n = Object.keys(g.creds).length;
    const dom = g.role === 'domains';
    const mineCard = gid === me.guardian.id;
    const see = (me.see_of || {})[gid] || {};
    const removeCred = (cred, num) => act(async () => {
      const on = devices.filter((d) => ((d.report && d.report.trust) || {})[gid] && d.report.trust[gid].includes(cred));
      if (!(await sheet({ title: `Remover a passkey ${num} de ${g.name}?`, rows: [['Guardião', g.name], ['Passkey', String(num)], ['Aparelhos que confiam nela', String(on.length)]],
        effect: 'vale na hora', effectKind: 'ok', note: `${on.length ? `Um toque de passkey por aparelho (${on.length}). ` : ''}Depois apague essa passkey também no gerenciador (conta Google, Windows Hello…) onde ela estiver.`,
        confirm: on.length ? 'Assinar e remover' : 'Remover', danger: true }))) return;
      for (const d of on) await sendCommand(d.id, 'remove_credential', { id: gid, cred });
      await api('POST', `/v1/guardians/${gid}/credentials/remove`, { cred });
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
    const removeMor = act(async () => {
      const alone = isMaster();  // o mestre remove sozinho; sem mestre ainda vale o modo antigo (dois guardiões-mor)
      if (!(await sheet({ title: `${alone ? 'Remover' : 'Pedir a remoção de'} ${g.name}?`, rows: [['Ação', `Remover ${roleLabel(g.role)}`], ['Guardião', g.name], ['Aparelhos', String(devices.length)]],
        effect: alone ? 'vale após a espera de cada aparelho' : 'dois guardiões-mor + espera', effectKind: 'warn',
        note: alone ? `Um toque de passkey por aparelho (${devices.length}). O acesso ao site acaba na hora; cada aparelho aplica depois da espera.` : 'Exige a co-assinatura do outro guardião-mor e passa pelo atraso de cada aparelho.',
        confirm: alone ? 'Assinar e remover' : 'Assinar e pedir', danger: true }))) return;
      for (const d of devices) await sendCommand(d.id, 'remove_guardian', { id: gid });
      if (alone) { await api('POST', `/v1/guardians/${gid}/remove`, {}); toast(`${g.name} removido.`); }
      route();
    });
    /** Muda o papel de um guardião (promover ou rebaixar) em cada destino que o conhece; o gateway muda o dele quando o comando fica pronto. */
    const setRole = (role) => act(async () => {
      const alone = true;  // uma assinatura: sem mestre, a promoção a mestre é a montagem do sistema; com mestre, só ele muda papéis
      const knows = devices.filter((d) => ((d.report && d.report.trust) || {})[gid]);
      const dests = knows.length ? knows : devices;
      const up = role === 'master';
      if (!(await sheet({ title: `${up ? 'Promover' : 'Rebaixar'} ${g.name} a ${roleLabel(role)}?`, rows: [['Guardião', g.name], ['Papel agora', roleLabel(g.role)], ['Papel novo', roleLabel(role)], ['Destinos', String(dests.length)]],
        effect: 'vale na hora', effectKind: 'warn',
        note: (up ? 'O mestre é quem inclui e remove guardiões, sozinho. ' : role === 'admin' ? 'Deixa de incluir e remover guardiões; continua com o resto. ' : 'Passa a cuidar só de domínios e apps. ') +
          `Um toque de passkey por destino (${dests.length}).` + (up && !hasMaster() ? ' Depois disso só um mestre promove, rebaixa, inclui ou remove guardiões.' : ''),
        confirm: `Assinar e ${up ? 'promover' : 'rebaixar'}`, danger: true }))) return;
      for (const d of dests) await sendCommand(d.id, 'set_role', { id: gid, role });
      route();
    });
    const roleBtns = [];
    if (canManage() && g.role === 'admin') roleBtns.push(h('button', { class: 'btn', type: 'button', onclick: setRole('master') }, 'Promover a mestre'));
    if (isMaster() && g.role === 'master') roleBtns.push(h('button', { class: 'btn dangero', type: 'button', onclick: setRole('admin') }, 'Rebaixar a guardião-mor'));
    if (isMaster() && g.role === 'admin') roleBtns.push(h('button', { class: 'btn dangero', type: 'button', onclick: setRole('domains') }, 'Rebaixar a guardião'));
    return h('div', { class: 'card gcard r-' + roleKey(g.role) },
      h('div', { class: 'row', style: 'align-items:flex-start;gap:14px' }, guardianHead(g, mineCard),
        mineCard || !canManage() ? null : dom ? h('button', { class: 'btn dangero', type: 'button', onclick: removeDomain }, 'Remover') : h('button', { class: 'btn dangero', type: 'button', onclick: removeMor }, 'Remover')),
      guardianInscr(g, n),
      roleBtns.length ? h('div', { style: 'margin-top:12px;display:flex;gap:8px;flex-wrap:wrap' }, roleBtns) : null,
      h('details', { class: 'gdet', style: 'margin-top:10px', open: gOpen.has(gid), ontoggle: (e) => { if (e.target.open) gOpen.add(gid); else gOpen.delete(gid); } }, h('summary', {}, dom ? 'Passkeys e permissões' : 'Passkeys'),
        Object.entries(g.creds).map(([cred], i) => {
          const info = (me.cred_info || {})[cred] || {};
          return h('div', { class: 'row', style: 'min-height:40px;gap:8px' },
            h('div', { class: 'sp muted' }, `Passkey ${i + 1}${info.created ? ` · cadastrada ${ago(info.created, me.now)}` : ''}`),
            inscr(info.be ? 'sync' : 'lock', info.be ? 'sincronizada' : 'só neste aparelho', info.be ? 'warn' : ''),
            n > 1 ? h('button', { class: 'btn dangero', type: 'button', onclick: removeCred(cred, i + 1) }, 'Remover') : null);
        }),
        mineCard ? h('div', { style: 'margin-top:8px' }, h('button', { class: 'btn' + (n < 2 ? ' pri' : ''), type: 'button', onclick: makeInviteLink(out, 'add_passkey') }, 'Cadastrar outra passkey')) : null,
        dom ? [h('div', { class: 'muted', style: 'margin:10px 0 6px' }, 'Pode ver, além de domínios e apps:'),
          h('div', { class: 'durs', role: 'group', 'aria-label': `O que ${g.name} pode ver` }, SEE_LABELS.map(([k, label]) => h('button', { type: 'button', 'aria-pressed': String(!!see[k]),
            onclick: act(async () => { await api('POST', `/v1/guardians/${gid}/see`, { ...see, [k]: !see[k] }); route(); }) }, label)))] : null));
  };

  show(top('Guardiões', { actions: canManage() ? h('a', { class: 'btn pri', href: '#/guardians/novo', style: 'min-height:40px;display:inline-flex;align-items:center;text-decoration:none' }, 'Convidar') : null }), h('div', { class: 'wrap' },
    !hasMaster() ? h('div', { class: 'card warnb' }, h('strong', {}, 'Ainda não há guardião-mestre'),
      h('p', { class: 'muted', style: 'margin:6px 0 0' }, 'O mestre é quem inclui e remove guardiões, sozinho; o guardião-mor faz o resto. Enquanto não existir um, incluir e remover guardiões exige dois guardiões-mor. Promova o primeiro mestre em "Promover a mestre" (uma assinatura); depois só um mestre mexe em guardiões.')) : null,
    hasMaster() && !isMaster() ? h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Só o guardião-mestre inclui, remove e propaga guardiões.')) : null,
    myCreds < 2 ? h('div', { class: 'card badb' }, h('strong', {}, 'Cadastre uma chave de reserva'),
      h('p', { class: 'muted', style: 'margin:6px 0 10px' }, 'Você é o guardião-mor e tem só 1 passkey. Se perder este celular, ninguém mais administra os aparelhos: cadastre outro celular ou uma chave física.'),
      h('button', { class: 'btn pri', type: 'button', onclick: makeInviteLink(out, 'add_passkey') }, 'Cadastrar outra passkey')) : null,
    h('div', { class: 'sec royal' }, `Guardiões · ${gs.length}`),
    gs.map(guardianCardFull),
    out,
    h('div', { class: 'sec' }, 'Confiança nos aparelhos'),
    h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, devices.length ? devices.map((d) => {
      const m = missing(d);
      return h('div', { class: 'li' }, h('div', { class: 'sp' }, h('strong', {}, d.name), d.kind === 'executor' ? ' ' : null, d.kind === 'executor' ? chip('executor') : null,
        h('div', { class: 'muted', style: m.length ? 'color:var(--orange)' : '' }, m.length ? `ainda não confia em ${[...new Set(m.map((x) => x.g.name))].join(', ')}` : 'confia em todos os passkeys')),
        m.length ? (canManage() ? h('button', { class: 'btn pri', type: 'button', onclick: propagate(d) }, 'Propagar') : chip('só o mestre propaga', 'warn')) : chip('ok', 'ok'));
    }) : h('p', { class: 'muted' }, 'Nenhum aparelho pareado.')),
    h('div', { class: 'sec' }, 'Co-assinaturas pendentes'),
    h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, aw.length ? aw.map((c) => h('div', { class: 'li' }, h('div', { class: 'sp' }, h('strong', {}, (devices.find((x) => x.id === c.dev) || { name: c.dev }).name),
      h('div', { class: 'muted' }, `${summarize(c.envelope)} · pedido de ${gname(c.guardian)}`)),
      c.can_cosign ? h('button', { class: 'btn pri', type: 'button', onclick: act(async () => {
        if (!(await sheet({ title: `Co-assinar: ${summarize(c.envelope)}?`, rows: [['Pedido de', gname(c.guardian)], ['Aparelho', (devices.find((x) => x.id === c.dev) || { name: c.dev }).name]],
          effect: 'dois guardiões + espera', effectKind: 'warn', note: 'Esta ação exige a assinatura de dois guardiões-mor.', confirm: 'Co-assinar' }))) return;
        const sig = await signPayload(dec(c.envelope.payload));
        await api('POST', `/v1/commands/${c.id}/cosign`, { sig });
        toast('Co-assinado.');
        route();
      }) }, 'Co-assinar') : chip('aguardando o outro guardião'))) : h('p', { class: 'muted', style: 'margin:10px 0' }, cos.length ? '' : 'Nenhuma.')),
    h('div', { class: 'sec' }, 'Notificações neste aparelho'), await pushCard(),
    h('div', { class: 'pad', style: 'margin-top:14px' }, h('button', { class: 'btn block', type: 'button', onclick: act(logout) }, 'Sair'))));
}

/** Convidar guardião: tela própria, em passos (quem, passkey, horário). */
async function guardianInviteView() {
  me = await api('GET', '/v1/me');
  renderNav('guardians');
  if (!canManage()) { show(top('Convidar guardião', { back: '#/guardians' }), h('div', { class: 'wrap' }, h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Só o guardião-mestre convida guardiões.')))); return; }
  const out = h('div', {});
  const nm = h('input', { class: 'inp', placeholder: 'Nome da pessoa', autocapitalize: 'words', autocomplete: 'off', enterkeyhint: 'done', 'aria-label': 'Nome do guardião', value: inviteName, oninput: (e) => { inviteName = e.target.value; } });
  const syncOn = inviteSync === null ? inviteRole === 'domains' : inviteSync;  // guardião-mor e mestre: só neste aparelho, a menos que se escolha o contrário
  const step = (n, title) => h('div', { class: 'stephead' }, h('span', { class: 'stepn' }, String(n)), h('strong', {}, title));
  show(top('Convidar guardião', { back: '#/guardians' }), h('div', { class: 'wrap' },
    h('div', { class: 'card' }, step(1, 'Quem'), nm,
      h('div', { class: 'durs', role: 'group', 'aria-label': 'Papel do convidado' },
        [['domains', 'Guardião (só domínios e apps)'], ['admin', 'Guardião-mor'], ...(isMaster() ? [['master', 'Mestre']] : [])].map(([k, label]) => h('button', { type: 'button', 'aria-pressed': String(inviteRole === k), onclick: () => { inviteRole = k; route(); } }, label))),
      h('p', { class: 'muted', style: 'margin:8px 0 0' }, inviteRole === 'master' ? 'Inclui e remove guardiões, inclusive outro mestre, sozinho; e tem tudo do guardião-mor. Use para a pessoa de confiança e para a reserva dela.' :
        inviteRole === 'admin' ? 'Faz tudo, menos incluir e remover guardiões: regras, PIN, janelas, domínios e apps.' :
        'Libera e bloqueia sites, responde às solicitações e aprova ou recusa apps. Não mexe em regras, PIN nem pessoas. O que mais ele pode ver você escolhe depois.')),
    h('div', { class: 'card' }, step(2, 'Passkey'),
      h('div', { class: 'durs', role: 'group', 'aria-label': 'Passkey sincronizável' },
        [[false, 'Só neste aparelho'], [true, 'Pode sincronizar']].map(([k, label]) => h('button', { type: 'button', 'aria-pressed': String(syncOn === k), onclick: () => { inviteSync = k; route(); } }, label))),
      h('p', { class: 'muted', style: 'margin:8px 0 0' }, syncOn ? 'A passkey pode ir para a conta Google ou Apple da pessoa e aparecer em outros aparelhos dela.' :
        'Só vale passkey presa ao aparelho (Windows Hello, Touch ID, chave de segurança). Uma passkey da conta Google é recusada. Não dá para mudar depois.')),
    h('div', { class: 'card' }, step(3, 'Horário'),
      h('div', { class: 'durs', role: 'group', 'aria-label': 'Limitar a um horário' },
        [[false, 'A qualquer hora'], [true, 'Só em um horário']].map(([k, label]) => h('button', { type: 'button', 'aria-pressed': String(inviteWin.on === k), onclick: () => { inviteWin.on = k; route(); } }, label))),
      inviteWin.on ? [h('div', { class: 'durs', role: 'group', 'aria-label': 'Dias da semana' },
        DAY_NAMES.map((d, i) => h('button', { type: 'button', 'aria-pressed': String(inviteWin.days.includes(i)), onclick: () => {
          inviteWin.days = inviteWin.days.includes(i) ? inviteWin.days.filter((x) => x !== i) : [...inviteWin.days, i]; route(); } }, d))),
        h('div', { class: 'row', style: 'margin-top:10px;gap:8px;align-items:center' }, 'Das',
          h('input', { class: 'inp', type: 'time', value: inviteWin.from, 'aria-label': 'Início', style: 'width:130px', onchange: (e) => { inviteWin.from = e.target.value; } }), 'às',
          h('input', { class: 'inp', type: 'time', value: inviteWin.to, 'aria-label': 'Fim', style: 'width:130px', onchange: (e) => { inviteWin.to = e.target.value; } })),
        h('p', { class: 'muted', style: 'margin:8px 0 0' }, 'Horário de Brasília. Fora dele os comandos dessa pessoa não valem, mesmo com a passkey certa; quem confere é o aparelho e o executor, com o relógio deles. Não dá para mudar depois.')] : null),
    h('div', { class: 'pad' }, h('button', { class: 'btn pri block', type: 'button', onclick: act(async () => {
      if (!nm.value.trim()) throw new Error('Digite o nome.');
      let window = null;
      if (inviteWin.on) {
        if (!inviteWin.days.length) throw new Error('Escolha pelo menos um dia.');
        if (!inviteWin.from || !inviteWin.to || toMin(inviteWin.from) >= toMin(inviteWin.to)) throw new Error('O horário final precisa ser depois do inicial.');
        window = { days: [...inviteWin.days].sort(), from: toMin(inviteWin.from), to: toMin(inviteWin.to), utc_offset_min: OFFSET_MIN };
      }
      await makeInviteLink(out, 'new_guardian', nm.value.trim(), inviteRole, { allow_sync: syncOn, window })();
    }) }, 'Gerar link de convite')),
    out));
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
    h('div', { class: 'card gcard r-' + roleKey(me.guardian.role) }, h('div', { class: 'row', style: 'align-items:flex-start;gap:14px' }, guardianHead(me.guardian, true))),
    h('div', { class: 'sec' }, 'Minhas passkeys'),
    h('div', { class: 'card' + (n < 2 ? ' warnb' : '') }, h('p', { style: 'margin:0 0 10px' }, `${n} passkey${n === 1 ? '' : 's'} cadastrada${n === 1 ? '' : 's'}.` + (n < 2 ? ' Cadastre outra para não perder o acesso se trocar de celular.' : '')),
      h('button', { class: 'btn' + (n < 2 ? ' pri' : ''), type: 'button', onclick: invite }, 'Cadastrar outra passkey')),
    out,
    ex && miss.length ? h('div', { class: 'card warnb' }, h('p', { style: 'margin:0 0 10px' }, `O executor ainda não conhece ${miss.length} passkey${miss.length > 1 ? 's' : ''} sua${miss.length > 1 ? 's' : ''}.`),
      h('button', { class: 'btn pri', type: 'button', onclick: act(async () => {
        for (const c of miss) await sendCommand(ex.id, 'add_credential', { id: gid, cred: c, spki: creds[c] });
        route();
      }) }, 'Propagar ao executor')) : null,
    ex && !exHave ? h('div', { class: 'card warnb' }, h('p', { style: 'margin:0' }, 'O executor ainda não confia em você. Peça ao guardião-mestre para abrir Guardiões e tocar em Propagar.')) : null,
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
    const dom = hash.match(/^#\/(?:domains\/)?(solicitacoes|pedidos|bloqueios|consultas|liberados|recusados|vetos|meus)$/) || hash.match(/^#\/(domains)$/);
    const ap = hash.match(/^#\/apps(?:\/(solicitacoes|aprovados|recusados|instalados|vetados))?$/);
    const his = hash.match(/^#\/history(?:\/(comandos|acessos))?$/);
    if (dm) await deviceView(dm[1], dm[2] || 'resumo');
    else if (dom) await domainsView(dom[1] === 'domains' ? undefined : dom[1]);
    else if (hash === '#/people') { if (isAdmin()) location.hash = '#/guardians'; else await contaView(); }
    else if (hash === '#/guardians' && isAdmin()) await guardiansView();
    else if (hash === '#/guardians/novo' && isAdmin()) await guardianInviteView();
    else if (hash === '#/devices' && isAdmin()) await devicesView();
    else if (hash === '#/pc' && isAdmin()) await pcView();
    else if (his) await (isAdmin() || canSee('history') ? historyView(his[1]) : domainsView());
    else if (hash === '#/pair' && isAdmin()) await pairView();
    else if (ap) await appsView(ap[1]);
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
