import { enc, dec, sha256, sealPin, commandBytes, pairingString } from './crypto.js';

const $ = (id) => document.getElementById(id);
const main = $('main');
let me = null;          // { guardian, trust, rp_id, origin }
let timer = null;

// ---------- DOM sem innerHTML: todo texto vindo da rede entra por textContent ----------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, '');
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : String(kid));
  return el;
}
const chip = (t, cls) => h('span', { class: 'chip ' + (cls || '') }, t);
let toastTimer;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
}
const fail = (e) => toast(e && e.message ? e.message : String(e));
const show = (...nodes) => { main.replaceChildren(...nodes.flat(Infinity).filter(Boolean)); };

async function api(method, path, body) {
  const r = await fetch(path, {
    method, credentials: 'same-origin', cache: 'no-store',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await r.json(); } catch (_) { /* corpo vazio */ }
  if (!r.ok) { const e = new Error(data.error || `erro ${r.status}`); e.status = r.status; throw e; }
  return data;
}

function ago(ts, now) {
  if (!ts) return 'nunca';
  const s = Math.max(0, now - ts);
  if (s < 90) return `há ${s}s`;
  if (s < 5400) return `há ${Math.round(s / 60)} min`;
  if (s < 172800) return `há ${Math.round(s / 3600)} h`;
  return `há ${Math.round(s / 86400)} d`;
}
const fp = (id) => id.match(/.{1,4}/g).join('-');
const SILENT_S = 300;

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
  toast(r.status === 'awaiting' ? 'Enviado: aguarda a co-assinatura de outro guardião.' : 'Comando enviado.');
  return r;
}
const act = (fn, after) => async () => { try { await fn(); if (after) await after(); } catch (e) { fail(e); } };

// ---------- login / registro ----------
async function loginView() {
  show(h('h1', {}, 'NotToday Guardian'),
    h('div', { class: 'card' },
      h('p', {}, 'Entre com o seu passkey (biometria ou chave de segurança).'),
      h('button', { onclick: act(async () => { await doLogin(); }) }, 'Entrar com passkey')));
}

async function doLogin() {
  const o = await api('POST', '/v1/auth/options', {});
  const pk = o.publicKey;
  pk.challenge = dec(pk.challenge);
  const a = await passkeyGet(pk);
  await api('POST', '/v1/auth/verify', { challengeId: o.challengeId, ...a });
  await boot();
}

async function inviteView(token) {
  show(h('h1', {}, 'Cadastrar passkey'),
    h('div', { class: 'card' },
      h('p', {}, 'Você foi convidado como guardião. Cadastre um passkey neste aparelho.'),
      h('button', { onclick: act(async () => {
        const o = await api('POST', '/v1/register/options', { invite: token });
        const reg = await passkeyCreate(o);
        await api('POST', '/v1/register/verify', { challengeId: o.challengeId, ...reg });
        location.hash = '#/';
        await boot();
        toast('Passkey cadastrado.');
      }) }, 'Cadastrar passkey')));
}

// ---------- telas ----------
async function loadDevices() { return api('GET', '/v1/devices'); }

function statusOf(d, now) {
  const silent = now - d.last_seen > SILENT_S;
  const r = d.report || {};
  const out = [];
  if (silent) out.push(['sem sinal ' + ago(d.last_seen, now), 'bad']);
  if (d.kind === 'device') {
    if (r.filterActive === false) out.push(['filtro NÃO confirmado', 'bad']);
    else if (r.filterActive) out.push(['filtro ok', 'ok']);
    if ((r.pendingApps || []).length) out.push([`${r.pendingApps.length} app(s) pendente(s)`, 'warn']);
  } else if (r.pihole_ok === false) {
    out.push(['Pi-hole inacessível', 'bad']);
  }
  if (d.pending) out.push([`${d.pending} comando(s) na fila`, 'warn']);
  return out;
}

async function dashboardView() {
  const [{ devices, now }, reqs, aw] = await Promise.all([loadDevices(), api('GET', '/v1/requests'), api('GET', '/v1/commands/awaiting')]);
  const cos = aw.commands.filter((c) => c.can_cosign);
  show(h('h1', {}, 'Aparelhos'),
    cos.length ? h('div', { class: 'card' }, h('strong', { class: 'warn' }, `${cos.length} comando(s) aguardam a sua co-assinatura `),
      h('a', { href: '#/guardians' }, 'ver')) : null,
    reqs.items.length ? h('div', { class: 'card' }, h('strong', {}, `${reqs.items.length} pedido(s) do usuário`),
      h('div', {}, reqs.items.slice(0, 5).map((q) => h('div', { class: 'muted' }, `${devName(devices, q.dev)}: [${q.kind}] ${q.text}`))),
      h('a', { href: '#/domains' }, 'responder pedidos de domínio')) : null,
    devices.length ? devices.map((d) => h('div', { class: 'card' },
      h('div', { class: 'row' },
        h('div', {}, h('strong', {}, d.name), ' ', chip(d.kind === 'executor' ? 'executor Pi-hole' : 'aparelho'),
          h('div', { class: 'muted' }, 'id ' + fp(d.id))),
        h('a', { href: `#/device/${d.id}` }, 'abrir')),
      h('div', {}, statusOf(d, now).map(([t, c]) => h('span', { class: c + ' ' }, t + ' · ')),
        statusOf(d, now).length ? null : h('span', { class: 'muted' }, 'visto ' + ago(d.last_seen, now))))) :
      h('div', { class: 'card' }, 'Nenhum aparelho pareado. Use "Guardiões → Parear".'));
}
const devName = (devices, id) => (devices.find((d) => d.id === id) || { name: id }).name;

async function deviceView(id) {
  const { devices, now } = await loadDevices();
  const d = devices.find((x) => x.id === id);
  if (!d) { show(h('p', {}, 'Aparelho não encontrado.')); return; }
  const r = d.report || {};
  const refresh = () => route();
  const nodes = [h('h1', {}, d.name), h('p', { class: 'muted' }, `${d.kind === 'executor' ? 'Executor' : 'Aparelho'} · id ${fp(d.id)} · visto ${ago(d.last_seen, now)} · relatório ${ago(d.report_ts, now)}`)];
  if (d.kind === 'executor') {
    nodes.push(h('div', { class: 'card' }, 'Executor do Pi-hole. Gerencie os domínios em ', h('a', { href: '#/domains' }, 'Domínios'), '.'));
  } else {
    nodes.push(h('div', { class: 'card' },
      h('div', {}, 'Filtro: ', r.filterActive ? h('strong', { class: 'ok' }, 'CONFIRMADO') : h('strong', { class: 'bad' }, 'NÃO confirmado'),
        r.filterReason ? h('span', { class: 'muted' }, ` (${r.filterReason})`) : null),
      h('div', { class: 'muted' }, `Device Owner: ${r.owner ? 'sim' : 'não'} · Tailscale: ${r.tailscale ? 'sim' : 'não'} · PIN local: ${r.pinSet ? 'definido' : 'não definido'} · versão ${r.version || '?'}`),
      r.windows ? h('div', { class: 'muted' }, `Manutenção: ${r.windows.maintenanceMs ? 'ATIVA' : 'fechada'} · janela de dev: ${r.windows.devMs ? 'ABERTA' : 'fechada'} (${r.windows.devUsed ?? '?'} usadas em 24 h)`) : null));
    const pend = r.pendingApps || [];
    nodes.push(h('h2', {}, 'Apps pendentes de aprovação'));
    nodes.push(pend.length ? pend.map((a) => h('div', { class: 'card' },
      h('div', { class: 'row' }, h('div', {}, h('strong', {}, a.label || a.pkg), h('div', { class: 'muted' }, a.pkg)),
        h('button', { onclick: act(() => sendCommand(id, 'approve_app', { pkg: a.pkg }), refresh) }, 'Aprovar')),
      (a.risks || []).map((x) => chip('⚠ ' + x, 'warn')))) : h('p', { class: 'muted' }, 'Nenhum.'));
    const pq = r.pending || [];
    nodes.push(h('h2', {}, 'Pedidos de desbloqueio em espera'));
    nodes.push(pq.length ? pq.map((p) => h('div', { class: 'card' },
      h('div', { class: 'row' }, h('div', {}, h('strong', {}, p.kind), ' ', p.summary || ''),
        h('div', {}, p.state === 'ready' ? h('button', { onclick: act(() => sendCommand(id, 'confirm', { kind: p.kind }), refresh) }, 'Confirmar') : chip(`disponível em ${Math.ceil((p.remainingMs || 0) / 60000)} min`),
          ' ', h('button', { class: 'ghost', onclick: act(() => sendCommand(id, 'cancel', { kind: p.kind }), refresh) }, 'Cancelar'))))) : h('p', { class: 'muted' }, 'Nenhum.'));
    const snap = r.snapshot || {};
    const keys = Object.keys(snap).sort();
    const sel = h('select', {}, keys.map((k) => h('option', { value: k }, k)));
    const val = h('input', { placeholder: 'novo valor', size: 18 });
    sel.addEventListener('change', () => { val.value = snap[sel.value] ?? ''; });
    val.value = keys.length ? snap[keys[0]] : '';
    nodes.push(h('h2', {}, 'Configuração'));
    nodes.push(h('div', { class: 'card' },
      h('p', { class: 'muted' }, 'Endurecer vale na hora; afrouxar espera o atraso do aparelho (chave unlock_delay_min, em minutos).'),
      h('form', { onsubmit: (e) => { e.preventDefault(); act(() => sendCommand(id, 'set_config', { patch: { [sel.value]: val.value } }), refresh)(); } },
        sel, val, h('button', {}, 'Enviar')),
      h('table', {}, keys.map((k) => h('tr', {}, h('td', {}, k), h('td', {}, snap[k]))))));
    const pin = h('input', { type: 'password', inputmode: 'numeric', placeholder: 'PIN (6+ dígitos)', autocomplete: 'off' });
    const devpin = h('input', { type: 'password', inputmode: 'numeric', placeholder: 'PIN de desenvolvedor', autocomplete: 'off' });
    const sendPin = (type, input) => async () => {
      if (!/^[0-9]{6,32}$/.test(input.value)) throw new Error('o PIN precisa ter 6 ou mais dígitos');
      const box = await sealPin(d.spki, input.value, `guardian/${type}/${id}`);
      input.value = '';
      await sendCommand(id, type, { box });
    };
    nodes.push(h('h2', {}, 'PINs'));
    nodes.push(h('div', { class: 'card' },
      h('p', { class: 'muted' }, 'O PIN viaja cifrado para a chave do aparelho: o gateway e o usuário não o veem.'),
      h('form', { onsubmit: (e) => { e.preventDefault(); act(sendPin('set_pin', pin), refresh)(); } }, pin, h('button', {}, 'Definir PIN local')),
      h('form', { onsubmit: (e) => { e.preventDefault(); act(sendPin('set_dev_pin', devpin), refresh)(); } }, devpin, h('button', { class: 'ghost' }, 'Definir PIN de desenvolvedor'))));
    const pkg = h('input', { placeholder: 'pacote (com.exemplo.app)', size: 26 });
    nodes.push(h('h2', {}, 'Outras ações'));
    nodes.push(h('div', { class: 'card' },
      h('form', { onsubmit: (e) => { e.preventDefault(); act(() => sendCommand(id, 'revoke_app', { pkg: pkg.value.trim() }), refresh)(); } },
        pkg, h('button', { class: 'ghost' }, 'Revogar aprovação')),
      h('button', { class: 'ghost', onclick: act(() => sendCommand(id, 'request_maintenance'), refresh) }, 'Pedir janela de manutenção')));
  }
  nodes.push(h('h2', {}, 'Gateway'));
  nodes.push(h('div', { class: 'card' }, h('button', { class: 'danger', onclick: act(async () => {
    if (!confirm('Remover este aparelho do gateway? (não mexe no aparelho)')) return;
    await api('POST', `/v1/devices/${id}/forget`, {});
    location.hash = '#/';
  }) }, 'Esquecer neste gateway')));
  show(nodes);
}

const TTLS = [['permanente', 0], ['1 hora', 3600], ['24 horas', 86400], ['7 dias', 604800]];

async function domainsView() {
  const [{ devices, now }, reqs] = await Promise.all([loadDevices(), api('GET', '/v1/requests')]);
  const ex = devices.find((d) => d.kind === 'executor');
  if (!ex) { show(h('h1', {}, 'Domínios'), h('div', { class: 'card' }, 'Nenhum executor do Pi-hole pareado. Veja "Guardiões → Parear".')); return; }
  const r = ex.report || {};
  const send = (type, args) => act(() => sendCommand(ex.id, type, args), () => route());
  const sendForm = (type) => (e) => { e.preventDefault(); act(() => sendCommand(ex.id, type, args()), () => route())(); };
  const dom = h('input', { placeholder: 'exemplo.com', size: 24, autocapitalize: 'none', autocomplete: 'off' });
  const ttl = h('select', {}, TTLS.map(([l, v]) => h('option', { value: v }, l)));
  const args = () => ({ domain: dom.value.trim(), ...(Number(ttl.value) ? { ttl_s: Number(ttl.value) } : {}) });
  const temp = new Map((r.temp || []).map((t) => [`${t.list}:${t.domain}`, t.expires]));
  const list = (name, key) => h('div', { class: 'card' }, h('strong', {}, name),
    (r[key] || []).length ? h('table', {}, (r[key] || []).map((x) => h('tr', {},
      h('td', {}, x, temp.has(`${key}:${x}`) ? chip('expira ' + new Date(temp.get(`${key}:${x}`) * 1000).toLocaleString()) : null),
      h('td', {}, h('button', { class: 'ghost', onclick: send('pihole_remove', { list: key, domain: x }) }, 'Remover'))))) :
      h('p', { class: 'muted' }, 'Vazia.'));
  const domReqs = reqs.items.filter((q) => q.kind === 'domain');
  show(h('h1', {}, 'Domínios'),
    h('p', { class: 'muted' }, `Executor "${ex.name}" · visto ${ago(ex.last_seen, now)}` + (r.pihole_ok === false ? ' · Pi-hole inacessível' : '')),
    domReqs.length ? h('div', {}, h('h2', {}, 'Pedidos dos usuários'), domReqs.map((q) => h('div', { class: 'card' },
      h('div', { class: 'row' }, h('div', {}, h('strong', {}, q.text), h('div', { class: 'muted' }, devName(devices, q.dev) + ' · ' + ago(q.ts, now))),
        h('div', {}, h('button', { onclick: act(async () => {
          await sendCommand(ex.id, 'pihole_allow', { domain: q.text.trim(), ttl_s: 3600 });
          await api('POST', `/v1/requests/${q.id}/dismiss`, {});
          route();
        }) }, 'Liberar 1 h'), ' ', h('button', { class: 'ghost', onclick: act(async () => { await api('POST', `/v1/requests/${q.id}/dismiss`, {}); route(); }) }, 'Dispensar')))))) : null,
    h('div', { class: 'card' },
      h('form', { onsubmit: (e) => e.preventDefault() }, dom, ttl,
        h('button', { onclick: sendForm('pihole_allow') }, 'Liberar'),
        h('button', { class: 'ghost', onclick: sendForm('pihole_deny') }, 'Bloquear'))),
    list('Liberados', 'allow'), list('Bloqueados', 'deny'));
}

function summarize(env) {
  try {
    const c = JSON.parse(new TextDecoder().decode(dec(env.payload)));
    return `${c.type} ${JSON.stringify(c.args)}`;
  } catch (_) { return '(ilegível)'; }
}

async function guardiansView() {
  me = await api('GET', '/v1/me');
  const [{ devices }, aw] = await Promise.all([loadDevices(), api('GET', '/v1/commands/awaiting')]);
  const gs = Object.entries(me.trust);
  const missing = (d) => {
    const have = (d.report && d.report.trust) || {};
    const out = [];
    for (const [gid, g] of gs) for (const cred of Object.keys(g.creds)) if (!(have[gid] || []).includes(cred)) out.push({ gid, g, cred });
    return out;
  };
  const propagate = (d) => act(async () => {
    const seen = new Set(Object.keys((d.report && d.report.trust) || {}));
    for (const m of missing(d)) {
      if (!seen.has(m.gid)) { await sendCommand(d.id, 'add_guardian', { id: m.gid, name: m.g.name, cred: m.cred, spki: m.g.creds[m.cred] }); seen.add(m.gid); }
      else await sendCommand(d.id, 'add_credential', { id: m.gid, cred: m.cred, spki: m.g.creds[m.cred] });
    }
  }, () => route());
  const out = h('div', {});
  const link = (kind, name) => act(async () => {
    const r = await api('POST', '/v1/invites', { kind, ...(name ? { name } : {}) });
    out.replaceChildren(h('div', { class: 'card' }, h('p', {}, 'Envie este link (vale 24 h, uso único):'), h('textarea', { readonly: true }, `${me.origin}/#invite=${r.token}`)));
  });
  const nm = h('input', { placeholder: 'nome do guardião' });
  const pair = (kind) => act(async () => {
    const r = await api('POST', '/v1/pairings', { kind });
    out.replaceChildren(h('div', { class: 'card' },
      h('p', {}, `Cole esta string de pareamento no ${kind === 'executor' ? 'executor (python -m guardian.executor pair --pairing …)' : 'NotToday, no aparelho'} (vale 24 h, uso único). Depois confira o fingerprint por voz.`),
      h('textarea', { readonly: true }, pairingString(me.origin, me.rp_id, r.token, me.trust))));
  });
  show(h('h1', {}, 'Guardiões'),
    gs.map(([gid, g]) => h('div', { class: 'card' },
      h('div', { class: 'row' }, h('div', {}, h('strong', {}, g.name), gid === me.guardian.id ? chip('você') : null,
        h('div', { class: 'muted' }, `${Object.keys(g.creds).length} passkey(s)`)),
        gid !== me.guardian.id && gs.length > 1 ? h('button', { class: 'danger', onclick: act(async () => {
          if (!confirm(`Pedir a remoção de ${g.name}? Exige a co-assinatura do outro guardião e passa pelo atraso.`)) return;
          for (const d of devices) await sendCommand(d.id, 'remove_guardian', { id: gid });
        }, () => route()) }, 'Remover…') : null))),
    h('h2', {}, 'Aparelhos e confiança'),
    devices.map((d) => { const m = missing(d); return h('div', { class: 'card' }, h('div', { class: 'row' },
      h('div', {}, h('strong', {}, d.name), h('div', { class: m.length ? 'warn muted' : 'ok muted' }, m.length ? `${m.length} passkey(s) ainda não confiados por este aparelho` : 'confia em todos os passkeys')),
      m.length ? h('button', { onclick: propagate(d) }, 'Propagar') : null)); }),
    h('h2', {}, 'Co-assinaturas pendentes'),
    aw.commands.length ? aw.commands.map((c) => h('div', { class: 'card' }, h('div', { class: 'row' },
      h('div', {}, h('strong', {}, devName(devices, c.dev)), h('div', { class: 'muted' }, summarize(c.envelope))),
      c.can_cosign ? h('button', { onclick: act(async () => {
        const bytes = dec(c.envelope.payload);
        const sig = await signPayload(bytes);
        await api('POST', `/v1/commands/${c.id}/cosign`, { sig });
        toast('Co-assinado.');
      }, () => route()) }, 'Co-assinar') : chip('aguardando o outro guardião')))) : h('p', { class: 'muted' }, 'Nenhuma.'),
    h('h2', {}, 'Convidar e parear'),
    h('div', { class: 'card' },
      h('form', { onsubmit: (e) => { e.preventDefault(); if (nm.value.trim()) link('new_guardian', nm.value.trim())(); } }, nm, h('button', {}, 'Convidar guardião')),
      h('button', { class: 'ghost', onclick: link('add_passkey') }, 'Adicionar outro passkey para mim'),
      ' ', h('button', { class: 'ghost', onclick: pair('device') }, 'Parear aparelho'),
      ' ', h('button', { class: 'ghost', onclick: pair('executor') }, 'Parear executor Pi-hole')),
    out);
}

async function auditView() {
  const [{ items }, { devices }] = await Promise.all([api('GET', '/v1/audit?limit=200'), loadDevices()]);
  show(h('h1', {}, 'Auditoria'), h('div', { class: 'card' }, h('table', {}, items.map((i) => h('tr', {},
    h('td', { class: 'muted' }, new Date(i.ts * 1000).toLocaleString()), h('td', {}, i.dev ? devName(devices, i.dev) : '—'),
    h('td', {}, chip(i.kind)), h('td', {}, i.text))))));
}

// ---------- roteamento ----------
const NAV = [['#/', 'Aparelhos'], ['#/domains', 'Domínios'], ['#/guardians', 'Guardiões'], ['#/audit', 'Auditoria']];

async function route() {
  clearTimeout(timer);
  const hash = location.hash || '#/';
  const inv = hash.match(/^#invite=([\w-]+)$/);
  if (inv) { $('top').hidden = true; return inviteView(inv[1]); }
  if (!me) { $('top').hidden = true; return loginView(); }
  $('top').hidden = false;
  $('nav').replaceChildren(...NAV.map(([href, t]) => h('a', { href, class: hash === href || (href === '#/' && hash.startsWith('#/device/')) ? 'on' : '' }, t)),
    h('a', { href: '#', onclick: async (e) => { e.preventDefault(); await api('POST', '/v1/auth/logout', {}); me = null; route(); } }, 'Sair'));
  try {
    const dm = hash.match(/^#\/device\/([a-z2-7]{20})$/);
    if (dm) await deviceView(dm[1]);
    else if (hash === '#/domains') await domainsView();
    else if (hash === '#/guardians') await guardiansView();
    else if (hash === '#/audit') await auditView();
    else await dashboardView();
    if (hash === '#/' || dm) timer = setTimeout(route, 20000);
  } catch (e) {
    if (e.status === 401) { me = null; return loginView(); }
    show(h('p', { class: 'bad' }, e.message));
  }
}

async function boot() {
  try { me = await api('GET', '/v1/me'); } catch (_) { me = null; }
  await route();
}

addEventListener('hashchange', route);
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
boot();
