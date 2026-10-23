// Tela local do agente: bloqueados, pedido de liberação, de programa e de comando, e o estado dos pedidos.
import { h, icon, chip, toast, insignia } from '/ui.js';

const main = document.getElementById('main');
let st = null;                 // último estado vindo do agente
let tab = 'bloqueados';
const picked = new Set();      // domínios marcados (o nome de base, como veio do Pi-hole)
const cut = {};                // quantos rótulos da esquerda foram cortados de cada domínio (« e »)
let sortBy = 'recent';
let showHidden = false;

// ---- o que fica guardado neste navegador (só preferências de tela: esconder, limpar histórico) ----
const store = {
  get(k, d) { try { const v = localStorage.getItem('guardian.' + k); return v === null ? d : JSON.parse(v); } catch (_) { return d; } },
  set(k, v) { try { localStorage.setItem('guardian.' + k, JSON.stringify(v)); } catch (_) { /* sem armazenamento: a tela só não lembra */ } },
};
const hidden = new Set(store.get('hidden', []));
let clearedAt = Number(store.get('cleared', 0)) || 0;

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
const small = (label, onclick, extra = {}) => h('button', { class: 'btn', type: 'button', style: 'min-height:38px;padding:0 12px;font-size:13px', onclick, ...extra }, label);

// Campos que sobrevivem ao redesenho (a pessoa pode estar digitando quando a lista atualiza).
const f = {
  search: input('Buscar domínio', { 'aria-label': 'Buscar domínio' }),
  wName: input('Nome do programa (ex.: 7-Zip)'), wId: input('Id do winget (ex.: 7zip.7zip)'), wVer: input('Versão (opcional, ex.: 24.09)'),
  uName: input('Nome do programa'), uUrl: input('https://…/instalador.msi'), uSha: input('SHA-256 do arquivo (64 caracteres)'),
  uKind: h('select', { class: 'sel' }, h('option', { value: 'msi' }, 'Instalador .msi'), h('option', { value: 'exe' }, 'Instalador .exe')),
  uArgs: input('Argumentos silenciosos (ex.: /S), se precisar'),
  fPath: input('C:\\Users\\allan\\Downloads\\programa-x64.exe'), fName: input('Nome do programa'), fArgs: input('/S', { value: '/S' }),   // sugerido de novo a cada arquivo conferido
  cName: input('O que o comando faz, em poucas palavras'),
  cScript: h('textarea', { class: 'ta', rows: '8', placeholder: 'Write-Output "olá"', spellcheck: 'false', 'aria-label': 'Script do PowerShell' }),
  cCount: h('div', { class: 'muted', style: 'margin-top:4px' }),
};
f.search.addEventListener('input', () => draw());
f.cScript.addEventListener('input', () => { f.cCount.textContent = `${new TextEncoder().encode(f.cScript.value).length} de 6000 bytes`; });

const STATE = { open: ['aguardando o guardião', 'warn'], approved: ['aprovado', 'ok'], denied: ['negado', 'bad'], done: ['resolvido', 'ok'] };
const ago = (ts) => { const s = Math.max(0, Math.floor(Date.now() / 1000) - ts); return s < 90 ? 'agora' : s < 5400 ? `há ${Math.round(s / 60)} min` : s < 129600 ? `há ${Math.round(s / 3600)} h` : `há ${Math.round(s / 86400)} d`; };

async function send(body, ok) {
  await api('POST', '/api/request', body);
  toast(ok);
  await refresh();
}

// ---- domínios: o domínio que será pedido é o de base com N rótulos cortados à esquerda (advertise.exemplo.com -> exemplo.com) ----
const parts = (d) => d.split('.');
// Sufixo público (cn, com.br, co.uk…): abriria um país ou uma categoria inteira, então nunca se pede. Mesma regra do executor.
const SLD = new Set(['com', 'net', 'org', 'gov', 'edu', 'co', 'ac', 'or', 'ne', 'go', 'mil', 'ltd', 'plc', 'sch', 'nom', 'ind', 'firm', 'gob']);
const isSuffix = (d) => { const p = parts(d); return p.length < 2 || (p.length === 2 && p[1].length === 2 && SLD.has(p[0])); };
// Quantos rótulos dá para cortar da esquerda sem chegar a um sufixo público.
const maxCut = (d) => { let k = 0; while (k + 1 < parts(d).length && !isSuffix(parts(d).slice(k + 1).join('.'))) k++; return k; };
const eff = (d) => parts(d).slice(Math.min(cut[d] || 0, maxCut(d))).join('.');
const openDomains = () => new Set((st.requests || []).flatMap((q) => (q.items || []).filter((i) => i.state === 'open').map((i) => i.domain)));

// Filtros da aba: aparelho ('' = todos) e origem ('' = todas; 'own' = regras próprias; 'list' = listas de bloqueio).
let devFilter = '';
let srcFilter = '';
const listName = (l) => { if (!l) return 'lista'; try { return new URL(l).hostname.replace(/^www\./, ''); } catch (_) { return l.length > 28 ? l.slice(0, 28) + '…' : l; } };
const pills = (label, options, current, onPick) => h('div', { class: 'durs filt', style: 'margin-top:10px', role: 'group', 'aria-label': label },
  options.map(([k, text]) => h('button', { type: 'button', 'aria-pressed': String(current === k), onclick: () => onPick(k) }, text)));

function blockedTab() {
  const all = st.blocked || [];
  const open = openDomains();
  const q = f.search.value.trim().toLowerCase();
  // Só as regras próprias deste computador podem ser pedidas; o resto (listas, outros aparelhos) é para ver.
  const mine = (b) => b.dev === st.me && b.src === 'own';
  const nHidden = all.filter((b) => hidden.has(b.domain)).length;
  let rows = all.filter((b) => (!devFilter || b.dev === devFilter) && (!srcFilter || b.src === srcFilter) && (showHidden || !hidden.has(b.domain)) && (!q || b.domain.includes(q)));
  rows = [...rows].sort((a, b) => (sortBy === 'count' ? b.count - a.count || b.last - a.last : b.last - a.last));
  const sel = [...picked].filter((d) => all.some((b) => b.domain === d && mine(b)));

  const request = act(async () => {
    const d = [...new Set(sel.map(eff))].slice(0, 20);
    if (!d.length) throw new Error('Marque ao menos um domínio.');
    await send({ kind: 'unblock', domains: d }, d.length > 1 ? `${d.length} domínios pedidos ao guardião.` : 'Pedido enviado ao guardião.');
    sel.forEach((x) => picked.delete(x));
    draw();
  });
  const clearList = () => { rows.forEach((b) => { hidden.add(b.domain); picked.delete(b.domain); }); store.set('hidden', [...hidden]); draw(); };
  const hideSelected = () => { sel.forEach((d) => { hidden.add(d); picked.delete(d); }); store.set('hidden', [...hidden]); draw(); };
  const devs = st.devices || [];
  const pickable = rows.filter((b) => mine(b) && !open.has(eff(b.domain)));

  const row = (b) => {
    const can = mine(b), e = can ? eff(b.domain) : b.domain, isOpen = can && open.has(e);
    return h('div', { class: 'li', style: hidden.has(b.domain) ? 'opacity:.6' : '' },
      can ? h('input', { type: 'checkbox', checked: picked.has(b.domain), disabled: isOpen, 'aria-label': e, style: 'width:22px;height:22px;flex:none',
        onchange: (ev) => { ev.target.checked ? picked.add(b.domain) : picked.delete(b.domain); draw(); } })
        : h('span', { class: 'ib', style: 'width:22px;height:22px;flex:none;color:var(--muted)', title: b.src === 'veto' ? 'Site vetado pelo guardião-mor: não se pede' : b.src === 'list' ? 'Bloqueado por lista: só o guardião libera' : 'De outro aparelho: só para ver' }, icon(b.src === 'list' || b.src === 'veto' ? 'lock' : 'device', 18)),
      h('div', { class: 'sp' }, h('span', { class: 'mono', style: 'font-weight:600' }, e), isOpen ? [' ', chip('aguardando', 'warn')] : null,
        h('div', { class: 'muted' }, `${b.count}× · ${ago(b.last)}${e !== b.domain ? ` · de ${b.domain}` : ''}${hidden.has(b.domain) ? ' · escondido' : ''}`),
        h('div', { style: 'display:flex;gap:6px;flex-wrap:wrap;margin-top:4px' }, chip(b.name || 'aparelho', b.dev === st.me ? 'ok' : ''), b.src === 'veto' ? chip(`vetado · ${b.list}`, 'bad') : b.src === 'list' ? chip(`lista · ${listName(b.list)}`, 'warn') : chip('regra do Guardian')))
      , can && maxCut(b.domain) ? [
        small('«', () => { cut[b.domain] = Math.min((cut[b.domain] || 0) + 1, maxCut(b.domain)); draw(); }, { 'aria-label': 'Encurtar: pedir o domínio pai', disabled: (cut[b.domain] || 0) >= maxCut(b.domain), style: 'min-height:38px;min-width:38px;padding:0' }),
        small('»', () => { cut[b.domain] = Math.max((cut[b.domain] || 0) - 1, 0); draw(); }, { 'aria-label': 'Ampliar: voltar ao domínio de baixo', disabled: !(cut[b.domain] > 0), style: 'min-height:38px;min-width:38px;padding:0' })] : null);
  };

  return [
    h('div', { class: 'sec' }, `Bloqueado agora · ${rows.length}`),
    h('div', { class: 'card' },
      h('p', { class: 'muted', style: 'margin:0 0 8px' }, 'Veja o que foi bloqueado em todos os aparelhos da rede. Nos bloqueios deste computador por regra do Guardian, marque o que precisa e peça a liberação; o guardião decide. Use « e » para pedir o domínio inteiro (exemplo.com).'),
      h('div', { class: 'note', style: 'margin:0 0 8px' }, h('span', { style: 'display:inline-flex;vertical-align:middle;margin-right:6px' }, icon('lock', 16)),
        'Domínios bloqueados por lista (cadeado) não podem ser pedidos. Se um deles estiver bloqueado por engano, avise o guardião: ele pode incluir o domínio à mão e liberar.'),
      h('div', { style: 'position:relative' }, f.search),
      pills('Filtrar por aparelho', [['', 'Todos os aparelhos'], ...devs.map((d) => [d.id, d.id === st.me ? `${d.name} (este)` : d.name])], devFilter, (k) => { devFilter = k; draw(); }),
      pills('Filtrar por origem', [['', 'Toda origem'], ['own', 'Regras do Guardian'], ['list', 'Listas'], ['veto', 'Vetados']], srcFilter, (k) => { srcFilter = k; draw(); }),
      h('div', { style: 'display:flex;gap:8px;flex-wrap:wrap;margin-top:10px' },
        small('Mais recentes', () => { sortBy = 'recent'; draw(); }, { 'aria-pressed': String(sortBy === 'recent') }),
        small('Mais bloqueados', () => { sortBy = 'count'; draw(); }, { 'aria-pressed': String(sortBy === 'count') }),
        small('Marcar os deste PC', () => { pickable.forEach((b) => picked.add(b.domain)); draw(); }, { disabled: !pickable.length }),
        small('Esconder marcados', hideSelected, { disabled: !sel.length }),
        small('Limpar lista', clearList, { disabled: !rows.length, title: 'Esconde todos os domínios visíveis (dá para mostrar de novo)' }),
        nHidden ? small(showHidden ? 'Ocultar escondidos' : `Mostrar escondidos (${nHidden})`, () => { showHidden = !showHidden; draw(); }) : null),
      rows.length ? rows.map(row) : h('p', { class: 'muted', style: 'margin:12px 0 0' }, all.length ? 'Nada com esses filtros.' : 'Nada bloqueado nas últimas 24 horas.'),
      // O botão de pedir fica logo abaixo dos domínios, onde a pessoa está olhando (não numa barra no rodapé da página).
      h('div', { class: 'row', style: 'margin-top:14px;gap:10px;flex-wrap:wrap;align-items:center' },
        h('button', { class: 'btn pri', type: 'button', disabled: !sel.length, onclick: request }, sel.length ? `Pedir liberação (${sel.length})` : 'Pedir liberação'),
        sel.length ? h('button', { class: 'btn', type: 'button', onclick: () => { picked.clear(); draw(); } }, 'Limpar seleção') : null,
        h('span', { class: 'muted' }, sel.length ? `${sel.length} marcado${sel.length > 1 ? 's' : ''}` : 'Marque os domínios deste computador'))),
  ];
}

// ---- programas ----
let inspected = null;      // o que a conferência do arquivo devolveu (tamanho, SHA-256, assinatura)
const fill = (map) => { for (const [el, v] of Object.entries(map)) f[el].value = v; draw(); };

const inspectFile = act(async () => {
  const path = f.fPath.value.trim();
  if (!path) throw new Error('Cole o caminho do arquivo.');
  const before = inspected ? inspected.name : '', beforeArgs = inspected ? inspected.suggested_args : null;
  inspected = await api('POST', '/api/inspect', { path });
  // os argumentos silenciosos também acompanham o programa (DBeaver pede /S /allusers), a menos que a pessoa tenha digitado outra coisa
  if (!f.fArgs.value.trim() || f.fArgs.value.trim() === '/S' || f.fArgs.value.trim() === beforeArgs) f.fArgs.value = inspected.suggested_args;
  // o nome acompanha o arquivo: troca se estiver vazio ou ainda for o nome automático do arquivo anterior (não o que a pessoa digitou)
  if (!f.fName.value.trim() || f.fName.value.trim() === before) f.fName.value = inspected.name;
  toast('Arquivo conferido.');
  draw();
});
const fileRequest = act(async () => {
  if (!inspected || inspected.path !== f.fPath.value.trim()) throw new Error('Confira o arquivo de novo: o caminho mudou.');
  const p = { name: f.fName.value.trim(), source: 'file', path: inspected.path, sha256: inspected.sha256, kind: inspected.kind };
  if (f.fArgs.value.trim()) p.args = f.fArgs.value.trim();
  if (inspected.status === 'Valid' && inspected.signer) p.publisher = inspected.signer;   // o agente só instala se a assinatura for válida e deste nome
  await send({ kind: 'install', payload: p }, 'Pedido de instalação enviado.');
});

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
  const step = (n, text) => h('div', { class: 'li', style: 'min-height:44px' }, h('span', { class: 'st cur' }, String(n)), h('div', { class: 'sp' }, text));
  return [
    h('div', { class: 'sec' }, 'Como funciona'),
    h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' },
      step(1, 'Você diz qual programa quer instalar (abaixo).'),
      step(2, 'O guardião-mor ou o mestre lê o pedido e aprova com a passkey.'),
      step(3, 'O agente instala sozinho, como administrador, sem você digitar senha. O resultado aparece na aba Pedidos.')),
    h('div', { class: 'sec' }, 'Opção 1: pelo winget (a mais simples)'),
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'O winget é a loja de programas do Windows. Para achar o id de um programa, abra o PowerShell e rode: winget search nome. O id tem a forma Fabricante.Programa.'),
      h('div', { style: 'margin-top:10px' }, small('Usar o exemplo (7-Zip)', () => fill({ wName: '7-Zip', wId: '7zip.7zip', wVer: '' }))),
      field('Nome', f.wName), field('Id do winget', f.wId), field('Versão (opcional)', f.wVer),
      h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: w }, 'Pedir instalação'))),
    h('div', { class: 'sec' }, 'Opção 2: arquivo que eu já baixei'),
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Cole o caminho completo do .exe ou .msi (em C:\\Users). A tela confere o tamanho, o SHA-256 e a assinatura digital; o guardião aprova exatamente esse arquivo. O agente copia o arquivo para uma pasta protegida antes de instalar, então trocá-lo depois não adianta.'),
      field('Caminho do arquivo', f.fPath),
      h('div', { class: 'row', style: 'margin-top:10px' }, h('button', { class: 'btn grow', type: 'button', onclick: inspectFile }, 'Conferir arquivo')),
      inspected ? h('div', { class: 'kvbox', style: 'margin-top:12px' },
        h('div', { class: 'kv' }, h('span', {}, 'Tamanho'), h('span', {}, `${(inspected.size / 1048576).toFixed(1)} MB`)),
        h('div', { class: 'kv' }, h('span', {}, 'Assinatura digital'), chip(inspected.status === 'Valid' ? `válida · ${inspected.signer}` : `sem assinatura válida (${inspected.status})`, inspected.status === 'Valid' ? 'ok' : 'bad')),
        h('div', { class: 'kv' }, h('span', {}, 'SHA-256'), h('span', { class: 'mono', style: 'font-size:11px;word-break:break-all' }, inspected.sha256))) : null,
      inspected && inspected.status !== 'Valid' ? h('div', { class: 'note bad' }, 'Este arquivo não tem assinatura digital válida. O guardião vai aprovar só pelo hash: confira de onde ele veio.') : null,
      inspected ? [field('Nome', f.fName), field('Argumentos silenciosos (sem isto o instalador espera uma janela que ninguém vê)', f.fArgs),
        h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: fileRequest }, 'Pedir instalação'))] : null),
    h('div', { class: 'sec' }, 'Opção 3: instalador por link'),
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Para programas que não estão no winget. Baixe o instalador uma vez, rode no PowerShell: Get-FileHash arquivo.msi (e copie o campo Hash). O agente só instala se o arquivo baixado for idêntico a esse hash. Só endereços https.'),
      field('Nome', f.uName), field('Endereço do instalador', f.uUrl), field('SHA-256', f.uSha), field('Tipo', f.uKind), field('Argumentos silenciosos', f.uArgs),
      h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: u }, 'Pedir instalação'))),
  ];
}

// ---- comando ----
const EXAMPLES = [
  ['Quem sou eu', 'Quem executa o comando', 'whoami\nhostname\nGet-Date'],
  ['Versão do Windows', 'Versão do Windows', '(Get-CimInstance Win32_OperatingSystem).Caption\n(Get-CimInstance Win32_OperatingSystem).Version'],
  ['Testar o winget', 'Testar o winget', 'winget --version\nwinget source list'],
  ['Espaço em disco', 'Espaço livre nos discos', 'Get-PSDrive -PSProvider FileSystem | Select-Object Name, @{n="LivreGB";e={[math]::Round($_.Free/1GB,1)}}, @{n="UsadoGB";e={[math]::Round($_.Used/1GB,1)}}'],
];

function commandTab() {
  f.cScript.dispatchEvent(new Event('input'));
  const c = act(async () => {
    const p = { script: f.cScript.value, shell: 'powershell', timeout_s: 600 };
    if (f.cName.value.trim()) p.name = f.cName.value.trim();
    await send({ kind: 'command', payload: p }, 'Pedido de comando enviado.');
  });
  return [
    h('div', { class: 'sec' }, 'Comando como administrador'),
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Escreva um script do PowerShell. O guardião lê o texto inteiro antes de aprovar e ele roda uma vez, como administrador (SYSTEM), com limite de 10 minutos. A saída volta na aba Pedidos.'),
      h('div', { class: 'sec', style: 'padding-left:0' }, 'Exemplos para testar'),
      h('div', { style: 'display:flex;gap:8px;flex-wrap:wrap' }, EXAMPLES.map(([label, name, script]) => small(label, () => fill({ cName: name, cScript: script })))),
      field('O que faz', f.cName), field('Script do PowerShell', f.cScript), f.cCount,
      h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { class: 'btn pri grow', type: 'button', onclick: c }, 'Pedir execução'))),
  ];
}

// ---- análise por IA (sugestão, nunca ação automática) ----
const ACTION_LABEL = { retry_with_args: 'Argumentos para tentar', release_domain: 'Domínio para liberar', admin_manual: 'Instalar com a conta de administrador', other: 'Sugestão' };
function aiCard(r) {
  if (!r.needs_help) return null;
  const a = (st.analyses || []).find((x) => x.ctr === r.ctr);
  if (!a) return h('p', { class: 'muted', style: 'margin:10px 0 0' }, 'Sem análise por IA (desligada, ou ainda não chegou).');
  if (a.status === 'pending') return h('p', { class: 'muted', style: 'margin:10px 0 0' }, 'A IA está analisando este resultado…');
  const res = a.result || {};
  const retry = (args) => act(async () => send({ kind: 'install', payload: { ...r.req, args } }, 'Pedido de instalação enviado com os novos argumentos.'));
  const release = (domains) => act(async () => send({ kind: 'unblock', domains }, 'Pedido de liberação enviado.'));
  return h('div', { class: 'note', style: 'margin:12px 0 0' },
    h('strong', {}, 'Sugestão da IA'), ' ', a.status === 'done' ? chip(`confiança ${({ low: 'baixa', medium: 'média', high: 'alta' })[res.confidence] || 'baixa'}`, res.confidence === 'high' ? 'ok' : 'warn') : null,
    h('div', { class: 'muted', style: 'margin-top:4px' }, 'Gerada automaticamente: pode estar errada. Confira antes de pedir. Nada é executado sem a aprovação do guardião.'),
    res.summary ? h('p', { style: 'margin:8px 0 0' }, res.summary) : null,
    res.cause && a.status === 'done' ? h('p', { class: 'muted', style: 'margin:4px 0 0' }, `Causa provável: ${res.cause}`) : null,
    (res.actions || []).map((x) => h('div', { class: 'li', style: 'min-height:48px;border-top:1px solid var(--line)' },
      h('div', { class: 'sp' }, h('strong', {}, ACTION_LABEL[x.kind] || 'Sugestão'),
        x.kind === 'retry_with_args' ? h('div', { class: 'mono' }, x.args) : null, x.kind === 'release_domain' ? h('div', { class: 'mono' }, (x.domains || []).join(', ')) : null,
        x.kind === 'other' ? h('div', {}, x.text) : null, x.why ? h('div', { class: 'muted' }, x.why) : null),
      x.kind === 'retry_with_args' && r.req ? h('button', { class: 'btn pri', type: 'button', onclick: retry(x.args) }, 'Pedir de novo com isto') : null,
      x.kind === 'release_domain' ? h('button', { class: 'btn pri', type: 'button', onclick: release(x.domains) }, 'Pedir liberação') : null)));
}

// ---- pedidos e o que foi executado ----
function requestsTab() {
  const keep = (ts, open) => open || ts > clearedAt;       // "limpar histórico" esconde o que já foi resolvido até agora; o que está aberto continua
  const admin = (st.admin || []).filter((a) => keep(a.ts, a.status === 'open'));
  const doms = (st.requests || []).filter((q) => (q.items || []).some((i) => i.state === 'open') || q.ts > clearedAt);
  const runs = [...(st.runs || [])].reverse().filter((r) => r.ts > clearedAt);
  const open = (st.admin || []).filter((a) => a.status === 'open').length;
  const blocks = [];
  blocks.push(h('div', { class: 'row', style: 'padding:14px 14px 0;gap:8px;flex-wrap:wrap' },
    small('Limpar histórico', act(async () => { clearedAt = Math.floor(Date.now() / 1000); store.set('cleared', clearedAt); draw(); toast('Histórico limpo nesta tela. Pedidos abertos continuam.'); })),
    clearedAt ? small('Mostrar tudo de novo', () => { clearedAt = 0; store.set('cleared', 0); draw(); }) : null));
  blocks.push(h('div', { class: 'sec' }, `Programas e comandos · ${admin.length}`));
  blocks.push(admin.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, admin.map((a) => {
    const [label, kind] = STATE[a.status] || [a.status, ''];
    return h('div', { class: 'li' }, h('div', { class: 'sp' }, h('strong', {}, a.text), h('div', { class: 'muted' }, ago(a.ts))), chip(label, kind));
  })) : h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum pedido.')));
  blocks.push(h('div', { class: 'sec' }, 'Liberações de domínio'));
  blocks.push(doms.length ? h('div', { class: 'card', style: 'padding-top:4px;padding-bottom:4px' }, doms.map((q) => h('div', { class: 'li' },
    h('div', { class: 'sp' }, (q.items || []).map((i) => h('div', {}, h('span', { class: 'mono' }, i.domain), ' ', chip(i.state === 'allowed' ? (i.ttl_s ? 'liberado por tempo' : 'liberado') : i.state === 'denied' ? 'negado' : 'aguardando', i.state === 'allowed' ? 'ok' : i.state === 'denied' ? 'bad' : 'warn'))),
      h('div', { class: 'muted' }, ago(q.ts)))))) : h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nenhum pedido.')));
  blocks.push(h('div', { class: 'sec' }, 'O que o agente executou'));
  blocks.push(runs.length ? runs.map((r) => h('details', { class: 'card', open: !!r.needs_help }, h('summary', { style: 'cursor:pointer;font-weight:600' }, `${r.name || (r.type === 'win_install' ? 'Instalação' : 'Comando')} `, chip(r.ok ? 'ok' : 'falhou', r.ok ? 'ok' : 'bad'),
      r.verified === true ? [' ', chip('conferido', 'ok')] : r.verified === false && r.ok ? [' ', chip('não confirmou', 'warn')] : null, ` ${ago(r.ts)}`),
    r.installed && r.installed.length ? h('div', { class: 'muted', style: 'margin-top:8px' }, `Apareceu: ${r.installed.join(', ')}`) : null,
    h('pre', { class: 'detail inline' }, `código ${r.rc ?? '-'}\n${r.out || ''}`),
    aiCard(r))) :
    h('div', { class: 'card' }, h('p', { class: 'muted', style: 'margin:0' }, 'Nada executado.')));
  return [blocks, open];
}

const TABS = [['bloqueados', 'Bloqueados', 'ban'], ['programas', 'Programas', 'box'], ['comando', 'Comando', 'terminal'], ['pedidos', 'Pedidos', 'inbox']];

function draw() {
  if (!st) return;
  const searching = document.activeElement === f.search;
  const [reqNodes, open] = requestsTab();
  const body = tab === 'bloqueados' ? blockedTab() : tab === 'programas' ? programsTab() : tab === 'comando' ? commandTab() : reqNodes;
  main.replaceChildren(
    h('header', { class: 'top' }, h('div', { style: 'margin-left:8px;display:flex;align-items:center;gap:10px' }, insignia('device', 28), h('h1', { style: 'padding-left:0' }, `NotToday PC · ${st.host}`)),
      h('span', { class: 'sp' }), st.busy ? chip(`executando ${st.busy.name || (st.busy.type === 'win_install' ? 'instalação' : 'comando')}`, 'warn') : null, chip(st.gateway_ok ? 'conectado' : 'sem conexão', st.gateway_ok ? 'ok' : 'bad'),
      h('button', { class: 'ib', type: 'button', 'aria-label': 'Atualizar', title: 'Atualizar', onclick: act(async () => { await refresh(); toast('Atualizado.'); }) }, icon('sync'))),
    h('div', { class: 'wrap' },
      h('nav', { class: 'seg', 'aria-label': 'Seções' }, TABS.map(([k, label, ic]) => h('a', { href: `#${k}`, class: k === tab ? 'on' : '', 'aria-current': k === tab ? 'page' : null, style: 'gap:6px' }, icon(ic, 18), k === 'pedidos' && open ? `${label} · ${open}` : label))),
      st.gateway_ok ? null : h('div', { class: 'note bad' }, `Sem conexão com o Guardian: ${st.error}`),
      body));
  if (searching) { f.search.focus(); f.search.setSelectionRange(f.search.value.length, f.search.value.length); }
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
