// Cofre de senhas: tudo é cifrado AQUI, no navegador. O servidor só guarda o envelope (sal, iv, texto cifrado) e nunca vê a frase nem o conteúdo.
// Chave: PBKDF2-SHA256 (600 mil voltas, sal aleatório) da frase-senha. Cifra: AES-256-GCM, iv novo a cada gravação, com o rótulo abaixo como dado autenticado.
import { enc, dec } from './crypto.js';

export const ITER = 600000;
export const MIN_PASS = 12;
const AAD = new TextEncoder().encode('guardian/vault/v1');
const utf8 = new TextEncoder();

async function keyFrom(pass, salt, it) {
  const base = await crypto.subtle.importKey('raw', utf8.encode(pass.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: it }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Contexto de uma frase já derivada: fica só na memória da página (nunca vai para o disco nem para o servidor). */
export async function newContext(pass, it = ITER) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return { key: await keyFrom(pass, salt, it), salt: enc(salt), it };
}

export async function seal(ctx, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, ctx.key, utf8.encode(JSON.stringify(data)));
  return { v: 1, kdf: 'PBKDF2-SHA256', it: ctx.it, salt: ctx.salt, iv: enc(iv), ct: enc(ct) };
}

/** Abre o envelope com uma chave já derivada (a lembrada neste aparelho). Chave que não serve lança 'frase errada'. */
export async function openWith(ctx, blob) {
  if (!blob || blob.v !== 1 || blob.salt !== ctx.salt || blob.it !== ctx.it) throw new Error('frase errada');  // a frase mudou em outro lugar
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: dec(blob.iv), additionalData: AAD }, ctx.key, dec(blob.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  } catch (_) {
    throw new Error('frase errada');
  }
}

// Lembrar neste aparelho: a chave (CryptoKey NÃO extraível) fica no IndexedDB deste navegador, por guardião. Ela não dá para copiar
// para fora, nunca vai ao servidor, e só é usada com o mestre logado (o login é por passkey). Sem IndexedDB, só não lembra.
const idb = () => new Promise((res, rej) => {
  const r = indexedDB.open('guardian-vault', 1);
  r.onupgradeneeded = () => r.result.createObjectStore('k');
  r.onsuccess = () => res(r.result);
  r.onerror = () => rej(r.error);
});
const tx = async (mode, fn) => {
  const db = await idb();
  try {
    return await new Promise((res, rej) => { const q = fn(db.transaction('k', mode).objectStore('k')); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); });
  } finally { db.close(); }
};
export const remember = (gid, ctx) => tx('readwrite', (s) => s.put({ key: ctx.key, salt: ctx.salt, it: ctx.it }, gid)).then(() => true, () => false);
export const recall = (gid) => tx('readonly', (s) => s.get(gid)).catch(() => null);
export const forget = (gid) => tx('readwrite', (s) => s.delete(gid)).then(() => true, () => false);

/** Abre o envelope com a frase. Frase errada (ou envelope adulterado) lança 'frase errada'. */
export async function open(pass, blob) {
  if (!blob || blob.v !== 1 || blob.kdf !== 'PBKDF2-SHA256') throw new Error('formato de cofre desconhecido');
  const ctx = { key: await keyFrom(pass, dec(blob.salt), blob.it), salt: blob.salt, it: blob.it };
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: dec(blob.iv), additionalData: AAD }, ctx.key, dec(blob.ct));
    return { ctx, data: JSON.parse(new TextDecoder().decode(pt)) };
  } catch (_) {
    throw new Error('frase errada');
  }
}

const AL = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const SYM = '!@#$%&*?-_+=';
/** Senha aleatória (sem letras que se confundem). Sorteio sem viés: descarta os valores que sobram na divisão. */
export function generate(n = 20, symbols = true) {
  const set = AL + (symbols ? SYM : '');
  const lim = 256 - (256 % set.length);
  let out = '';
  while (out.length < n) for (const b of crypto.getRandomValues(new Uint8Array(n * 2))) if (b < lim && out.length < n) out += set[b % set.length];
  return out;
}
