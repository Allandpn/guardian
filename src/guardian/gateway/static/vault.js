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
