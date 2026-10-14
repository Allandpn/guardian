// Utilitários de criptografia do site. Sem dependências. O mesmo formato é testado contra o Python (tests/test_webcrypto.py).
export const enc = (bytes) => {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export const dec = (text) => {
  const s = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
};

export const sha256 = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

const utf8 = new TextEncoder();

// Cifra o PIN para a chave do aparelho: ECDH P-256 efêmero + HKDF-SHA256 + AES-256-GCM (veja protocol/SPEC.md).
export async function sealPin(deviceSpkiB64, plaintext, aad) {
  const devPub = await crypto.subtle.importKey('spki', dec(deviceSpkiB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: devPub }, eph.privateKey, 256);
  const hk = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8.encode('guardian/pinbox/v1') },
    hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: utf8.encode(aad) }, key, utf8.encode(plaintext));
  return { epk: enc(await crypto.subtle.exportKey('raw', eph.publicKey)), nonce: enc(nonce), ct: enc(ct) };
}

// Bytes do comando: o gateway, o executor e o aparelho verificam exatamente estes bytes.
export const commandBytes = (cmd) => utf8.encode(JSON.stringify(cmd));

// String de pareamento: tudo o que o aparelho/executor precisa para fixar o gateway e os guardiões.
export const pairingString = (origin, rpId, token, trust) =>
  enc(utf8.encode(JSON.stringify({ v: 1, url: origin, rp: rpId, token, guardians: trust })));
