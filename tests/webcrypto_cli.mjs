// Usado por test_webcrypto.py: roda o crypto.js do site (WebCrypto do Node) e imprime JSON.
import { sealPin, pairingString, commandBytes, enc } from '../src/guardian/gateway/static/crypto.js';

const [op, ...a] = process.argv.slice(2);
if (op === 'seal') {
  console.log(JSON.stringify(await sealPin(a[0], a[1], a[2])));
} else if (op === 'pairing') {
  console.log(pairingString(a[0], a[1], a[2], JSON.parse(a[3])));
} else if (op === 'command') {
  console.log(enc(commandBytes(JSON.parse(a[0]))));
}
