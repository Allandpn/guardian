import { newContext, seal, open, openWith, generate, MIN_PASS } from '../src/guardian/gateway/static/vault.js';
const out = {};
const data = { items: [{ id: 'a', title: 'RaspberryPi', fields: [{ label: 'Usuário', value: 'allan', secret: false }, { label: 'Senha', value: 'sénha ✓', secret: true }] }] };
const ctx = await newContext('uma frase bem longa 123', 100000);
const blob = await seal(ctx, data);
out.roundtrip = JSON.stringify((await open('uma frase bem longa 123', blob)).data) === JSON.stringify(data);
out.nfkc = JSON.stringify((await open('uma frase bem longa 123'.normalize('NFD'), blob)).data) === JSON.stringify(data);
try { await open('outra frase qualquer 1', blob); out.wrong = 'abriu'; } catch (e) { out.wrong = e.message; }
const t = { ...blob, ct: blob.ct.slice(0, -4) + (blob.ct.slice(-4) === 'AAAA' ? 'BBBB' : 'AAAA') };
try { await open('uma frase bem longa 123', t); out.tamper = 'abriu'; } catch (e) { out.tamper = e.message; }
const b2 = await seal(ctx, data);
out.freshIv = b2.iv !== blob.iv && b2.ct !== blob.ct;
out.plainLeak = JSON.stringify(blob).includes('allan') || JSON.stringify(blob).includes('RaspberryPi');
const g = generate(24); out.gen = g.length === 24 && !/[0OIl1]/.test(generate(500, false)) && generate(24) !== g;
const re = (await open('uma frase bem longa 123', blob)).ctx;
out.openWith = JSON.stringify(await openWith(re, blob)) === JSON.stringify(data);
const other = await newContext('uma frase bem longa 123', 100000);   // outro sal: é a frase trocada em outro aparelho
try { await openWith(other, blob); out.openWithOtherSalt = 'abriu'; } catch (e) { out.openWithOtherSalt = e.message; }
try { await openWith({ ...ctx, key: other.key }, blob); out.openWithWrongKey = 'abriu'; } catch (e) { out.openWithWrongKey = e.message; }
out.min = MIN_PASS;
console.log(JSON.stringify(out));
