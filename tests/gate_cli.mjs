// Usado por test_gate_js.py: classifica cada caso com o gate.js do site e imprime os resultados.
import { classify } from '../src/guardian/gateway/static/gate.js';

const cases = JSON.parse(process.argv[2]);
console.log(JSON.stringify(cases.map(([k, o, n]) => classify(k, o, n))));
