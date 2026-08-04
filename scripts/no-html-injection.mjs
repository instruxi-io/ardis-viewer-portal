// Guards the one property this viewer cannot lose: no remote data may reach the
// DOM as markup. The share key K lives in location.hash, so a single injected
// script defeats the whole blind-broker design -- the server holds ciphertext it
// cannot read, but in-page script reads the fragment directly.
//
// Fails if any HTML-parsing sink is assigned an interpolated or concatenated
// string. Static markup and clearing (= '') stay allowed.
//
// ponytail: source-text check, not a DOM test, so it needs no jsdom and no
// browser. Ceiling: it cannot see a sink built up across statements. Upgrade
// path if that ever bites is eslint-plugin-no-unsanitized.

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = new URL('../src/', import.meta.url).pathname;
const SINKS = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write'];

const offences = [];

for (const file of readdirSync(SRC).filter(f => f.endsWith('.js'))) {
  const lines = readFileSync(join(SRC, file), 'utf8').split('\n');
  lines.forEach((line, i) => {
    const code = line.replace(/\/\/.*$/, '');
    for (const sink of SINKS) {
      if (!code.includes(sink)) continue;
      const assigned = code.slice(code.indexOf(sink) + sink.length);
      const interpolated = assigned.includes('${') || /\+\s*[A-Za-z_$]/.test(assigned);
      if (interpolated) offences.push(`${file}:${i + 1}: ${sink} <- interpolated value\n    ${line.trim()}`);
    }
  });
}

if (offences.length) {
  console.error(`html-injection check FAILED (${offences.length}):\n\n${offences.join('\n')}\n`);
  console.error('Build the node and set .textContent instead of assigning markup.');
  process.exit(1);
}
console.log('html-injection check: no interpolated markup sinks in src/');
