/**
 * PIN gate self-check: the two ways the gate used to strand an employer.
 *
 *   1. A rejected PIN called showError, which hides the gate for good. Links
 *      are often single-use, so the only way back was asking the professional
 *      to share again.
 *   2. The gate opened on every full link, including plaintext shares that
 *      have no PIN, leaving the viewer at a prompt for a code nobody issued.
 *
 * Run: node scripts/pin-retry-selfcheck.mjs
 *
 * ponytail: app.js calls main() on import and reads import.meta.env, so this
 * bundles it with vite (already a devDependency) rather than importing the
 * source. Ceiling: a build per run, about a second. Upgrade path if that ever
 * bites is exporting main() and passing the API base in.
 */

import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { build } from 'vite';

const outDir = mkdtempSync(join(tmpdir(), 'ardis-pin-selfcheck-'));
await build({
  root: new URL('..', import.meta.url).pathname,
  logLevel: 'silent',
  build: {
    outDir, emptyOutDir: true, modulePreload: false,
    lib: { entry: 'src/app.js', formats: ['es'], fileName: () => 'app.mjs' },
  },
});
const bundle = pathToFileURL(join(outDir, 'app.mjs')).href;

// ── Stubs: enough DOM for the gates and the error screen, nothing more ──────
let els, calls, listenerCount;

function fakeElement(id) {
  const el = {
    id, value: '', textContent: '', innerHTML: '', disabled: false, hidden: true,
    style: {}, dataset: {},
    focus() {}, remove() {}, setAttribute() {}, appendChild() {}, querySelector: () => null,
    addEventListener() { listenerCount.set(id, (listenerCount.get(id) ?? 0) + 1); },
  };
  el.classList = {
    add: (c) => { if (c === 'hidden') el.hidden = true; },
    remove: (c) => { if (c === 'hidden') el.hidden = false; },
    contains: (c) => c === 'hidden' && el.hidden,
  };
  return el;
}

const $ = (id) => (els.get(id) ?? (els.set(id, fakeElement(id)), els.get(id)));
const json = (status, body) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json' },
});

/** Loads a fresh copy of app.js, which runs main(). The query busts the ESM cache. */
async function startFlow(respond, run) {
  els = new Map();
  calls = [];
  listenerCount = new Map();
  globalThis.window = { location: { pathname: '/view/test-guid', search: '', hash: '' } };
  globalThis.document = {
    getElementById: $,
    createElement: () => fakeElement('created'),
    querySelectorAll: () => [],
    body: fakeElement('body'),
  };
  globalThis.fetch = async (url, opts = {}) => {
    calls.push({ url: String(url), pin: opts.headers?.['X-Share-Pin'] ?? null, signal: opts.signal ?? null });
    return respond(calls.length - 1);
  };
  await import(`${bundle}?${run}`);
}

/** The flow is async with no handle to await, so wait on the UI state itself. */
async function until(label, cond) {
  for (let i = 0; i < 300; i++) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  assert.fail(`timed out waiting for ${label}`);
}

// ── 1. A mistyped digit reopens the gate and the retry reaches the server ───
await startFlow((n) => {
  if (n === 0) return json(401, { error: 'pin_required' });
  if (n === 1) return json(403, { error: 'wrong_pin' });
  return json(200, { success: false, message: 'reached the server' });
}, 'retry');

const gate = $('pin-gate');
const input = $('pin-input');
const btn = $('pin-submit-btn');
const err = $('pin-error');

await until('the PIN gate to open', () => !gate.hidden);
input.value = '111 111 111';
await btn.onclick();

await until('the PIN gate to reopen after a rejected PIN', () => !gate.hidden && err.textContent !== '');
assert.match(err.textContent, /Incorrect PIN/,
  'the reopened gate must say why the first attempt failed');
assert.equal(input.value, '', 'the rejected PIN must be cleared, not left for the viewer to edit');
assert.ok($('error').hidden, 'a wrong PIN must not land on the dead error screen');

input.value = '222 222 222';
await btn.onclick();

await until('the retry to reach the server', () => $('error-body').textContent !== '');
assert.deepEqual(calls.map((c) => c.pin), [null, '111111111', '222222222'],
  'the corrected PIN must be sent on the retry');
assert.equal($('error-body').textContent, 'reached the server',
  'the retried response must drive the page, not the abandoned first attempt');

// Re-entering the gate rebinds its handlers. An added listener would survive
// the second pass still holding the first promise's resolve.
assert.equal(listenerCount.get('pin-submit-btn') ?? 0, 0);
assert.equal(listenerCount.get('pin-input') ?? 0, 0);

// Every request on the path to the credential is bounded: a service that
// accepts the connection and then goes quiet must not leave a viewer on a
// spinner with no way forward.
for (const c of calls) assert.ok(c.signal, `unbounded fetch: ${c.url}`);

// ── 2. A share with no PIN gate never shows the gate ────────────────────────
await startFlow(() => json(200, { success: false, message: 'no gate here' }), 'plaintext');

await until('the plaintext share to settle', () => $('error-body').textContent !== '');
assert.ok($('pin-gate').hidden,
  'a share the server never asked a PIN for must not open the PIN gate');
assert.deepEqual(calls.map((c) => c.pin), [null, null],
  'no PIN was issued for this share, so none may be sent');

console.log('pin-retry selfcheck: all assertions passed');
