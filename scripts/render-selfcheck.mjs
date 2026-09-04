/**
 * Render self-check: the two things this page must never get wrong.
 *
 *   1. A calendar date is the same day for every viewer, east or west of UTC.
 *   2. A status word we do not recognise never renders as a green "Active".
 *   3. The issuer verdict is never blank while the finished card is on screen.
 *
 * Run: npm run check (plain Node 18+; the third check drives renderCredential
 * against the small stub document below rather than pulling in a DOM library).
 */

import assert from 'node:assert/strict';
import { fmt, credentialStatus, renderCredential, renderIssuerVerdict } from '../src/render.js';

// ── 1. Date-only values are calendar days, not instants ─────────────────────
// The timezone comes from the environment (see the tz script in package.json).
// Setting process.env.TZ here would be a lie: Node has already initialised its
// timezone by the time this line runs.
assert.equal(fmt('2026-07-14', 'date'), 'July 14, 2026',
  'a date-only value must show the day it was issued, in every timezone');
assert.equal(fmt('2026-01-01', 'date'), 'January 1, 2026',
  'new year is the hardest case for the off-by-one');

// A real timestamp still renders, with its time, in the viewer's own clock.
// "Issued" and "Expires" are called with NO format argument, so the shape of
// the value is what decides — matching only date-only strings printed a raw
// RFC3339 string on the employer's page.
for (const iso of ['2026-07-14T18:30:00Z', '2026-07-14T18:30:00.000Z',
                   '2026-07-14 18:30:00']) {
  const out = fmt(iso);
  assert.ok(!out.includes('T') && !out.includes('Z'),
    `a timestamp must not render raw: ${iso} -> ${out}`);
  assert.match(out, /2026/);
  assert.match(out, /:\d\d/, `a timestamp must keep its time: ${iso} -> ${out}`);
}
// A timestamp is an instant, so which calendar day it lands on DEPENDS on the
// viewer's timezone — that is correct, and the opposite of a date-only value.
// Assert the semantics, not a fixed string: it must agree with the platform's
// own rendering of that instant.
{
  const iso = '2026-07-14T18:30:00Z';
  const expected = new Date(iso).toLocaleString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
    hour: 'numeric', minute: '2-digit',
  });
  assert.equal(fmt(iso, 'date-time'), expected);
  assert.equal(fmt(iso), expected, 'no format argument must behave the same');
}
// An explicit date format on a timestamp drops the time deliberately.
assert.ok(!fmt('2026-07-14T18:30:00Z', 'date').includes(':'));

// ── 2. Zero and false are answers, not missing data ─────────────────────────
assert.equal(fmt(0), '0', 'zero is a value, not "no data"');
assert.equal(fmt(false), 'No', 'false is a value, not "no data"');
assert.equal(fmt(''), '—');
assert.equal(fmt(null), '—');
assert.equal(fmt(undefined), '—');

// A field that merely looks like a date must not print "Invalid Date".
assert.equal(fmt('2026-13-45'), '2026-13-45');

// ── 3. Status: the claim first, the date second, green only when earned ─────
const future = '2030-01-01';
const past   = '2020-01-01';

assert.equal(credentialStatus({ status: 'current', expires_at: future }).statusText, 'Active');
assert.equal(credentialStatus({ status: 'suspended', expires_at: future }).statusText, 'Suspended');
assert.equal(credentialStatus({ status: 'current', expires_at: past }).statusText, 'Expired');

// The whole point: an unknown word is shown, never painted green.
for (const word of ['revoked', 'lapsed', 'under_review', 'pending']) {
  const r = credentialStatus({ status: word, expires_at: future });
  assert.notEqual(r.statusClass, 'status-active',
    `"${word}" must never render as Active`);
  assert.ok(r.statusText.length > 0);
}
assert.equal(credentialStatus({ status: 'under_review', expires_at: future }).statusText,
  'Under review');

// Whitespace around a status word must not turn a valid credential orange.
assert.equal(credentialStatus({ status: ' current ', expires_at: future }).statusClass,
  'status-active');

// A date-only expiry is good through the end of that day, everywhere.
const expiryDay = '2026-07-14';
assert.equal(
  credentialStatus({ status: 'current', expires_at: expiryDay },
    new Date('2026-07-14T12:00:00Z')).statusText,
  'Active', 'a licence is still valid during its final day');
assert.equal(
  credentialStatus({ status: 'current', expires_at: expiryDay },
    new Date('2026-07-15T00:00:01Z')).statusText,
  'Expired', 'and expired once that day is over');

// ── 4. The verdict box is on screen before the card is ──────────────────────
// renderCredential reveals a finished-looking card with a green status pill
// while the issuer check is still in flight. If the verdict box were still
// hidden at that instant, the page would be indistinguishable from one whose
// check came back clean.
//
// ponytail: a hand-written stub document, not jsdom, because these two
// functions only set text, classes and children. Ceiling: it knows nothing
// about layout or CSS. Upgrade path if that ever matters is jsdom.
class StubEl {
  constructor() { this.classes = new Set(); this.kids = []; this.textContent = ''; this.hidden = false; }
  get className() { return [...this.classes].join(' '); }
  set className(v) { this.classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get classList() {
    return {
      add: (c) => this.classes.add(c),
      remove: (c) => { this.classes.delete(c); this.onRemove?.(c); },
      contains: (c) => this.classes.has(c),
    };
  }
  get innerHTML() { return ''; }
  set innerHTML(_) { this.kids = []; }
  append(...n) { this.kids.push(...n); }
  appendChild(n) { this.kids.push(n); return n; }
  replaceChildren(...n) { this.kids = n; }
  setAttribute() {}
  get text() { return [this.textContent, ...this.kids.map(k => k.text)].join(' ').trim(); }
}

const byId = new Map();
globalThis.document = {
  getElementById(id) {
    if (!byId.has(id)) byId.set(id, new StubEl());
    return byId.get(id);
  },
  querySelector: () => new StubEl(),
  createElement: () => new StubEl(),
};

const verdict = document.getElementById('issuer-verdict');
verdict.hidden = true;                       // as declared in index.html
const card = document.getElementById('credential');
card.classes.add('hidden');
let atReveal = null;
card.onRemove = (c) => { if (c === 'hidden') atReveal = { hidden: verdict.hidden, text: verdict.text, cls: verdict.className }; };

renderCredential({
  credential_type: 'license',
  data: { provider_name: 'A. Nurse' },
  status: 'current',
  issued_at: '2026-01-01',
  expires_at: '2030-01-01',
});

assert.ok(atReveal, 'renderCredential must reveal the card');
assert.equal(atReveal.hidden, false,
  'the issuer verdict must be on screen before the card is, not after the check returns');
assert.match(atReveal.text, /issuer signature/i,
  'the pending verdict must say the issuer check is still running');
assert.ok(!atReveal.cls.includes('issuer-ok'),
  'an unfinished check must never look verified');

// And the real verdict replaces it rather than stacking under it.
renderIssuerVerdict({ status: 'invalid', detail: 'Signature does not match.' });
assert.ok(verdict.className.includes('issuer-bad'));
assert.ok(!verdict.text.match(/appears here in a moment/),
  'the pending copy must not survive the real verdict');

console.log(`render selfcheck: all assertions passed (TZ=${process.env.TZ || 'system'})`);
