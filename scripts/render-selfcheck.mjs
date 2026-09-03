/**
 * Render self-check: the two things this page must never get wrong.
 *
 *   1. A calendar date is the same day for every viewer, east or west of UTC.
 *   2. A status word we do not recognise never renders as a green "Active".
 *
 * Run: npm run check (plain Node 18+, no DOM needed — both functions are pure).
 */

import assert from 'node:assert/strict';
import { fmt, credentialStatus } from '../src/render.js';

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

console.log(`render selfcheck: all assertions passed (TZ=${process.env.TZ || 'system'})`);
