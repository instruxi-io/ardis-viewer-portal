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
process.env.TZ = 'America/Los_Angeles'; // set before Node builds any Date below
assert.equal(fmt('2026-07-14', 'date'), 'July 14, 2026',
  'a date-only value must show the day it was issued, in every timezone');
assert.equal(fmt('2026-01-01', 'date'), 'January 1, 2026',
  'new year is the hardest case for the off-by-one');

// A real timestamp still renders in the viewer's own time.
assert.match(fmt('2026-07-14T18:30:00Z', 'date-time'), /July 14, 2026/);

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

console.log('render selfcheck: all assertions passed');
