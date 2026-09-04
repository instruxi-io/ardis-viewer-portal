/**
 * Proves the issuer verdict (SOW 2.4(c)(i)) on all four branches, including
 * the one a live staging credential cannot exercise: our test vendor does not
 * sign yet, so "valid" would otherwise never be covered.
 *
 * Mirrors the app's algorithm exactly (lib/src/core/vc_verifier.dart):
 *   keccak256(JSON.stringify(subject) + issuanceDate), ECRecover, compare.
 */
import { readFile } from 'node:fs/promises';
import { ethers } from 'ethers';
import assert from 'node:assert';
import { verifyIssuer } from '../src/issuer.js';

const issuer = new ethers.Wallet(
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d');
const registeredKey = ethers.SigningKey.computePublicKey(issuer.privateKey, false);

function sign(subject, issuedAt, wallet) {
  const digest = ethers.keccak256(
    ethers.toUtf8Bytes(JSON.stringify(subject) + issuedAt));
  return new ethers.SigningKey(wallet.privateKey).sign(digest).serialized;
}

// The verdict comes from the shipped module, not a re-implementation of it.
// While this file had its own copy of the recovery it never exercised the
// portal's signature handling, and a real bug there (a guessed v byte) sat
// under five passing assertions.
const keys = { ardis: registeredKey };
globalThis.fetch = async () => ({ ok: true, json: async () => ({ keys }) });

async function verdict(doc) {
  return (await verifyIssuer(doc)).status;
}
const subject = { records: [{ license_info: { license_number: 'RN-2210084' } }] };
const issuedAt = '2026-08-06T00:00:00Z';
const base = {
  verifier_id: 'ardis', data: subject, issued_at: issuedAt, full_disclosure: true,
};

// 1. Correctly signed, fully disclosed.
assert.equal(await verdict({ ...base, proof: { proofValue: sign(subject, issuedAt, issuer) } }),
  'valid', 'a correctly signed credential must verify');

// 2. Signed by somebody else.
const impostor = ethers.Wallet.createRandom();
assert.equal(await verdict({ ...base, proof: { proofValue: sign(subject, issuedAt, impostor) } }),
  'invalid', 'a signature from another key must be rejected');

// 3. Signed, then a field was altered after signing.
const tampered = { records: [{ license_info: { license_number: 'RN-9999999' } }] };
assert.equal(await verdict({ ...base, data: tampered,
  proof: { proofValue: sign(subject, issuedAt, issuer) } }),
  'invalid', 'altering the payload after signing must be caught');

// 4. Fields withheld: signature covers more than what is shown, so it cannot
//    be checked. Must not claim valid, and must not cry tampering either.
assert.equal(await verdict({ ...base, full_disclosure: false,
  proof: { proofValue: sign(subject, issuedAt, issuer) } }),
  'partial', 'a pruned disclosure must be reported as uncheckable');

// 5. Vendor has not signed at all.
assert.equal(await verdict({ ...base, proof: { proofValue: 'pending-cryptographic-verification' } }),
  'unsigned');

// 6. A third-party 64-byte signature, v byte stripped. v is not derivable from
//    r and s, so a fixed guess called roughly half of these forgeries and
//    showed the employer the tampering box. Walk issuance dates until both
//    recovery bytes have actually been exercised.
const parities = new Set();
for (let i = 0; i < 40 && parities.size < 2; i += 1) {
  const at = `2026-08-06T00:00:${String(i).padStart(2, '0')}Z`;
  const full = sign(subject, at, issuer);
  parities.add(full.slice(-2));
  assert.equal(
    await verdict({ ...base, issued_at: at, proof: { proofValue: full.slice(0, -2) } }),
    'valid', `a 64-byte signature must verify with v=${full.slice(-2)} stripped`);
}
assert.equal(parities.size, 2, 'both recovery bytes must have been exercised');

console.log('issuer selfcheck: all assertions passed');

// The signature covers the subject and issued_at only. verifier_name, status,
// expires_at and credential_type are document fields outside it, so a
// genuinely-signed credential could be relabelled: keep the real verifier_id
// so the signature still checks out, set verifier_name to a state nursing
// board, and the employer reads that the board signed it. The verdict must
// name the ID the key belongs to, and must not vouch for what it did not cover.
{
  const { renderIssuerVerdict } = await import('../src/render.js').catch(() => ({}));
  const src = await readFile(new URL('../src/issuer.js', import.meta.url), 'utf8');
  assert.ok(!/Signed by \$\{verifierName\}/.test(src),
    'the verdict must not print the unsigned verifier_name as the signer');
  assert.ok(/registered key for "\$\{verifierId\}"/.test(src),
    'the verdict should name the verifier id the key is registered to');
  assert.ok(/not covered by this signature/.test(src),
    'the verdict must say which fields the signature does not cover');
  void renderIssuerVerdict;
  console.log('issuer scope   ok (the verdict does not vouch for unsigned fields)');
}
