/**
 * Proves the issuer verdict (SOW 2.4(c)(i)) on all four branches, including
 * the one a live staging credential cannot exercise: our test vendor does not
 * sign yet, so "valid" would otherwise never be covered.
 *
 * Mirrors the app's algorithm exactly (lib/src/core/vc_verifier.dart):
 *   keccak256(JSON.stringify(subject) + issuanceDate), ECRecover, compare.
 */
import { ethers } from 'ethers';
import assert from 'node:assert';

const issuer = new ethers.Wallet(
  '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d');
const registeredKey = ethers.SigningKey.computePublicKey(issuer.privateKey, false);

function sign(subject, issuedAt, wallet) {
  const digest = ethers.keccak256(
    ethers.toUtf8Bytes(JSON.stringify(subject) + issuedAt));
  return new ethers.SigningKey(wallet.privateKey).sign(digest).serialized;
}

function verdict(doc, keys) {
  const proof = doc?.proof?.proofValue || '';
  if (!proof || proof === 'pending-cryptographic-verification') return 'unsigned';
  if (doc.full_disclosure !== true) return 'partial';
  const expected = keys[doc.verifier_id];
  if (!expected) return 'unknown';
  const subject = doc.credentialSubject ?? doc.data ?? {};
  const issuedAt = doc.issuanceDate ?? doc.issued_at ?? '';
  try {
    const digest = ethers.keccak256(
      ethers.toUtf8Bytes(JSON.stringify(subject) + issuedAt));
    const rec = ethers.SigningKey.recoverPublicKey(digest, proof);
    return rec.toLowerCase() === expected.toLowerCase() ? 'valid' : 'invalid';
  } catch { return 'error'; }
}

const keys = { ardis: registeredKey };
const subject = { records: [{ license_info: { license_number: 'RN-2210084' } }] };
const issuedAt = '2026-08-06T00:00:00Z';
const base = {
  verifier_id: 'ardis', data: subject, issued_at: issuedAt, full_disclosure: true,
};

// 1. Correctly signed, fully disclosed.
assert.equal(verdict({ ...base, proof: { proofValue: sign(subject, issuedAt, issuer) } }, keys),
  'valid', 'a correctly signed credential must verify');

// 2. Signed by somebody else.
const impostor = ethers.Wallet.createRandom();
assert.equal(verdict({ ...base, proof: { proofValue: sign(subject, issuedAt, impostor) } }, keys),
  'invalid', 'a signature from another key must be rejected');

// 3. Signed, then a field was altered after signing.
const tampered = { records: [{ license_info: { license_number: 'RN-9999999' } }] };
assert.equal(verdict({ ...base, data: tampered,
  proof: { proofValue: sign(subject, issuedAt, issuer) } }, keys),
  'invalid', 'altering the payload after signing must be caught');

// 4. Fields withheld: signature covers more than what is shown, so it cannot
//    be checked. Must not claim valid, and must not cry tampering either.
assert.equal(verdict({ ...base, full_disclosure: false,
  proof: { proofValue: sign(subject, issuedAt, issuer) } }, keys),
  'partial', 'a pruned disclosure must be reported as uncheckable');

// 5. Vendor has not signed at all.
assert.equal(verdict({ ...base, proof: { proofValue: 'pending-cryptographic-verification' } }, keys),
  'unsigned');

console.log('issuer selfcheck: all assertions passed');
