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
import { verifyIssuer, setIxTrustRootForTesting, canonicalKeyMapAt } from '../src/issuer.js';

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

// The registry is only trusted if it is signed by the pinned IX key. The real
// private half is a deployment secret, so the trust root is pointed at a
// throwaway keypair here and the mocked server signs with it. Serving an
// unsigned registry, which is what this file used to do, is now correctly
// refused, so every assertion below depends on this being right.
const ix = new ethers.Wallet(
  '0x4c0883a69102937d6231471b5dbb6204fe512961708279e1c4d19bcfd8c8b9a1');
setIxTrustRootForTesting(
  ethers.SigningKey.computePublicKey(ix.privateKey, false));

const canonical = (issuedAt, k) => canonicalKeyMapAt(issuedAt, k);
// Relative to now, never hardcoded: a fixed date drifts past the future-skew
// guard or the staleness rules and the file rots into a false failure.
const at = (msFromNow) => new Date(Date.now() + msFromNow).toISOString();
function signedRegistry(k = keys, issuedAt = at(-60_000)) {
  const sig = new ethers.SigningKey(ix.privateKey)
    .sign(ethers.keccak256(ethers.toUtf8Bytes(canonical(issuedAt, k)))).serialized;
  return { keys: k, issued_at: issuedAt, sig_v2: sig };
}
let registryBody = signedRegistry();
globalThis.fetch = async () => ({ ok: true, json: async () => registryBody });
// localStorage does not exist under node; the high-water mark is guarded for
// exactly this, but give it a real one so the rollback assertion can run.
const _store = new Map();
globalThis.localStorage = {
  getItem: (key) => (_store.has(key) ? _store.get(key) : null),
  setItem: (key, v) => _store.set(key, String(v)),
};

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

// ── v2: the signature that also covers status, expiry and verifier ──────────
//
// v1 signed the subject and the issue date alone, so an employer read a status
// and an expiry the signature had never seen. These assertions are the reason
// the wider payload exists, and the pinned literal is the cross-language
// contract: the same string is asserted in Go's
// TestCredentialProofV2PayloadIsTheAgreedBytes and Dart's vc_proof_v2_test.
{
  const { proofPayloadV2 } = await import('../src/issuer.js');

  assert.strictEqual(
    proofPayloadV2({
      verifierId: 'ix',
      credentialType: 'identity-verification',
      status: 'current',
      issuedAt: '2026-09-05T12:00:00Z',
      expiresAt: '2027-09-05T12:00:00Z',
      subject: { full_name: 'A B' },
    }),
    'ardis-vc2\nix\nidentity-verification\ncurrent\n'
      + '2026-09-05T12:00:00Z\n2027-09-05T12:00:00Z\n{"full_name":"A B"}',
    'the v2 payload drifted from the one Go and Dart sign');

  const subject = { licence: 'SIM-XX-1000' };
  const base = {
    verifier_id: 'ardis',
    credential_type: 'license',
    status: 'current',
    data: subject,
    issued_at: '2026-09-05T12:00:00Z',
    expires_at: '2027-09-05T12:00:00Z',
    full_disclosure: true,
  };
  const signV2 = (d) => new ethers.SigningKey(issuer.privateKey).sign(
    ethers.keccak256(ethers.toUtf8Bytes(proofPayloadV2({
      verifierId: d.verifier_id,
      credentialType: d.credential_type,
      status: d.status,
      issuedAt: d.issued_at,
      expiresAt: d.expires_at,
      subject: d.data,
    })))).serialized;

  const signed = { ...base, proof: { proofValue: 'x', proofValueV2: signV2(base) } };
  const good = await verifyIssuer(signed);
  assert.strictEqual(good.status, 'valid', 'a correctly signed v2 credential must verify');
  assert.ok(/covers the status/.test(good.detail),
    'a v2 verdict must tell the employer the status is covered');

  // The whole point: editing a field v1 left outside the signature must now
  // break it, rather than being reported as verified.
  for (const [field, value] of [['status', 'suspended'], ['expires_at', '2099-01-01T00:00:00Z'], ['credential_type', 'other']]) {
    const tampered = { ...signed, [field]: value };
    const verdict = await verifyIssuer(tampered);
    assert.strictEqual(verdict.status, 'invalid',
      `editing ${field} must invalidate the v2 signature, got ${verdict.status}`);
  }

  // A present-but-broken v2 must not quietly fall back to checking less.
  const brokenV2 = { ...signed, proof: { proofValue: sign(subject, base.issued_at, issuer), proofValueV2: '0x' + '11'.repeat(65) } };
  assert.strictEqual((await verifyIssuer(brokenV2)).status, 'invalid',
    'a failed v2 must not fall back to v1');

  console.log('issuer v2 selfcheck: ok');
}

// ── The registry itself has to be trusted before any issuer on it is ────────
//
// This is the control that was missing entirely: the viewer read body.keys and
// used it, so anyone who could answer that fetch served their own key for
// "ardis" and this page printed "signature verified against the registered
// key" over a document they had forged.
{
  const { fetchVerifierKeys, keyFetchFailure } = await import('../src/issuer.js');
  const subject = { licence: 'SIM-XX-1000' };
  const goodDoc = {
    verifier_id: 'ardis', credential_type: 'license', status: 'current',
    data: subject, issued_at: '2026-09-05T12:00:00Z', full_disclosure: true,
    proof: { proofValue: sign(subject, '2026-09-05T12:00:00Z', issuer) },
  };

  // Baseline: a properly signed registry still verifies the issuer.
  setIxTrustRootForTesting(ethers.SigningKey.computePublicKey(ix.privateKey, false));
  registryBody = signedRegistry();
  assert.strictEqual((await verifyIssuer(goodDoc)).status, 'valid',
    'a signed registry must still let a genuine credential verify');

  // An unsigned registry is refused, not silently trusted.
  setIxTrustRootForTesting(ethers.SigningKey.computePublicKey(ix.privateKey, false));
  registryBody = { keys };
  assert.strictEqual(await fetchVerifierKeys(), null,
    'a registry with no signature must be refused');
  assert.strictEqual(keyFetchFailure(), 'untrusted');

  // The attack: someone answers the fetch with their own key for "ardis".
  // Before this control, the forged credential below verified.
  const attacker = new ethers.Wallet(
    '0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba');
  const forgedKeys = {
    ardis: ethers.SigningKey.computePublicKey(attacker.privateKey, false),
  };
  const forgedSubject = { licence: 'TOTALLY-MADE-UP' };
  const forgedDoc = {
    verifier_id: 'ardis', credential_type: 'license', status: 'current',
    data: forgedSubject, issued_at: '2026-09-05T12:00:00Z', full_disclosure: true,
    proof: { proofValue: sign(forgedSubject, '2026-09-05T12:00:00Z', attacker) },
  };
  setIxTrustRootForTesting(ethers.SigningKey.computePublicKey(ix.privateKey, false));
  const forgedAt = at(-60_000);
  registryBody = { keys: forgedKeys, issued_at: forgedAt,
    sig_v2: new ethers.SigningKey(attacker.privateKey).sign(
      ethers.keccak256(ethers.toUtf8Bytes(
        canonicalKeyMapAt(forgedAt, forgedKeys)))).serialized };
  const verdict = await verifyIssuer(forgedDoc);
  assert.notStrictEqual(verdict.status, 'valid',
    'a registry signed by anyone but IX must never produce a valid verdict');
  assert.strictEqual(verdict.status, 'invalid',
    'and it must read as untrustworthy, not as a network problem');

  // A captured older registry must not roll a revoked key back in.
  setIxTrustRootForTesting(ethers.SigningKey.computePublicKey(ix.privateKey, false));
  registryBody = signedRegistry(keys, at(-60_000));
  assert.ok(await fetchVerifierKeys(), 'precondition: the current one is accepted');
  const { fetchVerifierKeys: refetch } = await import('../src/issuer.js');
  setIxTrustRootForTesting(ethers.SigningKey.computePublicKey(ix.privateKey, false));
  registryBody = signedRegistry(keys, at(-400 * 86400_000));
  assert.strictEqual(await refetch(), null,
    'a registry older than one already accepted is a rollback and must be refused');

  // A registry dated far in the future must not be stored, or one bad server
  // clock pins this browser above every legitimate registry that follows.
  setIxTrustRootForTesting(ethers.SigningKey.computePublicKey(ix.privateKey, false));
  _store.clear();
  registryBody = signedRegistry(keys, at(3 * 86400_000));
  assert.strictEqual(await (await import('../src/issuer.js')).fetchVerifierKeys(), null,
    'a registry dated days in the future must be refused');
  assert.strictEqual(_store.size, 0,
    'and it must not leave a high-water mark behind, or nothing verifies again');

  // Stale is not the same as forged, and must not be reported as tampering.
  setIxTrustRootForTesting(ethers.SigningKey.computePublicKey(ix.privateKey, false));
  _store.clear();
  registryBody = signedRegistry(keys, at(-60_000));
  assert.ok(await (await import('../src/issuer.js')).fetchVerifierKeys());
  setIxTrustRootForTesting(ethers.SigningKey.computePublicKey(ix.privateKey, false));
  registryBody = signedRegistry(keys, at(-400 * 86400_000));
  const staleVerdict = await verifyIssuer(goodDoc);
  assert.strictEqual(staleVerdict.status, 'error',
    'an old but genuinely IX-signed registry is not tampering');
  assert.ok(/older than one this browser/.test(staleVerdict.detail),
    'and it must say so rather than claim the signature was invalid');

  // Leave the trust root where the rest of the file expects it.
  setIxTrustRootForTesting(ethers.SigningKey.computePublicKey(ix.privateKey, false));
  registryBody = signedRegistry();
  console.log('registry trust selfcheck: ok');
}
