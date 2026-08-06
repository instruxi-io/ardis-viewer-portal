/**
 * Issuer signature verification for the Viewer Interface (SOW 2.4(c)(i)).
 *
 * The share signature (verify.js) proves the professional authorised THIS
 * share. It says nothing about who issued the credential. This module answers
 * the other half: was the payload signed by the verifier it claims to come
 * from.
 *
 * Algorithm matches the app exactly (lib/src/core/vc_verifier.dart):
 *   payload   = JSON.stringify(subject) + issuanceDate
 *   digest    = keccak256(payload)
 *   recovered = ecrecover(digest, proofValue)      // raw digest, no EIP-191
 *   valid     = recovered === the verifier's registered public key
 *
 * One structural limit, stated rather than hidden: selective disclosure prunes
 * fields out of the subject before it is shared. A signature over the whole
 * payload cannot verify against a subset of it, so when the professional
 * withholds anything the issuer signature is genuinely uncheckable here. That
 * is a property of the scheme, not a gap in this code, and the UI says so
 * instead of showing a red "invalid" that would imply tampering.
 * Verifying a partial disclosure needs a signature scheme built for it
 * (SD-JWT or BBS+), which is a change to what the vendor issues.
 */

import { ethers } from 'ethers';

const API_BASE = (import.meta.env.VITE_ARDIS_API_BASE || 'https://ardis-ms-ix.fly.dev')
  .replace(/\/+$/, '');

export const IssuerStatus = {
  VALID: 'valid',            // signed by the named verifier, checked
  INVALID: 'invalid',        // a signature is present and does not match
  UNSIGNED: 'unsigned',      // vendor has not signed this credential yet
  PARTIAL: 'partial',        // fields withheld, so the signature cannot apply
  UNKNOWN_ISSUER: 'unknown', // no registered key for this verifier_id
  ERROR: 'error',
};

let keyCache = null;

/** Registered verifier public keys, keyed by verifier_id. Cached per page. */
export async function fetchVerifierKeys() {
  if (keyCache) return keyCache;
  try {
    const res = await fetch(`${API_BASE}/api/v1/ardis/public/verifier-keys`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return {};
    const body = await res.json();
    keyCache = body.keys || {};
    return keyCache;
  } catch {
    return {};
  }
}

/**
 * @param {object} doc the disclosed credential document
 * @returns {Promise<{status: string, detail: string, verifierId: string}>}
 */
export async function verifyIssuer(doc) {
  const verifierId = doc?.verifier_id || 'ardis';
  const verifierName = doc?.verifier_name || verifierId;

  const proof = doc?.proof?.proofValue || '';
  if (!proof || proof === 'pending-cryptographic-verification') {
    return {
      status: IssuerStatus.UNSIGNED,
      verifierId,
      detail: `${verifierName} has not cryptographically signed this credential. `
        + 'The record is genuine to this share, but its issuer cannot be proven here.',
    };
  }

  // full_disclosure is written by the app. Treat its absence as partial: an
  // older share gives no way to know what was removed, and guessing "full"
  // would let a pruned document be reported as issuer-verified.
  if (doc.full_disclosure !== true) {
    return {
      status: IssuerStatus.PARTIAL,
      verifierId,
      detail: 'Some fields were withheld by the professional, so the issuer '
        + 'signature covers more than what is shown and cannot be checked '
        + 'against this subset.',
    };
  }

  const keys = await fetchVerifierKeys();
  const expected = keys[verifierId];
  if (!expected) {
    return {
      status: IssuerStatus.UNKNOWN_ISSUER,
      verifierId,
      detail: `No registered public key for "${verifierId}", so this issuer cannot be checked.`,
    };
  }

  // Match the app's field selection: W3C shape uses credentialSubject +
  // issuanceDate, the vendor shape uses data + issued_at.
  const isW3c = doc.credentialSubject !== undefined;
  const subject = (isW3c ? doc.credentialSubject : doc.data) || {};
  const issuedAt = (isW3c ? doc.issuanceDate : doc.issued_at) || '';

  try {
    const payload = JSON.stringify(subject) + issuedAt;
    const digest = ethers.keccak256(ethers.toUtf8Bytes(payload));
    const recovered = ethers.SigningKey.recoverPublicKey(digest, normalise(proof));
    const ok = recovered.toLowerCase().replace(/^0x/, '')
      === expected.toLowerCase().replace(/^0x/, '');
    return ok
      ? {
          status: IssuerStatus.VALID,
          verifierId,
          detail: `Signed by ${verifierName} and verified against their registered key.`,
        }
      : {
          status: IssuerStatus.INVALID,
          verifierId,
          detail: 'The signature does not match the registered key for this verifier. '
            + 'Treat this credential as unverified.',
        };
  } catch (e) {
    return {
      status: IssuerStatus.ERROR,
      verifierId,
      detail: `The issuer signature could not be read (${e.message || e}).`,
    };
  }
}

/** Accepts 0x-prefixed or bare hex, and 64-byte sigs missing the v byte. */
function normalise(sig) {
  let s = sig.startsWith('0x') ? sig : `0x${sig}`;
  if (s.length === 130) s = `${s}1b`; // 64 bytes, assume v = 27
  return s;
}
