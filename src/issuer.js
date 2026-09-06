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

// Optional chaining because import.meta.env only exists under Vite, and the
// selfcheck runs this module under plain node to test the shipped code path
// rather than a copy of it.
const API_BASE = (import.meta.env?.VITE_ARDIS_API_BASE || 'https://ardis-ms-ix.fly.dev')
  .replace(/\/+$/, '');

/**
 * The v2 proof payload. Byte-identical to credentialProofV2Payload in ardis-ms
 * and proofPayloadV2 in the app; the same literal is pinned in a test in all
 * three. v1 covered the subject and the issue date alone, so the status, the
 * expiry and the claimed verifier could all be edited between the issuer and
 * this screen without disturbing the signature.
 */
export function proofPayloadV2({ verifierId, credentialType, status, issuedAt, expiresAt, subject }) {
  return [
    'ardis-vc2',
    verifierId,
    credentialType,
    status,
    issuedAt,
    expiresAt,
    JSON.stringify(subject),
  ].join('\n');
}

export const IssuerStatus = {
  VALID: 'valid',            // signed by the named verifier, checked
  INVALID: 'invalid',        // a signature is present and does not match
  UNSIGNED: 'unsigned',      // vendor has not signed this credential yet
  PARTIAL: 'partial',        // fields withheld, so the signature cannot apply
  UNKNOWN_ISSUER: 'unknown', // no registered key for this verifier_id
  ERROR: 'error',
};

let keyCache = null;

/**
 * Registered verifier public keys, keyed by verifier_id. Cached per page.
 * Returns null when the directory could not be reached — an empty object would
 * be indistinguishable from "this issuer has no key", which downgraded a
 * perfectly good credential to "unknown issuer" on a dropped request.
 *
 * The request is bounded for the same reason every fetch in app.js is: a
 * directory that accepts the connection and then goes quiet never rejects on
 * its own. app.js awaits this verdict before it renders the documents and the
 * signer row, so a hung key fetch left the employer on "Checking the issuer
 * signature" with the rest of the share never appearing at all. A timeout
 * lands in the catch below and comes back as null, which is the honest answer:
 * the signature has not been checked, and the page carries on.
 */
/**
 * The IX platform signing key, pinned here the same way the app pins it.
 *
 * This is the trust root for the whole issuer verdict. Without it the registry
 * was taken on faith from whatever answered the fetch, so anyone able to answer
 * it (a hostile network, a compromised host or DNS) could serve their own key
 * for a verifier id and have this page print "signature verified against the
 * registered key" over a document they forged. The app has always checked this.
 * The employer's page, which is the surface a buyer actually looks at, did not.
 */
let IX_SIGNING_PUBKEY =
  '04938d191544007d075299483456b31404842b657660c04e3a072ca4daa88b3010847fea8a61c449bcd68dd999ea928cabed9a219549d8adda2cde125a99c4741c';

/**
 * Point the trust root at a throwaway key so the selfcheck can prove this
 * verification actually rejects a forged registry. The real IX private key is
 * a deployment secret and is not available to a test, so there is no way to
 * mint a valid registry signature without this seam. Nothing in the app calls
 * it, and the name is meant to make any other use obviously wrong.
 */
export function setIxTrustRootForTesting(pubKeyHex) {
  IX_SIGNING_PUBKEY = pubKeyHex;
  keyCache = null;
  lastKeyFetchFailure = null;
}

/** Why the last key fetch produced nothing: 'unreachable' or 'untrusted'.
 *  These are very different things to tell an employer, and collapsing both
 *  into "could not be reached" would describe a forged registry as a network
 *  blip. */
let lastKeyFetchFailure = null;
export const keyFetchFailure = () => lastKeyFetchFailure;

/** Byte for byte what ardis-ms signs. Must match canonicalVerifierKeysAt in Go
 *  and VerifierKeysService.canonicalKeyMapAt in Dart. */
export function canonicalKeyMapAt(issuedAt, keys) {
  const ids = Object.keys(keys).sort();
  return `${issuedAt}\n${ids.map((id) => `${id}:${keys[id]}`).join('\n')}`;
}

/** Highest issue time this browser has already trusted, so a captured older
 *  registry cannot be replayed to put a revoked key back. Mirrors the app's
 *  high-water mark. Storage being unavailable must not break verification, so
 *  every access is guarded. */
const HWM_KEY = 'ardis:verifier-keys:issued-at';
function highWaterMark() {
  try {
    return localStorage.getItem(HWM_KEY);
  } catch {
    return null;
  }
}
function setHighWaterMark(issuedAt) {
  try {
    localStorage.setItem(HWM_KEY, issuedAt);
  } catch {
    /* private mode: we simply lose rollback protection, not correctness */
  }
}

export async function fetchVerifierKeys() {
  if (keyCache) return keyCache;
  try {
    const res = await fetch(`${API_BASE}/api/v1/ardis/public/verifier-keys`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) {
      lastKeyFetchFailure = 'unreachable';
      return null;
    }
    const body = await res.json();
    const keys = body.keys || {};
    const issuedAt = body.issued_at;
    const sig = body.sig_v2;

    // Only sig_v2 is accepted. v1 covered the key map alone, so every registry
    // ever served stayed valid for ever and a captured copy could reinstate a
    // revoked issuer. A server that speaks only v1 is treated as unsigned.
    if (!sig || !issuedAt) {
      lastKeyFetchFailure = 'untrusted';
      return null;
    }

    const digest = ethers.keccak256(
      ethers.toUtf8Bytes(canonicalKeyMapAt(issuedAt, keys)));
    const want = IX_SIGNING_PUBKEY.toLowerCase().replace(/^0x/, '');
    const signed = candidates(sig).some((c) => {
      try {
        return ethers.SigningKey.recoverPublicKey(digest, c)
          .toLowerCase().replace(/^0x/, '') === want;
      } catch {
        return false;
      }
    });
    if (!signed) {
      lastKeyFetchFailure = 'untrusted';
      return null;
    }

    // A registry dated far in the future must not be stored, or one bad clock
    // on the server pins this browser above every legitimate registry that
    // follows and the employer can never verify anything again. The mark only
    // ever moves up, so a poisoned value is permanent.
    const issued = Date.parse(issuedAt);
    const DAY = 86400000;
    if (!Number.isFinite(issued) || issued > Date.now() + DAY) {
      lastKeyFetchFailure = 'untrusted';
      return null;
    }

    // Never move backwards. An older registry is a rollback whatever this
    // machine thinks the time is, which is why the comparison is against what
    // we have already accepted rather than against the clock. Compared as
    // instants, not as strings: the server could legitimately change precision
    // or offset format and a lexical compare would read that as a rollback.
    const seen = Date.parse(highWaterMark() ?? '');
    if (Number.isFinite(seen) && issued < seen) {
      // This one IS signed by us, it is just old, so calling it unsigned
      // would be a lie in the one place an employer is deciding whether to
      // trust a person's licence.
      lastKeyFetchFailure = 'stale';
      return null;
    }
    setHighWaterMark(issuedAt);

    lastKeyFetchFailure = null;
    keyCache = keys;
    return keyCache;
  } catch {
    lastKeyFetchFailure = 'unreachable';
    return null;
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
  if (keys === null) {
    const why = keyFetchFailure();
    const detail = {
      untrusted:
        'The issuer key directory did not carry a valid signature from '
        + 'Instruxi, so no issuer on it can be trusted. Do not rely on this '
        + 'credential.',
      stale:
        'The issuer key directory came back older than one this browser has '
        + 'already seen, so it was refused. Reload to try again.',
    }[why] ?? 'The issuer key directory could not be reached, so the signature '
      + 'has not been checked yet. Reload to try again.';
    return {
      // Only a bad signature is a reason to distrust the credential. Stale or
      // unreachable both mean "not checked yet", which is an error state.
      status: why === 'untrusted' ? IssuerStatus.INVALID : IssuerStatus.ERROR,
      verifierId,
      detail,
    };
  }
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
    const want = expected.toLowerCase().replace(/^0x/, '');
    // A signature that cannot even be parsed is a signature that does not
    // match. Letting the recovery throw made a malformed proofValue come back
    // as ERROR, which renders as "could not be checked, reload to try again"
    // and invites the employer to keep trying a credential that will never
    // verify. Only a genuine fault outside this loop is an error.
    const recovers = (payload, sig) => {
      const digest = ethers.keccak256(ethers.toUtf8Bytes(payload));
      return candidates(sig).some((s) => {
        try {
          return ethers.SigningKey.recoverPublicKey(digest, s)
            .toLowerCase().replace(/^0x/, '') === want;
        } catch {
          return false;
        }
      });
    };

    // Prefer the signature that also covers the status, the expiry and the
    // verifier. A v2 that is present and fails is a reason to distrust the
    // document, not a reason to quietly check less of it, so there is no
    // fallback to v1 in that case.
    const proofV2 = doc?.proof?.proofValueV2 || '';
    if (proofV2) {
      const wideOk = recovers(proofPayloadV2({
        verifierId,
        credentialType: doc.credential_type || '',
        status: doc.status || '',
        issuedAt,
        expiresAt: (isW3c ? doc.expirationDate : doc.expires_at) || '',
        subject,
      }), proofV2);
      return wideOk
        ? {
            status: IssuerStatus.VALID,
            verifierId,
            detail: `Signature verified against the registered key for "${verifierId}". `
              + 'This signature covers the status, the issue and expiry dates '
              + 'and the verifier, so those values are the ones the issuer signed.',
          }
        : {
            status: IssuerStatus.INVALID,
            verifierId,
            detail: 'The signature does not match the registered key for this verifier. '
              + 'Treat this credential as unverified.',
          };
    }

    const payload = JSON.stringify(subject) + issuedAt;
    const ok = recovers(payload, proof);
    return ok
      ? {
          status: IssuerStatus.VALID,
          verifierId,
          // The verifier ID, not verifier_name. The name is free text in the
          // document and is NOT covered by the signature, so printing it here
          // let any genuinely-signed credential be relabelled: keep the real
          // verifier_id so the signature still checks out, set verifier_name
          // to a state nursing board, and the employer reads "Signed by
          // California Board of Registered Nursing and verified against their
          // registered key". The ID is bound, because it selects the key the
          // signature is checked against.
          detail: `Signature verified against the registered key for "${verifierId}". `
            + 'The issuer name, status and dates shown above are part of the '
            + 'document and are not covered by this signature.',
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

/**
 * The signatures to try, from 0x-prefixed or bare hex. A 64-byte signature has
 * no v byte and v cannot be derived from r and s, so both recovery values are
 * candidates: assuming 27 reported roughly half of all such signatures as
 * forgeries, which is the red "treat this as unverified" box shown for real
 * tampering. Trying both costs one extra ecrecover and rejects only when
 * neither matches.
 */
function candidates(sig) {
  const body = sig.replace(/^0x/, '');
  return body.length === 128 ? [`0x${body}1b`, `0x${body}1c`] : [`0x${body}`];
}
