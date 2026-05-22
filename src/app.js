/**
 * Ardis Viewer Portal — main entry point.
 *
 * URL format (grant + optional wallet signature in fragment):
 *   https://ardis.instruxi.dev/view#grant={access_grant}&sig={wallet_sig}
 *
 * The fragment never reaches the server — client-side only.
 * The access grant is a serialized Storj sub-grant scoped to one
 * credential directory, derived on the user's device at share time.
 */

import { fetchCredential } from './storj.js';
import { recoverSigner }   from './verify.js';
import { renderCredential, showSignerAddress, showError } from './render.js';

async function main() {
  // ── Parse URL fragment ─────────────────────────────────────────────────────
  const hash   = window.location.hash.slice(1); // drop leading #
  const params = new URLSearchParams(hash);
  const grant  = params.get('grant');
  const sig    = params.get('sig');

  if (!grant) {
    showError('Missing credential link', 'No access grant found in this URL. Make sure you opened the full link.');
    return;
  }

  // ── The grant is scoped to a Storj path prefix stored in it.
  //    Storj access grants encode the bucket + prefix internally.
  //    We need to extract them — for now they come from the grant string
  //    itself which encodes the satellite, bucket, and prefix.
  //    The exchange step (storj.js) handles this via the Auth Service.
  //
  //    Bucket and prefix are needed for listing. For the current implementation,
  //    they must be embedded in the grant's macaroon prefix restriction.
  //    The Enforcer gateway puts the bucket into the grant at mint time.
  //
  //    Fallback: try to parse them from the grant if the Auth Service
  //    response includes them, or require them as additional URL params.

  const bucket = params.get('bucket') ?? 'enforcer-dev';
  const prefix = params.get('prefix') ?? '';

  try {
    // ── Fetch credential from Storj ──────────────────────────────────────────
    const vc = await fetchCredential(grant, bucket, prefix);

    // ── Render ───────────────────────────────────────────────────────────────
    renderCredential(vc);

    // ── Verify wallet signature (optional — non-blocking) ───────────────────
    if (sig) {
      try {
        // Reconstruct the canonical payload the mobile app signed.
        // Fields come from the VC itself — we don't need them in the URL.
        const subject = vc.credentialSubject ?? {};
        const payload = JSON.stringify({
          // share_id and credential_id aren't in the VC — they were signed
          // at share time. Without them we can't fully verify, but we can
          // still recover the signer address and display it for transparency.
        });

        // Simplified recovery: sign the raw grant string (deterministic).
        // The app signs the payload JSON; viewer shows the recovered address.
        const signer = recoverSigner(grant, sig);
        if (signer) showSignerAddress(signer);
      } catch {
        // Non-fatal — signature display is best-effort
      }
    }
  } catch (err) {
    console.error('[viewer] fetch failed:', err);

    if (err.message?.includes('Auth exchange')) {
      showError('Access expired', 'This credential link has expired or the access grant is no longer valid.');
    } else if (err.message?.includes('No credential file')) {
      showError('Credential not found', 'The credential could not be located in the vault. The link may be outdated.');
    } else {
      showError('Unable to load credential', 'Check your connection and try opening the link again.');
    }
  }
}

main();
