/**
 * Ardis Viewer Portal — main entry point.
 *
 * URL format (opaque GUID, no secrets in the URL):
 *   https://ardis.instruxi.dev/view/{guid}
 *
 * The viewer calls the Ardis public share endpoint, which holds the Storj
 * access grant server-side and returns only the credential JSON. The grant is
 * never exposed to the browser, request logs, or anyone who copies the link.
 */

import { fetchSharedCredential } from './api.js';
import { recoverSigner } from './verify.js';
import { renderCredential, showSignerAddress, showError } from './render.js';

/**
 * Extract the share GUID from the URL. Supports /view/{guid}, /{guid}, and a
 * ?guid= query fallback.
 */
function parseShareId() {
  const parts = window.location.pathname.split('/').filter(Boolean);
  const viewIdx = parts.indexOf('view');
  if (viewIdx >= 0) return parts[viewIdx + 1] || null;
  if (parts.length > 0) return parts[parts.length - 1];
  return new URLSearchParams(window.location.search).get('guid');
}

async function main() {
  const guid = parseShareId();
  if (!guid) {
    showError('Missing credential link', 'This URL has no share code. Make sure you opened the full link you were sent.');
    return;
  }

  let data;
  try {
    data = await fetchSharedCredential(guid);
  } catch (err) {
    if (err.status === 404 || err.code === 'not_found') {
      showError('Link not found', 'This credential link does not exist. Check that you copied the full link.');
    } else if (err.code === 'already_viewed') {
      showError('Link already used', 'This is a single-use link and it has already been opened.');
    } else if (err.status === 410 || err.code === 'expired') {
      showError('Link expired', 'This credential link has expired. Ask the holder to send a new one.');
    } else {
      showError('Unable to load credential', err.message || String(err));
    }
    return;
  }

  const vc = data.credential;
  if (!vc || typeof vc !== 'object') {
    showError('Unable to load credential', 'The credential could not be read.');
    return;
  }

  renderCredential(vc);

  // Best-effort signer display when the server includes the wallet signature.
  const sig = data.signature;
  if (sig && sig.payload && sig.value) {
    try {
      const signer = recoverSigner(sig.payload, sig.value);
      if (signer) showSignerAddress(signer);
    } catch {
      /* signature display is non-fatal */
    }
  }
}

main();
