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
import {
  renderCredential,
  showSignerAddress,
  showError,
  showLandingMessage,
} from './render.js';

/**
 * Extract the share GUID from the URL. Only /view/{guid} (or ?guid=...) is a
 * credential-fetch path. Every other route is a landing page (Stripe success,
 * Stripe cancel, KYC return) handled separately.
 */
function parseShareId() {
  const parts = window.location.pathname.split('/').filter(Boolean);
  const viewIdx = parts.indexOf('view');
  if (viewIdx >= 0) return parts[viewIdx + 1] || null;
  return new URLSearchParams(window.location.search).get('guid');
}

/**
 * Match the current path against known non-credential landing routes returned
 * to the browser by Stripe Checkout / Stripe Identity. Each landing page
 * fires a credpass:// deep link to hand control back to the app and shows
 * the matching success or cancel state if the user stays in the browser.
 */
function matchLandingRoute() {
  const path = window.location.pathname.toLowerCase();
  if (path.startsWith('/billing/success')) {
    return {
      kind: 'success',
      title: 'Subscription complete',
      body: 'Welcome aboard. Returning you to the Ardis app to unlock your vault.',
      ctaLabel: 'Open Ardis',
      deepLink: 'credpass://subscribe/complete',
    };
  }
  if (path.startsWith('/billing/cancel')) {
    return {
      kind: 'cancel',
      title: 'Checkout cancelled',
      body: 'No charge was made. You can try again from inside the Ardis app whenever you are ready.',
      ctaLabel: 'Back to Ardis',
      deepLink: 'credpass://subscribe/cancel',
    };
  }
  if (path.startsWith('/kyc/return') || path.startsWith('/kyc/success')) {
    return {
      kind: 'success',
      title: 'Identity verified',
      body: 'You are good to go. Returning you to the Ardis app to continue.',
      ctaLabel: 'Open Ardis',
      deepLink: 'credpass://kyc/complete',
    };
  }
  return null;
}

async function main() {
  const landing = matchLandingRoute();
  if (landing) {
    showLandingMessage(landing);
    return;
  }

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
