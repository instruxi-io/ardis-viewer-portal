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

import { fetchSharedCredential, fetchShareDocument, fetchSchema } from './api.js';
import { recoverSigner } from './verify.js';
import {
  renderCredential,
  renderDocuments,
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
  if (path.startsWith('/billing/order-success')) {
    return {
      kind: 'success',
      title: 'Payment confirmed',
      body: 'Your verification order is being processed. Return to the Ardis app to track progress.',
      ctaLabel: 'Back to Ardis',
      deepLink: 'credpass://order/complete',
    };
  }
  if (path.startsWith('/billing/success')) {
    return {
      kind: 'success',
      title: 'Subscription complete',
      body: 'Welcome aboard. Returning you to the Ardis app to unlock your vault.',
      ctaLabel: 'Open Ardis',
      deepLink: 'credpass://subscribe/complete',
    };
  }
  if (path.startsWith('/billing/portal-return')) {
    return {
      kind: 'success',
      title: 'All done',
      body: 'Your billing settings have been updated. Return to the Ardis app to continue.',
      ctaLabel: 'Back to Ardis',
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

  // Peek at Content-Type first — personal documents (PDF, image) are served
  // as binary with their mime type, not as JSON credential wrappers.
  const API_BASE = (import.meta.env.VITE_ARDIS_API_BASE || 'https://gateway.instruxi.dev').replace(/\/+$/, '');
  const ENFORCER_BASE = (import.meta.env.VITE_ENFORCER_BASE || 'https://gateway-staging.instruxi.dev/api/v1/enforcer').replace(/\/+$/, '');
  const VIEWER_TENANT = 'CredPass-Viewer-Portal';
  const shareUrl = `${API_BASE}/api/v1/ardis/public/share/${encodeURIComponent(guid)}`;

  async function fetchShare(bearerToken) {
    const headers = { Accept: 'application/json, */*' };
    if (bearerToken) headers['Authorization'] = `Bearer ${bearerToken}`;
    return fetch(shareUrl, { headers });
  }

  // Handles a 401 response — runs OTP flow and retries. Returns the final
  // response (post-auth) or null if the flow was abandoned.
  async function handleOTPChallenge(resp) {
    let body = null;
    try { body = await resp.json(); } catch { /* ignore */ }
    if (!body?.otp_required) return null;
    const token = await runOTPFlow(ENFORCER_BASE, VIEWER_TENANT, body.email_hint);
    if (!token) return null;
    try {
      return await fetchShare(token);
    } catch {
      showError('Unable to load', 'Could not reach the credential service. Check your connection.');
      return null;
    }
  }

  let rawResp;
  try {
    rawResp = await fetchShare(null);
  } catch (e) {
    showError('Unable to load', 'Could not reach the credential service. Check your connection.');
    return;
  }

  // First OTP challenge — unauthenticated request returned 401.
  if (rawResp.status === 401) {
    rawResp = await handleOTPChallenge(rawResp);
    if (!rawResp) return;
    // Second 401 means the token expired or was rejected immediately after verify.
    if (rawResp.status === 401) {
      showError('Session expired', 'Your verification session expired. Please refresh the page and verify again.');
      return;
    }
  }

  const contentType = rawResp.headers.get('Content-Type') || '';

  if (!contentType.includes('application/json')) {
    // Binary personal document
    if (!rawResp.ok) { showError('Unable to load document', `HTTP ${rawResp.status}`); return; }
    const blob = await rawResp.blob();
    const blobUrl = URL.createObjectURL(blob);
    const ext = contentType.includes('pdf') ? '.pdf' : contentType.includes('image') ? '.jpg' : '';
    document.getElementById('loading').classList.add('hidden');
    const container = document.getElementById('credential');
    container.classList.remove('hidden');
    document.getElementById('cred-title').textContent = 'Shared Document';
    document.getElementById('cred-issuer').textContent = '';
    document.querySelector('.credential-type-icon').textContent = contentType.includes('pdf') ? '📄' : '🖼';
    document.getElementById('cred-fields').innerHTML =
      `<a href="${blobUrl}" download="document${ext}" style="display:inline-block;margin-top:8px;padding:10px 20px;background:var(--gold,#CBAF7C);color:#0A0F18;font-weight:700;border-radius:12px;text-decoration:none;">⬇ Download Document</a>`;
    document.getElementById('cred-issued').textContent = '';
    document.getElementById('cred-expires').textContent = '';
    document.getElementById('cred-status').textContent = '';
    return;
  }

  let body;
  try {
    body = await rawResp.json();
  } catch (e) {
    showError('Unable to load credential', 'The server returned an unexpected response.');
    return;
  }

  let data;
  try {
    if (!rawResp.ok) {
      const err = new Error(body?.message || `Request failed (HTTP ${rawResp.status})`);
      err.status = rawResp.status;
      err.code = body?.error || `http_${rawResp.status}`;
      throw err;
    }
    if (!body?.success || !body?.data) throw Object.assign(new Error(body?.message || 'Unexpected response'), { code: 'malformed_response' });
    data = body.data;
  } catch (err) {
    if (err.status === 404 || err.code === 'not_found') {
      showError('Link not found', 'This credential link does not exist. Check that you copied the full link.');
    } else if (err.code === 'already_viewed') {
      showError('Link already used', 'This is a single-use link and it has already been opened.');
    } else if (err.status === 410 || err.code === 'expired') {
      showError('Link expired', 'This credential link has expired. Ask the holder to send a new one.');
    } else if (err.status === 403 || err.code === 'wrong_recipient') {
      showError('Wrong recipient', 'This link was shared with a different recipient. Please use the correct email address to access this credential.');
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

  // Fetch display schema from ardis-ms using the schema_version pointer in the VC.
  // Format: "{verifierId}/{credentialType}/{version}" e.g. "pmacedoflores0/license/v1"
  const schemaVersion = vc.schema_version ?? vc.ardis_schema_version;
  if (schemaVersion && !vc.data_schema) {
    const schema = await fetchSchema(schemaVersion);
    if (schema) {
      vc.data_schema = schema.data_schema;
      vc.ui_schema   = schema.ui_schema ?? {};
    }
  }

  renderCredential(vc);

  // Render download buttons for any backup documents attached to this credential.
  const backupDocs = vc.backup_documents ?? vc.ardis_backup_documents;
  if (Array.isArray(backupDocs) && backupDocs.length > 0) {
    const docObjects = backupDocs.map(d => ({ ...d, key: d.storage_key }));
    renderDocuments(docObjects, (storageKey) => fetchShareDocument(guid, storageKey));
  }

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

/**
 * Runs the OTP verification flow. Shows the OTP gate UI, drives the two-step
 * Enforcer email login, and resolves with the viewer's JWT on success or null
 * if the flow is abandoned / errors out unrecoverably.
 *
 * @param {string} enforcerBase  e.g. "https://gateway.instruxi.dev/api/v1/enforcer"
 * @param {string} tenantCode    "CredPass-Viewer-Portal"
 * @param {string} emailHint     masked hint from server e.g. "h***@hospital.com"
 */
function runOTPFlow(enforcerBase, tenantCode, emailHint) {
  return new Promise((resolve) => {
    const gate      = document.getElementById('otp-gate');
    const loading   = document.getElementById('loading');
    const stepEmail = document.getElementById('otp-step-email');
    const stepCode  = document.getElementById('otp-step-code');
    const bodyEl    = document.getElementById('otp-body');
    const emailInput = document.getElementById('otp-email-input');
    const codeInput  = document.getElementById('otp-code-input');
    const sendBtn    = document.getElementById('otp-send-btn');
    const verifyBtn  = document.getElementById('otp-verify-btn');
    const resendBtn  = document.getElementById('otp-resend-btn');
    const emailErr   = document.getElementById('otp-error');
    const codeErr    = document.getElementById('otp-code-error');
    const hintEl     = document.getElementById('otp-hint');

    loading.classList.add('hidden');
    if (emailHint) {
      bodyEl.textContent = `This credential was shared with ${emailHint}. Enter that email address to receive your verification code.`;
    }
    gate.classList.remove('hidden');

    function showEmailError(msg) {
      emailErr.textContent = msg;
      emailErr.classList.remove('hidden');
    }
    function showCodeError(msg) {
      codeErr.textContent = msg;
      codeErr.classList.remove('hidden');
    }
    function clearErrors() {
      emailErr.classList.add('hidden');
      codeErr.classList.add('hidden');
    }

    let verifiedEmail = '';

    async function sendCode() {
      clearErrors();
      const email = emailInput.value.trim().toLowerCase();
      if (!email || !email.includes('@')) {
        showEmailError('Please enter a valid email address.');
        return;
      }
      sendBtn.disabled = true;
      emailInput.disabled = true;
      sendBtn.textContent = 'Sending…';
      try {
        const res = await fetch(`${enforcerBase}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, tenant_code: tenantCode }),
        });
        if (!res.ok) {
          const b = await res.json().catch(() => ({}));
          if (res.status === 404) {
            showEmailError('No account found for that address. Make sure you are using the email address this credential was shared with.');
          } else {
            showEmailError(b.message || 'Failed to send verification code. Please try again.');
          }
          return;
        }
        verifiedEmail = email;
        hintEl.textContent = `Enter the 6-digit code sent to ${email}.`;
        stepEmail.classList.add('hidden');
        stepCode.classList.remove('hidden');
        codeInput.focus();
      } catch {
        showEmailError('Could not reach the verification service. Check your connection.');
      } finally {
        sendBtn.disabled = false;
        emailInput.disabled = false;
        sendBtn.textContent = 'Send Code';
      }
    }

    async function verifyCode() {
      clearErrors();
      const code = codeInput.value.replace(/\D/g, '').slice(0, 6);
      if (code.length < 4) {
        showCodeError('Please enter the full verification code.');
        return;
      }
      verifyBtn.disabled = true;
      codeInput.disabled = true;
      verifyBtn.textContent = 'Verifying…';
      try {
        const res = await fetch(`${enforcerBase}/auth/login/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: verifiedEmail, otp: code, tenant_code: tenantCode }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) {
          if (res.status === 429) {
            showCodeError('Too many attempts. Please request a new code.');
          } else {
            showCodeError('Invalid or expired code. Please try again.');
          }
          codeInput.value = '';
          return;
        }
        const token = body.data?.token;
        if (!token) {
          showCodeError('Verification succeeded but no token was returned. Please try again.');
          return;
        }
        gate.classList.add('hidden');
        document.getElementById('loading').classList.remove('hidden');
        resolve(token);
      } catch {
        showCodeError('Could not reach the verification service. Check your connection.');
      } finally {
        verifyBtn.disabled = false;
        codeInput.disabled = false;
        verifyBtn.textContent = 'Verify';
      }
    }

    sendBtn.addEventListener('click', sendCode);
    emailInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') sendCode(); });
    verifyBtn.addEventListener('click', verifyCode);
    codeInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') verifyCode(); });
    resendBtn.addEventListener('click', () => {
      stepCode.classList.add('hidden');
      stepEmail.classList.remove('hidden');
      codeInput.value = '';
      clearErrors();
    });
  });
}
