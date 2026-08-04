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
import { parseKeyFromHash, isEnvelope, decryptEnvelope } from './envelope.js';
import { recoverSigner } from './verify.js';
import {
  renderCredential,
  renderAlerts,
  renderDocuments,
  renderNotes,
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

  const API_BASE = (import.meta.env.VITE_ARDIS_API_BASE || 'https://ardis-ms-ix.fly.dev').replace(/\/+$/, '');

  // ── Step 1: resolve GUID ──────────────────────────────────────────────────
  // If the viewer opened a full link the GUID is in the URL path.
  // If they only have the 9-digit code, the code-entry flow maps it to a GUID.
  // When the viewer entered the code we already have it, so PIN step can reuse
  // it without prompting again.
  let enteredPin = null; // set when the user typed the code manually
  let guid = parseShareId();
  if (!guid) {
    const codeResult = await runCodeEntryFlow(API_BASE);
    if (!codeResult) return;
    guid = codeResult.guid;
    enteredPin = codeResult.pin; // digits the user typed, reused as the PIN
  }

  const shareUrl = `${API_BASE}/api/v1/ardis/public/share/${encodeURIComponent(guid)}`;
  // The gateway is a different host from ardis-ms, so this cannot be derived from
  // API_BASE. VITE_ENFORCER_BASE already includes the /api/v1/enforcer prefix and
  // must name the same gateway ardis-ms validates the resulting JWT against.
  const ENFORCER_BASE = (import.meta.env.VITE_ENFORCER_BASE
    || 'https://gateway-staging.instruxi.dev/api/v1/enforcer').replace(/\/+$/, '');
  const VIEWER_TENANT = 'CredPass-Viewer-Portal';

  // ── Step 2: OTP gate (layer 1 — dormant until viewer provisioning is built) ─
  // ardis-ms returns 401 { error: "otp_required" } when the share requires
  // the viewer to prove email ownership via Enforcer OTP.
  // Currently RequireOTP is always false server-side, so this branch never fires.
  // It is scaffolded here so enabling OTP later only flips the server flag.
  let viewerToken = null;
  let rawProbe;
  try {
    rawProbe = await fetch(shareUrl, { headers: { Accept: 'application/json, */*' } });
  } catch (e) {
    showError('Unable to load', 'Could not reach the credential service. Check your connection.');
    return;
  }
  if (rawProbe.status === 401) {
    let errBody = null;
    try { errBody = await rawProbe.json(); } catch (_) {}
    if (errBody && errBody.error === 'otp_required') {
      const emailHint = errBody.email_hint || '';
      viewerToken = await runOTPFlow(ENFORCER_BASE, VIEWER_TENANT, emailHint);
      if (!viewerToken) return;
    } else if (!errBody || errBody.error !== 'pin_required') {
      // Unexpected 401 that is neither OTP nor PIN — surface it.
      showError('Unable to load', errBody?.message || 'Authentication required.');
      return;
    }
    // pin_required falls through to Step 3 below.
  }

  // ── Step 3: PIN gate (layer 2 — second factor for encrypted shares) ──────
  // The link carries the decryption key K in its #k= fragment.
  // The PIN gates the server releasing the ciphertext.
  // Neither the link nor the PIN alone is sufficient to open the share.
  // If the viewer came via code-entry, enteredPin is already known.
  // If they came via a full link, we prompt them for the PIN now.
  let sharePin = enteredPin;
  if (!sharePin) {
    sharePin = await runPinEntryFlow();
    if (!sharePin) return; // user closed the PIN prompt
  }

  // ── Step 4: fetch the share (with OTP token + PIN) ───────────────────────
  const fetchHeaders = { Accept: 'application/json, */*', 'X-Share-Pin': sharePin };
  if (viewerToken) fetchHeaders['Authorization'] = `Bearer ${viewerToken}`;

  let rawResp;
  try {
    rawResp = await fetch(shareUrl, { headers: fetchHeaders });
  } catch (e) {
    showError('Unable to load', 'Could not reach the credential service. Check your connection.');
    return;
  }

  // Wrong PIN: let the viewer retry rather than leaving them stranded.
  if (rawResp.status === 401 || rawResp.status === 403) {
    let errBody = null;
    try { errBody = await rawResp.json(); } catch (_) {}
    if (errBody?.error === 'pin_required' || errBody?.error === 'wrong_pin') {
      showError(
        'Incorrect PIN',
        'The PIN you entered is incorrect. Please check the code sent with the link and try again.'
      );
      return;
    }
    if (errBody?.error === 'wrong_recipient') {
      showError('Wrong recipient', 'This link was shared with a different recipient.');
      return;
    }
  }

  const contentType = rawResp.headers.get('Content-Type') || '';

  if (!contentType.includes('application/json')) {
    // Binary personal document
    if (!rawResp.ok) { showError('Unable to load document', `HTTP ${rawResp.status}`); return; }
    let bytes = new Uint8Array(await rawResp.arrayBuffer());
    let docType = contentType;
    if (isEnvelope(bytes)) {
      const keyBytes = parseKeyFromHash();
      if (!keyBytes) { showMissingKeyError(); return; }
      try {
        bytes = await decryptEnvelope(bytes, keyBytes);
      } catch {
        showDecryptError();
        return;
      }
      docType = sniffContentType(bytes, contentType);
    }
    renderSharedDocument(new Blob([bytes], { type: docType }), docType);
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

  // Encrypted share (blind broker): the server returns only the ciphertext
  // envelope as payload_b64 and never sees the plaintext. Decrypt locally
  // with the key from the URL fragment, which is never sent to any server.
  let sharedNotes = null;
  if (data.encrypted === true) {
    const keyBytes = parseKeyFromHash();
    if (!keyBytes) { showMissingKeyError(); return; }
    let plainBytes;
    try {
      const cipherBytes = base64ToBytes(data.payload_b64);
      if (!isEnvelope(cipherBytes)) throw new Error('bad envelope');
      plainBytes = await decryptEnvelope(cipherBytes, keyBytes);
    } catch {
      showDecryptError();
      return;
    }
    // Notes are sealed with the same share key as the payload, in their own
    // envelope rather than wrapped around it, so the server stores notes it
    // cannot read. Failure here is not fatal: the credential is the thing the
    // recipient came for, and losing the annotations should not lose the page.
    sharedNotes = await decryptNotes(data.notes_cipher_b64, keyBytes);
    try {
      data.credential = JSON.parse(new TextDecoder().decode(plainBytes));
    } catch {
      // ponytail: not-JSON means an encrypted personal document share (raw
      // file bytes); a document that happens to parse as JSON would render
      // as a credential. Upgrade path: an explicit share-kind metadata field.
      const docType = sniffContentType(plainBytes, 'application/octet-stream');
      renderSharedDocument(new Blob([plainBytes], { type: docType }), docType);
      // Documents carry notes too, and renderSharedDocument writes the same
      // #cred-fields container, so this has to come after it.
      renderNotes(sharedNotes ?? data.notes);
      return;
    }
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

  // Notes from the decrypted envelope when present, falling back to the share
  // record's old plaintext field so shares created before the change still show
  // theirs.
  renderNotes(sharedNotes ?? data.notes);

  // Render active monitoring alerts (adverse actions, sanctions) if present in
  // the share response. The server includes alerts attached to this credential.
  const alerts = data.alerts;
  if (Array.isArray(alerts) && alerts.length > 0) {
    renderAlerts(alerts);
  }

  // Render download buttons for any backup documents attached to this credential.
  const backupDocs = vc.backup_documents ?? vc.ardis_backup_documents;
  if (Array.isArray(backupDocs) && backupDocs.length > 0) {
    const docObjects = backupDocs.map(d => ({ ...d, key: d.storage_key }));
    // Pass the fragment key and the document's own content type so encrypted
    // envelopes can be decrypted client-side; both are ignored on legacy shares.
    renderDocuments(docObjects, (storageKey) => {
      const doc = docObjects.find(d => d.key === storageKey);
      return fetchShareDocument(guid, storageKey, parseKeyFromHash(), doc?.content_type ?? null, sharePin);
    });
  }

  // Wallet signature over the share. Both halves come from the same server
  // response, so recovering an address proves nothing on its own -- any
  // self-consistent pair recovers to something. The only claim we can make
  // client-side is that the signed payload refers to THIS share, so bind it
  // before showing anything, and never show it when the binding fails.
  //
  // ponytail: this authenticates the share, not the issuer. Ceiling: it cannot
  // tell a legitimate wallet from an attacker's, because the viewer has no
  // trusted record of the professional's address. Upgrade path is verifying
  // vc.proof against GET /public/verifier-keys (itself signed) the way the
  // Flutter app's vc_verifier.dart does.
  const sig = data.signature;
  if (sig && sig.payload && sig.value) {
    try {
      const signer = recoverSigner(sig.payload, sig.value);
      let signed;
      try { signed = JSON.parse(sig.payload); } catch { signed = null; }
      const boundToThisShare = !!signed
        && (!signed.share_id || signed.share_id === guid)
        && (!signed.credential_id || !vc.id || signed.credential_id === vc.id);
      if (signer && boundToThisShare) showSignerAddress(signer);
    } catch {
      /* signature display is non-fatal */
    }
  }
}

main();

/** Decode a standard base64 string (as sent in payload_b64) to bytes. */
/**
 * Opens the notes envelope with the share key. Returns null when there are no
 * notes or they cannot be read, which the caller treats as "no notes section"
 * rather than an error — a failed annotation must not cost the credential.
 */
async function decryptNotes(cipherB64, keyBytes) {
  if (!cipherB64 || !keyBytes) return null;
  try {
    const bytes = base64ToBytes(cipherB64);
    if (!isEnvelope(bytes)) return null;
    const plain = await decryptEnvelope(bytes, keyBytes);
    const parsed = JSON.parse(new TextDecoder().decode(plain));
    return Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/**
 * Best-effort content type for decrypted document bytes. The server sends
 * ciphertext as application/octet-stream, so the real type is only knowable
 * from the plaintext itself.
 * ponytail: sniffs PDF and JPEG/PNG magic only; upgrade path is a content_type
 * field in the share metadata.
 */
function sniffContentType(bytes, fallback) {
  if (bytes.length >= 4) {
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return 'application/pdf';
    if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return 'image/jpeg';
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return 'image/png';
  }
  return fallback || 'application/octet-stream';
}

function showMissingKeyError() {
  showError(
    'Missing decryption key',
    'This link is missing its key fragment. Ask the sender to re-send the full link, including everything after the # symbol.',
  );
}

function showDecryptError() {
  showError(
    'Unable to decrypt',
    'This share could not be decrypted. The link key may be wrong or the data corrupted. Ask the sender for a new link.',
  );
}

/**
 * Renders a shared personal document as a download card. Used by both the
 * legacy plaintext path and the client-side decrypted path.
 */
function renderSharedDocument(blob, contentType) {
  const blobUrl = URL.createObjectURL(blob);
  const ext = contentType.includes('pdf') ? '.pdf' : contentType.includes('image') ? '.jpg' : '';
  document.getElementById('loading').classList.add('hidden');
  const container = document.getElementById('credential');
  container.classList.remove('hidden');
  document.getElementById('cred-title').textContent = 'Shared Document';
  document.getElementById('cred-issuer').textContent = '';
  document.querySelector('.credential-type-icon').textContent = contentType.includes('pdf') ? '📄' : '🖼';
  const fieldsEl = document.getElementById('cred-fields');
  fieldsEl.replaceChildren();
  const dl = document.createElement('a');
  dl.href = blobUrl;                       // same-origin blob: URL we created
  dl.download = `document${ext}`;          // ext derives from a server-declared type
  dl.style.cssText = 'display:inline-block;margin-top:8px;padding:10px 20px;background:var(--gold,#CBAF7C);color:#0A0F18;font-weight:700;border-radius:12px;text-decoration:none;';
  dl.textContent = '⬇ Download Document';
  fieldsEl.appendChild(dl);
  // Hide credential-specific metadata rows, not applicable to personal documents
  document.getElementById('cred-issued').textContent = '';
  document.getElementById('cred-expires').textContent = '';
  document.getElementById('cred-status').textContent = '';
  ['cred-issued', 'cred-expires', 'cred-status'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      const row = el.closest('.meta-row') || el.parentElement;
      if (row) row.style.display = 'none';
    }
  });
}

/**
 * Shows the code entry gate and resolves a 9-digit share code to a GUID.
 * Returns the GUID string on success, or null if the flow errors out.
 */
async function runCodeEntryFlow(apiBase) {
  return new Promise((resolve) => {
    const gate    = document.getElementById('code-gate');
    const input   = document.getElementById('code-input');
    const btn     = document.getElementById('code-submit-btn');
    const errEl   = document.getElementById('code-error');

    document.getElementById('loading').classList.add('hidden');
    gate.classList.remove('hidden');
    input.focus();

    function showErr(msg) {
      errEl.textContent = msg;
      errEl.classList.remove('hidden');
    }
    function clearErr() {
      errEl.classList.add('hidden');
    }

    // Auto-format digits into "000 000 000" as user types.
    input.addEventListener('input', () => {
      const digits = input.value.replace(/\D/g, '').slice(0, 9);
      if (digits.length <= 3) {
        input.value = digits;
      } else if (digits.length <= 6) {
        input.value = `${digits.slice(0, 3)} ${digits.slice(3)}`;
      } else {
        input.value = `${digits.slice(0, 3)} ${digits.slice(3, 6)} ${digits.slice(6)}`;
      }
      clearErr();
    });

    async function submit() {
      clearErr();
      const digits = input.value.replace(/\D/g, '');
      if (digits.length !== 9) {
        showErr('Please enter the full 9-digit code.');
        return;
      }
      btn.disabled = true;
      btn.textContent = 'Looking up…';
      try {
        const resp = await fetch(`${apiBase}/api/v1/ardis/public/share/code/${digits}`);
        const body = await resp.json().catch(() => ({}));
        if (resp.status === 404) {
          showErr('That code was not found or has expired.');
          return;
        }
        if (!resp.ok) {
          showErr(body.message || 'Could not resolve that code. Please try again.');
          return;
        }
        const guid = body.data?.guid;
        if (!guid) {
          showErr('Unexpected response. Please try again.');
          return;
        }
        gate.classList.add('hidden');
        document.getElementById('loading').classList.remove('hidden');
        // Return both the GUID and the raw digits so the PIN step can
        // reuse the code the viewer already typed (no double-entry).
        resolve({ guid, pin: digits });
      } catch {
        showErr('Could not reach the service. Check your connection.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Continue';
      }
    }

    btn.addEventListener('click', submit);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  });
}

/**
 * Shows the PIN entry gate and waits for the viewer to enter the 9-digit
 * share code as a second factor. Returns the raw digit string on success, or
 * null if the viewer closes the prompt without entering a valid code.
 *
 * Called only on the full-link path; the code-entry path reuses the digits
 * the viewer already typed via runCodeEntryFlow.
 *
 * OTP slot (future): when OTP is enabled this runs AFTER the OTP step, so
 * the sequence becomes OTP (who are you) → PIN (second factor) → decrypt.
 */
function runPinEntryFlow() {
  return new Promise((resolve) => {
    const gate   = document.getElementById('pin-gate');
    const input  = document.getElementById('pin-input');
    const btn    = document.getElementById('pin-submit-btn');
    const errEl  = document.getElementById('pin-error');

    document.getElementById('loading').classList.add('hidden');
    gate.classList.remove('hidden');
    input.value = '';
    input.focus();

    function showErr(msg) { errEl.textContent = msg; errEl.classList.remove('hidden'); }
    function clearErr()   { errEl.classList.add('hidden'); }

    input.addEventListener('input', () => {
      const digits = input.value.replace(/\D/g, '').slice(0, 9);
      if      (digits.length <= 3) input.value = digits;
      else if (digits.length <= 6) input.value = `${digits.slice(0,3)} ${digits.slice(3)}`;
      else                         input.value = `${digits.slice(0,3)} ${digits.slice(3,6)} ${digits.slice(6)}`;
      clearErr();
    });

    async function submit() {
      clearErr();
      const digits = input.value.replace(/\D/g, '');
      if (digits.length !== 9) { showErr('Please enter the full 9-digit PIN.'); return; }
      gate.classList.add('hidden');
      document.getElementById('loading').classList.remove('hidden');
      resolve(digits);
    }

    btn.addEventListener('click', submit);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  });
}

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
