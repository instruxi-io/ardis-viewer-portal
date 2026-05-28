/**
 * Renders a parsed VC JSON credential into the #credential DOM section.
 * The credential type drives field selection and labelling.
 * Falls back to rendering all credentialSubject fields generically.
 */

// Per-credential-type display schemas.
// Add an entry here when a new VP joins the marketplace.
const SCHEMAS = {
  NPPESCredential: {
    icon: '🏥',
    title: 'NPI / NPPES Registration',
    fields: ['npi', 'provider_name', 'specialty', 'practice_address', 'status'],
    labels: {
      npi: 'NPI Number',
      provider_name: 'Provider Name',
      specialty: 'Specialty',
      practice_address: 'Practice Address',
      status: 'License Status',
    },
  },
  AHACredential: {
    icon: '❤️',
    title: 'AHA Membership',
    fields: ['member_id', 'name', 'certification_level', 'valid_until'],
    labels: {
      member_id: 'Member ID',
      name: 'Member Name',
      certification_level: 'Certification Level',
      valid_until: 'Valid Until',
    },
  },
  ABMSCredential: {
    icon: '🎓',
    title: 'Board Certification',
    fields: ['physician_name', 'specialty', 'certification_date', 'expiration_date'],
    labels: {
      physician_name: 'Physician Name',
      specialty: 'Specialty',
      certification_date: 'Certified',
      expiration_date: 'Expires',
    },
  },
};

function fmt(val) {
  if (!val) return '—';
  // ISO date → readable
  if (/^\d{4}-\d{2}-\d{2}/.test(String(val))) {
    try { return new Date(val).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }); }
    catch { return String(val); }
  }
  return String(val);
}

export function renderCredential(vc) {
  const subject = vc.credentialSubject ?? {};
  const types   = Array.isArray(vc.type) ? vc.type : [vc.type];
  const credType = types.find(t => t !== 'VerifiableCredential') ?? 'VerifiableCredential';
  const schema   = SCHEMAS[credType] ?? null;

  // Title + issuer
  const issuerName = vc.issuer?.name ?? vc.issuer ?? 'Unknown Issuer';
  document.getElementById('cred-title').textContent  = schema?.title ?? credType.replace(/Credential$/, '') + ' Credential';
  document.getElementById('cred-issuer').textContent = `Issued by ${issuerName}`;
  document.querySelector('.credential-type-icon').textContent = schema?.icon ?? '📋';

  // Fields
  const fieldsEl = document.getElementById('cred-fields');
  fieldsEl.innerHTML = '';

  const fieldsToShow = schema?.fields ?? Object.keys(subject).filter(k => k !== 'id').slice(0, 8);
  for (const key of fieldsToShow) {
    if (!(key in subject)) continue;
    const label = schema?.labels?.[key] ?? key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    const row = document.createElement('div');
    row.className = 'field-row';
    row.innerHTML = `<span class="field-label">${label}</span><span class="field-value">${fmt(subject[key])}</span>`;
    fieldsEl.appendChild(row);
  }

  // Dates + status
  document.getElementById('cred-issued').textContent  = fmt(vc.issuanceDate);
  document.getElementById('cred-expires').textContent = fmt(vc.expirationDate);

  const now     = new Date();
  const expires = vc.expirationDate ? new Date(vc.expirationDate) : null;
  const expired = expires && expires < now;
  const statusEl = document.getElementById('cred-status');
  statusEl.textContent = expired ? 'Expired' : 'Active';
  statusEl.className   = `meta-value ${expired ? 'status-expired' : 'status-active'}`;

  document.getElementById('credential').classList.remove('hidden');
  document.getElementById('loading').classList.add('hidden');
}

export function renderDocuments(pdfObjects, fetchUrl) {
  const section = document.getElementById('cred-docs');
  if (!section) return;

  section.innerHTML = '';
  const heading = document.createElement('p');
  heading.className = 'docs-heading';
  heading.textContent = 'Supporting Documents';
  section.appendChild(heading);

  for (const obj of pdfObjects) {
    const name = obj.key.split('/').pop();
    const btn  = document.createElement('button');
    btn.className   = 'doc-btn';
    btn.textContent = `⬇ ${name}`;
    btn.addEventListener('click', async () => {
      btn.textContent = '…';
      btn.disabled    = true;
      try {
        const url = await fetchUrl(obj.key);
        const a   = document.createElement('a');
        a.href     = url;
        a.download = name;
        a.click();
        setTimeout(() => URL.revokeObjectURL(url), 60_000);
      } catch (e) {
        alert(`Download failed: ${e.message}`);
      } finally {
        btn.textContent = `⬇ ${name}`;
        btn.disabled    = false;
      }
    });
    section.appendChild(btn);
  }

  section.classList.remove('hidden');
}

export function showSignerAddress(address) {
  document.getElementById('signer-address').textContent = address;
  document.getElementById('signature-row').classList.remove('hidden');
  document.getElementById('verification-badge').classList.remove('hidden');
}

export function showError(title, body) {
  document.getElementById('loading').classList.add('hidden');
  document.getElementById('credential').classList.add('hidden');
  document.getElementById('error-title').textContent = title;
  document.getElementById('error-body').textContent  = body;
  document.getElementById('error').classList.remove('hidden');
}

// Used by the Stripe Checkout success / cancel and Stripe Identity return
// pages. Dark-themed landing screen with a gold checkmark (success) or X
// (cancel), the right copy, and a deep-link button back to the Ardis app.
// We also attempt to open the deep link automatically after a short beat
// so the user is dropped straight back into the app on iOS.
export function showLandingMessage({ title, body, ctaLabel, deepLink, kind }) {
  document.getElementById('loading').classList.add('hidden');
  document.getElementById('credential').classList.add('hidden');
  document.getElementById('error').classList.add('hidden');

  const screen = document.getElementById('landing');
  screen.classList.remove('hidden');
  screen.classList.toggle('is-cancel', kind === 'cancel');

  document.getElementById('landing-title').textContent = title;
  document.getElementById('landing-body').textContent = body;

  const cta = document.getElementById('landing-cta');
  cta.textContent = ctaLabel ?? 'Open Ardis';
  cta.href = deepLink;

  // Draw the success checkmark or the cancel "X" inside the gold orb.
  const mark = document.getElementById('landingMark');
  if (kind === 'cancel') {
    // X mark — two crossed strokes.
    mark.setAttribute('d', 'M24 24 L40 40 M40 24 L24 40');
  } else {
    // Checkmark.
    mark.setAttribute('d', 'M22 33 L29 40 L42 25');
  }

  // Best-effort auto deep-link after a short visual beat so users see the
  // success state before iOS prompts to open the app. iOS Safari does not
  // honour location.href=custom-scheme without a user gesture in some
  // versions — the visible button covers that case.
  if (deepLink) {
    setTimeout(() => {
      try { window.location.href = deepLink; } catch { /* user can tap cta */ }
    }, 900);
  }
}
