/**
 * Renders a parsed VC JSON credential into the #credential DOM section.
 *
 * Schema priority (highest to lowest):
 *  1. ardis_data_schema / ardis_ui_schema embedded in the VC by the VP
 *  2. Static SCHEMAS fallback keyed by credential type (legacy/built-in VPs)
 *  3. Generic display of all credentialSubject fields
 *
 * VPs define their own schemas and embed them at fulfillment time — no
 * viewer-portal code change is needed when a new VP joins.
 */

// Legacy static schemas — used only when a VC does not embed ardis_data_schema.
const STATIC_SCHEMAS = {
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

function fmt(val, format) {
  if (!val) return '—';
  const str = String(val);
  const isDate = format === 'date' || format === 'date-time' || /^\d{4}-\d{2}-\d{2}/.test(str);
  if (isDate) {
    try {
      const opts = format === 'date-time'
        ? { year: 'numeric', month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit' }
        : { year: 'numeric', month: 'long', day: 'numeric' };
      return new Date(val).toLocaleDateString('en-US', opts);
    } catch { return str; }
  }
  return str;
}

/**
 * Build a normalised field list from ardis_data_schema + ardis_ui_schema.
 * Returns [{key, label, format}] in display order.
 */
function fieldsFromArdisSchema(dataSchema, uiSchema, subject) {
  const props = dataSchema?.properties ?? {};
  const order = uiSchema?.['ui:order'] ?? Object.keys(props);
  return order
    .filter(k => k in subject)
    .map(k => ({
      key: k,
      label: props[k]?.title ?? k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      format: props[k]?.format,
    }));
}

export function renderCredential(vc) {
  const subject    = vc.credentialSubject ?? {};
  const types      = Array.isArray(vc.type) ? vc.type : [vc.type];
  const credType   = types.find(t => t !== 'VerifiableCredential') ?? 'VerifiableCredential';
  // Support new (no prefix) and old (ardis_ prefix) field names
  const dataSchema = vc.data_schema ?? vc.ardis_data_schema ?? null;
  const uiSchema   = vc.ui_schema   ?? vc.ardis_ui_schema   ?? null;
  const staticSchema = STATIC_SCHEMAS[credType] ?? null;

  // Title + issuer
  const issuerName = vc.issuer?.name ?? vc.issuer ?? 'Unknown Issuer';
  document.getElementById('cred-title').textContent =
    staticSchema?.title ?? credType.replace(/Credential$/, '') + ' Credential';
  document.getElementById('cred-issuer').textContent = `Issued by ${issuerName}`;
  document.querySelector('.credential-type-icon').textContent = staticSchema?.icon ?? '📋';

  // Fields — prefer embedded schema, fall back to static schema, then generic
  const fieldsEl = document.getElementById('cred-fields');
  fieldsEl.innerHTML = '';

  if (dataSchema) {
    const props = dataSchema?.properties ?? {};
    const order = Object.keys(props);
    for (const key of order) {
      if (!(key in subject)) continue;
      _renderNode(fieldsEl, key, subject[key], props[key] ?? {});
    }
    // Any subject keys not in schema
    for (const key of Object.keys(subject).filter(k => k !== 'id' && !(k in props))) {
      _renderNode(fieldsEl, key, subject[key], {});
    }
  } else if (staticSchema) {
    for (const key of staticSchema.fields) {
      if (!(key in subject)) continue;
      const label = staticSchema.labels?.[key] ?? key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      fieldsEl.appendChild(_fieldRow(label, fmt(subject[key])));
    }
  } else {
    for (const key of Object.keys(subject).filter(k => k !== 'id').slice(0, 10)) {
      const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      fieldsEl.appendChild(_fieldRow(label, fmt(subject[key])));
    }
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

function _fieldRow(label, value) {
  const row = document.createElement('div');
  row.className = 'field-row';
  row.innerHTML = `<span class="field-label">${label}</span><span class="field-value">${value}</span>`;
  return row;
}

/** Recursively render a value based on its schema type. */
function _renderNode(container, key, value, propSchema) {
  if (value === null || value === undefined) return;
  if (typeof value === 'string' && value.trim() === '') return;

  const type   = propSchema.type;
  const title  = propSchema.title ?? _titleCase(key);
  const format = propSchema.format;

  if (type === 'array' && Array.isArray(value)) {
    if (value.length === 0) return;
    const section = document.createElement('div');
    section.className = 'field-array-section';

    const heading = document.createElement('p');
    heading.className = 'field-group-heading';
    heading.textContent = title;
    section.appendChild(heading);

    const itemSchema = propSchema.items ?? {};
    const itemProps  = itemSchema.properties ?? {};

    value.forEach((item, i) => {
      if (value.length > 1) {
        const divider = document.createElement('p');
        divider.className = 'field-array-divider';
        divider.textContent = `${i + 1}`;
        section.appendChild(divider);
      }
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        for (const [k, v] of Object.entries(item)) {
          if (v === null || v === undefined || v === '') continue;
          _renderNode(section, k, v, itemProps[k] ?? {});
        }
      } else {
        section.appendChild(_fieldRow('', fmt(item, null)));
      }
    });

    container.appendChild(section);
  } else if (type === 'object' && value && typeof value === 'object') {
    const nestedProps = propSchema.properties ?? {};
    const hasContent  = Object.entries(value).some(([, v]) => v !== null && v !== undefined && v !== '');
    if (!hasContent) return;

    if (title) {
      const label = document.createElement('p');
      label.className = 'field-object-label';
      label.textContent = title;
      container.appendChild(label);
    }
    for (const [k, v] of Object.entries(value)) {
      if (v === null || v === undefined || v === '') continue;
      _renderNode(container, k, v, nestedProps[k] ?? {});
    }
  } else if (Array.isArray(value) || (value && typeof value === 'object')) {
    // Untyped array or object — render recursively without schema
    _renderNode(container, key, value, { type: Array.isArray(value) ? 'array' : 'object', title });
  } else {
    container.appendChild(_fieldRow(title, fmt(value, format)));
  }
}

function _titleCase(key) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
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
