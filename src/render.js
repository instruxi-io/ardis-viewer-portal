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

// A date-only value ("2026-07-14") is a calendar day, not an instant. Date
// parses it as UTC midnight, so every viewer west of UTC was shown the day
// before — an employer in New York read a licence issued on the 14th as the
// 13th. Render those in UTC and leave real timestamps to render locally.
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

export function fmt(val, format) {
  // Not `!val`: 0 and false are answers, and both used to print as "no data".
  if (val === null || val === undefined || val === '') return '—';
  if (typeof val === 'boolean') return val ? 'Yes' : 'No';
  const str = String(val);
  const isDate = format === 'date' || format === 'date-time' || DATE_ONLY.test(str);
  if (isDate) {
    const d = new Date(str);
    // A field that merely looks like a date but is not one (a reference number,
    // a version) used to render the words "Invalid Date".
    if (Number.isNaN(d.getTime())) return str;
    const dateOnly = DATE_ONLY.test(str);
    const opts = format === 'date-time' && !dateOnly
      ? { year: 'numeric', month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit' }
      : { year: 'numeric', month: 'long', day: 'numeric' };
    if (dateOnly) opts.timeZone = 'UTC';
    return d.toLocaleDateString('en-US', opts);
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

/**
 * The status shown to the employer, from the credential's own claim first and
 * its expiry date second. Exported so the self-check can assert on it without
 * a DOM: this is the single most consequential thing this page renders.
 */
export function credentialStatus(vc, now = new Date()) {
  const expiryVal = vc.expires_at ?? vc.expirationDate;
  // A date-only expiry means the licence is good through the end of that day.
  // Parsing it as UTC midnight retired a still-valid licence up to a day early.
  const expires = expiryVal
    ? new Date(DATE_ONLY.test(String(expiryVal))
        ? `${expiryVal}T23:59:59.999Z`
        : expiryVal)
    : null;
  const expiredByDate = expires && expires < now;
  const claimed = String(vc.status ?? '').toLowerCase();
  if (claimed === 'suspended') {
    return { statusText: 'Suspended', statusClass: 'status-suspended' };
  }
  if (claimed === 'expired' || expiredByDate) {
    return { statusText: 'Expired', statusClass: 'status-expired' };
  }
  if (claimed === '' || claimed === 'current' || claimed === 'active' ||
      claimed === 'valid') {
    return { statusText: 'Active', statusClass: 'status-active' };
  }
  // A word this page does not recognise (revoked, lapsed, under_review) must
  // never fall through to a green "Active". Show it as written and let the
  // employer read the actual claim.
  return {
    statusText: claimed.replace(/[_-]+/g, ' ').replace(/^./, c => c.toUpperCase()),
    statusClass: 'status-suspended',
  };
}

export function renderCredential(vc) {
  // Support both new simplified format (data, issued_at, expires_at)
  // and legacy W3C format (credentialSubject, issuanceDate, expirationDate).
  const subject    = vc.data ?? vc.credentialSubject ?? {};
  const credType   = vc.credential_type ?? vc.credentialType
    ?? (Array.isArray(vc.type) ? vc.type.find(t => t !== 'VerifiableCredential') : vc.type)
    ?? 'VerifiableCredential';
  const dataSchema = vc.data_schema ?? vc.ardis_data_schema ?? null;
  const uiSchema   = vc.ui_schema   ?? vc.ardis_ui_schema   ?? null;
  const staticSchema = STATIC_SCHEMAS[credType] ?? null;

  // Title + issuer. Humanise the credential_type slug into a readable title
  // ("identity-verification" -> "Identity Verification") rather than showing
  // the raw slug, which reads like a filename.
  const humanize = (s) => String(s)
    .replace(/([a-z])([A-Z])/g, '$1 $2')     // camelCase boundaries
    .replace(/[-_]+/g, ' ')                    // hyphens/underscores
    .replace(/\bCredential\b/gi, '')           // drop a redundant "Credential"
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());
  const issuerName = vc.verifier_name ?? vc.issuer?.name ?? vc.issuer ?? 'Unknown Issuer';
  document.getElementById('cred-title').textContent =
    staticSchema?.title ?? humanize(credType);
  document.getElementById('cred-issuer').textContent = `Issued by ${issuerName}`;
  document.querySelector('.credential-type-icon').textContent = staticSchema?.icon ?? '📋';

  // Fields — prefer embedded schema, fall back to static schema, then generic.
  // META_KEYS never render as credential content: id and disclosed_fields are
  // provenance metadata, not fields.
  const META_KEYS = new Set(['id', 'disclosed_fields']);
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
    for (const key of Object.keys(subject).filter(k => !META_KEYS.has(k) && !(k in props))) {
      _renderNode(fieldsEl, key, subject[key], {});
    }
  } else if (staticSchema) {
    for (const key of staticSchema.fields) {
      if (!(key in subject)) continue;
      const label = staticSchema.labels?.[key] ?? key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      fieldsEl.appendChild(_fieldRow(label, fmt(subject[key])));
    }
  } else {
    // No schema: still recurse — nested records[] must render as sections,
    // not stringify to "[object Object]".
    for (const key of Object.keys(subject).filter(k => !META_KEYS.has(k))) {
      _renderNode(fieldsEl, key, subject[key], {});
    }
  }

  // Dates + status — support both new (issued_at/expires_at) and legacy W3C format
  document.getElementById('cred-issued').textContent  = fmt(vc.issued_at ?? vc.issuanceDate);
  document.getElementById('cred-expires').textContent = fmt(vc.expires_at ?? vc.expirationDate);

  const now     = new Date();
  const { statusText, statusClass } = credentialStatus(vc, now);
  const statusEl = document.getElementById('cred-status');
  statusEl.textContent = statusText;
  statusEl.className   = `meta-value ${statusClass}`;

  document.getElementById('credential').classList.remove('hidden');
  document.getElementById('loading').classList.add('hidden');
}

function _fieldRow(label, value) {
  const row = document.createElement('div');
  row.className = 'field-row';
  // Built as nodes, never as markup: label and value are vendor-authored
  // credential content, and the share key K lives in location.hash where any
  // injected script could read it.
  const labelEl = document.createElement('span');
  labelEl.className = 'field-label';
  labelEl.textContent = label;
  const valueEl = document.createElement('span');
  valueEl.className = 'field-value';
  valueEl.textContent = value;
  row.append(labelEl, valueEl);
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

/**
 * Renders monitoring alerts (adverse actions, sanctions) above the credential.
 * Alerts are sorted by severity: critical first, then warning, then info.
 * @param {Array<{type: string, severity: string, title: string, message: string, created_at: string}>} alerts
 */
/// Brings the two alert shapes together.
///
/// The employer has to see adverse actions and monitoring updates (SOW
/// 2.4(c)(ii)), and they arrive by two different routes that do not agree:
///
///   - the share response carries platform alerts as {title, message, severity}
///     with severity in critical|warning|info
///   - the credential itself carries the VENDOR's alerts as
///     {type, summary, severity} with severity in high|medium|low, per
///     docs/integration/fulfillment.md
///
/// The viewer only ever read the first, and only understood the first
/// vocabulary, so a vendor's "license revoked" was invisible; and had it been
/// passed through it would have rendered blank, because it carries no title or
/// message field, and coloured blue, because "medium" is not "warning".
export function normalizeAlerts(vcAlerts, platformAlerts) {
  const SEVERITY = {
    critical: 'critical', high: 'critical',
    warning: 'warning', medium: 'warning',
    info: 'info', low: 'info',
  };
  const norm = (a, fromVendor) => ({
    title: a.title ?? a.type ?? (fromVendor ? 'Verifier alert' : 'Alert'),
    message: a.message ?? a.summary ?? '',
    severity: SEVERITY[String(a.severity ?? '').toLowerCase()] ?? 'info',
    created_at: a.created_at ?? a.issued_at ?? null,
  });
  return [
    ...(Array.isArray(vcAlerts) ? vcAlerts.map(a => norm(a, true)) : []),
    ...(Array.isArray(platformAlerts) ? platformAlerts.map(a => norm(a, false)) : []),
  ];
}

export function renderAlerts(alerts) {
  const container = document.getElementById('credential');
  if (!container) return;

  const sorted = [...alerts].sort((a, b) => {
    const order = { critical: 0, warning: 1, info: 2 };
    return (order[a.severity] ?? 2) - (order[b.severity] ?? 2);
  });

  const section = document.createElement('div');
  section.style.cssText = 'margin-bottom:16px';

  for (const alert of sorted) {
    const colors = {
      critical: { bg: '#fef2f2', border: '#ef4444', icon: '🚨' },
      warning:  { bg: '#fffbeb', border: '#f59e0b', icon: '⚠️' },
      info:     { bg: '#eff6ff', border: '#3b82f6', icon: 'ℹ️' },
    };
    const { bg, border, icon } = colors[alert.severity] ?? colors.info;

    const el = document.createElement('div');
    el.style.cssText = `
      background:${bg};
      border:1px solid ${border};
      border-left:4px solid ${border};
      border-radius:8px;
      padding:12px 16px;
      margin-bottom:8px;
    `;
    const date = alert.created_at
      ? new Date(alert.created_at).toLocaleDateString(undefined, { year:'numeric', month:'short', day:'numeric' })
      : '';
    // Nodes, not markup: alert.title/message are vendor-authored. See _fieldRow.
    const head = document.createElement('div');
    head.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:4px';
    const iconEl = document.createElement('span');
    iconEl.textContent = icon;
    const titleEl = document.createElement('strong');
    titleEl.style.fontSize = '14px';
    titleEl.textContent = alert.title ?? '';
    head.append(iconEl, titleEl);
    if (date) {
      const dateEl = document.createElement('span');
      dateEl.style.cssText = 'margin-left:auto;font-size:11px;opacity:0.6';
      dateEl.textContent = date;
      head.appendChild(dateEl);
    }
    el.appendChild(head);
    if (alert.message) {
      const msgEl = document.createElement('p');
      msgEl.style.cssText = 'margin:0;font-size:13px;opacity:0.8';
      msgEl.textContent = alert.message;
      el.appendChild(msgEl);
    }
    section.appendChild(el);
  }

  // Insert before the first child of the credential container.
  container.insertBefore(section, container.firstChild);
}

/// Renders the professional's context notes under the credential fields.
///
/// Accepts both shapes on the wire: a plain string, which is what shares
/// created before notes moved into the encrypted envelope carry, and
/// `{ text, createdAt }`, which is what the app sends now. An object used to
/// fall through `String(n)` and render "[object Object]", so the shape is
/// resolved explicitly rather than coerced.
///
/// Note text is author-supplied, so it goes in via textContent. Nothing here
/// builds HTML from it.
export function renderNotes(notes) {
  const container = document.getElementById('cred-fields');
  if (!container || !Array.isArray(notes)) return;

  const entries = notes
    .map((n) => (n && typeof n === 'object' ? n : { text: n }))
    .map((n) => ({
      text: n.text == null ? '' : String(n.text).trim(),
      createdAt: n.createdAt ?? n.created_at ?? null,
    }))
    .filter((n) => n.text !== '');
  if (entries.length === 0) return;

  const section = document.createElement('div');
  section.className = 'notes-section';

  const title = document.createElement('p');
  title.className = 'notes-title';
  title.textContent =
    entries.length === 1 ? 'Note from the professional' : 'Notes from the professional';
  section.appendChild(title);

  for (const entry of entries) {
    const item = document.createElement('p');
    item.className = 'note-item';

    const when = entry.createdAt ? new Date(entry.createdAt) : null;
    if (when && !Number.isNaN(when.getTime())) {
      const stamp = document.createElement('span');
      stamp.className = 'note-date';
      stamp.textContent = when.toLocaleDateString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
      });
      item.appendChild(stamp);
    }

    appendTextWithLinks(item, entry.text);
    section.appendChild(item);
  }

  container.appendChild(section);
}

/// Appends note text, turning any https link in it into one you can click.
///
/// Professionals paste links into notes: a supporting document they have
/// shared, or another credential. As plain text the recipient had to select a
/// long URL by hand, and the fragment after the # is the part that carries the
/// decryption key, so a selection that stopped early opened nothing.
///
/// Built as DOM nodes with textContent, never innerHTML, and only https is
/// linkified: note text comes from a person and must never be able to inject
/// markup or a javascript: target.
function appendTextWithLinks(el, text) {
  const source = String(text ?? '');
  const pattern = /https:\/\/[^\s<>"']+/g;
  let last = 0;
  for (const match of source.matchAll(pattern)) {
    if (match.index > last) {
      el.appendChild(document.createTextNode(source.slice(last, match.index)));
    }
    const href = match[0];
    let url = null;
    try { url = new URL(href); } catch { url = null; }
    if (url && url.protocol === 'https:') {
      const a = document.createElement('a');
      a.href = url.href;
      a.textContent = href;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.className = 'note-link';
      el.appendChild(a);
    } else {
      el.appendChild(document.createTextNode(href));
    }
    last = match.index + href.length;
  }
  if (last < source.length) {
    el.appendChild(document.createTextNode(source.slice(last)));
  }
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

/**
 * Shows the issuer verdict required by SOW 2.4(c)(i): whether the credential
 * itself was signed by the verifier it names, as distinct from whether this
 * share was authorised by the professional.
 *
 * Only a checked signature is allowed to look green. "Not signed" and
 * "fields withheld" are neutral rather than red, because neither means the
 * document is suspect, and colouring them as failures would train employers
 * to ignore the one state that does mean something is wrong.
 */
export function renderIssuerVerdict({ status, detail }) {
  const el = document.getElementById('issuer-verdict');
  if (!el) return;

  const look = {
    valid:   { cls: 'issuer-ok',      icon: '✓', title: 'Issuer verified' },
    invalid: { cls: 'issuer-bad',     icon: '✕', title: 'Issuer signature does not match' },
    unsigned:{ cls: 'issuer-neutral', icon: '•', title: 'Not signed by the verifier' },
    partial: { cls: 'issuer-neutral', icon: '•', title: 'Partial disclosure, issuer signature not applicable' },
    unknown: { cls: 'issuer-neutral', icon: '•', title: 'Unrecognised issuer' },
    error:   { cls: 'issuer-neutral', icon: '•', title: 'Issuer signature unreadable' },
  }[status] || { cls: 'issuer-neutral', icon: '•', title: 'Issuer not checked' };

  el.className = `issuer ${look.cls}`;
  el.replaceChildren();

  const head = document.createElement('div');
  head.className = 'issuer-head';
  const ic = document.createElement('span');
  ic.className = 'issuer-icon';
  ic.textContent = look.icon;
  const t = document.createElement('strong');
  t.textContent = look.title;
  head.append(ic, t);

  const p = document.createElement('p');
  p.className = 'issuer-detail';
  p.textContent = detail;

  el.append(head, p);
  el.hidden = false;
}
