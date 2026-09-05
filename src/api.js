/**
 * Ardis API client.
 *
 * The viewer never touches Storj directly. All credential and document
 * requests go through ardis-ms, which holds the Storj access grant
 * server-side and returns only the data the browser needs. The grant is
 * never exposed to the browser, request logs, or the URL.
 */

import { isEnvelope, decryptEnvelope } from './envelope.js';

// Fallback is the staging ardis-ms, not the Enforcer gateway: every path below
// is an /api/v1/ardis route, which the gateway does not serve.
const API_BASE = (import.meta.env.VITE_ARDIS_API_BASE || 'https://ardis-ms-ix.fly.dev').replace(/\/+$/, '');

/**
 * Fetch a shared credential by its opaque GUID.
 * Resolves to { credential_id, purpose, expires_at, credential, signature? }.
 * Throws an Error with `.status` and `.code` set on failure.
 */
export async function fetchSharedCredential(guid) {
  const url = `${API_BASE}/api/v1/ardis/public/share/${encodeURIComponent(guid)}`;

  let res;
  try {
    res = await fetch(url, { headers: { Accept: 'application/json' } });
  } catch (e) {
    const err = new Error('Could not reach the credential service. Check your connection and try again.');
    err.code = 'network_error';
    throw err;
  }

  let body = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON or empty body handled below */
  }

  if (!res.ok) {
    const err = new Error(body?.message || `Request failed (HTTP ${res.status})`);
    err.status = res.status;
    err.code = body?.error || `http_${res.status}`;
    throw err;
  }

  if (!body?.success || !body?.data) {
    const err = new Error(body?.message || 'The server returned an unexpected response.');
    err.code = 'malformed_response';
    throw err;
  }

  return body.data;
}

/**
 * Fetch a credential display schema from ardis-ms.
 * schemaVersion format: "{verifierId}/{credentialType}/{version}" e.g. "ardis/license/v1"
 * Returns { data_schema, ui_schema } or null if not found.
 * Public endpoint, no auth required.
 *
 * This asked for /latest and threw the version away, while the app renders the
 * version the credential names. So the two sides of one credential could be
 * laid out by different schemas: a field the vendor renamed, reordered or
 * stopped publishing showed one way to the professional and another way to the
 * employer, from the same signed document. Whichever is right, they cannot
 * both be, and the employer is the one making a decision on it.
 *
 * The version the credential declares wins. /latest is the fallback for a
 * credential that names no version, and for one whose version has since been
 * unpublished, where a current layout beats no layout at all.
 */
export async function fetchSchema(schemaVersion) {
  const parts = schemaVersion.split('/');
  if (parts.length < 2) return null;
  const [verifierId, credentialType, version] = parts;
  const base = `${API_BASE}/api/v1/ardis/public/credential-schemas/${encodeURIComponent(verifierId)}/${encodeURIComponent(credentialType)}`;
  const wanted = version ? [`${base}/${encodeURIComponent(version)}`, `${base}/latest`] : [`${base}/latest`];
  for (const url of wanted) {
    try {
      const res = await fetch(url, { headers: { Accept: 'application/json' } });
      if (!res.ok) continue;
      const body = await res.json();
      if (body?.data) return body.data;
    } catch {
      // Try the fallback; a network blip on the pinned version should not
      // leave the employer with an unrendered credential.
    }
  }
  return null;
}

/**
 * Fetch a backup document (e.g. a PDF verification report) belonging to a
 * share and return a blob URL suitable for driving an <a download> click.
 *
 * Why a blob URL rather than a direct link?
 * The document lives in Storj behind the server-side grant. ardis-ms streams
 * the bytes back as application/pdf. We convert to a blob URL so the browser
 * can trigger a file-save without ever exposing a Storj-signed URL or the
 * access grant itself.
 *
 * Encrypted shares: the server streams the ciphertext envelope as-is
 * (application/octet-stream). When the bytes carry the "ARDIS1" magic we
 * decrypt locally with the key from the URL fragment before building the
 * blob, using the content type from the document metadata since the wire
 * type is opaque. Legacy plaintext documents pass through unchanged.
 *
 * storageKey   - the storage_key value from ardis_backup_documents in the VC JSON.
 * keyBytes     - raw share key from the URL fragment, or null for legacy shares.
 * contentType  - original content type from the document metadata (encrypted path only).
 */
export async function fetchShareDocument(guid, storageKey, keyBytes = null, contentType = null, sharePin = null) {
  const url = `${API_BASE}/api/v1/ardis/public/share/${encodeURIComponent(guid)}/documents?key=${encodeURIComponent(storageKey)}`;
  const headers = {};
  if (sharePin) headers['X-Share-Pin'] = sharePin;

  let res;
  try {
    res = await fetch(url, { headers });
  } catch (e) {
    const err = new Error('Could not reach the document service. Check your connection and try again.');
    err.code = 'network_error';
    throw err;
  }

  if (!res.ok) {
    let body = null;
    try { body = await res.json(); } catch { /* non-JSON body */ }
    const err = new Error(body?.message || `Document fetch failed (HTTP ${res.status})`);
    err.status = res.status;
    err.code   = body?.error || `http_${res.status}`;
    throw err;
  }

  const bytes = new Uint8Array(await res.arrayBuffer());

  if (isEnvelope(bytes)) {
    if (!keyBytes) {
      const err = new Error('This link is missing its key fragment.');
      err.code = 'missing_key';
      throw err;
    }
    let plain;
    try {
      plain = await decryptEnvelope(bytes, keyBytes);
    } catch {
      const err = new Error('This document could not be decrypted. The link key may be wrong or the data corrupted.');
      err.code = 'decrypt_failed';
      throw err;
    }
    return URL.createObjectURL(new Blob([plain], { type: contentType || 'application/octet-stream' }));
  }

  // Legacy plaintext document: keep the server-reported content type.
  const legacyType = res.headers.get('Content-Type') || 'application/octet-stream';
  return URL.createObjectURL(new Blob([bytes], { type: legacyType }));
}
