/**
 * Ardis API client.
 *
 * The viewer no longer touches Storj directly. It calls the Ardis public share
 * endpoint, which holds the access grant server-side and returns only the
 * credential JSON. The grant is never exposed to the browser.
 */

const API_BASE = (import.meta.env.VITE_ARDIS_API_BASE || 'https://gateway.instruxi.dev').replace(/\/+$/, '');

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
