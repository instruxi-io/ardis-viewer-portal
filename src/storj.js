/**
 * Storj credential fetch module.
 *
 * The access grant embedded in the URL fragment is a serialized Storj access
 * grant (base58). To fetch the credential over HTTPS we exchange it for
 * short-lived S3 credentials via Storj's Auth Service, then call the S3
 * gateway to list and download the VC JSON file.
 *
 * Zero-knowledge upgrade path: replace exchange() + s3Fetch() with
 * @storj/uplink-browser WASM (same grant string, direct satellite access,
 * server never decrypts). Swap implementation below when the package matures.
 */

const AUTH_SERVICE  = 'https://auth.storjshare.io';
const S3_ENDPOINT   = 'https://gateway.storjshare.io';

/**
 * Exchange a Storj access grant for temporary S3 credentials.
 * The auth service never stores the grant — it derives S3 creds from it.
 */
async function exchangeGrant(accessGrant) {
  const res = await fetch(`${AUTH_SERVICE}/v1/access`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ access_grant: accessGrant, public: false }),
  });
  if (!res.ok) throw new Error(`Auth exchange failed: HTTP ${res.status}`);
  return res.json(); // { access_key_id, secret_key, endpoint }
}

/**
 * List objects in the given bucket/prefix using S3 ListObjectsV2 (XML).
 * Returns an array of { key, size } objects.
 */
async function listObjects(creds, bucket, prefix) {
  const url = `${S3_ENDPOINT}/${bucket}?list-type=2&prefix=${encodeURIComponent(prefix)}`;
  const res = await s3Fetch(creds, 'GET', bucket, '', url);
  const text = await res.text();
  // Parse XML — browser DOMParser handles S3 ListObjectsV2 response.
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  return Array.from(doc.querySelectorAll('Contents')).map(el => ({
    key:  el.querySelector('Key')?.textContent ?? '',
    size: parseInt(el.querySelector('Size')?.textContent ?? '0', 10),
  }));
}

/**
 * Download an object from the S3 gateway and return its bytes.
 */
async function downloadObject(creds, bucket, key) {
  const url = `${S3_ENDPOINT}/${bucket}/${key.split('/').map(encodeURIComponent).join('/')}`;
  const res = await s3Fetch(creds, 'GET', bucket, key, url);
  if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);
  return res.arrayBuffer();
}

/**
 * Make an S3-authenticated request using AWS Signature V4.
 * Storj's gateway is S3-compatible and accepts the same signing scheme.
 */
async function s3Fetch(creds, method, bucket, key, url) {
  const { access_key_id: accessKey, secret_key: secretKey } = creds;
  const endpoint = creds.endpoint ?? S3_ENDPOINT;
  const host = new URL(endpoint).host;

  const now = new Date();
  const amzDate   = now.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const region    = 'us1'; // Storj uses region identifiers but ignores them for auth
  const service   = 's3';
  const scope     = `${dateStamp}/${region}/${service}/aws4_request`;

  // Canonical headers
  const canonicalHeaders = `host:${host}\nx-amz-date:${amzDate}\n`;
  const signedHeaders    = 'host;x-amz-date';

  // Payload hash (empty body for GETs)
  const payloadHash = await sha256Hex('');

  // Build canonical request
  const parsedUrl     = new URL(url);
  const canonicalUri  = parsedUrl.pathname;
  const canonicalQs   = parsedUrl.search.slice(1);
  const canonicalReq  = [method, canonicalUri, canonicalQs,
    canonicalHeaders, signedHeaders, payloadHash].join('\n');

  // String to sign
  const hashedCR   = await sha256Hex(canonicalReq);
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, hashedCR].join('\n');

  // Derive signing key
  const signingKey = await deriveSigningKey(secretKey, dateStamp, region, service);
  const signature  = await hmacHex(signingKey, stringToSign);

  const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, `
    + `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return fetch(url, {
    method,
    headers: {
      'X-Amz-Date': amzDate,
      'Authorization': authHeader,
    },
  });
}

// ── Crypto helpers (Web Crypto API) ─────────────────────────────────────────

async function sha256Hex(message) {
  const buf = await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(message));
  return hex(buf);
}

async function hmacHex(key, message) {
  const sig = await crypto.subtle.sign('HMAC', key,
    new TextEncoder().encode(message));
  return hex(sig);
}

async function hmacKey(keyMaterial, message) {
  const rawKey = typeof keyMaterial === 'string'
    ? new TextEncoder().encode(keyMaterial)
    : new Uint8Array(await crypto.subtle.exportKey('raw', keyMaterial));
  const key = await crypto.subtle.importKey(
    'raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key,
    new TextEncoder().encode(message));
  return crypto.subtle.importKey(
    'raw', buf, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
}

async function deriveSigningKey(secret, date, region, service) {
  let key = await hmacKey(`AWS4${secret}`, date);
  key = await hmacKey(key, region);
  key = await hmacKey(key, service);
  return hmacKey(key, 'aws4_request');
}

function hex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Fetch the first VC JSON file found under the given prefix using the
 * provided Storj access grant. Returns the parsed JSON object.
 */
/**
 * Fetch the credential and return { vc, creds, bucket, objects } so callers
 * can offer PDF downloads for any .pdf files found alongside the JSON.
 */
export async function fetchCredential(accessGrant, bucket, prefix, credentialId) {
  console.log('[storj] exchangeGrant start, grant length:', accessGrant.length);
  const creds = await exchangeGrant(accessGrant);
  console.log('[storj] exchangeGrant OK, access_key_id:', creds.access_key_id?.slice(0, 12),
    'endpoint:', creds.endpoint);

  console.log('[storj] listObjects bucket:', bucket, 'prefix:', prefix);
  const objects = await listObjects(creds, bucket, prefix);
  console.log('[storj] listObjects returned', objects.length, 'objects:', objects.map(o => o.key));

  // If credentialId is present, find the JSON file whose filename starts with it.
  // This narrows the match when the grant is scoped to a directory-level prefix.
  const jsonObj = objects.find(o => {
    if (!o.key.endsWith('.json')) return false;
    if (credentialId) {
      const fileName = o.key.split('/').pop();
      return fileName.startsWith(credentialId);
    }
    return true;
  });
  if (!jsonObj) throw new Error('No credential file found in vault path');

  console.log('[storj] downloading:', jsonObj.key);
  const buf  = await downloadObject(creds, bucket, jsonObj.key);
  const text = new TextDecoder().decode(buf);
  const vc   = JSON.parse(text);

  return { vc, creds, bucket, objects };
}

/**
 * Download an object and return a blob URL for in-browser use (e.g. PDF preview/download).
 * The caller is responsible for revoking the URL when done.
 */
export async function fetchObjectUrl(creds, bucket, key, mimeType = 'application/octet-stream') {
  const buf  = await downloadObject(creds, bucket, key);
  const blob = new Blob([buf], { type: mimeType });
  return URL.createObjectURL(blob);
}
