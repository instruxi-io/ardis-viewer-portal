/**
 * Ardis encryption envelope (v1): shared binary format with the app.
 *
 * Layout:
 *   bytes 0-5   ASCII magic "ARDIS1"
 *   bytes 6-17  12-byte random nonce
 *   bytes 18+   AES-256-GCM ciphertext with the 16-byte auth tag appended
 *
 * No AAD. Detection: payload starts with "ARDIS1" => encrypted envelope,
 * anything else is legacy plaintext.
 *
 * The share key K travels only in the URL fragment (#k=<base64url no-pad>),
 * which the browser never sends to any server. This module runs in both the
 * browser and Node 18+ (globalThis.crypto / atob are available in both).
 */

const MAGIC = new TextEncoder().encode('ARDIS1');
const NONCE_LEN = 12;
const TAG_LEN = 16;

/**
 * Read the share key from a URL hash fragment ("#k=<base64url no-pad>").
 * Defaults to the current page's location.hash when called in a browser.
 * Returns the raw key bytes as a Uint8Array, or null if absent/malformed.
 */
export function parseKeyFromHash(hash = globalThis.location?.hash ?? '') {
  const part = hash.replace(/^#/, '').split('&').find(p => p.startsWith('k='));
  if (!part) return null;
  const b64u = part.slice(2);
  if (!/^[A-Za-z0-9_-]+$/.test(b64u)) return null;
  try {
    const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

/** True if the bytes carry the "ARDIS1" magic and are long enough to hold a nonce + auth tag. */
export function isEnvelope(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (b.length < MAGIC.length + NONCE_LEN + TAG_LEN) return false;
  for (let i = 0; i < MAGIC.length; i++) {
    if (b[i] !== MAGIC[i]) return false;
  }
  return true;
}

/**
 * Decrypt an envelope with the raw 32-byte share key.
 * Returns the plaintext as a Uint8Array. Throws on a malformed envelope or
 * GCM auth failure (wrong key or tampered ciphertext).
 */
export async function decryptEnvelope(bytes, keyBytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (!isEnvelope(b)) throw new Error('Not an Ardis envelope');
  const nonce = b.subarray(MAGIC.length, MAGIC.length + NONCE_LEN);
  const ciphertext = b.subarray(MAGIC.length + NONCE_LEN);
  const key = await globalThis.crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt'],
  );
  const plain = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce }, key, ciphertext,
  );
  return new Uint8Array(plain);
}
