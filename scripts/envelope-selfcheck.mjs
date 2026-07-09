/**
 * Envelope self-check: builds an "ARDIS1" envelope the same way the app does
 * (magic + 12-byte nonce + AES-256-GCM ciphertext with the tag appended),
 * then decrypts it with the REAL viewer functions from src/envelope.js.
 *
 * Run: npm run selfcheck (plain Node 18+, WebCrypto via globalThis.crypto).
 * Fails loudly (non-zero exit) if the envelope logic breaks.
 */

import assert from 'node:assert/strict';
import { parseKeyFromHash, isEnvelope, decryptEnvelope } from '../src/envelope.js';

const MAGIC = new TextEncoder().encode('ARDIS1');

/** App-side envelope builder, mirrored in pure JS per the contract. */
async function encryptEnvelope(plainBytes, keyBytes) {
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await globalThis.crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt'],
  );
  const ciphertext = new Uint8Array(
    await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plainBytes),
  );
  const out = new Uint8Array(MAGIC.length + nonce.length + ciphertext.length);
  out.set(MAGIC, 0);
  out.set(nonce, MAGIC.length);
  out.set(ciphertext, MAGIC.length + nonce.length);
  return out;
}

const key = globalThis.crypto.getRandomValues(new Uint8Array(32));
const plaintext = new TextEncoder().encode(JSON.stringify({
  credential_type: 'SelfCheck',
  credentialSubject: { name: 'Round Trip', disclosed_fields: ['name'] },
}));

// Magic detection
const envelope = await encryptEnvelope(plaintext, key);
assert.ok(isEnvelope(envelope), 'envelope must carry the ARDIS1 magic');
assert.ok(!isEnvelope(plaintext), 'legacy plaintext must not detect as an envelope');
assert.ok(!isEnvelope(envelope.subarray(0, 20)), 'truncated envelope must not detect');

// Round trip
const decrypted = await decryptEnvelope(envelope, key);
assert.deepEqual(decrypted, plaintext, 'decrypt must return the exact plaintext');

// Tamper: flip one ciphertext byte, GCM auth must reject it
const tampered = envelope.slice();
tampered[tampered.length - 1] ^= 0x01;
await assert.rejects(() => decryptEnvelope(tampered, key), 'tampered ciphertext must fail auth');

// Wrong key must also fail auth
const wrongKey = globalThis.crypto.getRandomValues(new Uint8Array(32));
await assert.rejects(() => decryptEnvelope(envelope, wrongKey), 'wrong key must fail auth');

// URL fragment key parsing (base64url, no padding)
const b64u = Buffer.from(key).toString('base64url');
assert.deepEqual(parseKeyFromHash(`#k=${b64u}`), key, 'hash key must round-trip');
assert.deepEqual(parseKeyFromHash(`#foo=bar&k=${b64u}`), key, 'k must parse among other params');
assert.equal(parseKeyFromHash('#foo=bar'), null, 'missing k must return null');
assert.equal(parseKeyFromHash(''), null, 'empty hash must return null');
assert.equal(parseKeyFromHash('#k=***'), null, 'non-base64url k must return null');

console.log('envelope selfcheck: all assertions passed');
