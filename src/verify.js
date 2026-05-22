/**
 * Wallet signature verification — ECRecover using ethers.js.
 *
 * The share payload signed by the mobile app wallet is:
 *   '{"share_id":"...","credential_id":"...","purpose":"...","expires_at":"..."}'
 *
 * The signature is EIP-191 personal_sign (prefixed with
 * "\x19Ethereum Signed Message:\n{len}"). ethers.js verifyMessage handles
 * this prefix automatically.
 */
import { ethers } from 'ethers';

/**
 * Recover the signer address from a share event signature.
 * Returns the EVM address (0x...) or null if verification fails.
 */
export function recoverSigner(payload, signature) {
  try {
    return ethers.verifyMessage(payload, signature);
  } catch {
    return null;
  }
}

/**
 * Build the canonical share payload string from URL fragment params.
 * Must match the format used in sharecode_flow_screen.dart.
 */
export function buildSignPayload({ shareId, credentialId, purpose, expiresAt }) {
  return `{"share_id":"${shareId}","credential_id":"${credentialId}","purpose":"${purpose}","expires_at":"${expiresAt}"}`;
}
