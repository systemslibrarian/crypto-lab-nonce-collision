/**
 * ChaCha20-Poly1305 AEAD, hand-rolled per RFC 8439 §2.8, plus the two
 * nonce-reuse consequences the lab teaches:
 *
 *   1. Keystream reuse — ChaCha20 is a stream cipher, so C₁ ⊕ C₂ = P₁ ⊕ P₂
 *      exactly as in AES-CTR. (Shown with the shared crib-drag interaction.)
 *   2. Poly1305 one-time-key recovery — the per-message key (r, s) is fixed by
 *      (key, nonce); two messages authenticated under it reveal (r, s), enabling
 *      forgery for that nonce.
 *
 * PRECISION: the recovered secret is the Poly1305 one-time key (r, s). The
 * ChaCha20 encryption key is NOT recovered. Forgery is possible only under the
 * reused nonce; a fresh nonce yields a fresh (r, s) and the break does not carry.
 */

import { chacha20, chacha20Block } from './chacha20.ts';
import {
  poly1305Mac,
  poly1305MacRS,
  splitKey,
  tagsEqual,
  recoverOneTimeKey,
} from './poly1305.ts';

const enc = new TextEncoder();

function pad16(len: number): Uint8Array {
  const rem = len % 16;
  return new Uint8Array(rem === 0 ? 0 : 16 - rem);
}
function le64(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** poly1305_key_gen (RFC 8439 §2.6): ChaCha20 block 0 under (key, nonce), first 32 bytes. */
export function poly1305KeyGen(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  return chacha20Block(key, 0, nonce).subarray(0, 32);
}

/** The Poly1305 MAC input for AEAD (RFC 8439 §2.8): aad ‖ pad ‖ ct ‖ pad ‖ len64s. */
function aeadMacData(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return concat(
    aad,
    pad16(aad.length),
    ciphertext,
    pad16(ciphertext.length),
    le64(aad.length),
    le64(ciphertext.length),
  );
}

export interface AeadResult {
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

/** ChaCha20-Poly1305 AEAD encrypt (RFC 8439 §2.8). */
export function chachaPolyEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): AeadResult {
  const otk = poly1305KeyGen(key, nonce);
  const ciphertext = chacha20(key, nonce, plaintext, 1);
  const tag = poly1305Mac(otk, aeadMacData(aad, ciphertext));
  return { ciphertext, tag };
}

/** ChaCha20-Poly1305 AEAD verify+decrypt. Returns plaintext, or null on auth failure. */
export function chachaPolyVerify(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
): Uint8Array | null {
  const otk = poly1305KeyGen(key, nonce);
  const expected = poly1305Mac(otk, aeadMacData(aad, ciphertext));
  if (!tagsEqual(expected, tag)) return null;
  return chacha20(key, nonce, ciphertext, 1);
}

export interface OneTimeKeyRecoveryResult {
  probes: Uint8Array[];
  tags: Uint8Array[];
  /** True clamped r derived directly from (key, nonce), for ground-truth display. */
  trueR: bigint;
  trueS: bigint;
  recoveredR: bigint;
  recoveredS: bigint;
  recovered: boolean;
  forgedMessage: Uint8Array;
  forgedTag: Uint8Array;
  /** Whether the REAL Poly1305 verifier (true one-time key) accepts the forged tag. */
  forgeryAccepted: boolean;
}

/**
 * Recover the Poly1305 one-time key (r, s) from two single-block messages MACed
 * under the reused (key, nonce), then forge a tag for a message the attacker
 * chose and prove the real Poly1305 verifier accepts it.
 *
 * The two probes are raw Poly1305 messages under the demo's one-time key — the
 * cleanest single-block case. The same reused key underlies the full AEAD tag;
 * the framing (§2.8) only changes which polynomial is solved, not that (r, s)
 * leaks once a nonce repeats.
 */
export function runOneTimeKeyRecovery(
  key: Uint8Array,
  nonce: Uint8Array,
): OneTimeKeyRecoveryResult {
  const otk = poly1305KeyGen(key, nonce);
  const { r: trueR, s: trueS } = splitKey(otk);

  // Three well-separated single-block probes MACed under the reused one-time
  // key. Three data points make the (r, s) solution provably unique.
  const probes = [
    enc.encode('crib:KNOWN-plain'),
    enc.encode('MALLORY::9000!!!'),
    enc.encode('probe-block-#003'),
  ];
  const tags = probes.map((p) => poly1305Mac(otk, p));

  // Attacker sees only (message, tag) pairs.
  const rec = recoverOneTimeKey(probes, tags);
  const recovered = rec.ok && rec.r === trueR && rec.s === trueS;

  // Forge a tag for a chosen message using the recovered (r, s).
  const forgedMessage = enc.encode('forged under reused nonce');
  const forgedTag = poly1305MacRS(rec.r, rec.s, forgedMessage);

  // Prove it against the REAL verifier (which uses the true one-time key).
  const honestTag = poly1305Mac(otk, forgedMessage);
  const forgeryAccepted = tagsEqual(forgedTag, honestTag);

  return {
    probes,
    tags,
    trueR,
    trueS,
    recoveredR: rec.r,
    recoveredS: rec.s,
    recovered,
    forgedMessage,
    forgedTag,
    forgeryAccepted,
  };
}
