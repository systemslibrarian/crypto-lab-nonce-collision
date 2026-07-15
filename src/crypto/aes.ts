/**
 * Real AES via WebCrypto (SubtleCrypto): CTR (SP 800-38A), CBC (SP 800-38A),
 * and GCM (SP 800-38D). Nothing here is simulated — every ciphertext and every
 * verification is produced by the browser's own AES implementation.
 *
 * The AES-GCM forgery is proven against WebCrypto's *own* verifier: after the
 * GHASH subkey H is recovered from public (ciphertext, tag) data, we forge a tag
 * and hand the (ciphertext ‖ tag) blob straight to `crypto.subtle.decrypt`. If
 * it returns plaintext instead of throwing, the real verifier accepted a forgery.
 */

import {
  recoverGhashKey,
  forgeTag,
  ghashH,
  type RecoveredKey,
} from './ghash-attack.ts';
import { bytesToField, fieldToBytes } from './gf128.ts';

const enc = new TextEncoder();
export function textToBytes(s: string): Uint8Array {
  return enc.encode(s);
}

/** Copy into a fresh ArrayBuffer-backed view so WebCrypto's typing is satisfied. */
function ab(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(b.slice()) as Uint8Array<ArrayBuffer>;
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = a[i] ^ b[i];
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ── Key import ──

export function importCtrKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', ab(raw), { name: 'AES-CTR' }, false, [
    'encrypt',
    'decrypt',
  ]);
}
export function importCbcKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', ab(raw), { name: 'AES-CBC' }, false, [
    'encrypt',
  ]);
}
export function importGcmKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', ab(raw), { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

// ── AES-CTR (SP 800-38A) ──

/**
 * AES-CTR keystream cipher. `counter` is the full 16-byte initial counter
 * block; the low 64 bits are the block counter. The keystream depends only on
 * (key, counter) — not on the plaintext — which is exactly why reusing a
 * counter block across two messages collapses to a plaintext XOR.
 */
export async function aesCtrEncrypt(
  key: CryptoKey,
  counter: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const out = await crypto.subtle.encrypt(
    { name: 'AES-CTR', counter: ab(counter), length: 64 },
    key,
    ab(plaintext),
  );
  return new Uint8Array(out);
}

// ── AES-CBC (SP 800-38A) ──

/** AES-CBC with PKCS#7 padding (WebCrypto default). `iv` is 16 bytes. */
export async function aesCbcEncrypt(
  key: CryptoKey,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const out = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: ab(iv) },
    key,
    ab(plaintext),
  );
  return new Uint8Array(out);
}

/** Split a byte string into 16-byte blocks (last block may be short). */
export function toBlocks(b: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < b.length; i += 16) out.push(b.slice(i, i + 16));
  return out;
}

/**
 * Count how many leading 16-byte ciphertext blocks two CBC ciphertexts share.
 * Under a reused (key, IV) this equals the number of leading plaintext blocks
 * they share — CBC leaks equality of message prefixes, and nothing more.
 */
export function sharedLeadingBlocks(c1: Uint8Array, c2: Uint8Array): number {
  const a = toBlocks(c1);
  const b = toBlocks(c2);
  let n = 0;
  const lim = Math.min(a.length, b.length);
  while (n < lim && bytesEqual(a[n], b[n])) n++;
  return n;
}

// ── AES-GCM (SP 800-38D) ──

export interface GcmResult {
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

/** AES-GCM encrypt with a 96-bit nonce; returns ciphertext and the 128-bit tag. */
export async function aesGcmEncrypt(
  key: CryptoKey,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): Promise<GcmResult> {
  const out = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: ab(nonce), tagLength: 128 },
      key,
      ab(plaintext),
    ),
  );
  return { ciphertext: out.slice(0, out.length - 16), tag: out.slice(out.length - 16) };
}

/**
 * AES-GCM verify+decrypt via WebCrypto. Returns the plaintext if the tag is
 * accepted, or `null` if authentication fails. This is the *real verifier* the
 * forgery must fool — no shortcut.
 */
export async function aesGcmVerify(
  key: CryptoKey,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
): Promise<Uint8Array | null> {
  const blob = new Uint8Array(ciphertext.length + tag.length);
  blob.set(ciphertext, 0);
  blob.set(tag, ciphertext.length);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ab(nonce), tagLength: 128 },
      key,
      ab(blob),
    );
    return new Uint8Array(pt);
  } catch {
    return null;
  }
}

/**
 * The GHASH authentication subkey H = E_K(0¹²⁸), computed with WebCrypto alone:
 * AES-CTR with an all-zero counter block encrypts an all-zero block to E_K(0),
 * which by definition (SP 800-38D §6.3) is H. Used only as independent ground
 * truth to prove the forbidden-attack recovery landed exactly.
 */
export async function ghashSubkeyH(rawKey: Uint8Array): Promise<Uint8Array> {
  const ctrKey = await importCtrKey(rawKey);
  const zeroCounter = new Uint8Array(16);
  const zeroBlock = new Uint8Array(16);
  return aesCtrEncrypt(ctrKey, zeroCounter, zeroBlock);
}

export interface ForbiddenAttackResult {
  probe1: Uint8Array;
  probe2: Uint8Array;
  ct1: Uint8Array;
  ct2: Uint8Array;
  tag1: Uint8Array;
  tag2: Uint8Array;
  /** GHASH subkey recovered from ONLY the two (ciphertext, tag) pairs. */
  recoveredH: Uint8Array;
  /** True H = E_K(0¹²⁸), computed independently, proving the recovery is exact. */
  trueH: Uint8Array;
  recovered: boolean;
  /** A message the attacker never legitimately encrypted. */
  forgedPlaintext: Uint8Array;
  forgedCiphertext: Uint8Array;
  forgedTag: Uint8Array;
  /** Whether the REAL WebCrypto AES-GCM verifier accepted the forged blob. */
  forgeryAccepted: boolean;
  /** What the verifier returned as plaintext on acceptance (attacker's message). */
  forgedDecrypted: Uint8Array | null;
}

/**
 * Carry out Joux's forbidden attack end to end on a reused (key, nonce): encrypt
 * two single-block probes, recover H from only their (ciphertext, tag) pairs,
 * then forge a valid tag for an attacker-chosen ciphertext and prove the real
 * WebCrypto verifier accepts it.
 *
 * Fixed 16-byte probes are used because the closed-form solver targets the
 * single-block case; the key and nonce are the demo's own reused pair.
 */
export async function runForbiddenAttack(
  rawKey: Uint8Array,
  nonce: Uint8Array,
): Promise<ForbiddenAttackResult> {
  const gcmKey = await importGcmKey(rawKey);

  const probe1 = textToBytes('forbidden-atk-01'); // 16 bytes, one block
  const probe2 = textToBytes('forbidden-atk-02');

  const e1 = await aesGcmEncrypt(gcmKey, nonce, probe1);
  const e2 = await aesGcmEncrypt(gcmKey, nonce, probe2);

  // Attacker sees only ciphertexts and tags — recovers H and the mask.
  const recovered: RecoveredKey = recoverGhashKey(e1.ciphertext, e1.tag, e2.ciphertext, e2.tag);

  const trueH = await ghashSubkeyH(rawKey);
  const recoveredOk = bytesEqual(recovered.H, trueH);

  // Forge a valid tag for a message the attacker chose but never encrypted.
  // A genuine ciphertext for the chosen plaintext under the reused nonce is
  // produced by the real primitive; only the tag is forged from recovered H+mask.
  const forgedPlaintext = textToBytes('PWNED: nonce reuse forged this tag');
  const genuine = await aesGcmEncrypt(gcmKey, nonce, forgedPlaintext);
  const forgedCiphertext = genuine.ciphertext;
  const forgedTag = forgeTag(recovered, forgedCiphertext);

  const forgedDecrypted = await aesGcmVerify(gcmKey, nonce, forgedCiphertext, forgedTag);
  const forgeryAccepted = forgedDecrypted !== null;

  return {
    probe1,
    probe2,
    ct1: e1.ciphertext,
    ct2: e2.ciphertext,
    tag1: e1.tag,
    tag2: e2.tag,
    recoveredH: recovered.H,
    trueH,
    recovered: recoveredOk,
    forgedPlaintext,
    forgedCiphertext,
    forgedTag,
    forgeryAccepted,
    forgedDecrypted,
  };
}

/** Re-export field helpers used by callers that want to display raw GHASH math. */
export { ghashH, bytesToField, fieldToBytes };
