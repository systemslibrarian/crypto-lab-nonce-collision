/**
 * Poly1305 one-time authenticator, hand-rolled per RFC 8439 §2.5.
 *
 * Poly1305 is a Wegman–Carter MAC: for a one-time key (r, s) the tag of a
 * message is  ( poly_r(message) + s )  mod 2¹²⁸,  where poly_r evaluates the
 * message as a polynomial in r over the prime field GF(2¹³⁰−5). "One-time"
 * is load-bearing: the (r, s) pair may authenticate exactly ONE message. In
 * ChaCha20-Poly1305 that pair is ChaCha20(key, nonce, counter=0)[0:32], so it
 * is fixed by (key, nonce). Reuse the nonce and you reuse (r, s) — and two
 * messages under one (r, s) leak enough to solve for r and s and forge.
 *
 * The recovery here is genuine: it takes only the two (message, tag) pairs an
 * attacker can see, never the key, and the forged tags it enables are accepted
 * by the real Poly1305 verifier (see poly1305.test.ts).
 */

const P = (1n << 130n) - 5n;
/** The Poly1305 prime 2¹³⁰−5, exported so the cancellation panel can recompute
 *  polyval on this run's numbers rather than assert the identity. */
export const POLY_P = P;
/** The RFC 8439 clamp: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff. */
export const CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;

function leToBig(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}

function bigTo16LE(v: bigint): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Split a 32-byte one-time key into clamped r and s (both field-sized ints). */
export function splitKey(oneTimeKey: Uint8Array): { r: bigint; s: bigint } {
  if (oneTimeKey.length !== 32) throw new Error('Poly1305: one-time key must be 32 bytes');
  const r = leToBig(oneTimeKey.subarray(0, 16)) & CLAMP;
  const s = leToBig(oneTimeKey.subarray(16, 32));
  return { r, s };
}

/** The block value n_i = int(block ‖ 0x01) little-endian (RFC 8439 §2.5.1). */
export function blockValue(block: Uint8Array): bigint {
  return leToBig(block) + (1n << BigInt(8 * block.length));
}

/** Core MAC from an explicit (r, s) — used both for the standard MAC and forging. */
export function poly1305MacRS(r: bigint, s: bigint, msg: Uint8Array): Uint8Array {
  let acc = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    acc = ((acc + blockValue(msg.subarray(i, i + 16))) * r) % P;
  }
  acc = (acc + s) % (1n << 128n);
  return bigTo16LE(acc);
}

/** Standard Poly1305: derive (r, s) from the 32-byte one-time key, then MAC. */
export function poly1305Mac(oneTimeKey: Uint8Array, msg: Uint8Array): Uint8Array {
  const { r, s } = splitKey(oneTimeKey);
  return poly1305MacRS(r, s, msg);
}

/** Constant-time-ish 16-byte compare for the real verifier. */
export function tagsEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return r;
}
function modinv(a: bigint, mod: bigint): bigint {
  return modpow(((a % mod) + mod) % mod, mod - 2n, mod);
}

export interface RecoveredOneTimeKey {
  r: bigint;
  s: bigint;
  ok: boolean;
}

/**
 * Recover the Poly1305 one-time key (r, s) from ≥2 EQUAL-LENGTH single-block
 * messages (≤16 bytes) authenticated under the SAME reused key — using only the
 * public (message, tag) pairs.
 *
 * For single blocks poly_r(m) = n·r, so tag = (n·r + s) truncated mod 2¹²⁸
 * (NOT reduced mod p again). Subtracting two tags cancels s and leaves a LINEAR
 * relation in r, up to a small unknown reduction carry k from the 2¹²⁸
 * truncation:
 *
 *     (tag₁ − tag₂) + k·2¹²⁸  ≡  (n₁ − n₂)·r   (mod 2¹³⁰−5)
 *
 * We enumerate every carry k, invert (n₁ − n₂) to get a candidate r, recover s
 * as the exact integer tag₁ + k₁·2¹²⁸ − (n₁·r mod p), and keep only clamp-valid
 * candidates that reproduce EVERY supplied tag. Two well-separated probes are
 * almost always enough; a third makes the solution provably unique (two data
 * points can otherwise admit more than one clamp-valid key). We return a key
 * only when exactly one survives — otherwise `ok` is false and the attacker
 * simply grabs another message under the reused nonce.
 */
export function recoverOneTimeKey(
  msgs: Uint8Array[],
  tags: Uint8Array[],
): RecoveredOneTimeKey {
  if (msgs.length < 2 || msgs.length !== tags.length) return { r: 0n, s: 0n, ok: false };
  const len = msgs[0].length;
  if (len === 0 || len > 16 || msgs.some((m) => m.length !== len)) {
    return { r: 0n, s: 0n, ok: false };
  }
  const n1 = blockValue(msgs[0]);
  const n2 = blockValue(msgs[1]);
  const D = (((n1 - n2) % P) + P) % P;
  if (D === 0n) return { r: 0n, s: 0n, ok: false };
  const Dinv = modinv(D, P);
  const T1 = leToBig(tags[0]);
  const T2 = leToBig(tags[1]);
  const TWO128 = 1n << 128n;

  const found: Array<{ r: bigint; s: bigint }> = [];
  for (let k = -4; k <= 4; k++) {
    const lhs = (((T1 - T2 + BigInt(k) * TWO128) % P) + P) % P;
    const r = (lhs * Dinv) % P;
    if ((r & CLAMP) !== r) continue; // must match the RFC clamp pattern
    const base = (n1 * r) % P; // polyval₁ = n₁·r mod p
    for (let k1 = 0; k1 <= 4; k1++) {
      const s = T1 + BigInt(k1) * TWO128 - base; // exact integer, not mod p
      if (s < 0n || s >= TWO128) continue;
      const matchesAll = msgs.every((m, i) => tagsEqual(poly1305MacRS(r, s, m), tags[i]));
      if (matchesAll && !found.some((c) => c.r === r && c.s === s)) found.push({ r, s });
    }
  }
  if (found.length === 1) return { r: found[0].r, s: found[0].s, ok: true };
  return { r: 0n, s: 0n, ok: false };
}
