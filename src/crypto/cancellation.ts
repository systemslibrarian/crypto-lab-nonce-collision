/**
 * The "why the forgery works" derivations — computed, not drawn.
 *
 * The algebra section used to be a static diagram of symbols (tag₁, mask, s)
 * that faded out on a button press. The shape was right, but a learner could
 * not tell whether it described the numbers the cards had just produced. These
 * functions re-derive the cancellation from an ACTUAL run's bytes and check
 * each identity numerically, so every claim on the page is something this run
 * computed:
 *
 *   AES-GCM   T = GHASH_H(C) ⊕ mask, mask = E_K(J₀) fixed by (key, nonce).
 *             Recover the mask from EACH tag independently and compare; then
 *             recompute (C₁ ⊕ C₂)·H² from the recovered H and compare it with
 *             tag₁ ⊕ tag₂.
 *
 *   Poly1305  tag = (n·r mod 2¹³⁰−5 + s) mod 2¹²⁸.  Recover s from EACH probe
 *             independently and compare; then check that the tag difference
 *             equals the polyval difference, both mod 2¹²⁸ — the subtraction
 *             that removes s.
 *
 * Nothing here is illustrative. Every field marked `…Holds` is the result of a
 * comparison between two independently computed values.
 */

import { bytesToField, fieldToBytes, gmul } from './gf128.ts';
import { ghashH } from './ghash-attack.ts';
import { blockValue, CLAMP, POLY_P } from './poly1305.ts';

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export interface GcmCancellation {
  tag1: Uint8Array;
  tag2: Uint8Array;
  ct1: Uint8Array;
  ct2: Uint8Array;
  /** The recovered GHASH subkey H, as handed over by the forbidden attack. */
  H: Uint8Array;
  /** H·H in GF(2¹²⁸) — the coefficient the single-block equation is linear in. */
  hSquared: Uint8Array;
  /** mask = tag₁ ⊕ GHASH_H(C₁), derived from probe 1 alone. */
  maskFrom1: Uint8Array;
  /** mask = tag₂ ⊕ GHASH_H(C₂), derived from probe 2 alone. */
  maskFrom2: Uint8Array;
  /** Byte comparison of the two masks: the "mask ⊕ mask = 0" claim, verified. */
  masksIdentical: boolean;
  /** tag₁ ⊕ tag₂ — the left-hand side, straight off the wire. */
  tagXor: Uint8Array;
  /** C₁ ⊕ C₂. */
  ctXor: Uint8Array;
  /** (C₁ ⊕ C₂)·H² recomputed from the recovered H — the right-hand side. */
  rhs: Uint8Array;
  /** Byte comparison of tagXor and rhs: the cancellation identity, verified. */
  equationHolds: boolean;
}

/**
 * Re-derive the GCM cancellation from one run's ciphertexts, tags and recovered
 * subkey. Both probes must be single-block (1–16 bytes) and equal length, which
 * is what the forbidden-attack runner produces.
 */
export function gcmCancellation(
  ct1: Uint8Array,
  tag1: Uint8Array,
  ct2: Uint8Array,
  tag2: Uint8Array,
  recoveredH: Uint8Array,
): GcmCancellation {
  const H = bytesToField(recoveredH);
  const hSquared = gmul(H, H);

  // The mask is whatever is left of each tag once the polynomial part is
  // removed. Computed from each probe SEPARATELY — if the two agree, the pad
  // really is shared, and that is what makes it cancel.
  const maskFrom1 = bytesToField(tag1) ^ ghashH(H, ct1);
  const maskFrom2 = bytesToField(tag2) ^ ghashH(H, ct2);

  const b1 = new Uint8Array(16);
  b1.set(ct1);
  const b2 = new Uint8Array(16);
  b2.set(ct2);
  const ctXor = bytesToField(b1) ^ bytesToField(b2);
  const tagXor = bytesToField(tag1) ^ bytesToField(tag2);
  const rhs = gmul(ctXor, hSquared);

  return {
    tag1,
    tag2,
    ct1,
    ct2,
    H: recoveredH,
    hSquared: fieldToBytes(hSquared),
    maskFrom1: fieldToBytes(maskFrom1),
    maskFrom2: fieldToBytes(maskFrom2),
    masksIdentical: maskFrom1 === maskFrom2,
    tagXor: fieldToBytes(tagXor),
    ctXor: fieldToBytes(ctXor),
    rhs: fieldToBytes(rhs),
    equationHolds: bytesEqual(fieldToBytes(tagXor), fieldToBytes(rhs)),
  };
}

const TWO128 = 1n << 128n;

function leToBig(b: Uint8Array): bigint {
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
  return v;
}

export interface PolyCancellation {
  /** Block values n₁, n₂ of the two probes (RFC 8439 §2.5.1 encoding). */
  n1: bigint;
  n2: bigint;
  tag1: bigint;
  tag2: bigint;
  /** The recovered one-time key. */
  r: bigint;
  s: bigint;
  /** n·r mod 2¹³⁰−5 for each probe, recomputed from the recovered r. */
  polyval1: bigint;
  polyval2: bigint;
  /** s = (tag − polyval) mod 2¹²⁸, derived from each probe SEPARATELY. */
  sFrom1: bigint;
  sFrom2: bigint;
  /** The "s − s = 0" claim, verified on this run's numbers. */
  sIdentical: boolean;
  /** Does the recovered s match what the probes independently yield? */
  sMatchesRecovered: boolean;
  /** (tag₁ − tag₂) mod 2¹²⁸ — the left-hand side, straight off the wire. */
  tagDiff: bigint;
  /** (polyval₁ − polyval₂) mod 2¹²⁸ — the right-hand side, s already gone. */
  polyDiff: bigint;
  /** The cancellation identity, verified. */
  equationHolds: boolean;
  /** Is the recovered r clamp-valid, as RFC 8439 requires? */
  rClampValid: boolean;
}

/**
 * Re-derive the Poly1305 cancellation from one run's probes, tags and recovered
 * one-time key. Probes must be single-block and equal length.
 */
export function polyCancellation(
  probe1: Uint8Array,
  tag1Bytes: Uint8Array,
  probe2: Uint8Array,
  tag2Bytes: Uint8Array,
  r: bigint,
  s: bigint,
): PolyCancellation {
  const n1 = blockValue(probe1);
  const n2 = blockValue(probe2);
  const tag1 = leToBig(tag1Bytes);
  const tag2 = leToBig(tag2Bytes);

  const polyval1 = (n1 * r) % POLY_P;
  const polyval2 = (n2 * r) % POLY_P;

  const mod128 = (v: bigint): bigint => ((v % TWO128) + TWO128) % TWO128;
  const sFrom1 = mod128(tag1 - polyval1);
  const sFrom2 = mod128(tag2 - polyval2);

  const tagDiff = mod128(tag1 - tag2);
  const polyDiff = mod128(polyval1 - polyval2);

  return {
    n1,
    n2,
    tag1,
    tag2,
    r,
    s,
    polyval1,
    polyval2,
    sFrom1,
    sFrom2,
    sIdentical: sFrom1 === sFrom2,
    sMatchesRecovered: sFrom1 === s,
    tagDiff,
    polyDiff,
    equationHolds: tagDiff === polyDiff,
    rClampValid: (r & CLAMP) === r,
  };
}
