import { describe, it, expect } from 'vitest';
import { gcmCancellation, polyCancellation } from './cancellation.ts';
import { randomBytes, runForbiddenAttack } from './aes.ts';
import { runOneTimeKeyRecovery } from './aead.ts';
import { bytesToField, gmul } from './gf128.ts';
import { blockValue, CLAMP, POLY_P, splitKey } from './poly1305.ts';
import { poly1305KeyGen } from './aead.ts';

describe('AES-GCM cancellation, derived from a real run', () => {
  it('the mask recovered from each tag separately is the same value', async () => {
    const res = await runForbiddenAttack(randomBytes(32), randomBytes(12));
    const c = gcmCancellation(res.ct1, res.tag1, res.ct2, res.tag2, res.recoveredH);
    expect(c.masksIdentical).toBe(true);
    expect(Array.from(c.maskFrom1)).toEqual(Array.from(c.maskFrom2));
  });

  it('tag1 XOR tag2 equals (C1 XOR C2)·H² recomputed from the recovered H', async () => {
    const res = await runForbiddenAttack(randomBytes(32), randomBytes(12));
    const c = gcmCancellation(res.ct1, res.tag1, res.ct2, res.tag2, res.recoveredH);
    expect(c.equationHolds).toBe(true);
    expect(Array.from(c.tagXor)).toEqual(Array.from(c.rhs));
  });

  it('the reported XOR and product are the real ones, not copies of each other', async () => {
    const res = await runForbiddenAttack(randomBytes(32), randomBytes(12));
    const c = gcmCancellation(res.ct1, res.tag1, res.ct2, res.tag2, res.recoveredH);
    // Independently recompute both sides here.
    const tagXor = bytesToField(res.tag1) ^ bytesToField(res.tag2);
    const b1 = new Uint8Array(16);
    b1.set(res.ct1);
    const b2 = new Uint8Array(16);
    b2.set(res.ct2);
    const ctXor = bytesToField(b1) ^ bytesToField(b2);
    const H = bytesToField(res.recoveredH);
    expect(bytesToField(c.tagXor)).toBe(tagXor);
    expect(bytesToField(c.ctXor)).toBe(ctXor);
    expect(bytesToField(c.hSquared)).toBe(gmul(H, H));
    expect(bytesToField(c.rhs)).toBe(gmul(ctXor, gmul(H, H)));
  });

  it('a wrong H breaks the identity — the check is not vacuous', async () => {
    const res = await runForbiddenAttack(randomBytes(32), randomBytes(12));
    const bogusH = res.recoveredH.slice();
    bogusH[0] ^= 0x01;
    const c = gcmCancellation(res.ct1, res.tag1, res.ct2, res.tag2, bogusH);
    expect(c.equationHolds).toBe(false);
    expect(c.masksIdentical).toBe(false);
  });

  it('the run really does reuse one nonce for two distinct probes', async () => {
    const res = await runForbiddenAttack(randomBytes(32), randomBytes(12));
    expect(Array.from(res.ct1)).not.toEqual(Array.from(res.ct2));
    expect(Array.from(res.tag1)).not.toEqual(Array.from(res.tag2));
    expect(res.recovered).toBe(true);
  });
});

describe('Poly1305 cancellation, derived from a real run', () => {
  it('the s recovered from each probe separately is the same number', () => {
    const res = runOneTimeKeyRecovery(randomBytes(32), randomBytes(12));
    const c = polyCancellation(
      res.probes[0], res.tags[0], res.probes[1], res.tags[1], res.recoveredR, res.recoveredS,
    );
    expect(c.sIdentical).toBe(true);
    expect(c.sMatchesRecovered).toBe(true);
  });

  it('the tag difference equals the polyval difference mod 2^128', () => {
    const res = runOneTimeKeyRecovery(randomBytes(32), randomBytes(12));
    const c = polyCancellation(
      res.probes[0], res.tags[0], res.probes[1], res.tags[1], res.recoveredR, res.recoveredS,
    );
    expect(c.equationHolds).toBe(true);
    expect(c.tagDiff).toBe(c.polyDiff);
  });

  it('polyvals are recomputed from the recovered r against the true block values', () => {
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const res = runOneTimeKeyRecovery(key, nonce);
    const { r: trueR, s: trueS } = splitKey(poly1305KeyGen(key, nonce));
    const c = polyCancellation(
      res.probes[0], res.tags[0], res.probes[1], res.tags[1], res.recoveredR, res.recoveredS,
    );
    expect(c.r).toBe(trueR);
    expect(c.s).toBe(trueS);
    expect(c.n1).toBe(blockValue(res.probes[0]));
    expect(c.n2).toBe(blockValue(res.probes[1]));
    expect(c.polyval1).toBe((c.n1 * trueR) % POLY_P);
    expect(c.rClampValid).toBe(true);
    expect(c.r & CLAMP).toBe(c.r);
  });

  it('a wrong r breaks the identity — the check is not vacuous', () => {
    const res = runOneTimeKeyRecovery(randomBytes(32), randomBytes(12));
    const c = polyCancellation(
      res.probes[0], res.tags[0], res.probes[1], res.tags[1], res.recoveredR ^ 0x10n, res.recoveredS,
    );
    // The tag difference is fixed by the wire; the polyval difference moves.
    expect(c.equationHolds).toBe(false);
    expect(c.sIdentical).toBe(false);
  });

  it('the two probes are distinct, so the cancellation has something to cancel', () => {
    const res = runOneTimeKeyRecovery(randomBytes(32), randomBytes(12));
    const c = polyCancellation(
      res.probes[0], res.tags[0], res.probes[1], res.tags[1], res.recoveredR, res.recoveredS,
    );
    expect(c.n1).not.toBe(c.n2);
    expect(c.tag1).not.toBe(c.tag2);
    expect(c.tagDiff).not.toBe(0n);
  });
});
