import { describe, it, expect } from 'vitest';
import {
  collisionProbability,
  countForProbability,
  GCM_RANDOM_IV_LIMIT,
} from './nonce.ts';

describe('Nonce birthday-bound math', () => {
  it('probability is 0 below two draws and rises monotonically', () => {
    expect(collisionProbability(96, 0)).toBe(0);
    expect(collisionProbability(96, 1)).toBe(0);
    const a = collisionProbability(96, 1_000_000);
    const b = collisionProbability(96, 10_000_000);
    expect(a).toBeGreaterThan(0);
    expect(b).toBeGreaterThan(a);
  });

  it('countForProbability round-trips against collisionProbability', () => {
    for (const bits of [32, 64, 96]) {
      const n = countForProbability(bits, 0.5);
      expect(collisionProbability(bits, n)).toBeCloseTo(0.5, 2);
    }
  });

  it('50% collision for a 96-bit space needs ~2^48.2 nonces', () => {
    const n = countForProbability(96, 0.5);
    const log2 = Math.log2(n);
    expect(log2).toBeGreaterThan(47.5);
    expect(log2).toBeLessThan(49);
  });

  it('exposes the SP 800-38D 2^32 random-IV ceiling', () => {
    expect(GCM_RANDOM_IV_LIMIT).toBe(2 ** 32);
  });
});
