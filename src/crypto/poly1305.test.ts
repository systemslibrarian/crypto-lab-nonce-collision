import { describe, it, expect } from 'vitest';
import {
  poly1305Mac,
  poly1305MacRS,
  splitKey,
  recoverOneTimeKey,
  tagsEqual,
} from './poly1305.ts';
import { poly1305KeyGen } from './aead.ts';

const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');

function fromHex(s: string): Uint8Array {
  const clean = s.replace(/\s+/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function randBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

describe('Poly1305 — RFC 8439 §2.5.2 KAT', () => {
  it('MACs the Research Group message to the RFC tag', () => {
    const key = fromHex(
      '85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8' +
        '01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b',
    );
    const msg = new TextEncoder().encode('Cryptographic Forum Research Group');
    const expected = 'a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9';
    expect(hex(poly1305Mac(key, msg))).toBe(hex(fromHex(expected)));
  });
});

describe('Poly1305 key generation — RFC 8439 §2.6.2 KAT', () => {
  it('derives the one-time key from ChaCha20 block 0', () => {
    const key = new Uint8Array(32).map((_, i) => 0x80 + i);
    const nonce = fromHex('00 00 00 00 00 01 02 03 04 05 06 07');
    const expected =
      '8a d5 a0 8b 90 5f 81 cc 81 50 40 27 4a b2 94 71' +
      'a8 33 b6 37 e3 fd 0d a5 08 db b8 e2 fd d1 a6 46';
    expect(hex(poly1305KeyGen(key, nonce))).toBe(hex(fromHex(expected)));
  });
});

describe('One-time-key reuse recovers (r, s) from public tags, then forges', () => {
  it('recovers the exact (r, s) and forges accepted tags over random keys', () => {
    for (let i = 0; i < 40; i++) {
      const otk = randBytes(32);
      const { r, s } = splitKey(otk);
      const msgs = [randBytes(16), randBytes(16), randBytes(16)];
      const tags = msgs.map((m) => poly1305Mac(otk, m));

      const rec = recoverOneTimeKey(msgs, tags);
      expect(rec.ok).toBe(true);
      expect(rec.r).toBe(r);
      expect(rec.s).toBe(s);

      // Forge a tag for a fresh chosen message; the real verifier must accept.
      const forgedMsg = randBytes(16);
      const forged = poly1305MacRS(rec.r, rec.s, forgedMsg);
      expect(tagsEqual(forged, poly1305Mac(otk, forgedMsg))).toBe(true);
    }
  });

  it('a tag forged under a WRONG one-time key is rejected (break is real)', () => {
    const otk = randBytes(32);
    const msg = randBytes(16);
    const honest = poly1305Mac(otk, msg);
    const wrong = poly1305MacRS(1n, 2n, msg);
    expect(tagsEqual(wrong, honest)).toBe(false);
  });
});
