import { describe, it, expect } from 'vitest';
import {
  chachaPolyEncrypt,
  chachaPolyVerify,
  runOneTimeKeyRecovery,
} from './aead.ts';
import { combineCiphertexts } from './cribdrag.ts';

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

describe('ChaCha20-Poly1305 AEAD — RFC 8439 §2.8.2 KAT', () => {
  const key = new Uint8Array(32).map((_, i) => 0x80 + i);
  const nonce = fromHex('07 00 00 00 40 41 42 43 44 45 46 47');
  const aad = fromHex('50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7');
  const plaintext = new TextEncoder().encode(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  );
  const expectedCt =
    'd3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2' +
    'a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6' +
    '3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b' +
    '1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36' +
    '92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58' +
    'fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc' +
    '3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b' +
    '61 16';
  const expectedTag = '1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91';

  it('encrypts to the RFC ciphertext and tag', () => {
    const { ciphertext, tag } = chachaPolyEncrypt(key, nonce, aad, plaintext);
    expect(hex(ciphertext)).toBe(hex(fromHex(expectedCt)));
    expect(hex(tag)).toBe(hex(fromHex(expectedTag)));
  });

  it('verifies and decrypts back to the plaintext', () => {
    const { ciphertext, tag } = chachaPolyEncrypt(key, nonce, aad, plaintext);
    const dec = chachaPolyVerify(key, nonce, aad, ciphertext, tag);
    expect(dec).not.toBeNull();
    expect(hex(dec as Uint8Array)).toBe(hex(plaintext));
  });

  it('rejects a tampered tag', () => {
    const { ciphertext, tag } = chachaPolyEncrypt(key, nonce, aad, plaintext);
    const bad = tag.slice();
    bad[0] ^= 1;
    expect(chachaPolyVerify(key, nonce, aad, ciphertext, bad)).toBeNull();
  });
});

describe('Nonce reuse consequence 1: keystream reuse leaks P₁ ⊕ P₂', () => {
  it('C₁ ⊕ C₂ equals P₁ ⊕ P₂ under a reused (key, nonce)', () => {
    const key = randBytes(32);
    const nonce = randBytes(12);
    const p1 = new TextEncoder().encode('attack at dawn, bring the maps');
    const p2 = new TextEncoder().encode('retreat at dusk, burn the maps');
    const c1 = chachaPolyEncrypt(key, nonce, new Uint8Array(0), p1).ciphertext;
    const c2 = chachaPolyEncrypt(key, nonce, new Uint8Array(0), p2).ciphertext;
    const combined = combineCiphertexts(c1, c2);
    const pxor = p1.map((b, i) => b ^ p2[i]);
    expect(hex(combined)).toBe(hex(pxor));
  });
});

describe('Nonce reuse consequence 2: Poly1305 one-time-key recovery → forgery', () => {
  it('recovers (r, s) and forges a tag the real verifier accepts', () => {
    const key = randBytes(32);
    const nonce = randBytes(12);
    const res = runOneTimeKeyRecovery(key, nonce);
    expect(res.recovered).toBe(true);
    expect(res.forgeryAccepted).toBe(true);
    expect(res.recoveredR).toBe(res.trueR);
    expect(res.recoveredS).toBe(res.trueS);
  });
});
