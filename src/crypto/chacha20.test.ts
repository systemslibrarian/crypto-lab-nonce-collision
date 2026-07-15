import { describe, it, expect } from 'vitest';
import { chacha20, chacha20Block } from './chacha20.ts';

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

// RFC 8439 §2.3: key = 00..1f
const KEY = new Uint8Array(32).map((_, i) => i);

describe('ChaCha20 block function — RFC 8439 §2.3.2 KAT', () => {
  it('produces the exact serialized keystream block (counter=1)', () => {
    const nonce = fromHex('00 00 00 09 00 00 00 4a 00 00 00 00');
    const expected =
      '10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4' +
      'c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e' +
      'd2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2' +
      'b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e';
    expect(hex(chacha20Block(KEY, 1, nonce))).toBe(hex(fromHex(expected)));
  });
});

describe('ChaCha20 encryption — RFC 8439 §2.4.2 KAT', () => {
  it("encrypts the 'sunscreen' plaintext to the RFC ciphertext (counter=1)", () => {
    const nonce = fromHex('00 00 00 00 00 00 00 4a 00 00 00 00');
    const plaintext = new TextEncoder().encode(
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
    );
    const expected =
      '6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81' +
      'e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b' +
      'f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57' +
      '16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8' +
      '07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e' +
      '52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36' +
      '5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42' +
      '87 4d';
    const ct = chacha20(KEY, nonce, plaintext, 1);
    expect(hex(ct)).toBe(hex(fromHex(expected)));
  });

  it('is its own inverse (decrypt = encrypt with same keystream)', () => {
    const nonce = fromHex('00 00 00 00 00 00 00 4a 00 00 00 00');
    const pt = new TextEncoder().encode('round trip through the keystream');
    const ct = chacha20(KEY, nonce, pt, 1);
    expect(hex(chacha20(KEY, nonce, ct, 1))).toBe(hex(pt));
  });
});
