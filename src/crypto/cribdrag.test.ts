import { describe, it, expect } from 'vitest';
import { combineCiphertexts, cribDrag, readsWell, toReadable } from './cribdrag.ts';
import { importCtrKey, aesCtrEncrypt, textToBytes } from './aes.ts';

const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
function randBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

describe('Crib-drag XOR reveal against real AES-CTR ciphertext', () => {
  it('a correct crib on P₁ reveals the true bytes of P₂', async () => {
    const key = await importCtrKey(randBytes(32));
    const counter = randBytes(16);
    const p1 = textToBytes('Transfer $1000 to Alice right now please');
    const p2 = textToBytes('Transfer $9000 to Mallory immediately!!!');
    const c1 = await aesCtrEncrypt(key, counter, p1);
    const c2 = await aesCtrEncrypt(key, counter, p2);

    const combined = combineCiphertexts(c1, c2);
    // Drag the known opening of P₁ across the combined stream.
    const crib = textToBytes('Transfer $');
    const { revealed, printable } = cribDrag(combined, crib, 0);

    // Revealed bytes must equal the true P₂ prefix.
    expect(hex(revealed)).toBe(hex(p2.slice(0, crib.length)));
    expect(toReadable(revealed)).toBe('Transfer $');
    expect(readsWell(printable)).toBe(true);
  });

  it('a wrong-offset crib generally yields non-printable garble', async () => {
    const key = await importCtrKey(randBytes(32));
    const counter = randBytes(16);
    const p1 = textToBytes('the eagle lands at midnight sharp okay');
    const p2 = textToBytes('the walrus swims at noonday bright yes!');
    const combined = combineCiphertexts(
      await aesCtrEncrypt(key, counter, p1),
      await aesCtrEncrypt(key, counter, p2),
    );
    // Crib that does not correspond to P₁ at this offset.
    const { printable } = cribDrag(combined, textToBytes('ZZZZZZZZ'), 3);
    expect(readsWell(printable)).toBe(false);
  });
});
