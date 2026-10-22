import { describe, it, expect } from 'vitest';
import { createCipheriv } from 'node:crypto';
import {
  importCtrKey,
  importCbcKey,
  aesCtrEncrypt,
  aesCbcEncrypt,
  cbcCompensatingBlock,
  sharedLeadingBlocks,
  ghashSubkeyH,
  xorBytes,
  textToBytes,
} from './aes.ts';

const hex = (b: Uint8Array) =>
  Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
function randBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

describe('AES-CTR keystream reuse (SP 800-38A)', () => {
  it('round-trips and reuses the keystream when the counter block repeats', async () => {
    const key = await importCtrKey(randBytes(32));
    const counter = randBytes(16);
    const p1 = textToBytes('the quiet part said out loud, block 1');
    const p2 = textToBytes('a different message, exactly same len');
    const c1 = await aesCtrEncrypt(key, counter, p1);
    const c2 = await aesCtrEncrypt(key, counter, p2);

    // round trip
    expect(hex(await aesCtrEncrypt(key, counter, c1))).toBe(hex(p1));
    // C₁ ⊕ C₂ == P₁ ⊕ P₂ (keystream cancels)
    expect(hex(xorBytes(c1, c2))).toBe(hex(xorBytes(p1, p2)));
  });
});

describe('AES-CBC IV reuse leaks shared prefixes (SP 800-38A)', () => {
  it('shares leading ciphertext blocks exactly while plaintext prefixes match', async () => {
    const key = await importCbcKey(randBytes(32));
    const iv = randBytes(16);
    // Two messages sharing the first 32 bytes (two blocks), differing after.
    const prefix = 'PREFIX-BLOCK-01!PREFIX-BLOCK-02!';
    const c1 = await aesCbcEncrypt(key, iv, textToBytes(prefix + 'alice gets paid'));
    const c2 = await aesCbcEncrypt(key, iv, textToBytes(prefix + 'mallory gets it'));
    expect(sharedLeadingBlocks(c1, c2)).toBe(2);

    // Change the very first block: no shared prefix leaks.
    const c3 = await aesCbcEncrypt(key, iv, textToBytes('XREFIX-BLOCK-01!' + prefix.slice(16)));
    expect(sharedLeadingBlocks(c1, c3)).toBe(0);
  });

  it('a fresh IV hides even identical plaintexts', async () => {
    const key = await importCbcKey(randBytes(32));
    const msg = textToBytes('IDENTICAL-BLOCK!IDENTICAL-BLOCK!');
    const c1 = await aesCbcEncrypt(key, randBytes(16), msg);
    const c2 = await aesCbcEncrypt(key, randBytes(16), msg);
    expect(sharedLeadingBlocks(c1, c2)).toBe(0);
  });
});

describe('CBC distinct predictable IVs (SP 800-38A Appendix C)', () => {
  it('matches the first AES-CBC block only when the second plaintext targets the known next IV', async () => {
    const rawKey = Uint8Array.from({ length: 32 }, (_, i) => i);
    const key = await importCbcKey(rawKey);
    const originalIv = new Uint8Array(16);
    const predictableIv = new Uint8Array(16);
    predictableIv[15] = 1;
    const randomControlIv = new Uint8Array(16);
    randomControlIv[15] = 2;
    const original = textToBytes('PAY ALICE $0100!');
    const chosen = cbcCompensatingBlock(original, originalIv, predictableIv);

    expect(hex(originalIv)).not.toBe(hex(predictableIv));
    expect(hex(original)).not.toBe(hex(chosen));
    expect(hex(xorBytes(original, originalIv))).toBe(hex(xorBytes(chosen, predictableIv)));

    const [c1, c2, control] = await Promise.all([
      aesCbcEncrypt(key, originalIv, original),
      aesCbcEncrypt(key, predictableIv, chosen),
      aesCbcEncrypt(key, randomControlIv, chosen),
    ]);
    expect(hex(c1.slice(0, 16))).toBe(hex(c2.slice(0, 16)));
    expect(hex(c1.slice(0, 16))).not.toBe(hex(control.slice(0, 16)));

    // Independent AES-CBC implementation checks the generated WebCrypto blocks.
    const nodeBlock = (iv: Uint8Array, plaintext: Uint8Array) => {
      const cipher = createCipheriv('aes-256-cbc', rawKey, iv);
      return new Uint8Array(Buffer.concat([cipher.update(plaintext), cipher.final()]).subarray(0, 16));
    };
    expect(hex(c1.slice(0, 16))).toBe(hex(nodeBlock(originalIv, original)));
    expect(hex(c2.slice(0, 16))).toBe(hex(nodeBlock(predictableIv, chosen)));
    expect(hex(control.slice(0, 16))).toBe(hex(nodeBlock(randomControlIv, chosen)));
  });

  it('rejects invalid block or IV lengths before computing the compensation', () => {
    expect(() => cbcCompensatingBlock(new Uint8Array(15), new Uint8Array(16), new Uint8Array(16))).toThrow(RangeError);
    expect(() => cbcCompensatingBlock(new Uint8Array(16), new Uint8Array(16), new Uint8Array(17))).toThrow(RangeError);
  });
});

describe('GHASH subkey via CTR-zero equals the GCM spec AES-256 test vector', () => {
  it('E_K(0¹²⁸) for the all-zero key matches the published GCM test vector', async () => {
    // GCM spec (McGrew & Viega, "The Galois/Counter Mode of Operation (GCM)"),
    // Appendix B, Test Case 13: K = 0³², so the GHASH subkey is
    // H = AES-256(key=0³², block=0¹⁶) = dc95c078a2408989ad48a21492842087.
    // Not a FIPS 197 vector — FIPS 197 Appendix C.3's AES-256 example uses
    // key 000102…1e1f with plaintext 00112233…eeff.
    const H = await ghashSubkeyH(new Uint8Array(32));
    expect(hex(H)).toBe('dc95c078a2408989ad48a21492842087');
  });
});
