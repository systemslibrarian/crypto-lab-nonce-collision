import { describe, it, expect } from 'vitest';
import { recoverGhashKey, forgeTag, ghashH } from './ghash-attack.ts';
import { bytesToField, fieldToBytes } from './gf128.ts';
import {
  importGcmKey,
  aesGcmEncrypt,
  aesGcmVerify,
  ghashSubkeyH,
  runForbiddenAttack,
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

describe("Joux's forbidden attack recovers the GHASH subkey H (WebCrypto AES-GCM)", () => {
  it('recovered H exactly equals E_K(0¹²⁸) over random keys/nonces', async () => {
    for (let i = 0; i < 15; i++) {
      const rawKey = randBytes(32);
      const nonce = randBytes(12);
      const key = await importGcmKey(rawKey);
      const p1 = randBytes(16);
      let p2 = randBytes(16);
      if (hex(p1) === hex(p2)) p2 = randBytes(16);

      const e1 = await aesGcmEncrypt(key, nonce, p1);
      const e2 = await aesGcmEncrypt(key, nonce, p2);

      const { H } = recoverGhashKey(e1.ciphertext, e1.tag, e2.ciphertext, e2.tag);
      expect(hex(H)).toBe(hex(await ghashSubkeyH(rawKey)));
    }
  });

  it('needs a real nonce collision: unique nonces do NOT recover H', async () => {
    const rawKey = randBytes(32);
    const key = await importGcmKey(rawKey);
    const e1 = await aesGcmEncrypt(key, randBytes(12), randBytes(16));
    const e2 = await aesGcmEncrypt(key, randBytes(12), randBytes(16));
    const { H } = recoverGhashKey(e1.ciphertext, e1.tag, e2.ciphertext, e2.tag);
    expect(hex(H)).not.toBe(hex(await ghashSubkeyH(rawKey)));
  });

  it('rejects unequal-length ciphertexts', async () => {
    const key = await importGcmKey(randBytes(32));
    const nonce = randBytes(12);
    const a = await aesGcmEncrypt(key, nonce, randBytes(16));
    const b = await aesGcmEncrypt(key, nonce, randBytes(8));
    expect(() => recoverGhashKey(a.ciphertext, a.tag, b.ciphertext, b.tag)).toThrow();
  });
});

describe('Forged tags are accepted by the REAL WebCrypto AES-GCM verifier', () => {
  it('the end-to-end attack recovers H, forges, and the verifier accepts', async () => {
    for (let i = 0; i < 8; i++) {
      const res = await runForbiddenAttack(randBytes(32), randBytes(12));
      expect(res.recovered).toBe(true);
      expect(res.forgeryAccepted).toBe(true);
      expect(res.forgedDecrypted).not.toBeNull();
      expect(hex(res.forgedDecrypted as Uint8Array)).toBe(hex(res.forgedPlaintext));
    }
  });

  it('a wrong (non-recovered) tag is rejected — the break is not trivial', async () => {
    const rawKey = randBytes(32);
    const nonce = randBytes(12);
    const key = await importGcmKey(rawKey);
    const { ciphertext } = await aesGcmEncrypt(key, nonce, randBytes(16));
    const bogus = randBytes(16);
    expect(await aesGcmVerify(key, nonce, ciphertext, bogus)).toBeNull();
  });
});

describe('ghashH sanity: mask cancels across two same-nonce tags', () => {
  it('T₁ ⊕ T₂ equals GHASH_H(C₁) ⊕ GHASH_H(C₂)', async () => {
    const rawKey = randBytes(32);
    const nonce = randBytes(12);
    const key = await importGcmKey(rawKey);
    const e1 = await aesGcmEncrypt(key, nonce, randBytes(16));
    const e2 = await aesGcmEncrypt(key, nonce, randBytes(16));
    const H = bytesToField(await ghashSubkeyH(rawKey));
    const dTag = bytesToField(e1.tag) ^ bytesToField(e2.tag);
    const dGhash = ghashH(H, e1.ciphertext) ^ ghashH(H, e2.ciphertext);
    expect(hex(fieldToBytes(dTag))).toBe(hex(fieldToBytes(dGhash)));
    void forgeTag;
  });
});
