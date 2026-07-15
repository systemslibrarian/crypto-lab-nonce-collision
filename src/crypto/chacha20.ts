/**
 * ChaCha20 stream cipher, hand-rolled per RFC 8439 §2.
 *
 * The keystream is the teaching subject of this lab, so it is implemented from
 * scratch and inspectable rather than hidden in a library. The block function
 * and the "Ladies and Gentlemen" encryption vector are verified against the
 * RFC's own known-answer tests (see chacha20.test.ts).
 *
 * Like every stream cipher, ChaCha20 encrypts by XOR with a keystream that
 * depends only on (key, nonce, counter). Reuse a (key, nonce) and both messages
 * are masked by the identical keystream — the same collapse as AES-CTR.
 */

const CONSTANTS = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

function readLE(b: Uint8Array, i: number): number {
  return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
}

function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
}

/** The 16-word ChaCha20 state for (key, counter, nonce). */
export function chachaState(key: Uint8Array, counter: number, nonce: Uint8Array): Uint32Array {
  if (key.length !== 32) throw new Error('ChaCha20: key must be 32 bytes');
  if (nonce.length !== 12) throw new Error('ChaCha20: nonce must be 12 bytes');
  const s = new Uint32Array(16);
  s.set(CONSTANTS, 0);
  for (let i = 0; i < 8; i++) s[4 + i] = readLE(key, i * 4);
  s[12] = counter >>> 0;
  for (let i = 0; i < 3; i++) s[13 + i] = readLE(nonce, i * 4);
  return s;
}

/** One 64-byte ChaCha20 keystream block (RFC 8439 §2.3). */
export function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  const start = chachaState(key, counter, nonce);
  const s = start.slice();
  for (let i = 0; i < 10; i++) {
    quarterRound(s, 0, 4, 8, 12);
    quarterRound(s, 1, 5, 9, 13);
    quarterRound(s, 2, 6, 10, 14);
    quarterRound(s, 3, 7, 11, 15);
    quarterRound(s, 0, 5, 10, 15);
    quarterRound(s, 1, 6, 11, 12);
    quarterRound(s, 2, 7, 8, 13);
    quarterRound(s, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) dv.setUint32(i * 4, (s[i] + start[i]) >>> 0, true);
  return out;
}

/**
 * ChaCha20 encrypt/decrypt (XOR with the keystream), RFC 8439 §2.4.
 * `initialCounter` defaults to 1, matching the AEAD construction where counter
 * 0 is reserved for the Poly1305 one-time key.
 */
export function chacha20(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  initialCounter = 1,
): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += 64) {
    const block = chacha20Block(key, initialCounter + (off >>> 6), nonce);
    const n = Math.min(64, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ block[i];
  }
  return out;
}

/** The raw ChaCha20 keystream for `length` bytes (for showing the reused pad). */
export function chacha20Keystream(
  key: Uint8Array,
  nonce: Uint8Array,
  length: number,
  initialCounter = 1,
): Uint8Array {
  return chacha20(key, nonce, new Uint8Array(length), initialCounter);
}
