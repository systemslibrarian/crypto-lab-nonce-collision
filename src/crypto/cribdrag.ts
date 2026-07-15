/**
 * The XOR reveal — the headline mechanism of the lab.
 *
 * Any stream cipher (AES-CTR, ChaCha20) encrypts as Cᵢ = Pᵢ ⊕ KS. When the
 * SAME keystream KS masks two messages, XORing the ciphertexts annihilates it:
 *
 *     C₁ ⊕ C₂ = (P₁ ⊕ KS) ⊕ (P₂ ⊕ KS) = P₁ ⊕ P₂
 *
 * No key is involved in the result. If you know (or guess) a run of P₁, XOR it
 * into P₁ ⊕ P₂ at that offset and the matching bytes of P₂ fall out. That is
 * "crib-dragging," and every function here operates on real ciphertext bytes.
 */

/** C₁ ⊕ C₂ over the shared length — equals P₁ ⊕ P₂ when the keystream is reused. */
export function combineCiphertexts(c1: Uint8Array, c2: Uint8Array): Uint8Array {
  const len = Math.min(c1.length, c2.length);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = c1[i] ^ c2[i];
  return out;
}

/**
 * Drag a crib (a guessed run of P₁) across P₁ ⊕ P₂ at `offset`, revealing the
 * corresponding bytes of P₂. Returns the recovered bytes and which are
 * printable ASCII — a real recovery, not a hint.
 */
export function cribDrag(
  combined: Uint8Array,
  crib: Uint8Array,
  offset: number,
): { revealed: Uint8Array; printable: boolean[] } {
  const revealed = new Uint8Array(crib.length);
  const printable: boolean[] = [];
  for (let i = 0; i < crib.length; i++) {
    const idx = offset + i;
    const val = idx >= 0 && idx < combined.length ? combined[idx] ^ crib[i] : 0;
    revealed[i] = val;
    printable.push(val >= 0x20 && val < 0x7f);
  }
  return { revealed, printable };
}

/**
 * A crib guess "reads well" when every recovered byte is printable ASCII — a
 * cheap plausibility score a human uses to slide the crib into place.
 */
export function readsWell(printable: boolean[]): boolean {
  return printable.length > 0 && printable.every(Boolean);
}

/** Render bytes as text, non-printables shown as "·". */
export function toReadable(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '·'))
    .join('');
}
