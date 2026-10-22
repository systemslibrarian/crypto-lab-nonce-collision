# Nonce Collision

**Mode-specific IV/nonce requirements · NIST SP 800-38A/38D · RFC 8439**

Reuse one nonce under one key across AES-CTR, AES-GCM, ChaCha20-Poly1305, and AES-CBC, and watch each construction break in its own way — recovering plaintext, forging tags, or leaking prefixes against the *real* primitives. The point of the lab is the precision: the consequence is construction-specific, and none of them fails gracefully.

> **Not production crypto — a teaching demo.** Every operation is real (AES via WebCrypto; ChaCha20 and Poly1305 hand-rolled to the RFC 8439 vectors), but keys live only in memory for the session and nothing here is hardened for production.

---

## What It Is

A nonce ("number used once") or initialization vector (IV) is a public input whose security requirement depends on the mode. AES-CTR must not repeat a counter block under one key; AES-GCM and ChaCha20-Poly1305 require nonce uniqueness under one key. AES-CBC requires an IV that an attacker cannot predict before choosing the plaintext. CBC IV reuse leaks shared-prefix equality, and a *different but predictable* IV can also enable a chosen-plaintext first-block comparison. The lab runs each construction against real encryption and reports the primitive's result separately from the security verdict.

- **AES-CTR / AES-CBC** — NIST SP 800-38A, run in your browser's WebCrypto engine.
- **AES-GCM** — NIST SP 800-38D, including the IV-uniqueness requirement.
- **ChaCha20-Poly1305** — RFC 8439, hand-rolled (the keystream and the Poly1305 polynomial MAC are the teaching subject, so they are inspectable, not hidden in a library).
- **GHASH & Poly1305** — the two polynomial MACs whose one-time secrets collapse under nonce reuse.

**Security model.** Attacks recover keys from *public* data only — ciphertexts and tags, never the key. The GHASH forbidden attack recovers the **authentication** subkey; the Poly1305 attack recovers the **one-time MAC key**. Neither recovers the AES/ChaCha **encryption** key — and the lab is built to keep that distinction exact.

## Exhibits

1. **The XOR reveal (crib-drag).** Encrypt two messages under one AES-CTR key and one nonce. Because a stream cipher XORs plaintext with a keystream fixed by (key, nonce), the two ciphertexts XOR to `P₁ ⊕ P₂` — the keystream cancels. Drag a guessed run of one message across it and the other message's bytes fall out, live, against real ciphertext. A hero "break a reused nonce now" button and a "show me a working crib" helper give the first payoff in one click.
2. **Reuse, four outcomes — one click.** Flip each construction from a fresh IV/nonce to a *reused* one (or hit **Run all**) and read **two independent indicators** per card — the cryptographic result and the security verdict. Colour tracks the verdict, so a forgery the verifier *accepts* renders as an ALARM, never a green success. Fresh CBC uses random, unpredictable IVs; a distinct CBC IV alone is insufficient.
3. **CBC predictable-IV experiment.** The first AES-CBC encryption reveals its IV and first ciphertext block. The page predicts a distinct counter IV for the next encryption and chooses a second first plaintext block `P₂ = P₁ ⊕ IV₁ ⊕ IV₂`. The real first ciphertext blocks match because AES receives the same input. In the control, the same second plaintext is committed *before* a fresh random IV is drawn, and its first ciphertext block differs. This illustrates a chosen-plaintext confidentiality failure under a predictable IV; it does not recover an unknown plaintext or key and does not test authentication.
4. **The "what broke?" scoreboard + consequence table.** A running tally updates as you run cards — Plaintext exposure, Forgery possible, Encryption key recovered — the last row staying *No* everywhere. The consequence table summarizes the reuse experiments separately from CBC's predictable-IV exhibit.
5. **Why the forgeries work.** Step through the single cancellation behind both authenticated breaks: XOR two same-nonce tags and the per-nonce secret (GCM's mask; Poly1305's `s`) cancels, exposing an equation in the key you want. The panel is **computed, not drawn**: pressing it encrypts (or MACs) two probes under a fresh key and one reused nonce, re-derives the shared pad from *each* tag independently, prints both, and checks them against each other — then recomputes `(C₁ ⊕ C₂)·H²` from the recovered H and compares it byte-for-byte with `tag₁ ⊕ tag₂` (and, for Poly1305, `tag₁ − tag₂` against `polyval₁ − polyval₂` mod 2¹²⁸). Press again and every number changes, because every number came from that run.
6. **Where nonces repeat.** Live birthday-bound math for random nonces (32/64/96-bit), the SP 800-38D 2³² random-IV ceiling, and the counter-rewind failure (VM snapshot / fork).
7. **The mitigation, in-frame.** A compact AES-GCM vs AES-GCM-SIV contrast (described from RFC 8452 — SIV is deliberately *not* implemented here) closes the loop before linking to [Nonce Guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) for the live side-by-side.

## When to Use It

- **Use** to see how each mode's IV or nonce requirement changes the result: CTR/AEAD reuse, CBC reused-IV prefix leakage, and the separate CBC predictable-IV chosen-plaintext comparison.
- **Use** to see a real forbidden-attack GHASH-key recovery and a real Poly1305 one-time-key recovery end in a forgery the genuine verifier accepts.
- **Do NOT** use this code as a crypto library or take a passing encryption/decryption as a complete security guarantee. CTR and CBC provide no authentication here. The exhibits establish only their stated conditions; in particular, the new CBC exhibit requires the attacker to know the next IV before choosing the plaintext.

## Live Demo

**https://systemslibrarian.github.io/crypto-lab-nonce-collision/**

Type two messages and crib-drag a secret out of the XOR; toggle reuse and watch AES-GCM and ChaCha20-Poly1305 accept forged tags while CBC reveals shared-prefix equality. Then run the separate CBC experiment to compare distinct predictable IVs with a random IV chosen only after plaintext commitment.

## What Can Go Wrong

The failures this lab *causes on purpose*:

- **Keystream reuse (CTR, ChaCha20).** `C₁ ⊕ C₂ = P₁ ⊕ P₂`; crib-dragging recovers plaintext. No integrity claim exists to lose.
- **GHASH authentication-key recovery (GCM).** Two ciphertexts under one nonce → the forbidden attack solves for `H = E_K(0¹²⁸)` → existential forgery. **Authentication-key recovery, not AES-key recovery.**
- **Poly1305 one-time-key recovery (ChaCha20-Poly1305).** The reused nonce fixes `(r, s)`; messages under it reveal `(r, s)` → forgery for that nonce. **The ChaCha20 key is not recovered.**
- **CBC IV reuse.** Reusing an IV makes CBC deterministic on shared prefixes: equal leading plaintext blocks produce equal leading ciphertext blocks. It is a pattern leak, not keystream collapse.
- **CBC predictable but distinct IVs.** If an attacker can choose a plaintext after seeing the next IV, the first plaintext block can compensate for the IV difference and yield the same first ciphertext block as a known encryption. This controlled chosen-plaintext result is not unknown-plaintext recovery or a padding-oracle attack. A new random IV drawn after plaintext commitment prevents this specific compensation, but CBC by itself does not authenticate messages.

NIST [SP 800-38A §5.3 and Appendix C](https://csrc.nist.gov/pubs/sp/800/38/a/final) specify CBC IV unpredictability and `C₁ = Eₖ(P₁ ⊕ IV)`. [NIST IR 8459 §4.1 (September 2024)](https://csrc.nist.gov/pubs/ir/8459/final) discusses predictable CBC IVs, including the historical BEAST attack context. The CBC review also draws on Khan and Cox, *Hacking Cryptography* (2025), §10.1.3; the linked NIST publications provide the public primary references.

## Real-World Usage

Nonce reuse is not hypothetical. A 2016 survey (Böck, Zauner, Devlin, et al.) found production HTTPS servers reusing AES-GCM nonces, exposed to exactly the forbidden attack. Counter-based nonces have rewound after VM snapshots and process forks, re-emitting values under a long-lived key. This is why SP 800-38D caps a single key at **2³² invocations** when 96-bit IVs are random, and why misuse-resistant designs such as **AES-GCM-SIV** (RFC 8452) exist — see the [Nonce Guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) lab.

## How to Run Locally

```bash
npm install
npm run dev        # Vite dev server
npm run build      # type-check + production build to dist/
npm test           # Vitest unit + KAT suite
npm run test:a11y  # axe-core WCAG gate against the built site (needs: npx playwright install chromium)
```

## Related Demos

- [Nonce Guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — AES-GCM vs AES-GCM-SIV under nonce misuse (the mitigation this lab points to).
- [Padding Oracle](https://systemslibrarian.github.io/crypto-lab-padding-oracle/) — the CBC integrity break this lab deliberately skips.
- [ChaCha20 Stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — the keystream on its own.
- [AES Modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — CTR, CBC, and friends side by side.
- [MAC Race](https://systemslibrarian.github.io/crypto-lab-mac-race/) — how message authentication is supposed to work.
- **Entropy Collapse** — how randomness and counters fail upstream of the nonce (in the [catalog](https://crypto-lab.systemslibrarian.dev/)).

## Build & Verify

The Vitest suite (`npm test`) includes these spec known-answer tests:

| Vector | Source | File |
| --- | --- | --- |
| ChaCha20 block function | RFC 8439 §2.3.2 | `src/crypto/chacha20.test.ts` |
| ChaCha20 encryption ("sunscreen") | RFC 8439 §2.4.2 | `src/crypto/chacha20.test.ts` |
| Poly1305 MAC | RFC 8439 §2.5.2 | `src/crypto/poly1305.test.ts` |
| Poly1305 key generation | RFC 8439 §2.6.2 | `src/crypto/poly1305.test.ts` |
| ChaCha20-Poly1305 AEAD | RFC 8439 §2.8.2 | `src/crypto/aead.test.ts` |
| GHASH field math | cross-checked vs an independent GHASH reference | `src/crypto/gf128.test.ts` |
| AES-256 `E_K(0¹²⁸)` (GHASH subkey `H`) | GCM spec (McGrew & Viega) Appendix B, Test Case 13 | `src/crypto/aes.test.ts` |

Beyond the KATs, the suite proves the attacks are real: the forbidden attack recovers `H` byte-for-byte over random keys and the forged blob is accepted by **WebCrypto's own** AES-GCM verifier; the Poly1305 recovery reproduces the true `(r, s)` and the forged tag is accepted by the real verifier; unique nonces provably do **not** recover either key.

The CBC predictable-IV test independently cross-checks the WebCrypto demonstration against Node's AES-CBC for the known `P₁ ⊕ IV₁ = P₂ ⊕ IV₂` relation, checks distinct IVs and plaintexts, and compares a third IV drawn after plaintext commitment. The browser regression test checks the rendered distinct-IV and random-control outcomes and public source links.

**Accessibility is gated in CI.** `@axe-core/playwright` scans the production build for zero WCAG 2.1 A/AA violations in **both** themes — driving the demo into its ALARM/LEAK states first — and the GitHub Pages deploy is blocked if it fails.

## Performance

Everything runs client-side with no backend. The GF(2¹²⁸) and Poly1305 solvers use native `BigInt`; each attack completes in well under a frame. AES uses hardware-accelerated WebCrypto.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*

## Wider-block proposal

The live demo now distinguishes the [1 June 2026 wGCM consultation](https://csrc.nist.gov/pubs/sp/800/38/d/r1/2prd) from finalized GCM and AES key-size selection. It does not implement wGCM.
