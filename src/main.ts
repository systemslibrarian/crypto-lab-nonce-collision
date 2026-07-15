import './style.css';
import {
  importCtrKey,
  importCbcKey,
  importGcmKey,
  aesCtrEncrypt,
  aesCbcEncrypt,
  aesGcmEncrypt,
  aesGcmVerify,
  sharedLeadingBlocks,
  toBlocks,
  runForbiddenAttack,
  randomBytes,
  textToBytes,
  xorBytes,
} from './crypto/aes.ts';
import { combineCiphertexts, cribDrag, readsWell, toReadable } from './crypto/cribdrag.ts';
import {
  chachaPolyEncrypt,
  chachaPolyVerify,
  runOneTimeKeyRecovery,
} from './crypto/aead.ts';
import {
  collisionProbability,
  countForProbability,
  formatProbability,
} from './crypto/nonce.ts';

// ── small DOM + format helpers ──
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const enc = new TextEncoder();

function hex(bytes: Uint8Array, maxBytes = 0): string {
  const arr = maxBytes > 0 && bytes.length > maxBytes ? bytes.slice(0, maxBytes) : bytes;
  const s = Array.from(arr)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(' ');
  return maxBytes > 0 && bytes.length > maxBytes ? s + ' …' : s;
}

function renderByteLane(container: HTMLElement, bytes: Uint8Array, printableFlags?: boolean[]): void {
  container.textContent = '';
  bytes.forEach((b, i) => {
    const span = document.createElement('span');
    span.className = 'byte';
    if (printableFlags) span.classList.add(printableFlags[i] ? 'printable' : 'nonprint');
    span.textContent = b.toString(16).padStart(2, '0');
    container.appendChild(span);
  });
}

type Level = 'safe' | 'leak' | 'broken';
const ICON: Record<Level, string> = { safe: '✓', leak: '⚠', broken: '✗' };

interface ResultSpec {
  cryptoLabel: string;
  cryptoValue: string;
  level: Level;
  verdictTitle: string;
  verdictDetail: string;
  extraHTML?: string;
}

function renderResult(slot: HTMLElement, spec: ResultSpec): void {
  slot.textContent = '';
  const wrap = document.createElement('div');
  wrap.className = 'result';
  wrap.innerHTML = `
    <div class="crypto-result">
      <span class="cr-label">Cryptographic result</span>
      <span class="cr-value">${escapeHTML(spec.cryptoValue)}</span>
      <span class="cr-sub">${escapeHTML(spec.cryptoLabel)}</span>
    </div>
    <div class="verdict verdict-${spec.level}">
      <span class="v-label">Security verdict</span>
      <span class="v-title"><span class="v-icon" aria-hidden="true">${ICON[spec.level]}</span>${escapeHTML(spec.verdictTitle)}</span>
      <p class="v-detail">${spec.verdictDetail}</p>
    </div>
    ${spec.extraHTML ?? ''}`;
  slot.appendChild(wrap);
}

function escapeHTML(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] as string);
}

// ════════════════════════════════════════════════════════════════════════
//  1. THE XOR REVEAL — crib-drag against real AES-CTR ciphertext
// ════════════════════════════════════════════════════════════════════════
let combined: Uint8Array = new Uint8Array(0);

async function encryptForReveal(): Promise<void> {
  const p1 = enc.encode(($('cd-msg1') as HTMLTextAreaElement).value);
  const p2 = enc.encode(($('cd-msg2') as HTMLTextAreaElement).value);
  const key = await importCtrKey(randomBytes(32));
  const counter = randomBytes(16); // ONE reused counter block — the mistake
  const c1 = await aesCtrEncrypt(key, counter, p1);
  const c2 = await aesCtrEncrypt(key, counter, p2);
  combined = combineCiphertexts(c1, c2);

  renderByteLane($('cd-combined'), combined);
  $('cd-panel').hidden = false;
  const off = $('cd-offset') as HTMLInputElement;
  const crib = ($('cd-crib') as HTMLInputElement).value;
  off.max = String(Math.max(0, combined.length - Math.max(1, enc.encode(crib).length)));
  ($('cd-status')).textContent =
    'Both messages encrypted under one key and one reused counter block. The combined lane is P1 XOR P2. Use the crib and offset to recover message 2.';
  updateCribDrag();
}

function updateCribDrag(): void {
  if (combined.length === 0) return;
  const cribBytes = enc.encode(($('cd-crib') as HTMLInputElement).value);
  const off = $('cd-offset') as HTMLInputElement;
  off.max = String(Math.max(0, combined.length - Math.max(1, cribBytes.length)));
  const offset = Math.min(Number(off.value), Number(off.max));
  off.value = String(offset);
  $('cd-offset-val').textContent = `offset ${offset}`;

  const { revealed, printable } = cribDrag(combined, cribBytes, offset);
  renderByteLane($('cd-reveal-lane'), revealed, printable);
  const text = toReadable(revealed);
  const well = readsWell(printable);
  const revealEl = $('cd-reveal-text');
  revealEl.textContent = cribBytes.length
    ? `Message 2 here reads: “${text}”${well ? ' — all printable, your crib fits.' : ''}`
    : 'Type a crib to begin.';
  revealEl.classList.toggle('reveal-hit', well && cribBytes.length > 0);
}

// ════════════════════════════════════════════════════════════════════════
//  2. FOUR OUTCOMES — one scenario, four constructions, verdicts separated
// ════════════════════════════════════════════════════════════════════════
const SCENARIO_P1 = 'Transfer $100 to Alice, confirm by noon.';
const SCENARIO_P2 = 'Transfer $9k to Mallory, confirm by noon.';
// Two messages sharing a two-block (32-byte) prefix, differing only after.
const CBC_P1 = 'ACCT 0009: standing order to ::: pay the landlord monthly';
const CBC_P2 = 'ACCT 0009: standing order to ::: pay an attacker one time';

function reused(id: string): boolean {
  return ($(id) as HTMLInputElement).checked;
}

async function runCtr(): Promise<void> {
  const slot = $('out-ctr');
  const key = await importCtrKey(randomBytes(32));
  const p1 = textToBytes(SCENARIO_P1);
  const p2 = textToBytes(SCENARIO_P2);

  if (!reused('reuse-ctr')) {
    const c1 = await aesCtrEncrypt(key, randomBytes(16), p1);
    const c2 = await aesCtrEncrypt(key, randomBytes(16), p2);
    const combo = combineCiphertexts(c1, c2);
    renderResult(slot, {
      cryptoLabel: 'AES-CTR decrypt round-trips normally.',
      cryptoValue: 'Decryption: OK',
      level: 'safe',
      verdictTitle: 'SAFE — unique nonce',
      verdictDetail:
        'Different counter blocks mean different keystreams. C₁ ⊕ C₂ is noise; XORing the ciphertexts reveals nothing about the plaintexts.',
      extraHTML: laneExtra('C₁ ⊕ C₂ (fresh nonces) — noise', combo, toReadable(combo)),
    });
    return;
  }

  const counter = randomBytes(16);
  const c1 = await aesCtrEncrypt(key, counter, p1);
  const c2 = await aesCtrEncrypt(key, counter, p2);
  const combo = combineCiphertexts(c1, c2);
  // Prove the pad is gone: XOR the known P₁ back in and P₂ appears verbatim.
  const p2Recovered = xorBytes(combo, p1);
  renderResult(slot, {
    cryptoLabel: 'AES-CTR still decrypts fine — there is no integrity check to fail.',
    cryptoValue: 'Decryption: OK',
    level: 'broken',
    verdictTitle: 'CONFIDENTIALITY LOST',
    verdictDetail:
      'One counter block, two messages: the keystream cancels and <code>C₁ ⊕ C₂ = P₁ ⊕ P₂</code>. XOR a known message back in and the other appears — no key needed.',
    extraHTML: laneExtra('(C₁ ⊕ C₂) ⊕ P₁ = P₂ — message 2, recovered', combo, toReadable(p2Recovered)),
  });
}

async function runGcm(): Promise<void> {
  const slot = $('out-gcm');
  const rawKey = randomBytes(32);
  const key = await importGcmKey(rawKey);

  if (!reused('reuse-gcm')) {
    const { ciphertext, tag } = await aesGcmEncrypt(key, randomBytes(12), textToBytes(SCENARIO_P1));
    const ok = (await aesGcmVerify(key, randomBytes(12), ciphertext, tag)) !== null;
    renderResult(slot, {
      cryptoLabel: 'Honest tag under a unique nonce.',
      cryptoValue: ok ? 'WebCrypto verify: VALID' : 'WebCrypto verify: (mismatched nonce) REJECT',
      level: 'safe',
      verdictTitle: 'SAFE — unique nonce',
      verdictDetail:
        'With the nonce fresh, the per-nonce mask never repeats, so H stays hidden and no tag can be forged.',
    });
    return;
  }

  const res = await runForbiddenAttack(rawKey, randomBytes(12));
  const forged = res.forgedDecrypted ? toReadable(res.forgedDecrypted) : '(rejected)';
  renderResult(slot, {
    cryptoLabel: 'WebCrypto AES-GCM decrypt returned the attacker’s plaintext for a tag the key never produced.',
    cryptoValue: res.forgeryAccepted ? 'WebCrypto verify(forged): VALID' : 'WebCrypto verify(forged): REJECT',
    level: 'broken',
    verdictTitle: 'FORGERY ACCEPTED — AUTHENTICATION BROKEN',
    verdictDetail:
      'Two ciphertexts under one nonce recovered the GHASH subkey H via the forbidden attack; the forged tag is accepted by WebCrypto’s own verifier.',
    extraHTML: `
      <div class="key-detail" role="group" aria-label="What was and was not recovered">
        <p class="precision"><span class="pill pill-bad">Recovered</span> GHASH authentication subkey H = E<sub>K</sub>(0¹²⁸) — matches ground truth: <strong>${res.recovered ? 'yes' : 'no'}</strong>.</p>
        <p class="precision"><span class="pill pill-good">NOT recovered</span> the AES-256 key K. Forgery works only under this reused nonce.</p>
        <p class="mono-line"><span class="ml-label">recovered H</span> ${hex(res.recoveredH)}</p>
        <p class="mono-line"><span class="ml-label">forged&nbsp;msg</span> “${escapeHTML(forged)}”</p>
      </div>`,
  });
}

function runChacha(): void {
  const slot = $('out-chacha');
  const key = randomBytes(32);

  if (!reused('reuse-chacha')) {
    const { ciphertext, tag } = chachaPolyEncrypt(key, randomBytes(12), new Uint8Array(0), textToBytes(SCENARIO_P1));
    const ok = chachaPolyVerify(key, randomBytes(12), new Uint8Array(0), ciphertext, tag) !== null;
    renderResult(slot, {
      cryptoLabel: 'Honest tag under a unique nonce.',
      cryptoValue: ok ? 'Poly1305 verify: VALID' : 'Poly1305 verify: (mismatched nonce) REJECT',
      level: 'safe',
      verdictTitle: 'SAFE — unique nonce',
      verdictDetail:
        'A fresh nonce gives a fresh Poly1305 one-time key (r, s); with only one message under it, nothing leaks.',
    });
    return;
  }

  const nonce = randomBytes(12);
  const res = runOneTimeKeyRecovery(key, nonce);
  // Also show the confidentiality side: keystream reuse under this nonce.
  const c1 = chachaPolyEncrypt(key, nonce, new Uint8Array(0), textToBytes(SCENARIO_P1)).ciphertext;
  const c2 = chachaPolyEncrypt(key, nonce, new Uint8Array(0), textToBytes(SCENARIO_P2)).ciphertext;
  const combo = combineCiphertexts(c1, c2);
  renderResult(slot, {
    cryptoLabel: 'The real Poly1305 verifier accepts a tag produced from the recovered one-time key.',
    cryptoValue: res.forgeryAccepted ? 'Poly1305 verify(forged): VALID' : 'Poly1305 verify(forged): REJECT',
    level: 'broken',
    verdictTitle: 'FORGERY ACCEPTED — ONE-TIME KEY RECOVERED',
    verdictDetail:
      'The nonce fixes the Poly1305 one-time key (r, s); messages authenticated under it reveal (r, s), and a forged tag verifies. Separately, the ChaCha keystream reuse exposes <code>P₁ ⊕ P₂</code>.',
    extraHTML: `
      <div class="key-detail" role="group" aria-label="What was and was not recovered">
        <p class="precision"><span class="pill pill-bad">Recovered</span> Poly1305 one-time key (r, s) — matches ground truth: <strong>${res.recovered ? 'yes' : 'no'}</strong>.</p>
        <p class="precision"><span class="pill pill-good">NOT recovered</span> the ChaCha20 key. Forgery works only under this reused nonce.</p>
        <p class="mono-line"><span class="ml-label">recovered r</span> ${res.recoveredR.toString(16)}</p>
      </div>
      ${laneExtra('C₁ ⊕ C₂ = P₁ ⊕ P₂ — keystream also gone', combo, toReadable(combo))}`,
  });
}

async function runCbc(): Promise<void> {
  const slot = $('out-cbc');
  const key = await importCbcKey(randomBytes(32));
  const p1 = textToBytes(CBC_P1);
  const p2 = textToBytes(CBC_P2);

  if (!reused('reuse-cbc')) {
    const c1 = await aesCbcEncrypt(key, randomBytes(16), p1);
    const c2 = await aesCbcEncrypt(key, randomBytes(16), p2);
    renderResult(slot, {
      cryptoLabel: 'AES-CBC decrypt round-trips normally.',
      cryptoValue: 'Decryption: OK',
      level: 'safe',
      verdictTitle: 'SAFE — fresh IV',
      verdictDetail: `A random IV randomises the first block, so even a shared prefix hides. Shared leading ciphertext blocks: <strong>${sharedLeadingBlocks(c1, c2)}</strong>.`,
    });
    return;
  }

  const iv = randomBytes(16);
  const c1 = await aesCbcEncrypt(key, iv, p1);
  const c2 = await aesCbcEncrypt(key, iv, p2);
  const shared = sharedLeadingBlocks(c1, c2);
  const b1 = toBlocks(c1);
  renderResult(slot, {
    cryptoLabel: 'AES-CBC decrypt round-trips normally — this is a leak, not a decryption break.',
    cryptoValue: 'Decryption: OK',
    level: 'leak',
    verdictTitle: 'PREFIX EQUALITY LEAKED',
    verdictDetail: `Same key, same IV: the two messages share their first <strong>${shared}</strong> plaintext block${shared === 1 ? '' : 's'}, so their first ${shared} ciphertext block${shared === 1 ? '' : 's'} are byte-identical. That reveals the messages share a prefix — <em>not</em> the keystream, <em>not</em> the plaintext.`,
    extraHTML: blockCompareExtra(b1, toBlocks(c2), shared),
  });
}

function laneExtra(label: string, bytes: Uint8Array, readable: string): string {
  const laneId = 'lane-' + Math.abs(hashStr(label)).toString(36);
  queueMicrotask(() => {
    const el = document.getElementById(laneId);
    if (el) renderByteLane(el, bytes.slice(0, 48));
  });
  return `
    <div class="lane-block">
      <p class="output-label">${escapeHTML(label)}</p>
      <div id="${laneId}" class="byte-lane" role="region" aria-label="${escapeHTML(label)} as hex bytes" tabindex="0"></div>
      <p class="reveal-text">as text: “${escapeHTML(readable.slice(0, 48))}”</p>
    </div>`;
}

function blockCompareExtra(b1: Uint8Array[], b2: Uint8Array[], shared: number): string {
  const rows = Math.max(b1.length, b2.length);
  let html = '<div class="block-compare" role="group" aria-label="Ciphertext blocks compared, matching leading blocks highlighted">';
  for (let i = 0; i < rows; i++) {
    const match = i < shared;
    const h1 = b1[i] ? hex(b1[i]) : '—';
    const h2 = b2[i] ? hex(b2[i]) : '—';
    html += `<div class="bc-row ${match ? 'bc-match' : ''}">
      <span class="bc-idx">blk ${i}</span>
      <span class="bc-hex">${h1}</span>
      <span class="bc-hex">${h2}</span>
      <span class="bc-flag">${match ? 'identical ✓' : 'differs'}</span>
    </div>`;
  }
  html += '</div>';
  return html;
}

function hashStr(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return h;
}

// ════════════════════════════════════════════════════════════════════════
//  3. ALGEBRA — action-triggered cancellation (no idle motion)
// ════════════════════════════════════════════════════════════════════════
function wireCancel(btnId: string, capId: string, doneText: string): void {
  const btn = $(btnId) as HTMLButtonElement;
  const cap = $(capId);
  const viz = btn.closest('details')?.querySelector('.cancel-viz') ?? null;
  btn.addEventListener('click', () => {
    if (!viz) return;
    viz.classList.add('cancelled');
    viz.querySelectorAll('.cancel-fadeable').forEach((el) => el.classList.add('faded'));
    viz.querySelectorAll('.cancel-gone').forEach((el) => el.classList.add('show'));
    cap.textContent = doneText;
    btn.disabled = true;
    btn.textContent = 'Cancelled ✓';
  });
}

// ════════════════════════════════════════════════════════════════════════
//  4. NONCE SOURCES — live birthday math
// ════════════════════════════════════════════════════════════════════════
let nonceBits = 96;

function updateNonce(): void {
  const exp = Number(($('nonce-count') as HTMLInputElement).value);
  const count = Math.pow(2, exp);
  $('nonce-count-val').textContent = `2^${exp} ≈ ${formatCount(count)} messages`;
  const p = collisionProbability(nonceBits, count);
  $('nonce-prob').textContent = formatProbability(p);
  const at50 = countForProbability(nonceBits, 0.5);
  $('nonce-5050').textContent = `2^${log2(at50).toFixed(1)} messages`;
}

function formatCount(n: number): string {
  if (n < 1e4) return n.toLocaleString('en-US');
  const units = [
    [1e18, 'quintillion'],
    [1e15, 'quadrillion'],
    [1e12, 'trillion'],
    [1e9, 'billion'],
    [1e6, 'million'],
    [1e3, 'thousand'],
  ] as const;
  for (const [v, name] of units) if (n >= v) return `${(n / v).toPrecision(3)} ${name}`;
  return n.toPrecision(3);
}
function log2(n: number): number {
  return Math.log(n) / Math.LN2;
}

function setBits(bits: number, activeId: string): void {
  nonceBits = bits;
  ['bits-32', 'bits-64', 'bits-96'].forEach((id) => {
    const el = $(id) as HTMLButtonElement;
    const on = id === activeId;
    el.classList.toggle('is-active', on);
    el.setAttribute('aria-checked', on ? 'true' : 'false');
  });
  updateNonce();
}

// ════════════════════════════════════════════════════════════════════════
//  wire-up
// ════════════════════════════════════════════════════════════════════════
function init(): void {
  $('cd-encrypt').addEventListener('click', () => void encryptForReveal());
  $('cd-crib').addEventListener('input', updateCribDrag);
  $('cd-offset').addEventListener('input', updateCribDrag);

  $('run-ctr').addEventListener('click', () => void runCtr());
  $('run-gcm').addEventListener('click', () => void runGcm());
  $('run-chacha').addEventListener('click', () => runChacha());
  $('run-cbc').addEventListener('click', () => void runCbc());

  wireCancel('cancel-gcm-btn', 'cancel-gcm-cap', 'mask ⊕ mask = 0 — what remains is (C₁ ⊕ C₂)·H², solved for H.');
  wireCancel('cancel-poly-btn', 'cancel-poly-cap', 's − s = 0 — what remains is (n₁ − n₂)·r, solved for r, then s.');

  $('bits-32').addEventListener('click', () => setBits(32, 'bits-32'));
  $('bits-64').addEventListener('click', () => setBits(64, 'bits-64'));
  $('bits-96').addEventListener('click', () => setBits(96, 'bits-96'));
  $('nonce-count').addEventListener('input', updateNonce);
  updateNonce();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
