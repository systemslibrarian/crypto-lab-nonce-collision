import AxeBuilder from '@axe-core/playwright';
import type { Result } from 'axe-core';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Four landmark rules axe classifies as "best-practice" rather than tagging
 * `wcag*`, so `withTags(TAGS)` alone does not run them. This page has the shape
 * they catch: a shared `<header role="banner">` above a `<div id="app">` that
 * holds a second `<header class="cl-hero">`, that hero's `<aside>`, a `<nav>`
 * and a `<main>`.
 */
export const EXTRA_RULES = [
  'landmark-no-duplicate-banner',
  'landmark-unique',
  'landmark-one-main',
  'landmark-complementary-is-top-level',
];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * WHAT THE GATE THIS REPLACES ACTUALLY DID. One `prepare()` walk followed by
 * one `scan()`, twice — once per theme, both at the project's default 1280x720:
 *
 *  1. IT INJECTED `animation:none!important; transition:none!important` THROUGH
 *     `addStyleTag`, as the very first thing it did. That BYPASSED
 *     `style.css`'s own `@media (prefers-reduced-motion: reduce)` block instead
 *     of exercising it, which matters here because that block does NOT set
 *     `animation: none` — it collapses durations to `0.01ms` deliberately, "so
 *     transitionend listeners still fire". The injected form and the real one
 *     are therefore different renderings, and only one of them is what a reader
 *     with the preference gets.
 *
 *  2. IT FORCE-REVEALED EVERYTHING. `d.open = true` on every `<details>` and
 *     `removeAttribute('hidden')` on every hidden element. The second is the
 *     damaging one: `#cd-panel`, `#cancel-gcm-run` and `#cancel-poly-run` all
 *     ship `hidden` and are all EMPTY until their button is pressed, so the
 *     scan measured three revealed panels with nothing in them — a document no
 *     visitor can load. This gate never writes `open` or touches `hidden`; the
 *     panels are revealed by the buttons that fill them and the disclosures are
 *     opened by clicking their own `<summary>`.
 *
 *  3. IT TICKED THE TOGGLES FROM SCRIPT. `cb.checked = true` on every
 *     `.reuse-toggle` sets the property without dispatching an event or moving
 *     focus — so it never exercised the label, the `:checked + .slider` rule
 *     that is the toggle's entire visual state, or the possibility that the
 *     control is unreachable. And it only ever set them ON: the FRESH-nonce
 *     branch of all four constructions, which renders the `verdict-safe` panel
 *     and the green scoreboard column, was never scanned in either theme. A
 *     gate that scans one branch scans one half, and which half depends on
 *     which line someone wrote first.
 *
 *  4. EVERY CLICK WAS SWALLOWED. `.click().catch(() => {})` on the crib-drag
 *     reveal, on all four `.run-btn`s and on both `.cancel-btn`s. A control
 *     that had been renamed or that threw produced no error and no scan of the
 *     state it should have built.
 *
 *  5. IT SCANNED ONCE, AT THE END. Every state it built was overwritten by the
 *     next step before anything measured it, and only the final frame was
 *     asserted on. This gate scans after every single step.
 *
 * Two more holes: it read `violations` only, so the whole `incomplete` bucket
 * went unread; and it had no reflow oracle and no viewport narrower than 1280,
 * so WCAG 1.4.10 was never tested — on a page whose two data tables carry
 * `min-width: 640px`.
 *
 * A SIXTH SHORTCUT LIVED IN A SEPARATE FILE. `e2e/border.spec.ts` was the
 * lab's SC 1.4.11 check, and it queried `textarea, input[type='text']` —
 * exactly the set `--control-border` was written for and correctly applied to —
 * took `.first()` of them, and compared that one border to its own FILL rather
 * than to the card outside it. It is deleted; `nontext.ts` measures every
 * control against what surrounds it, in every driven state.
 *
 * HAND-MEASURED, BECAUSE NOTHING AUTOMATED REACHES THEM. Two classes have no
 * oracle here or in `nontext.ts` — a CSS-drawn shape with no glyph, and a
 * native widget the author only recoloured:
 *
 *  - `.switch .slider::before`, the knob of the four "reuse the nonce" toggles.
 *    `content: ''`, so the pseudo-element pass skips it for having no ink to
 *    attribute — and its position and colour are the whole visual state of the
 *    control. Unchecked it is `--text-muted` on the `--surface-alt` track:
 *    3.29:1 dark, 4.83:1 light. Checked it is `--accent-text` on
 *    `color-mix(in oklab, var(--accent) 35%, var(--surface-alt))`: 3.10:1 dark
 *    and 3.72:1 light. All four clear the 3:1 SC 1.4.11 asks of a control's
 *    state indicator, and the state is carried in text as well — the run's
 *    result names the nonce as reused or fresh.
 *  - `input[type='range']` (`#cd-offset`, `#nonce-count`), painted by the UA
 *    with an author `accent-color: var(--accent)`. `--accent` (#b91c1c) against
 *    the `--surface` card behind it is 5.06:1 light and 3.62:1 dark.
 *  - `.cancel-gone`, an `aria-hidden` `= 0` that both oracles skip:
 *    `--safe-text` on `--code-bg`, 8.66:1 dark and 5.32:1 light.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead. This page needs it: the cancellation
 * animation is a `color` transition on several `.cancel-fadeable` terms plus an
 * `opacity` transition on `.cancel-gone`, started in the same frame.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page's reduced-motion block was deliberately written NOT to do that: it
 * collapses `animation-duration` and `transition-duration` to `0.01ms` rather
 * than setting `animation: none`, so a transition still runs, still fires
 * `transitionend`, and still lands on its end value. `.cancel-gone` is the
 * element that would break under the other spelling — it is declared
 * `opacity: 0` and only reaches 1 through a transition the `.show` class
 * starts. Under `transition: none` that class would still apply the end value,
 * but a stylesheet that instead cancelled an ANIMATION into the same shape
 * would strand it invisible. The assertion turns that reasoning into a
 * measurement, in every driven state.
 *
 * `aria-hidden` subtrees are excluded, and `.cancel-gone` is one — so this
 * check does not cover it and `contrast.ts`'s header records its hand
 * measurement instead.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * There IS a mechanism here and it is load-bearing, which is why the OUTCOME is
 * asserted rather than the mechanism: this lab's hero is a real
 * `<header class="cl-hero">` and it is a direct child of `<div id="app">`, so
 * it is NOT scoped inside sectioning content and would imply a second banner on
 * its own. `index.html`'s `dedupeBanner()` demotes it to `role="group"` after
 * DOMContentLoaded. Counting banners catches both a change to the hero's
 * element and a change to that script.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which also pins down a real failure mode: `index.html`'s anti-flash
 * script reads `localStorage.getItem('theme')` and the bar's toggle writes
 * `localStorage.setItem('theme', …)`. If those keys drift apart the theme
 * silently stops persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice.
 *
 * The defaults are asserted because the gate this replaces got one of them
 * backwards and never noticed. All four `.reuse-toggle`s ship UNCHECKED — the
 * fresh-nonce, `verdict-safe` branch is the arrival state — and the old gate
 * set all four to `checked` before its only scan, so the green half of this
 * lab was never measured in either theme. Three output panels ship `hidden`
 * AND empty, and both algebra disclosures ship shut.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // The `hidden` attribute is the only thing hiding the three output panels, and
  // the UA rule that implements it (`[hidden] { display: none }`) has
  // specificity (0,1,0) — the same as a class, so ANY later author rule with a
  // `display` beats it silently. This stylesheet has no `#app [hidden]` guard,
  // so the attribute is working on nothing but source order and the absence of
  // a `display` declaration on `.cancel-run`. Probe it rather than trust it.
  expect(
    await page.evaluate(() => {
      const probe = document.createElement('div');
      probe.className = 'cancel-run';
      probe.hidden = true;
      document.getElementById('main')!.append(probe);
      const d = getComputedStyle(probe).display;
      probe.remove();
      return d;
    }),
    'the hidden attribute must still hide an element that carries a class'
  ).toBe('none');

  // `main.ts` wires everything on DOMContentLoaded, so a navigation that
  // resolves proves nothing. The scoreboard is rendered by `init()`.
  await expect(page.locator('#scoreboard .scoreboard-table')).toBeVisible();
  await expect(page.locator('#scoreboard td')).toHaveCount(12);
  await expect(page.locator('#nonce-prob')).not.toHaveText('—');

  // ── Everything this lab generates ships absent ───────────────────────────
  for (const sel of ['#cd-panel', '#cancel-gcm-run', '#cancel-poly-run']) {
    await expect(page.locator(sel)).toBeHidden();
  }
  await expect(page.locator('.result-slot')).toHaveCount(4);
  for (const sel of ['#out-ctr', '#out-gcm', '#out-chacha', '#out-cbc']) {
    await expect(page.locator(sel)).toBeEmpty();
  }

  // ── Every shipped control default ────────────────────────────────────────
  // The four toggles ship OFF. This is the assertion the old gate needed.
  await expect(page.locator('.reuse-toggle')).toHaveCount(4);
  for (const sel of ['#reuse-ctr', '#reuse-gcm', '#reuse-chacha', '#reuse-cbc']) {
    await expect(page.locator(sel)).not.toBeChecked();
  }
  await expect(page.locator('#cd-crib')).toHaveValue('the ');
  await expect(page.locator('#cd-offset')).toHaveValue('0');
  await expect(page.locator('#nonce-count')).toHaveValue('40');
  await expect(page.locator('#bits-96')).toHaveAttribute('aria-checked', 'true');
  await expect(page.locator('.chip-toggle.is-active')).toHaveCount(1);

  // Both algebra disclosures shut.
  await expect(page.locator('#algebra details')).toHaveCount(2);
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and the gate this
 * replaces had no viewport narrower than 1280 — so the criterion was untested
 * on a page that carries two `min-width: 640px` tables, a 640px-min scoreboard,
 * long unbroken hex in three places, and four-column grids in the CBC block
 * comparison. Each wide thing is meant to scroll inside its own
 * `.table-scroll` / `.scoreboard-wrap` / `.byte-lane`; the assertion here is
 * that none of them scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. This page
    // has a decoy behind every `.table-scroll`.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * `index.html` handles its four known cases by hand — both `.byte-lane`s, both
 * `.table-scroll`s and `#scoreboard` carry `role="region"`, `tabindex="0"` and
 * an `aria-label`. The assertion stays because that is a convention rather than
 * an enforcement, and because at 380px the set of things that scroll is not the
 * set of things anyone designed to scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/** Run an assertion that throws, recording rather than throwing when collecting. */
async function soft(label: string, fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(`${label}\n  ${String(e).slice(0, 8000)}`);
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node.
 *
 * It ratchets rather than merely logging: anything NOT in the baseline fails,
 * anything in the baseline that got WORSE fails, and anything in the baseline
 * that has been FIXED fails until its entry is deleted. That last rule is what
 * stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${f.detail}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  if (process.env.NT_BASELINE_CAPTURE) {
    expect(
      'NT_BASELINE_CAPTURE was set',
      'a capture run is not a passing gate — unset NT_BASELINE_CAPTURE'
    ).toBe('');
  }
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Run axe twice and merge, because `withTags` and `withRules` CANNOT BE
 * COMBINED.
 *
 * Both write `options.runOnly`, so chaining them silently keeps only the last
 * one — `@axe-core/playwright`'s own docblock says "Cannot be used with
 * AxeBuilder#withTags" and the implementation is a plain overwrite. A
 * `.withTags(TAGS).withRules([...four landmark rules])` chain therefore runs
 * FOUR BEST-PRACTICE RULES AND NO WCAG RULES AT ALL, and reports a clean
 * `violations` array for a page with any number of WCAG failures on it. Two
 * analyses and a merge is the only shape that runs both sets.
 */
async function analyzeAll(page: Page): Promise<{ violations: Result[]; incomplete: Result[] }> {
  const byTag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const byRule = await new AxeBuilder({ page }).withRules(EXTRA_RULES).analyze();
  return {
    violations: [...byTag.violations, ...byRule.violations],
    incomplete: [...byTag.incomplete, ...byRule.incomplete],
  };
}

/**
 * Scan the page as it currently stands.
 *
 * Six assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus the four landmark
 *    best-practice rules in `EXTRA_RULES`, merged from a second axe run.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters more here than in most labs, since
 *    every verdict panel, the callout, the CBC match highlight and the crib
 *    "this fits" green are all `color-mix()` surfaces axe declines to resolve.
 *    Everything else in that bucket is a real result axe simply could not
 *    finish, including `aria-prohibited-attr`, where an `aria-label` on a
 *    role-less element hides — a defect that never reaches `violations` at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast and generated content — SC 1.4.11, which axe has no rule
 *    for; see `nontext.ts`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await analyzeAll(page);

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await soft(`non-text contrast in state: ${label}`, () =>
    expectNoNewNonTextFailures(page, label)
  );
  await soft(`scrollers in state: ${label}`, () => expectScrollersReachable(page, label));
  await soft(`reflow in state: ${label}`, () => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/** The four constructions, with the id of each card's toggle and run button. */
const CONSTRUCTIONS = [
  { key: 'ctr', label: 'AES-CTR', toggle: '#reuse-ctr', run: '#run-ctr', out: '#out-ctr' },
  { key: 'gcm', label: 'AES-GCM', toggle: '#reuse-gcm', run: '#run-gcm', out: '#out-gcm' },
  { key: 'chacha', label: 'ChaCha20-Poly1305', toggle: '#reuse-chacha', run: '#run-chacha', out: '#out-chacha' },
  { key: 'cbc', label: 'AES-CBC', toggle: '#reuse-cbc', run: '#run-cbc', out: '#out-cbc' },
] as const;

/**
 * Open one `<details>` by clicking its summary, and assert it opened.
 *
 * Never `d.open = true`. The gate this replaces set `open` on every `<details>`
 * from script, which skipped the summary's own `::before` disclosure marker —
 * the `▸`/`▾` that REPLACES the UA triangle here — and never exercised the
 * click that a keyboard user makes.
 */
async function openDetails(page: Page, index: number): Promise<void> {
  const d = page.locator('#algebra details').nth(index);
  await d.locator('summary').click();
  await expect(d).toHaveAttribute('open', '');
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, AND IT IS EMPTY. Three output panels
 *    ship `hidden`, all four result slots are empty, both disclosures are shut
 *    and the scoreboard reads "not run" in all twelve cells. That is the state
 *    a reader meets, and the gate this replaces never measured it — it unhid
 *    the three empty panels and ticked all four toggles before its only scan.
 *
 *  - BOTH BRANCHES OF EVERY CONSTRUCTION. Each of the four cards renders a
 *    different panel with a fresh nonce than with a reused one, in different
 *    colours: `verdict-safe` (green), `verdict-leak` (amber, CBC only) and
 *    `verdict-broken` (red). The old gate only ever ran the reused branch, so
 *    four of the eight renderings had never been scanned. Both are driven, per
 *    card and then through the two "run all four" buttons.
 *
 *  - THE EXTREMES OF EVERY INPUT. `#cd-offset` and `#nonce-count` are moved to
 *    both ends. The nonce slider's ends are the interesting ones — `2⁰` and
 *    `2⁷²` produce the shortest and longest readouts on the page, and the
 *    probability formula prints differently at each.
 *
 *  - THE CRIB THAT FITS AND THE CRIB THAT DOES NOT. `.reveal-lane .byte
 *    .printable` (a `--safe` tint) and `.byte.nonprint` (`--text-muted`) are
 *    two different renderings of the same lane, and the difference between them
 *    is the entire point of the exhibit. Both are driven.
 *
 *  - NO FIXED TIMEOUTS. Every step here has a DOM completion signal: a panel
 *    becoming visible, a result slot filling, a scoreboard cell changing class,
 *    a `.cancelled` class landing on the diagram.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint — nothing run, three panels hidden, four toggles off');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  // ── The XOR reveal ──────────────────────────────────────────────────────
  await page.click('#cd-encrypt');
  await expect(page.locator('#cd-panel')).toBeVisible();
  await expect(page.locator('#cd-combined .byte').first()).toBeVisible();
  await expect(page.locator('#cd-status')).not.toBeEmpty();
  await scanAt('two messages encrypted under one nonce, combined lane rendered');

  // The shipped crib "the " at offset 0 already fits; a crib that cannot occur
  // renders the same lane entirely as `.byte.nonprint`, which is the other half
  // of the exhibit and the state the reader spends most of their time in.
  // A WRONG crib position, found rather than assumed. Both messages are ASCII
  // over most of their length, and XORing ASCII with ASCII usually lands back
  // in ASCII — so several "wrong" offsets still render an all-printable lane
  // and would scan the same rendering as the right one. Walk forward until the
  // lane genuinely contains an unprintable byte, and fail if none exists: that
  // would mean `.byte.nonprint`, half of what this exhibit teaches, is
  // unreachable.
  const nonprint = page.locator('#cd-reveal-lane .byte.nonprint');
  const limit = Number(await page.locator('#cd-offset').getAttribute('max')) || 10;
  let wrongOffset = -1;
  for (let i = 1; i <= limit; i++) {
    await page.locator('#cd-offset').fill(String(i));
    if ((await nonprint.count()) > 0) {
      wrongOffset = i;
      break;
    }
  }
  expect(wrongOffset, 'no crib position renders an unprintable byte').toBeGreaterThan(0);
  await expect(nonprint.first()).toBeVisible();
  await expect(page.locator('#cd-reveal-text')).not.toHaveClass(/reveal-hit/);
  await scanAt(`crib at the wrong offset ${wrongOffset} — unprintable recovered bytes`);

  await page.click('#cd-show-crib');
  await expect(page.locator('#cd-reveal-lane .byte.printable').first()).toBeVisible();
  await expect(page.locator('#cd-reveal-text')).toHaveClass(/reveal-hit/);
  await scanAt('the working crib — recovered plaintext, the green "it fits" lane');

  // Both ends of the offset slider. The maximum is the state where the crib
  // hangs off the end of the combined stream.
  const maxOffset = await page.locator('#cd-offset').getAttribute('max');
  await page.locator('#cd-offset').fill(maxOffset ?? '10');
  await expect(page.locator('#cd-offset-val')).toHaveText(`offset ${maxOffset}`);
  await scanAt('crib slid to the maximum offset');

  await page.locator('#cd-offset').fill('0');
  await expect(page.locator('#cd-offset-val')).toHaveText('offset 0');
  await scanAt('crib slid back to offset 0');

  // ── The four constructions, fresh nonce then reused ─────────────────────
  for (const c of CONSTRUCTIONS) {
    await expect(page.locator(c.toggle)).not.toBeChecked();
    await page.click(c.run);
    await expect(page.locator(c.out)).not.toBeEmpty();
    await expect(page.locator(`${c.out} .verdict-safe`)).toBeVisible();
    await scanAt(`${c.label} with a fresh nonce — the safe verdict`);

    // Checked through the control itself, not by assigning `.checked` from
    // script: that is what renders `:checked + .slider`, the toggle's whole
    // visual state, and what a reader actually does.
    await page.locator(c.toggle).check();
    await expect(page.locator(c.toggle)).toBeChecked();
    await scanAt(`${c.label} toggle flipped to reuse, before the run`);

    await page.click(c.run);
    await expect(page.locator(`${c.out} .verdict-safe`)).toHaveCount(0);
    await expect(page.locator(`${c.out} .verdict`)).toBeVisible();
    await scanAt(`${c.label} with a reused nonce — the broken or leaking verdict`);
  }

  // CBC is the one that leaks rather than breaks, and its block comparison is
  // the only place `.bc-match` (an amber tint) is painted.
  await expect(page.locator('#out-cbc .verdict-leak')).toBeVisible();
  await expect(page.locator('#out-cbc .bc-row.bc-match').first()).toBeVisible();
  await scanAt('CBC prefix leak — identical leading blocks highlighted');

  // ── The two orchestration buttons, which rewrite all four cards at once ──
  await page.click('#run-all-fresh');
  for (const c of CONSTRUCTIONS) {
    await expect(page.locator(c.toggle)).not.toBeChecked();
    await expect(page.locator(`${c.out} .verdict-safe`)).toBeVisible();
  }
  await expect(page.locator('#scoreboard .sc-broken')).toHaveCount(0);
  await scanAt('run all four with fresh nonces — the whole scoreboard green');

  await page.click('#run-all-reuse');
  for (const c of CONSTRUCTIONS) await expect(page.locator(c.toggle)).toBeChecked();
  await expect(page.locator('#scoreboard .sc-broken').first()).toBeVisible();
  await expect(page.locator('#scoreboard .sc-leak').first()).toBeVisible();
  await scanAt('run all four with one reused nonce — the full scoreboard');

  // ── The algebra section: two disclosures, two cancellations ─────────────
  await openDetails(page, 0);
  await expect(page.locator('#cancel-gcm-run')).toBeHidden();
  await scanAt('the AES-GCM algebra disclosure open, nothing computed yet');

  await page.click('#cancel-gcm-btn');
  await expect(page.locator('#cancel-gcm-run')).toBeVisible();
  await expect(page.locator('#cancel-gcm-run .cr-row').first()).toBeVisible();
  await expect(page.locator('#cancel-gcm-btn').locator('xpath=ancestor::details').locator('.cancel-viz')).toHaveClass(
    /cancelled/
  );
  await scanAt('AES-GCM cancellation run on real bytes — the mask struck through');

  await openDetails(page, 1);
  await expect(page.locator('#cancel-poly-run')).toBeHidden();
  await scanAt('the Poly1305 algebra disclosure open, nothing computed yet');

  await page.click('#cancel-poly-btn');
  await expect(page.locator('#cancel-poly-run')).toBeVisible();
  await expect(page.locator('#cancel-poly-run .cr-row').first()).toBeVisible();
  await scanAt('Poly1305 cancellation run on real numbers');

  // ── The birthday-bound panel ────────────────────────────────────────────
  for (const [id, bits] of [
    ['#bits-32', '32'],
    ['#bits-64', '64'],
    ['#bits-96', '96'],
  ] as const) {
    await page.click(id);
    await expect(page.locator(id)).toHaveAttribute('aria-checked', 'true');
    await expect(page.locator('.chip-toggle.is-active')).toHaveCount(1);
    await scanAt(`birthday bound at ${bits}-bit nonces`);
  }

  await page.locator('#nonce-count').fill('0');
  await expect(page.locator('#nonce-count-val')).toContainText('messages');
  await scanAt('birthday bound at the smallest message count');

  await page.locator('#nonce-count').fill('72');
  await expect(page.locator('#nonce-count-val')).toContainText('messages');
  await scanAt('birthday bound at the largest message count — collision certain');

  // ── The hero CTA, which is a compound action nothing else covers ────────
  await page.click('#hero-cta');
  await expect(page.locator('#cd-panel')).toBeVisible();
  await expect(page.locator('#cd-reveal-lane .byte.printable').first()).toBeVisible();
  await scanAt('the hero call to action — re-encrypted and cribbed in one press');
}
