import { expect, test } from '@playwright/test';
import {
  NARROW,
  boot,
  driveAllStates,
  expectBaselineNotStale,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * The WCAG 2.1 A/AA gate: {dark, light} × {1280 desktop, 380 phone}.
 *
 * Four configurations rather than two, because the gate this replaces ran only
 * at the project's default 1280x720 and so never tested WCAG 1.4.10 (Reflow) at
 * all — on a page carrying two `min-width: 640px` tables. See `gate.ts` for
 * what the previous spec actually did and why each of its five shortcuts turned
 * a failure into a pass.
 *
 * Every configuration runs the SAME drive: the crib-drag exhibit with a crib
 * that fits and one that does not, all four constructions with a fresh nonce
 * AND with a reused one, both "run all four" buttons, both algebra disclosures
 * and both cancellations, all three nonce widths, both ends of both sliders,
 * and the hero call to action — scanning after every one of them.
 */
const CONFIGS = [
  { theme: 'dark' as const, width: 1280, height: 800, label: 'dark / 1280px' },
  { theme: 'light' as const, width: 1280, height: 800, label: 'light / 1280px' },
  { theme: 'dark' as const, ...NARROW, label: 'dark / 380px' },
  { theme: 'light' as const, ...NARROW, label: 'light / 380px' },
];

for (const cfg of CONFIGS) {
  test(`WCAG 2.1 A/AA — ${cfg.label}`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize({ width: cfg.width, height: cfg.height });
    await boot(page, cfg.theme);
    await driveAllStates(page, cfg.label);
    expectBaselineNotStale();
    expect(errors, 'no page or console errors during the drive').toEqual([]);
    reportCollected();
  });
}
