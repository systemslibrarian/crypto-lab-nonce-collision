import { expect, test } from '@playwright/test';

/**
 * Two regressions from re-deriving the module's instructor notes against the live
 * page. Both are about a rendered claim disagreeing with what the page computed.
 *
 * 1. The fresh-nonce branch drew one random nonce to encrypt with and a SECOND to
 *    verify with, so the honest tag never verified and the card printed
 *    "(mismatched nonce) REJECT" — underneath a heading that read SAFE. The whole
 *    point of that branch is that a unique nonce verifies, so it has to verify.
 *
 * 2. The scoreboard was written from the reuse toggle before the run started, so a
 *    card could report SAFE while its own verification had just failed. A toggle
 *    says what was asked for; only the computation says what happened.
 */

async function runFresh(page: import('@playwright/test').Page): Promise<void> {
  await page.goto('.');
  await page.locator('#run-all-fresh').click();
  await expect(page.locator('#out-gcm')).toContainText('unique nonce', { timeout: 30_000 });
}

test('an honest tag under a fresh nonce actually verifies', async ({ page }) => {
  await runFresh(page);

  for (const [slot, verifier] of [['#out-gcm', 'WebCrypto verify'], ['#out-chacha', 'Poly1305 verify']] as const) {
    const text = (await page.locator(slot).innerText()).replace(/\s+/g, ' ');
    expect(text, `${slot} must not report a mismatched nonce on the fresh-nonce path`)
      .not.toContain('mismatched nonce');
    expect(text, `${slot}: a tag made and checked under one fresh nonce must verify`)
      .toContain(`${verifier}: VALID`);
  }
});

test('a card never reports SAFE while its own verification failed', async ({ page }) => {
  await runFresh(page);

  for (const slot of ['#out-gcm', '#out-chacha']) {
    const text = (await page.locator(slot).innerText()).replace(/\s+/g, ' ');
    const verified = /verify: VALID/.test(text);
    const claimsSafe = /SAFE/.test(text);
    expect(
      claimsSafe,
      `${slot} says SAFE while its rendered verification line does not say VALID: ${text.slice(0, 160)}`,
    ).toBe(verified);
  }
});

test('the scoreboard follows the run, not the toggle', async ({ page }) => {
  await page.goto('.');
  await page.locator('#run-all-reuse').click();
  await expect(page.locator('#scoreboard')).toContainText('Full', { timeout: 30_000 });
  const reuse = (await page.locator('#scoreboard').innerText()).replace(/\s+/g, ' ');

  await page.locator('#run-all-fresh').click();
  await expect(page.locator('#out-gcm')).toContainText('unique nonce', { timeout: 30_000 });
  const fresh = (await page.locator('#scoreboard').innerText()).replace(/\s+/g, ' ');

  expect(fresh, 'the scoreboard must move when the run does').not.toBe(reuse);
  expect(reuse, 'a reused nonce loses plaintext').toContain('Full');
  expect(fresh, 'fresh nonces lose nothing').not.toContain('Full');
});
