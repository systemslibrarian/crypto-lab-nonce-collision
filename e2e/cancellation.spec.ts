import { expect, test, type Page } from '@playwright/test';

/**
 * Browser gate for the "why the forgeries work" panel.
 *
 * The panel used to be a static diagram of symbols that faded on click. It now
 * runs the attack and prints that run's bytes, so these assertions check the
 * COMPUTED values: that the printed sides of each identity are equal to each
 * other and are real 128-bit values, that they change when the run changes, and
 * that a wrong value would show as a failed check rather than a passing one.
 */

const HEX32 = /^[0-9a-f]{32}$/;

/* Click a run button and WAIT FOR THE RUN TO LAND, rather than reading whatever is
 * in the panel at the moment the click returns.
 *
 * `runGcmCancellation` and its Poly1305 twin both `await runForbiddenAttack(...)`
 * -- real WebCrypto -- BEFORE they rewrite the panel's innerHTML. So between the
 * click and the repaint the panel still shows the PREVIOUS run's bytes, and a read
 * taken there compares a run with itself. The two re-running tests did exactly
 * that: click, read, click, read. They pass on a fast machine because the read
 * happens to land after the await, and the WebKit job in CI is where that stopped
 * being true.
 *
 * Polling on "the value is no longer the one I had" is the completion signal that
 * is actually available here: the panel is rewritten in one assignment, so the new
 * tag appearing IS the new run having finished. */
async function clickAndAwaitNewValue(
  page: Page,
  button: string,
  panel: string,
  label: string,
  previous: string,
): Promise<string> {
  await page.locator(button).click();
  await expect
    .poll(() => rowValue(page, panel, label), { timeout: 15_000 })
    .not.toBe(previous);
  return rowValue(page, panel, label);
}

async function openAlgebra(page: Page): Promise<void> {
  await page.goto('.');
  await page.evaluate(() => {
    document
      .querySelectorAll<HTMLDetailsElement>('#algebra details')
      .forEach((d) => (d.open = true));
  });
}

async function rowValue(page: Page, panel: string, label: string): Promise<string> {
  return (
    await page
      .locator(`#${panel} .cr-row`, { has: page.locator('.cr-key', { hasText: label }) })
      .first()
      .locator('.cr-val')
      .innerText()
  ).trim();
}

test('AES-GCM: the panel prints this run’s bytes and the identity holds on them', async ({
  page,
}) => {
  await openAlgebra(page);
  await expect(page.locator('#cancel-gcm-run')).toBeHidden();

  await page.locator('#cancel-gcm-btn').click();
  await expect(page.locator('#cancel-gcm-run')).toBeVisible();

  const tag1 = await rowValue(page, 'cancel-gcm-run', 'tag₁');
  const tag2 = await rowValue(page, 'cancel-gcm-run', 'tag₂');
  const mask1 = await rowValue(page, 'cancel-gcm-run', 'mask from tag₁');
  const mask2 = await rowValue(page, 'cancel-gcm-run', 'mask from tag₂');
  const tagXor = await rowValue(page, 'cancel-gcm-run', 'tag₁ ⊕ tag₂');
  const rhs = await rowValue(page, 'cancel-gcm-run', '(C₁ ⊕ C₂)·H² recomputed');

  for (const v of [tag1, tag2, mask1, mask2, tagXor, rhs]) expect(v).toMatch(HEX32);

  // Two different probes really were tagged...
  expect(tag1).not.toBe(tag2);
  // ...the shared pad recovered from each is the same number...
  expect(mask1).toBe(mask2);
  // ...and the XOR of the tags equals the product recomputed from H.
  expect(tagXor).toBe(rhs);
  // The XOR is genuinely the XOR of the two printed tags.
  const xored = Array.from({ length: 32 }, (_, i) =>
    (parseInt(tag1[i], 16) ^ parseInt(tag2[i], 16)).toString(16),
  ).join('');
  expect(tagXor).toBe(xored);

  await expect(page.locator('#cancel-gcm-run .cancel-check.cc-ok')).toHaveCount(3);
  await expect(page.locator('#cancel-gcm-run .cancel-check.cc-bad')).toHaveCount(0);
  await expect(page.locator('#cancel-gcm-cap')).toContainText('verified on this run');
});

test('AES-GCM: re-running produces different bytes — the panel is computed, not baked', async ({
  page,
}) => {
  await openAlgebra(page);
  await page.locator('#cancel-gcm-btn').click();
  await expect.poll(() => rowValue(page, 'cancel-gcm-run', 'tag₁')).toMatch(HEX32);
  const first = await rowValue(page, 'cancel-gcm-run', 'tag₁');
  const second = await clickAndAwaitNewValue(
    page, '#cancel-gcm-btn', 'cancel-gcm-run', 'tag₁', first,
  );
  expect(first).toMatch(HEX32);
  expect(second).toMatch(HEX32);
  expect(second).not.toBe(first);
  await expect(page.locator('#cancel-gcm-run .cancel-check.cc-bad')).toHaveCount(0);
  await expect(page.locator('#cancel-gcm-run .cancel-check.cc-ok')).toHaveCount(3);
});

test('Poly1305: the panel prints this run’s numbers and the identity holds on them', async ({
  page,
}) => {
  await openAlgebra(page);
  await expect(page.locator('#cancel-poly-run')).toBeHidden();

  await page.locator('#cancel-poly-btn').click();
  await expect(page.locator('#cancel-poly-run')).toBeVisible();

  const tag1 = await rowValue(page, 'cancel-poly-run', 'tag₁');
  const tag2 = await rowValue(page, 'cancel-poly-run', 'tag₂');
  const s1 = await rowValue(page, 'cancel-poly-run', 's from tag₁');
  const s2 = await rowValue(page, 'cancel-poly-run', 's from tag₂');
  const tagDiff = await rowValue(page, 'cancel-poly-run', 'tag₁ − tag₂ mod');
  const polyDiff = await rowValue(page, 'cancel-poly-run', 'polyval₁ − polyval₂ mod');

  for (const v of [tag1, tag2, s1, s2, tagDiff, polyDiff]) expect(v).toMatch(HEX32);

  expect(tag1).not.toBe(tag2);
  expect(s1).toBe(s2);
  expect(tagDiff).toBe(polyDiff);
  // The printed difference really is tag₁ − tag₂ mod 2¹²⁸.
  const expected = (((BigInt('0x' + tag1) - BigInt('0x' + tag2)) % (1n << 128n)) + (1n << 128n)) % (1n << 128n);
  expect(tagDiff).toBe(expected.toString(16).padStart(32, '0'));

  await expect(page.locator('#cancel-poly-run .cancel-check.cc-ok')).toHaveCount(3);
  await expect(page.locator('#cancel-poly-run .cancel-check.cc-bad')).toHaveCount(0);
  await expect(page.locator('#cancel-poly-cap')).toContainText('verified on this run');
});

test('Poly1305: re-running produces different numbers', async ({ page }) => {
  await openAlgebra(page);
  await page.locator('#cancel-poly-btn').click();
  await expect.poll(() => rowValue(page, 'cancel-poly-run', 'tag₁')).toMatch(HEX32);
  const first = await rowValue(page, 'cancel-poly-run', 'tag₁');
  const second = await clickAndAwaitNewValue(
    page, '#cancel-poly-btn', 'cancel-poly-run', 'tag₁', first,
  );
  expect(first).toMatch(HEX32);
  expect(second).toMatch(HEX32);
  expect(second).not.toBe(first);
  await expect(page.locator('#cancel-poly-run .cancel-check.cc-bad')).toHaveCount(0);
});
