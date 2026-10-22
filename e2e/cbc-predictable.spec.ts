import { expect, test } from '@playwright/test';

test('CBC exhibit demonstrates distinct predictable IVs against a committed random-IV control', async ({ page }) => {
  await page.goto('.');
  const exhibit = page.locator('#cbc-predictable');
  await exhibit.locator('#run-cbc-predictable').click();
  const output = exhibit.locator('#out-cbc-predictable');
  await expect(output).toContainText('FIRST BLOCKS MATCH');
  await expect(output).toContainText('NO FIRST-BLOCK MATCH');
  await expect(output).toContainText('IV₁ ≠ IV₂ and P₁ ≠ P₂');
  await expect(exhibit).toContainText('before the browser draws a fresh random IV');

  const paragraphs = await output.locator('.key-detail p').allTextContents();
  const first = paragraphs[0].match(/P₁ = ([0-9a-f ]+); IV₁ = ([0-9a-f ]+)/);
  const second = paragraphs[1].match(/IV₂ = ([0-9a-f ]+) \(counter \+ 1\); chooses and commits to P₂ = ([0-9a-f ]+)/);
  const third = paragraphs[2].match(/IV₃ = ([0-9a-f ]+)/);
  expect(first).not.toBeNull();
  expect(second).not.toBeNull();
  expect(third).not.toBeNull();
  const asBytes = (hex: string) => Uint8Array.from(hex.trim().split(/\s+/), pair => parseInt(pair, 16));
  const [p1, iv1, iv2, p2, iv3] = [first![1], first![2], second![1], second![2], third![1]].map(asBytes);
  expect(iv1).not.toEqual(iv2);
  expect(iv3).not.toEqual(iv1);
  expect(iv3).not.toEqual(iv2);
  expect(p1).not.toEqual(p2);
  expect([...p1].map((byte, i) => byte ^ iv1[i])).toEqual([...p2].map((byte, i) => byte ^ iv2[i]));
  const ciphertexts = paragraphs.slice(3).map(p => p.replace(/^C[₁₂₃]\[0\] = /, ''));
  expect(ciphertexts[0]).toBe(ciphertexts[1]);
  expect(ciphertexts[0]).not.toBe(ciphertexts[2]);

  const sourceLinks = await exhibit.locator('a[href^="https://csrc.nist.gov/pubs/"]').count();
  expect(sourceLinks).toBe(2);
  await expect(exhibit).toContainText('This is a controlled chosen-plaintext example');
});
