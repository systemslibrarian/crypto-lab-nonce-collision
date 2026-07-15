import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG 2.1 A/AA gate. Scans the production build (via `vite preview`) in both
 * themes. Before scanning we drive the demo into its most colour-loaded states
 * — every reuse toggle ON so the ALARM / LEAK verdict panels render, the
 * crib-drag panel revealed, and the cancellation animations run to completion —
 * so the dynamic result regions are actually audited, not just the static shell.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: '*, *::before, *::after { animation: none !important; transition: none !important; }',
  });

  // Reveal collapsed / injected content.
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
    document.querySelectorAll<HTMLElement>('[hidden]').forEach((el) => el.removeAttribute('hidden'));
  });

  // Reveal the crib-drag panel.
  await page.getByRole('button', { name: /encrypt both under one key/i }).click().catch(() => {});

  // Turn on every reuse toggle (visually-hidden inputs; set via DOM) so the
  // broken / leak verdict panels render, then run every construction card.
  await page.evaluate(() => {
    document.querySelectorAll<HTMLInputElement>('.reuse-toggle').forEach((cb) => (cb.checked = true));
  });
  for (const b of await page.locator('.run-btn').all()) {
    await b.click().catch(() => {});
  }
  // Complete the cancellation animations.
  for (const b of await page.locator('.cancel-btn').all()) {
    await b.click().catch(() => {});
  }
  await page.waitForTimeout(500);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await prepare(page);
  await scan(page);
});
