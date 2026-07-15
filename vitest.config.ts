import { defineConfig } from 'vitest/config';

/**
 * Unit-test config for the crypto core. Runs the RFC 8439 / SP 800-38D
 * known-answer vectors and the attack property tests in `src/`. The Playwright
 * accessibility suite in `e2e/` is deliberately excluded — it is driven by
 * `npm run test:a11y`.
 */
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
