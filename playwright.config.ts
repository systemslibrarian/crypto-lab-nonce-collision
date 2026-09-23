import { defineConfig, devices } from '@playwright/test';

/**
 * Accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * Run `npm run build` first (CI does).
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    // Build before serving. `preview` only serves whatever is already in
    // dist/; without the build in front, a failing build leaves the previous
    // good bundle on disk and the suite passes green against code that no
    // longer compiles — silently invalidating mutation checks.
    command: 'npm run build && npm run preview -- --port 4226 --strictPort',
    url: 'http://localhost:4226/crypto-lab-nonce-collision/',
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: 'http://localhost:4226/crypto-lab-nonce-collision/',
    colorScheme: 'dark',
  },
  /* All three engines: the fresh-nonce branch below asserts that WebCrypto's own
     verifier accepts an honest tag, and "WebCrypto does X" is an engine claim. */
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    /* firefox and webkit run the functional specs only. The axe sweep is a far
       heavier check and belongs in one engine; tripling it triples the gate and
       buys load-dependent failures rather than coverage. See the same note in
       crypto-lab-aes-modes, where that cost showed up as a false red. */
    { name: 'firefox', use: { ...devices['Desktop Firefox'] }, testIgnore: /a11y\.spec\.ts/ },
    { name: 'webkit', use: { ...devices['Desktop Safari'] }, testIgnore: /a11y\.spec\.ts/ },
  ],
});
