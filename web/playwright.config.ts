import { defineConfig } from '@playwright/test';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  testDir: './e2e',
  outputDir: resolve(dirname(fileURLToPath(import.meta.url)), 'test-results'),
  timeout: 90_000,
  forbidOnly: true,
  use: {
    baseURL: 'https://chat.localhost:8443',
    ignoreHTTPSErrors: true,
    ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
      ? { launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } }
      : {}),
  },
  projects: [
    { name: 'task8-matrix-oauth', testMatch: 'task8-matrix-oauth.spec.ts' },
    { name: 'task9-sas-startup-quarantine', testMatch: 'task9-sas-startup-quarantine.spec.ts', use: { browserName: 'chromium', trace: 'off', video: 'off', screenshot: 'off' } },
    { name: 'g2-encrypted-direct-chat', testMatch: 'encrypted-vertical-slice.spec.ts' },
  ],
});
