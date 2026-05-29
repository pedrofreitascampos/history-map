// Playwright config for Oikumene e2e harness.
// Launches the real server with NODE_ENV=test + isolated DATA_DIR.
// Auth state is seeded once by e2e/auth.setup.js then shared across specs.

const path = require('path');
const { defineConfig, devices } = require('@playwright/test');

const PORT = 3101;
const BASE_URL = `http://localhost:${PORT}`;
const DATA_DIR = path.join(__dirname, 'data-e2e');
const STORAGE_STATE = path.join(__dirname, 'e2e', '.auth', 'state.json');

module.exports = defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  timeout: 30_000,
  expect: { timeout: 5_000 },

  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'setup',
      testMatch: /auth\.setup\.js$/,
      use: { baseURL: BASE_URL },
    },
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        baseURL: BASE_URL,
        storageState: STORAGE_STATE,
      },
      dependencies: ['setup'],
    },
  ],

  webServer: {
    command: 'node server/index.js',
    url: BASE_URL,
    reuseExistingServer: false,
    timeout: 30_000,
    stdout: 'pipe',
    stderr: 'pipe',
    env: {
      NODE_ENV: 'test',
      PORT: String(PORT),
      DATA_DIR,
      JWT_SECRET: 'e2e-secret',
      ALLOWED_EMAILS: '',
    },
  },
});
