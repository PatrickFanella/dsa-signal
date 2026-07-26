import { expect, test, chromium, type BrowserContext, type Page, type TestInfo } from '@playwright/test';
import { access, readFile, rm } from 'node:fs/promises';
import { resolve } from 'node:path';

const origin = 'https://task9.localhost';
const harnessUrl = `${origin}/__task9_browser_harness.js`;
const harnessPage = `${origin}/__task9_browser_harness`;
const harness = await readFile(resolve('.matrix-browser-harness/harness.js'), 'utf8');
type Snapshot = { locator: { profileId: string; generation: number }; authorization: Record<string, unknown>; operation: Record<string, unknown>; result?: string };
const timeout = 5_000;

const launch = (profile: string): Promise<BrowserContext> => chromium.launchPersistentContext(profile, { ignoreHTTPSErrors: true, ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {}) });
const inject = async (context: BrowserContext): Promise<Page> => { const page = await context.newPage(); await page.route(harnessPage, route => route.fulfill({ body: '<!doctype html><title>Task 9 harness</title>', contentType: 'text/html' })); await page.route(harnessUrl, route => route.fulfill({ body: harness, contentType: 'text/javascript' })); await page.goto(harnessPage); await page.addScriptTag({ url: harnessUrl, type: 'module' }); await page.waitForFunction(() => window.__task9StartupQuarantineHarness !== undefined); return page; };
const bounded = async <T>(operation: Promise<T>, action: string): Promise<T> => {
  let handle: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([operation, new Promise<never>((_, reject) => { handle = setTimeout(() => reject(new Error(`${action} timed out after ${timeout}ms`)), timeout); })]); } finally { if (handle !== undefined) clearTimeout(handle); }
};
const aggregate = (errors: unknown[], message: string): void => { if (errors.length === 1) throw errors[0]; if (errors.length > 1) throw new AggregateError(errors, message); };

/** The sole owner of a persistent profile and its browser context. */
class PersistentProfile {
  #context: BrowserContext | undefined;
  constructor(readonly path: string) {}

  async launch(): Promise<BrowserContext> {
    if (this.#context !== undefined) throw new Error('persistent profile already has a live context');
    this.#context = await launch(this.path);
    return this.#context;
  }

  async #terminate(): Promise<void> {
    const context = this.#context;
    if (context === undefined) return;
    try {
      await bounded(context.close(), 'context.close');
    } catch (contextError) {
      const browser = context.browser();
      if (browser === null) throw contextError;
      try { await bounded(browser.close(), 'browser.close after context.close'); } catch (browserError) { throw new AggregateError([contextError, browserError], 'could not terminate persistent context'); }
    }
    this.#context = undefined;
  }

  async crash(page: Page): Promise<void> {
    const context = this.#context;
    if (context === undefined) throw new Error('cannot crash a terminated persistent context');
    const cdp = await context.newCDPSession(page);
    const observedCrash = page.waitForEvent('crash', { timeout });
    const command = cdp.send('Page.crash');
    const commandSettled = command.then(() => undefined, () => undefined);
    const errors: unknown[] = [];
    let detachError: unknown;
    try { await observedCrash; } catch (error) { errors.push(error); }
    try { await bounded(cdp.detach(), 'CDP detach after renderer crash'); } catch (error) { detachError = error; }
    try { await this.#terminate(); } catch (error) { if (detachError !== undefined) errors.push(detachError); errors.push(error); }
    if (this.#context === undefined) {
      try { await bounded(commandSettled, 'Page.crash command settlement'); } catch (error) { errors.push(error); }
    } else errors.push(new Error('Page.crash command was not awaited because browser termination is uncertain'));
    aggregate(errors, 'renderer crash lifecycle failed');
  }

  async cleanup(): Promise<void> {
    const errors: unknown[] = [];
    try { await this.#terminate(); } catch (error) { errors.push(error); }
    if (this.#context !== undefined) {
      errors.push(new Error('profile deletion skipped because browser termination is uncertain'));
      aggregate(errors, 'persistent profile cleanup failed');
      return;
    }
    try { await bounded(rm(this.path, { recursive: true, force: true }), 'profile deletion'); } catch (error) { errors.push(error); }
    try { await access(this.path); errors.push(new Error('profile deletion check found the profile still exists')); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') errors.push(error); }
    aggregate(errors, 'persistent profile cleanup failed');
  }
}

const barrier = (seed: Snapshot): Record<string, unknown> => ({ schemaVersion: 1, profileId: seed.locator.profileId, sessionGeneration: seed.locator.generation, homeserver: 'https://matrix.localhost:8443', localUserId: '@task9:hs.example', localDeviceId: 'd'.repeat(43), state: 'reverification-required', generation: (seed.authorization.generation as number) + 1 });

// eslint-disable-next-line no-empty-pattern -- this test deliberately creates only its persistent context.
test('quarantines active v4 after renderer crashes without mutating same-profile v3', async ({}, testInfo: TestInfo) => {
  const profile = new PersistentProfile(resolve(testInfo.outputPath(), 'task9-confirmation-profile')); const name = 'task9-confirmation-store';
  try {
    let page = await inject(await profile.launch()); const seeded = await page.evaluate(store => window.__task9StartupQuarantineHarness!.seedConfirmationIntent(store), name) as Snapshot; const v3Bytes = JSON.stringify(seeded.operation);
    await profile.crash(page); page = await inject(await profile.launch());
    const prepared = await page.evaluate(store => window.__task9StartupQuarantineHarness!.prepare(store), name) as Snapshot;
    expect(prepared.result).toBe('reverification-required'); expect(prepared.authorization).toEqual(barrier(seeded)); expect(JSON.stringify(prepared.operation)).toBe(v3Bytes);
    await profile.crash(page); page = await inject(await profile.launch());
    const replay = await page.evaluate(store => window.__task9StartupQuarantineHarness!.prepare(store), name) as Snapshot;
    expect(replay.result).toBe('reverification-required'); expect(replay.authorization).toEqual(prepared.authorization); expect(JSON.stringify(replay.operation)).toBe(v3Bytes);
  } finally { await profile.cleanup(); }
});

// eslint-disable-next-line no-empty-pattern -- this test deliberately creates only its persistent context.
test('requires grant revalidation after renderer crash without changing the grant', async ({}, testInfo: TestInfo) => {
  const profile = new PersistentProfile(resolve(testInfo.outputPath(), 'task9-grant-profile')); const name = 'task9-grant-store';
  try {
    let page = await inject(await profile.launch()); const seeded = await page.evaluate(store => window.__task9StartupQuarantineHarness!.seedGranted(store), name) as Snapshot; const grantBytes = JSON.stringify(seeded.authorization);
    await profile.crash(page); page = await inject(await profile.launch());
    const prepared = await page.evaluate(store => window.__task9StartupQuarantineHarness!.prepare(store), name) as Snapshot;
    expect(prepared.result).toBe('grant-revalidation-required'); expect(JSON.stringify(prepared.authorization)).toBe(grantBytes);
  } finally { await profile.cleanup(); }
});
