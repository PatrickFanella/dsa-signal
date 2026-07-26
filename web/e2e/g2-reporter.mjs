/* global process */
import { writeFileSync } from 'node:fs';

/** A deliberately tiny, nonce-bound result authority for the isolated G2 project. */
export function validateG2ReporterResult(value, nonce, project = 'g2-encrypted-direct-chat', file = 'encrypted-vertical-slice.spec.ts') {
  return Boolean(value && typeof value === 'object' && Object.keys(value).length === 8 && value.nonce === nonce && value.project === project && value.file === file && value.passed === 1 && value.skipped === 0 && value.failed === 0 && value.interrupted === 0 && value.timedOut === 0);
}

export default class G2Reporter {
  constructor() { this.results = []; }
  onTestEnd(test, result) { this.results.push({ project: test.parent.project()?.name, file: test.location.file.split('/').pop(), status: result.status }); }
  onEnd(result) {
    const statuses = this.results.map(x => x.status);
    const value = { nonce: process.env.G2_RUN_NONCE, project: 'g2-encrypted-direct-chat', file: 'encrypted-vertical-slice.spec.ts', passed: statuses.filter(x => x === 'passed').length, skipped: statuses.filter(x => x === 'skipped').length, failed: statuses.filter(x => x === 'failed').length + (result.status === 'interrupted' ? 1 : 0), interrupted: result.status === 'interrupted' ? 1 : 0, timedOut: statuses.filter(x => x === 'timedOut').length };
    if (!validateG2ReporterResult(value, process.env.G2_RUN_NONCE)) throw new Error('invalid isolated G2 Playwright result');
    writeFileSync(process.env.G2_REPORTER_RESULT, JSON.stringify(value), { flag: 'wx', mode: 0o600 });
  }
}
