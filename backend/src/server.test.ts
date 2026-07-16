import { describe, expect, it } from 'vitest';
import { getConfig } from './server.js';

describe('getConfig', () => {
  it('parses a port from env', () => {
expect(getConfig({ PORT: '9090' }).PORT).toBe(9090);
  });
});
