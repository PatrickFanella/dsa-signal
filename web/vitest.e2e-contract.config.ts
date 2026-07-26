import { defineConfig } from 'vitest/config';
export default defineConfig({ test: { environment: 'node', include: ['e2e/g2-browser-observation-contract.test.ts'] } });
