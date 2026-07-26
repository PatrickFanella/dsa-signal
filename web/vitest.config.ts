import { defineConfig } from 'vitest/config';
import vite from './vite.config';
export default defineConfig({ ...vite, test: { environment: 'jsdom', exclude: ['e2e/**', '**/node_modules/**', '**/dist/**'] } });
