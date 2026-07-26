/** Test-only bundle: never imported by the production Vite configuration. */
import { build } from 'vite';
import { mkdir, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
const outDir = resolve('.matrix-browser-harness');
await mkdir(outDir, { recursive: true });
await build({ configFile: false, root: resolve('.'), build: { outDir, emptyOutDir: true, assetsInlineLimit: Number.POSITIVE_INFINITY, lib: { entry: resolve('e2e/browser-harness.ts'), formats: ['es'], fileName: () => 'harness.js' }, rollupOptions: { output: { inlineDynamicImports: true } } } });
const output = await readdir(outDir);
if (output.length !== 1 || output[0] !== 'harness.js') throw new Error('browser harness injection requires one self-contained output');
