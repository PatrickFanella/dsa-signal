import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { parseDocument } from "yaml";

const root = new URL("../", import.meta.url).pathname;
const patchPath = "patches/matrix-js-sdk@42.0.0.patch";
const patchHash = "7f63b142c2aab67d18023a9e3390bf929f9fb382f76462d87012e3fe6bf36c93";
const expectedFinder = "requests.find(request => request.roomId?.toString() === roomId && !request.isCancelled() && !request.isDone() && !request.isPassive())";
const requireWeb = createRequire(resolve(root, "web/package.json"));
const shippedFinder = requireWeb.resolve("matrix-js-sdk/lib/rust-crypto/rust-crypto.js");
const shippedSource = resolve(shippedFinder, "../../../src/rust-crypto/rust-crypto.ts");

test("matrix-js-sdk v42 verification finder patch policy is pinned and shipped", async () => {
  const [workspace, lockfile, patch, packageJson, source, sourceTs] = await Promise.all([
    readFile(resolve(root, "pnpm-workspace.yaml"), "utf8"),
    readFile(resolve(root, "pnpm-lock.yaml"), "utf8"),
    readFile(resolve(root, patchPath), "utf8"),
    readFile(resolve(root, "web/package.json"), "utf8"),
    readFile(shippedFinder, "utf8"),
    readFile(shippedSource, "utf8"),
  ]);
  assert.equal(JSON.parse(packageJson).dependencies["matrix-js-sdk"], "42.0.0");
  assert.match(workspace, /^patchedDependencies:\n  matrix-js-sdk@42\.0\.0: patches\/matrix-js-sdk@42\.0\.0\.patch$/m);
  const lock = parseDocument(lockfile).toJS();
  assert.deepEqual(lock.patchedDependencies?.["matrix-js-sdk@42.0.0"], { hash: patchHash, path: patchPath });
  assert.match(lock.importers.web.dependencies["matrix-js-sdk"].version, new RegExp(`^42\\.0\\.0\\(patch_hash=${patchHash}\\)$`));
  assert.equal(createHash("sha256").update(patch).digest("hex"), patchHash);
  assert.match(patch, new RegExp(`^\\+    const request = ${expectedFinder.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")};$`, "m"));
  assert.match(source, new RegExp(`const request = ${expectedFinder.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")};`));
  assert.match(sourceTs, /!request\.isCancelled\(\) &&\n                !request\.isDone\(\) &&\n                !request\.isPassive\(\)/);
});

test("shipped finder excludes inactive requests and reveals the next pending request", () => {
  const loader = pathToFileURL(resolve(root, "scripts/matrix-sdk-esm-loader.mjs")).href;
  const registration = `data:text/javascript,import { register } from 'node:module'; import { pathToFileURL } from 'node:url'; register(${JSON.stringify(loader)}, pathToFileURL('./'));`;
  execFileSync(process.execPath, [
    "--import",
    registration,
    resolve(root, "scripts/matrix-sdk-verification-finder-runtime.mjs"),
  ], { cwd: root, stdio: "inherit" });
});
