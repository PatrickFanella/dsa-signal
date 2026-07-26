import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = new URL("../", import.meta.url).pathname;
const requireWeb = createRequire(resolve(root, "web/package.json"));
const shippedFinder = requireWeb.resolve("matrix-js-sdk/lib/rust-crypto/rust-crypto.js");
const { RustCrypto } = await import(pathToFileURL(shippedFinder).href);
const request = (name, { cancelled = false, done = false, passive = false } = {}) => ({
  name,
  roomId: { toString: () => "!room:example" },
  isCancelled: () => cancelled,
  isDone: () => done,
  isPassive: () => passive,
  setDone: (value) => { done = value; },
  setCancelled: (value) => { cancelled = value; },
});
const finder = (requests) => RustCrypto.prototype.findVerificationRequestDMInProgress.call({
  olmMachine: { getVerificationRequests: () => requests },
  makeVerificationRequest: (inner) => inner,
}, "!room:example", "@peer:example");

const pending = request("pending");
assert.equal(finder([request("done", { done: true }), request("passive", { passive: true }), request("cancelled", { cancelled: true }), pending]), pending);
assert.equal(finder([request("done", { done: true }), request("passive", { passive: true }), request("cancelled", { cancelled: true })]), undefined);
const first = request("first");
const next = request("next");
assert.equal(finder([first, next]), first);
first.setDone(true);
assert.equal(finder([first, next]), next);
next.setCancelled(true);
assert.equal(finder([first, next]), undefined);
