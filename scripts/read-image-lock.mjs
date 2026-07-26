import { readFileSync } from "node:fs";

const names = ["SYNAPSE_IMAGE", "MAS_IMAGE", "POSTGRES_IMAGE", "CADDY_IMAGE", "NODE_IMAGE", "NGINX_IMAGE"];
const image = /^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$/;
const name = process.argv[2];
try {
  if (!names.includes(name)) throw new Error("unknown image lock");
  const lines = readFileSync("deploy/locks/images.env", "utf8").trimEnd().split("\n");
  if (lines.length !== names.length) throw new Error("image lock must have exactly six entries");
  const entries = lines.map((line) => line.match(/^([A-Z_]+)=(.+)$/) ?? (() => { throw new Error("invalid image lock entry"); })());
  if (entries.some((entry, index) => entry[1] !== names[index] || !image.test(entry[2]))) throw new Error("image lock is not canonical");
  process.stdout.write(`${entries.find((entry) => entry[1] === name)[2]}\n`);
} catch (error) {
  process.stderr.write(`read-image-lock: ${error.message}\n`);
  process.exitCode = 1;
}
