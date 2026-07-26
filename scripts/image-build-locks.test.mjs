import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { checkBuildLockWiring } from "./check-matrix-policy.mjs";

const read = (file) => readFile(new URL(`../${file}`, import.meta.url), "utf8");
const node = "node@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd";
const nginx = "nginx@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de";

test("all Docker build paths require immutable Node/Nginx lock arguments", async () => {
  const [backend, web, local, root] = await Promise.all([read("backend/Dockerfile"), read("web/Dockerfile"), read("deploy/local/compose.yaml"), read("docker-compose.yml")]);
  assert.equal(checkBuildLockWiring({ backendDockerfile: backend, webDockerfile: web, rootCompose: root }), true);
  assert.equal((local.match(/NODE_IMAGE: "\$\{NODE_IMAGE:\?\}"/g) ?? []).length, 3);
  assert.match(local, /NGINX_IMAGE: "\$\{NGINX_IMAGE:\?\}"/);
  assert.match(root, /NODE_IMAGE: \$\{NODE_IMAGE:\?use deploy\/locks\/images\.env\}/);
  assert.match(root, /NGINX_IMAGE: \$\{NGINX_IMAGE:\?use deploy\/locks\/images\.env\}/);
  assert.match(root, /image: \$\{POSTGRES_IMAGE:\?use deploy\/locks\/images\.env\}/);
  assert.match(root, /BUILD_MARKER: \$\{VITE_BUILD_MARKER:-development\}/);
  assert.equal((await read("deploy/locks/images.env")).includes(`NODE_IMAGE=${node}`), true);
  assert.equal((await read("deploy/locks/images.env")).includes(`NGINX_IMAGE=${nginx}`), true);
});

test("Dockerfile and root Compose lock wiring reject unapproved bases and arguments", async () => {
  const [backend, web, root] = await Promise.all([read("backend/Dockerfile"), read("web/Dockerfile"), read("docker-compose.yml")]);
  const reject = (values) => assert.throws(() => checkBuildLockWiring(values));
  reject({ backendDockerfile: `${backend}\nFROM alpine:latest AS extra\n`, webDockerfile: web, rootCompose: root });
  reject({ backendDockerfile: backend.replace("FROM ${NODE_IMAGE} AS build", "FROM ${OTHER_IMAGE} AS build"), webDockerfile: web, rootCompose: root });
  reject({ backendDockerfile: backend, webDockerfile: web, rootCompose: root.replace("NODE_IMAGE: ${NODE_IMAGE:?use deploy/locks/images.env}", "NODE_IMAGE: node:latest") });
  reject({ backendDockerfile: backend, webDockerfile: web, rootCompose: root.replace("NGINX_IMAGE: ${NGINX_IMAGE:?use deploy/locks/images.env}\n        BUILD_MARKER", "BUILD_MARKER") });
});

test("root Compose passes the revocation role name without its credential", async () => {
  const root = await read("docker-compose.yml");
  assert.match(root, /CONTROL_PLANE_REVOCATION_ROLE: \$\{CONTROL_PLANE_REVOCATION_ROLE:\?configure the revocation role name\}/);
  assert.doesNotMatch(root, /CONTROL_PLANE_REVOCATION_(?:PASSWORD|CREDENTIAL|DATABASE_URL|SECRET|TOKEN)/);
});
