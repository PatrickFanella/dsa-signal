import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { parseDocument } from "yaml";

const fail = () => {
  throw new Error("policy");
};
const object = (x) =>
  x && typeof x === "object" && !Array.isArray(x) ? x : fail();
const array = (x) => (Array.isArray(x) ? x : fail());
const equal = (a, b) =>
  JSON.stringify(canonical(a)) === JSON.stringify(canonical(b)) || fail();
const keys = (x, expected) =>
  equal(Object.keys(object(x)).sort(), [...expected].sort());
const has = (x, key) => (Object.hasOwn(object(x), key) ? x[key] : fail());
const imageKeys = [
  "SYNAPSE_IMAGE",
  "MAS_IMAGE",
  "POSTGRES_IMAGE",
  "CADDY_IMAGE",
  "NODE_IMAGE",
  "NGINX_IMAGE",
];
const image = /^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$/;
const services = [
  "control-db",
  "matrix-db",
  "migrate",
  "api",
  "web",
  "synapse",
  "synapse-data-init",
  "mas",
  "mas-ready",
  "mas-migrate",
  "gateway",
  "gateway-ca-export",
  "egress-canary",
];
const networks = [
  "canary",
  "control-egress",
  "control-internal",
  "edge",
  "matrix-internal",
];
const volumes = [
  "caddy-ca",
  "caddy-config",
  "caddy-data",
  "control-db-data",
  "matrix-db-data",
  "synapse-data",
];
const secrets = [
  "control-owner-db-password",
  "control-revocation-db-password",
  "control-retention-db-password",
  "control-runtime-db-password",
  "mas-db-password",
  "mas-encryption-key",
  "mas-secrets.yaml",
  "mas-signing-key.pem",
  "mas-upstream-client-secret",
  "matrix-root-password",
  "oidc-cookie-keys",
  "oidc-signing-jwks",
  "synapse-db-password",
  "synapse-mas-shared-secret",
  "synapse-secrets.yaml",
  "synapse-signing-key",
];
// Golden artifacts are reviewed policy, never an automatically updated baseline.
// Arrays are significant; only object key order is made deterministic.
export const canonical = (value) =>
  Array.isArray(value)
    ? value.map(canonical)
    : value && typeof value === "object"
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]))
      : value;
export const canonicalJson = (value) => `${JSON.stringify(canonical(value), null, 2)}\n`;
const normalizeRepoPaths = (value, root) =>
  Array.isArray(value)
    ? value.map((item) => normalizeRepoPaths(item, root))
    : value && typeof value === "object"
      ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalizeRepoPaths(item, root)]))
      : typeof value === "string" && (value === resolve(root) || value.startsWith(`${resolve(root)}/`))
        ? `<repo>${value.slice(resolve(root).length)}`
        : value;
export const normalizeCompose = (value, root) => canonical(normalizeRepoPaths(value, root));
export const normalizeCaddy = (value, root) => {
  const groups = new Map();
  const visit = (item) => {
    if (Array.isArray(item)) return item.map(visit);
    if (!item || typeof item !== "object") return normalizeRepoPaths(item, root);
    return Object.fromEntries(Object.entries(item).map(([key, child]) => [
      key,
      key === "group" && typeof child === "string" && /^group\d+$/.test(child)
        ? `group${groups.get(child) ?? (groups.set(child, groups.size), groups.size - 1)}`
        : visit(child),
    ]));
  };
  return canonical(visit(value));
};
const provenanceDigest = "cd357f81ebefd93e065888f0dee24864c3b52b6ea9ca86b097f431a9ee95ea72";
const COMMAND_TIMEOUT_MS = 30_000;
const COMMAND_MAX_BYTES = 1024 * 1024;
const COMMAND_KILL_GRACE_MS = 100;

export function parseYaml(text) {
  const d = parseDocument(text, { uniqueKeys: true });
  if (d.errors.length || d.warnings.length || d.contents?.tag) fail();
  return object(d.toJS());
}
export function parseImageLocks(text) {
  const rows = text
    .trim()
    .split("\n")
    .map((line) => line.split("="));
  if (
    rows.length !== imageKeys.length ||
    rows.some(
      ([k, v, extra]) => !imageKeys.includes(k) || !image.test(v) || extra,
    )
  )
    fail();
  const locks = Object.fromEntries(rows);
  keys(locks, imageKeys);
  if (new Set(Object.values(locks)).size !== imageKeys.length) fail();
  return locks;
}
function validateLocks(locks) {
  keys(locks, imageKeys);
  if (
    new Set(Object.values(locks)).size !== imageKeys.length ||
    Object.values(locks).some(
      (value) => typeof value !== "string" || !image.test(value),
    )
  )
    fail();
}
export function checkSecretOverlay(kind, overlay) {
  if (kind === "synapse") {
    keys(overlay, [
      "database",
      "macaroon_secret_key",
      "form_secret",
      "signing_key_path",
    ]);
    keys(has(overlay, "database"), ["name", "args"]);
    keys(has(overlay.database, "args"), [
      "host",
      "database",
      "user",
      "password",
    ]);
    equal(overlay.database.name, "psycopg2");
    equal(overlay.database.args.host, "matrix-db");
    equal(overlay.database.args.database, "synapse");
    equal(overlay.database.args.user, "synapse");
    equal(overlay.signing_key_path, "/run/secrets/synapse-signing-key");
  } else if (kind === "mas") {
    keys(overlay, ["database"]);
    keys(overlay.database, ["uri"]);
    if (
      !/^postgresql:\/\/mas:.+@matrix-db\/mas\?sslmode=disable$/.test(
        overlay.database.uri,
      )
    )
      fail();
  } else fail();
  return true;
}
function synapse(s) {
  keys(s, [
    "server_name",
    "public_baseurl",
    "media_store_path",
    "report_stats",
    "listeners",
    "matrix_authentication_service",
    "enable_registration",
    "allow_guest_access",
    "enable_set_password",
    "password_config",
    "enable_3pid_lookup",
    "default_identity_server",
    "url_preview_enabled",
    "allow_public_rooms_without_auth",
    "allow_public_rooms_over_federation",
    "user_directory",
    "app_service_config_files",
    "allow_profile_lookup_over_federation",
    "allow_device_name_lookup_over_federation",
    "trusted_key_servers",
    "encryption_enabled_by_default_for_room_type",
    "room_list_publication_rules",
    "database",
  ]);
  equal(s.server_name, "chat.localhost");
  equal(s.public_baseurl, "https://matrix.localhost:8443/");
  equal(s.media_store_path, "/data/media_store");
  equal(s.report_stats, false);
  equal(s.listeners, [
    {
      port: 8008,
      type: "http",
      tls: false,
      bind_addresses: ["0.0.0.0"],
      x_forwarded: true,
      resources: [{ names: ["client"] }],
    },
  ]);
  equal(s.matrix_authentication_service, {
    enabled: true,
    endpoint: "http://mas:8080/",
    secret_path: "/run/secrets/synapse-mas-shared-secret",
  });
  equal(s.password_config, { enabled: false, localdb_enabled: false });
  equal(s.user_directory, { enabled: false });
  for (const key of [
    "enable_registration",
    "allow_guest_access",
    "enable_set_password",
    "enable_3pid_lookup",
    "url_preview_enabled",
    "allow_public_rooms_without_auth",
    "allow_public_rooms_over_federation",
    "allow_profile_lookup_over_federation",
    "allow_device_name_lookup_over_federation",
  ])
    equal(s[key], false);
  equal(s.default_identity_server, null);
  equal(s.app_service_config_files, []);
  equal(s.trusted_key_servers, []);
  equal(s.encryption_enabled_by_default_for_room_type, "invite");
  equal(s.room_list_publication_rules, []);
  equal(s.database, {
    name: "psycopg2",
    args: { host: "matrix-db", database: "synapse", user: "synapse" },
  });
}
function mas(m) {
  keys(m, [
    "http",
    "database",
    "matrix",
    "account",
    "passwords",
    "secrets",
    "upstream_oauth2",
  ]);
  keys(m.http, ["public_base", "listeners"]);
  equal(m.http.public_base, "https://auth.localhost:8443/");
  equal(m.http.listeners, [
    {
      name: "web",
      resources: [
        { name: "discovery" },
        { name: "human" },
        { name: "oauth" },
        { name: "compat" },
        { name: "graphql" },
        { name: "assets" },
      ],
      binds: [{ host: "0.0.0.0", port: 8080 }],
    },
    {
      name: "health",
      resources: [{ name: "health" }],
      binds: [{ host: "0.0.0.0", port: 8081 }],
    },
  ]);
  equal(m.database, { uri: "postgresql://mas@matrix-db/mas?sslmode=disable" });
  equal(m.matrix, {
    kind: "synapse",
    homeserver: "chat.localhost",
    endpoint: "http://synapse:8008",
    secret_file: "/run/secrets/synapse-mas-shared-secret",
  });
  equal(m.account, {
    enabled: false,
    password_registration_enabled: false,
    password_change_allowed: false,
    password_recovery_enabled: false,
  });
  equal(m.passwords, { enabled: false });
  equal(m.secrets, {
    encryption_file: "/run/secrets/mas-encryption-key",
    keys: [{ key_file: "/run/secrets/mas-signing-key.pem" }],
  });
  equal(m.upstream_oauth2, {
    providers: [
      {
        id: "01J00000000000000000000000",
        issuer: "https://chat.localhost:8443/oidc",
        client_id: "dsa-signal",
        client_secret_file: "/run/secrets/mas-upstream-client-secret",
        discovery_mode: "oidc",
        token_endpoint_auth_method: "client_secret_basic",
        scope: "openid dsa_signal_entitlement",
        pkce_method: "always",
        claims_imports: {
          subject: { template: "{{ user.sub }}" },
          localpart: { action: "ignore" },
          displayname: { action: "ignore" },
          email: { action: "ignore" },
        },
      },
    ],
  });
}
const networkNames = (s) => Object.keys(object(has(s, "networks"))).sort();
function compose(c, locks) {
  keys(c, ["name", "networks", "secrets", "services", "volumes"]);
  keys(c.services, services);
  keys(c.networks, networks);
  keys(c.volumes, volumes);
  keys(c.secrets, secrets);
  for (const s of Object.values(c.services)) {
    const allowed = [
      "profiles",
      "image",
      "build",
      "user",
      "command",
      "entrypoint",
      "environment",
      "volumes",
      "secrets",
      "networks",
      "network_mode",
      "depends_on",
      "healthcheck",
      "ports",
      "tmpfs",
    ];
    if (Object.keys(object(s)).some((k) => !allowed.includes(k))) fail();
  }
  const imageMap = {
    synapse: "SYNAPSE_IMAGE",
    "synapse-data-init": "SYNAPSE_IMAGE",
    mas: "MAS_IMAGE",
    "mas-migrate": "MAS_IMAGE",
    "matrix-db": "POSTGRES_IMAGE",
    "control-db": "POSTGRES_IMAGE",
    "egress-canary": "CADDY_IMAGE",
    gateway: "CADDY_IMAGE",
    "mas-ready": "CADDY_IMAGE",
    "gateway-ca-export": "CADDY_IMAGE",
  };
  for (const [name, lock] of Object.entries(imageMap))
    equal(c.services[name].image, locks[lock]);
  for (const name of Object.keys(c.services))
    if (c.services[name].image && !Object.hasOwn(imageMap, name)) fail();
  const buildArgs = (name, expected) => {
    const build = object(c.services[name].build);
    keys(build, ["context", "dockerfile", "args"]);
    if (typeof build.context !== "string" || !build.context.startsWith("/")) fail();
    equal(build.dockerfile, name === "web" ? "web/Dockerfile" : "backend/Dockerfile");
    equal(build.args, expected);
  };
  buildArgs("migrate", { NODE_IMAGE: locks.NODE_IMAGE, BUILD_MARKER: "development" });
  buildArgs("api", { NODE_IMAGE: locks.NODE_IMAGE, BUILD_MARKER: "development" });
  buildArgs("web", { NODE_IMAGE: locks.NODE_IMAGE, NGINX_IMAGE: locks.NGINX_IMAGE, BUILD_MARKER: "development", VITE_BUILD_MARKER: "development" });
  const memberships = {
    "control-db": ["control-internal"],
    "matrix-db": ["matrix-internal"],
    migrate: ["control-internal"],
    api: ["control-egress", "control-internal"],
    web: ["control-internal"],
    synapse: ["matrix-internal"],
    mas: ["matrix-internal"],
    "mas-ready": ["matrix-internal"],
    "mas-migrate": ["matrix-internal"],
    gateway: ["control-internal", "edge", "matrix-internal"],
    "egress-canary": ["canary"],
  };
  for (const [name, expected] of Object.entries(memberships))
    equal(networkNames(c.services[name]), expected);
  equal(c.services["egress-canary"].networks.canary.ipv4_address, "10.77.32.10");
  if (Object.hasOwn(c.services["egress-canary"], "environment") || Object.hasOwn(c.services["egress-canary"], "secrets") || Object.hasOwn(c.services["egress-canary"], "ports")) fail();
  for (const n of ["matrix-internal", "control-internal", "canary"])
    equal(c.networks[n].internal, true);
  if (c.networks["control-egress"].internal || c.networks.edge.internal) fail();
  equal(c.networks["matrix-internal"].ipam.config, [{ subnet: "10.77.30.0/24", gateway: "10.77.30.1" }]);
  equal(c.networks["control-internal"].ipam.config, [{ subnet: "10.77.31.0/24", gateway: "10.77.31.1" }]);
  equal(c.networks.canary.ipam.config, [{ subnet: "10.77.32.0/24", gateway: "10.77.32.1" }]);
  equal(c.services["synapse-data-init"].network_mode, "none");
  equal(c.services["gateway-ca-export"].network_mode, "none");
  equal(
    c.services.synapse.depends_on["matrix-db"].condition,
    "service_healthy",
  );
  equal(
    c.services.synapse.depends_on["synapse-data-init"].condition,
    "service_completed_successfully",
  );
  equal(
    c.services["mas-migrate"].depends_on["matrix-db"].condition,
    "service_healthy",
  );
  equal(
    c.services.mas.depends_on["mas-migrate"].condition,
    "service_completed_successfully",
  );
  equal(c.services.mas.depends_on.api.condition, "service_healthy");
  equal(c.services.mas.depends_on.synapse.condition, "service_healthy");
  equal(
    c.services.mas.depends_on["gateway-ca-export"].condition,
    "service_completed_successfully",
  );
  equal(c.services["mas-ready"].depends_on.mas.condition, "service_started");
  equal(
    c.services["gateway-ca-export"].depends_on.gateway.condition,
    "service_healthy",
  );
  const secretSources = (service) =>
    array(c.services[service].secrets ?? []).map((x) =>
      typeof x === "string" ? x : x.source,
    );
  const expectedSecrets = {
    "control-db": ["control-owner-db-password", "control-runtime-db-password", "control-retention-db-password", "control-revocation-db-password"],
    "matrix-db": ["matrix-root-password", "synapse-db-password", "mas-db-password"],
    migrate: ["control-owner-db-password"],
    api: ["control-runtime-db-password", "oidc-signing-jwks", "mas-upstream-client-secret", "oidc-cookie-keys"],
    web: [], synapse: ["synapse-secrets.yaml", "synapse-mas-shared-secret", "synapse-signing-key"],
    "synapse-data-init": [], mas: ["mas-secrets.yaml", "mas-upstream-client-secret", "synapse-mas-shared-secret", "mas-encryption-key", "mas-signing-key.pem"],
    "mas-ready": [], "mas-migrate": ["mas-secrets.yaml", "synapse-mas-shared-secret", "mas-encryption-key", "mas-signing-key.pem", "mas-upstream-client-secret"],
    gateway: [], "gateway-ca-export": [], "egress-canary": [],
  };
  for (const [name, expected] of Object.entries(expectedSecrets))
    equal(secretSources(name), expected);
  const secretBindings = (service) =>
    array(c.services[service].secrets ?? []).map((x) =>
      typeof x === "string" ? { source: x, target: `/run/secrets/${x}` } : { source: x.source, target: x.target },
    );
  for (const [name, expected] of Object.entries(expectedSecrets))
    equal(secretBindings(name), expected.map((source) => ({
      source,
      target: name === "api" && source === "oidc-signing-jwks" ? "oidc-signing-jwks.json" : name === "api" && source === "mas-upstream-client-secret" ? "mas-client-secret" : name === "api" && source === "oidc-cookie-keys" ? "oidc-cookie-keys.json" : `/run/secrets/${source}`,
    })));
  equal(c.services.api.secrets.slice(1).map((x) => x.target), [
    "oidc-signing-jwks.json", "mas-client-secret", "oidc-cookie-keys.json",
  ]);
  const volumeTargets = (service) =>
    array(c.services[service].volumes ?? []).map((x) =>
      typeof x === "string"
        ? x.split(":").slice(1).join(":")
        : `${x.target}${x.read_only ? ":ro" : ""}`,
    );
  const expectedVolumes = {
    "control-db": ["/var/lib/postgresql/data", "/docker-entrypoint-initdb.d/10-control.sh:ro"],
    "matrix-db": ["/var/lib/postgresql/data", "/docker-entrypoint-initdb.d/10-matrix.sh:ro"],
    api: ["/usr/local/bin/local-api-entrypoint.sh:ro", "/var/lib/dsa-signal/oidc-restore-floor:ro"],
    synapse: ["/data", "/data/homeserver.yaml:ro"], "synapse-data-init": ["/data"],
    mas: ["/config/config.yaml:ro", "/caddy-ca:ro"], "mas-migrate": ["/config/config.yaml:ro"],
    gateway: ["/etc/caddy/Caddyfile:ro", "/srv/well-known:ro", "/data", "/config"], "egress-canary": ["/etc/caddy/Caddyfile:ro"],
    "gateway-ca-export": ["/data:ro", "/caddy-ca"],
  };
  for (const [name, expected] of Object.entries(expectedVolumes))
    equal(volumeTargets(name), expected);
  for (const name of services)
    if (!Object.hasOwn(expectedVolumes, name)) equal(volumeTargets(name), []);
  const profiles = {
    "control-db": ["full"], "matrix-db": ["full", "negative"], migrate: ["full"], api: ["full"], web: ["full"], synapse: ["full", "negative"], "synapse-data-init": ["full", "negative"], mas: ["full"], "mas-ready": ["full"], "mas-migrate": ["full"], gateway: ["full", "negative"], "gateway-ca-export": ["full"], "egress-canary": ["negative"],
  };
  for (const [name, expected] of Object.entries(profiles)) equal(c.services[name].profiles, expected);
  equal(
    c.services.api.environment.OIDC_TRUSTED_PROXY_ADDRESS,
    c.services.gateway.networks["control-internal"].ipv4_address,
  );
  equal(c.services.gateway.ports, [
    {
      mode: "ingress",
      host_ip: "127.0.0.1",
      target: 8443,
      published: "8443",
      protocol: "tcp",
    },
  ]);
  for (const [name, service] of Object.entries(c.services))
    if (name !== "gateway" && Object.hasOwn(service, "ports")) fail();
  const command = (name, expected) => equal(c.services[name].command, expected);
  command("control-db", ["postgres", "-c", "max_connections=100"]);
  command("matrix-db", ["postgres", "-c", "max_connections=100"]);
  command("migrate", ["sh", "-ec", 'p=$$(cat /run/secrets/control-owner-db-password); export MIGRATION_DATABASE_URL="postgresql://$${POSTGRES_USER:-control_owner}:$$p@control-db/$${POSTGRES_DB:-control}"; exec node dist/migrate.js']);
  command("api", ["sh", "/usr/local/bin/local-api-entrypoint.sh"]);
  command("synapse", ["run", "-c", "/data/homeserver.yaml", "-c", "/run/secrets/synapse-secrets.yaml"]);
  command("synapse-data-init", ["mkdir -p /data/media_store; chown -R 991:991 /data; chmod 0700 /data"]);
  command("mas", ["server", "--no-migrate"]);
  command("mas-ready", ['deadline=$$(($$(date +%s) + 60)); until wget -q -T 2 -O /dev/null http://mas:8081/health; do [ "$$(date +%s)" -lt "$$deadline" ] || exit 1; sleep 1; done']);
  command("mas-migrate", ["database", "migrate"]);
  command("gateway-ca-export", ["find /caddy-ca -mindepth 1 -maxdepth 1 -exec rm -rf {} +; install -m 0444 /data/caddy/pki/authorities/local/root.crt /caddy-ca/root.crt"]);
  equal(c.services["synapse-data-init"].entrypoint, ["sh", "-ec"]);
  equal(c.services["mas-ready"].entrypoint, ["sh", "-ec"]);
  equal(c.services["gateway-ca-export"].entrypoint, ["sh", "-ec"]);
  equal(c.services.mas.environment, { MAS_CONFIG: "/config/config.yaml:/run/secrets/mas-secrets.yaml", SSL_CERT_FILE: "/caddy-ca/root.crt" });
  equal(c.services["mas-migrate"].environment, { MAS_CONFIG: "/config/config.yaml:/run/secrets/mas-secrets.yaml" });
  const apiEnv = object(c.services.api.environment);
  keys(apiEnv, ["APP_ENV", "PORT", "CONTROL_PLANE_RUNTIME_ROLE", "CONTROL_PLANE_RETENTION_ROLE", "CONTROL_PLANE_REVOCATION_ROLE", "PUBLIC_BASE_URL", "FOUNDATION_BASE_URL", "PWA_ORIGIN", "OIDC_SECTOR", "OIDC_EPOCH", "OIDC_TRUSTED_PROXY_ADDRESS", "MAS_CLIENT_ID", "MAS_REDIRECT_URI", "OIDC_SIGNING_JWKS_PATH", "MAS_CLIENT_SECRET_PATH", "OIDC_COOKIE_KEYS_PATH", "OIDC_RESTORE_FLOOR_DIR", "OIDC_RESTORE_FLOOR_HEAD", "COOKIE_SECURE", "COOKIE_KEY", "SUBJECT_KEY_RING", "ENVELOPE_KEY_RING", "CHALLENGE_KEY_RING", "SESSION_BINDING_KEY_RING", "JTI_KEY_RING", "IDEMPOTENCY_KEY_RING", "REQUEST_FINGERPRINT_KEY_RING", "OIDC_ADAPTER_KEY_RING", "OIDC_INDEX_KEY_RING", "REVOCATION_EVIDENCE_KEY_RING", "ROOT_DIDS", "ROOT_PUBLIC_JWKS", "AUTHORITY_POLICY_VERSION", "POLICY_MAX_STALENESS_SECONDS"]);
  equal(apiEnv.CONTROL_PLANE_REVOCATION_ROLE, "control_revocation");
  equal(apiEnv.PUBLIC_BASE_URL, "https://chat.localhost:8443");
  equal(apiEnv.PWA_ORIGIN, "https://chat.localhost:8443");
  equal(apiEnv.OIDC_SECTOR, "https://auth.localhost:8443");
  equal(apiEnv.MAS_REDIRECT_URI, "https://auth.localhost:8443/upstream/callback/01J00000000000000000000000");
  equal(apiEnv.MAS_CLIENT_ID, "dsa-signal");
  equal(apiEnv.OIDC_SIGNING_JWKS_PATH, "/run/private-oidc/oidc-signing-jwks.json");
  equal(apiEnv.MAS_CLIENT_SECRET_PATH, "/run/private-oidc/mas-client-secret");
  equal(apiEnv.OIDC_COOKIE_KEYS_PATH, "/run/private-oidc/oidc-cookie-keys.json");
}
function flattened(route) {
  const out = [];
  const visit = (r, inherited) => {
    const current = r.match ? r : { ...r, match: inherited };
    out.push(current);
    for (const h of r.handle ?? [])
      if (h.handler === "subroute")
        for (const x of h.routes ?? []) visit(x, current.match);
  };
  visit(route);
  return out;
}
const paths = (r) => r.match?.[0]?.path;
const proxy = (r) =>
  r.handle?.find((h) => h.handler === "reverse_proxy")?.upstreams?.length === 1
    ? r.handle.find((h) => h.handler === "reverse_proxy").upstreams[0].dial
    : undefined;
function caddy(adapted) {
  const server = Object.values(
    object(object(object(adapted).apps).http).servers,
  );
  if (server.length !== 1) fail();
  const s = server[0];
  equal(s.listen, [":8443"]);
  const tls = object(object(adapted).apps).tls;
  equal(object(object(tls).automation).policies, [{
    subjects: ["matrix.localhost", "chat.localhost", "auth.localhost"],
    issuers: [{ module: "internal" }],
  }]);
  const hosts = {};
  for (const route of array(s.routes)) {
    const host = route.match?.[0]?.host;
    if (!Array.isArray(host) || host.length !== 1 || hosts[host[0]]) fail();
    hosts[host[0]] = route;
  }
  keys(hosts, ["chat.localhost", "auth.localhost", "matrix.localhost"]);
  const chat = flattened(hosts["chat.localhost"]);
  const api = chat.filter((r) => proxy(r) === "api:8080");
  if (
    api.length !== 1 ||
    !equal(paths(api[0]), [
      "/v1/*",
      "/oidc/*",
      "/health",
      "/.well-known/oauth-authorization-server/oidc",
    ])
  )
    fail();
  if (
    chat.some(
      (r) =>
        proxy(r) === "api:8080" &&
        paths(r)?.some((p) => p.includes("_matrix") || p === "*"),
    )
  )
    fail();
  const health = chat.filter((r) => paths(r)?.join() === "/_gateway/health");
  if (health.length !== 1) fail();
  equal(health[0].handle, [{ body: "ok", handler: "static_response", status_code: 200 }]);
  const options = chat.filter((r) =>
    paths(r)?.join() === "/.well-known/matrix/client" &&
    r.match?.[0]?.method &&
    r.handle?.some((h) => h.status_code === 204),
  );
  if (options.length !== 1) fail();
  equal(options[0].match, [{ method: ["OPTIONS"], path: ["/.well-known/matrix/client"] }]);
  const headers = (r) => r.handle?.filter((h) => h.handler === "headers").map((h) => h.response.set);
  const optionInner = options[0];
  equal(headers(optionInner), [{ "Access-Control-Allow-Origin": ["https://chat.localhost:8443"] }, { "Access-Control-Allow-Methods": ["GET, OPTIONS"] }, { Vary: ["Origin"] }]);
  equal(optionInner.handle.at(-1), { handler: "static_response", status_code: 204 });
  const wellKnown = chat.filter((r) =>
    paths(r)?.join() === "/.well-known/matrix/client" &&
    !r.match?.[0]?.method && r.handle?.some((h) => h.handler === "vars"),
  );
  if (wellKnown.length !== 1) fail();
  const wellKnownInner = chat.filter((r) => paths(r)?.join() === "/.well-known/matrix/client");
  const get = wellKnownInner.find((r) => r.handle?.some((h) => h.handler === "file_server"));
  if (!get) fail();
  equal(headers(wellKnownInner.find((r) => r.handle?.some((h) => h.handler === "vars"))), [{ "Access-Control-Allow-Origin": ["https://chat.localhost:8443"] }, { Vary: ["Origin"] }, { "Content-Type": ["application/json"] }]);
  if (!wellKnownInner.some((r) => r.handle?.some((h) => h.handler === "vars" && h.root === "/srv/well-known")) || !chat.some((r) => r.handle?.some((h) => h.handler === "rewrite" && h.uri === "/matrix-client.json"))) fail();
  const web = chat.filter((r) => proxy(r) === "web:80");
  if (web.length !== 1 || paths(web[0])) fail();
  if (
    chat.some(
      (r) =>
        paths(r)?.includes("/.well-known/openid-configuration") ||
        paths(r)?.includes("/jwks"),
    )
  )
    fail();
  const auth = flattened(hosts["auth.localhost"]);
  if (
    auth.filter((r) => proxy(r)).length !== 1 ||
    !auth.some((r) => proxy(r) === "mas:8080")
  )
    fail();
  const matrix = flattened(hosts["matrix.localhost"]);
  const masRoutes = matrix.filter((r) => proxy(r) === "mas:8080");
  const synapseRoutes = matrix.filter((r) => proxy(r) === "synapse:8008");
  if (masRoutes.length !== 1 || synapseRoutes.length !== 1) fail();
  equal(paths(masRoutes[0]), [
    "/_matrix/client/*/login",
    "/_matrix/client/*/logout",
    "/_matrix/client/*/refresh",
    "/_matrix/client/*/register",
  ]);
  equal(paths(synapseRoutes[0]), [
    "/_matrix/client/*",
    "/_matrix/media/*",
    "/_synapse/client/*",
  ]);
  if (
    !matrix.some(
      (r) =>
        paths(r)?.join() ===
        "/_matrix/federation/*,/_matrix/key/*,/_synapse/admin/*",
    ) ||
    !matrix.some(
      (r) =>
        !paths(r) &&
        r.handle?.some(
          (h) => h.handler === "static_response" && h.status_code === 404,
        ),
    )
  )
    fail();
  // The adapter is allowed to add subroute grouping, but every executable leaf
  // must be one of this policy's deliberately small handler vocabulary.
  const leaves = Object.values(hosts).flatMap(flattened).filter((r) =>
    !r.handle?.some((h) => h.handler === "subroute"),
  );
  const allowedHandlers = new Set([
    "reverse_proxy",
    "static_response",
    "headers",
    "vars",
    "rewrite",
    "file_server",
  ]);
  if (
    leaves.length !== 12 ||
    leaves.some(
      (r) =>
        !Array.isArray(r.handle) ||
        r.handle.some((h) => !allowedHandlers.has(h.handler)),
    )
  )
    fail();
  // No leaf may smuggle a header, rewrite, response, or proxy into an otherwise
  // valid route. The earlier exact route checks establish the permitted leaves.
  for (const r of leaves) {
    const types = r.handle.map((h) => h.handler);
    if (types.includes("reverse_proxy") && types.length !== 1) fail();
    if (types.includes("file_server") && !types.every((x) => ["vars", "headers", "rewrite", "file_server"].includes(x))) fail();
    if (types.includes("rewrite") && !types.every((x) => ["vars", "headers", "rewrite", "file_server"].includes(x))) fail();
    if (types.includes("static_response") && !types.every((x) => ["headers", "static_response"].includes(x))) fail();
  }
}
export function checkProvenance(value, locks) {
  keys(value, [
    "reviewedOn",
    "reviewer",
    "commitGate",
    "resolverRecovery",
    "images",
  ]);
  equal(value.reviewedOn, "2026-07-23");
  equal(value.reviewer, "Repository operator approved the PostgreSQL 17.10-bookworm and Caddy 2.11.4-alpine Docker Official Image exceptions via OpenCode session on 2026-07-21 and the Node 24.18.0-alpine3.24 and Nginx 1.29.8-alpine3.23 Docker Official Image exceptions via OpenCode session on 2026-07-23; this is not index-level Cosign verification.");
  equal(value.commitGate, "The PostgreSQL 17.10-bookworm and Caddy 2.11.4-alpine Docker Official Image exceptions approved on 2026-07-21, and the Node 24.18.0-alpine3.24 and Nginx 1.29.8-alpine3.23 exceptions approved on 2026-07-23, are approved; future digest updates require fresh operator approval and must not imply index-level Cosign verification.");
  const rows = array(value.images);
  if (rows.length !== imageKeys.length) fail();
  const expected = {
    SYNAPSE_IMAGE: { tag: "matrixdotorg/synapse:v1.156.0", sourceCommit: "be8d90043896fc274be31c1a46c56d7227716b7e", identityRegex: "^https://github\\.com/element-hq/synapse/\\.github/workflows/docker\\.yml@refs/tags/v1\\.156\\.0$" },
    MAS_IMAGE: { tag: "ghcr.io/element-hq/matrix-authentication-service:1.20.0", sourceCommit: "20a1f660c988e24fa1fe2911c65089c08f1247ed", identityRegex: "^https://github\\.com/element-hq/matrix-authentication-service/\\.github/workflows/build\\.yaml@refs/tags/v1\\.20\\.0$" },
    POSTGRES_IMAGE: { tag: "postgres:17.10-bookworm", sourceCommit: "4f9ced003ba58a854656ba150d146243d27ae3ac" },
    CADDY_IMAGE: { tag: "caddy:2.11.4-alpine", sourceCommit: "fba2853501d36e8a72f946ac8cb7ff64d07e48f2" },
    NODE_IMAGE: { tag: "node:24.18.0-alpine3.24", sourceCommit: "303e6c3be0be8010403376712d3018fb99809f86", mappingCommit: "465551ce7cb1975c276a45f1cea20f71909aaa0d" },
    NGINX_IMAGE: { tag: "nginx:1.29.8-alpine3.23", sourceCommit: "71081b25390771f6b1275ddf7c73c965f304493f", mappingCommit: "f486d54b6d0839d0687d470e5539be40a0ea3854" },
  };
  for (const row of rows) {
    keys(
      row,
      row.name === "SYNAPSE_IMAGE" || row.name === "MAS_IMAGE"
        ? [
            "name",
            "tag",
            "indexDigest",
            "children",
            "sourceCommit",
            "imageSourceCommit",
            "signature",
          ]
        : row.name === "NODE_IMAGE" || row.name === "NGINX_IMAGE"
          ? ["name", "tag", "indexDigest", "children", "imageSourceCommit", "officialImagesMappingCommit", "verification"]
          : [
            "name",
            "tag",
            "indexDigest",
            "children",
            "imageSourceCommit",
            "verification",
          ],
    );
    const digest = /^sha256:[0-9a-f]{64}$/;
    const commit = /^[0-9a-f]{40}$/;
    if (
      !imageKeys.includes(row.name) ||
      !row.tag ||
      row.indexDigest !== locks[row.name].split("@")[1] ||
      !digest.test(row.indexDigest) ||
      row.tag.split(":").slice(0, -1).join(":") !== locks[row.name].split("@")[0] ||
      !digest.test(row.children?.amd64) || !digest.test(row.children?.arm64) ||
      new Set([row.indexDigest, row.children.amd64, row.children.arm64]).size !== 3 ||
      !commit.test(row.imageSourceCommit) ||
      (row.sourceCommit && !commit.test(row.sourceCommit))
    )
      fail();
    equal(row.tag, expected[row.name].tag);
    equal(row.imageSourceCommit, expected[row.name].sourceCommit);
    if (expected[row.name].mappingCommit) equal(row.officialImagesMappingCommit, expected[row.name].mappingCommit);
    if (row.sourceCommit) equal(row.sourceCommit, expected[row.name].sourceCommit);
    if (row.signature) {
      keys(row.signature, ["tool", "command", "identityRegex", "issuer", "bundles"]);
      if (!Array.isArray(row.signature.bundles) || !row.signature.bundles.length) fail();
      equal(row.signature.issuer, "https://token.actions.githubusercontent.com");
      equal(row.signature.identityRegex, expected[row.name].identityRegex);
      for (const bundle of row.signature.bundles) {
        keys(bundle, ["bundleSha256", "certificateSha256", "logIndex", "integratedTime", "rootHash", "treeSize", "subjectDigest"]);
        if (!/^[0-9a-f]{64}$/.test(bundle.bundleSha256) || !/^[0-9a-f]{64}$/.test(bundle.certificateSha256) || bundle.subjectDigest !== row.indexDigest) fail();
      }
    } else {
      keys(row.verification, row.name === "CADDY_IMAGE" ? ["status", "approvalDate", "approver", "reason", "upstreamReleaseTagSsh"] : ["status", "approvalDate", "approver", "reason"]);
      equal(row.verification.status, "operator-approved-docker-official-image-exception");
      equal(row.verification.approvalDate, row.name === "NODE_IMAGE" || row.name === "NGINX_IMAGE" ? "2026-07-23" : "2026-07-21");
      equal(row.verification.approver, "repository operator via OpenCode session");
      equal(row.verification.reason, row.name === "CADDY_IMAGE" ? "No image-index Cosign evidence; GitHub release-tag SSH verification is upstream-release evidence only." : row.name === "NODE_IMAGE" || row.name === "NGINX_IMAGE" ? "No documented index-level Cosign signatures; exact Docker Official Image exception approved by repository operator." : "No documented index-level Cosign identity for this image.");
      if (row.name === "CADDY_IMAGE") {
        keys(row.verification.upstreamReleaseTagSsh, ["upstreamCommit", "result"]);
        if (!commit.test(row.verification.upstreamReleaseTagSsh.upstreamCommit)) fail();
        equal(row.verification.upstreamReleaseTagSsh.result, "GitHub release tag SSH signature verified");
      }
    }
  }
  if (new Set(rows.map((x) => x.name)).size !== imageKeys.length) fail();
  return true;
}
function dockerfileFromReferences(dockerfile) {
  const logicalLines = dockerfile.replace(/\\\r?\n/g, " ").split(/\r?\n/);
  return logicalLines.flatMap((line) => {
    const tokens = line.trim().split(/\s+/);
    if (tokens[0]?.toUpperCase() !== "FROM") return [];
    const reference = tokens.slice(1).find((token) => !token.startsWith("--"));
    return reference ? [reference] : [];
  });
}
export function checkBuildLockWiring({ backendDockerfile, webDockerfile, rootCompose }) {
  const equalFrom = (dockerfile, expected) => equal(dockerfileFromReferences(dockerfile), expected);
  equalFrom(backendDockerfile, ["${NODE_IMAGE}", "${NODE_IMAGE}"]);
  equalFrom(webDockerfile, ["${NODE_IMAGE}", "${NGINX_IMAGE}"]);
  if (!/^ARG NODE_IMAGE\nFROM \$\{NODE_IMAGE\} AS build/m.test(backendDockerfile) || !/ARG BUILD_MARKER\nLABEL org\.dsa-signal\.build-marker=\$BUILD_MARKER/.test(backendDockerfile)) fail();
  if (!/^ARG NODE_IMAGE\nARG NGINX_IMAGE\nFROM \$\{NODE_IMAGE\} AS build/m.test(webDockerfile) || !/FROM \$\{NGINX_IMAGE\}\nARG BUILD_MARKER\nLABEL org\.dsa-signal\.build-marker=\$BUILD_MARKER/.test(webDockerfile)) fail();
  const compose = parseYaml(rootCompose);
  equal(compose.services?.postgres?.image, "${POSTGRES_IMAGE:?use deploy/locks/images.env}");
  equal(compose.services?.api?.build?.args, { NODE_IMAGE: "${NODE_IMAGE:?use deploy/locks/images.env}", BUILD_MARKER: "${VITE_BUILD_MARKER:-development}" });
  equal(compose.services?.web?.build?.args, { NODE_IMAGE: "${NODE_IMAGE:?use deploy/locks/images.env}", NGINX_IMAGE: "${NGINX_IMAGE:?use deploy/locks/images.env}", BUILD_MARKER: "${VITE_BUILD_MARKER:-development}", VITE_BUILD_MARKER: "${VITE_BUILD_MARKER:-development}" });
  return true;
}
export function checkMatrixPolicy({
  synapse: s,
  mas: m,
  compose: c,
  locks,
  wellKnown,
  adaptedCaddy,
  provenance,
  provenanceBytes,
  synapseOverlay,
  masOverlay,
}) {
  validateLocks(locks);
  synapse(s);
  mas(m);
  compose(c, locks);
  equal(JSON.parse(wellKnown), {
    "m.homeserver": { base_url: "https://matrix.localhost:8443" },
  });
  caddy(adaptedCaddy);
  if (
    typeof provenanceBytes !== "string" ||
    createHash("sha256").update(provenanceBytes).digest("hex") !== provenanceDigest
  )
    fail();
  checkProvenance(provenance, locks);
  checkSecretOverlay("synapse", synapseOverlay);
  checkSecretOverlay("mas", masOverlay);
  return true;
}
export const run = (command, args, cwd, { timeoutMs = COMMAND_TIMEOUT_MS, maxBytes = COMMAND_MAX_BYTES, input } = {}) =>
  new Promise((ok, no) => {
    const grouped = process.platform === "linux";
    const p = spawn(command, args, { cwd, detached: grouped, stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    let out = ""; let err = ""; let settled = false; let limited = false;
    const finish = (fn, value) => { if (!settled) { settled = true; clearTimeout(timer); fn(value); } };
    const signal = (name) => {
      try { grouped ? process.kill(-p.pid, name) : p.kill(name); } catch { /* Already exited or process groups unsupported. */ }
    };
    const limit = () => {
      if (limited) return;
      limited = true;
      p.stdout.resume(); p.stderr.resume();
      signal("SIGTERM");
      setTimeout(() => signal("SIGKILL"), COMMAND_KILL_GRACE_MS).unref();
      finish(no, Error("command failed"));
    };
    p.stdout.on("data", (x) => {
      if (limited) return;
      out += x;
      if (Buffer.byteLength(out) > maxBytes) limit();
    });
    p.stderr.on("data", (x) => { if (!limited) { err += x; if (Buffer.byteLength(err) > maxBytes) limit(); } });
    const timer = setTimeout(limit, timeoutMs);
    if (input !== undefined) { p.stdin.on("error", limit); p.stdin.end(input); }
    p.on("error", (error) => finish(no, error));
    p.on("close", (code) =>
      !limited && code === 0 && Buffer.byteLength(out) <= maxBytes && Buffer.byteLength(err) <= maxBytes ? finish(ok, out) : finish(no, Error("command failed")),
    );
  });
export const caddyAdaptArgs = image => ["run", "--rm", "-i", "--entrypoint", "sh", image, "-c", "cat > /etc/caddy/Caddyfile && exec caddy adapt --validate --config /etc/caddy/Caddyfile --adapter caddyfile"];
export async function main({ root = process.cwd(), runner = run } = {}) {
  try {
    const read = (f) => readFile(resolve(root, f), "utf8");
    const locks = parseImageLocks(await read("deploy/locks/images.env"));
    const policyEnv = "deploy/local/policy.env";
    const [rendered, adapted, canaryAdapted, st, mt, wk, provenance, composeGolden, caddyGolden, canaryGolden, backendDockerfile, webDockerfile, rootCompose] = await Promise.all([
      runner(
        "docker",
        [
          "compose",
          "--env-file",
          "deploy/locks/images.env",
          "--env-file",
          policyEnv,
          "-f",
          "deploy/local/compose.yaml",
          "--profile",
          "full",
          "--profile",
          "negative",
          "config",
          "--format",
          "json",
        ],
        root,
      ),
      ...["gateway", "canary"].map(async (service) => runner(
        "docker",
        caddyAdaptArgs(locks.CADDY_IMAGE),
        root,
        { input: await read(`deploy/local/${service}/Caddyfile`) },
      )),
      read("deploy/local/synapse/homeserver.yaml"),
      read("deploy/local/mas/config.yaml"),
      read("deploy/local/well-known/matrix-client.json"),
      read("deploy/locks/images.provenance.json"),
      read("deploy/local/policy-fixtures/compose.rendered.json"),
      read("deploy/local/policy-fixtures/caddy.adapted.json"),
      read("deploy/local/policy-fixtures/canary.adapted.json"),
      read("backend/Dockerfile"),
      read("web/Dockerfile"),
      read("docker-compose.yml"),
    ]);
    const compose = JSON.parse(rendered);
    const goldenCompose = JSON.parse(composeGolden);
    const goldenCaddy = JSON.parse(caddyGolden);
    const goldenCanary = JSON.parse(canaryGolden);
    // A golden must already be canonical and normalized; updates require review.
    equal(composeGolden, canonicalJson(goldenCompose));
    equal(caddyGolden, canonicalJson(goldenCaddy));
    equal(canaryGolden, canonicalJson(goldenCanary));
    equal(normalizeCompose(goldenCompose, root), goldenCompose);
    equal(normalizeCaddy(goldenCaddy, root), goldenCaddy);
    equal(normalizeCaddy(goldenCanary, root), goldenCanary);
    equal(normalizeCompose(compose, root), goldenCompose);
    equal(normalizeCaddy(JSON.parse(adapted), root), goldenCaddy);
    equal(normalizeCaddy(JSON.parse(canaryAdapted), root), goldenCanary);
    const overlayPath = (name) => {
      const file = has(has(compose, "secrets"), name).file;
      if (typeof file !== "string" || !file.startsWith("/")) fail();
      return file;
    };
    // These are the resolved Compose bindings, not a process-env convention.
    const overlays = {
      synapse: parseYaml(await readFile(overlayPath("synapse-secrets.yaml"), "utf8")),
      mas: parseYaml(await readFile(overlayPath("mas-secrets.yaml"), "utf8")),
    };
    checkMatrixPolicy({
      synapse: parseYaml(st),
      mas: parseYaml(mt),
      compose,
      locks,
      wellKnown: wk,
      adaptedCaddy: JSON.parse(adapted),
      provenance: JSON.parse(provenance),
      provenanceBytes: provenance,
      synapseOverlay: overlays.synapse,
      masOverlay: overlays.mas,
    });
    checkBuildLockWiring({ backendDockerfile, webDockerfile, rootCompose });
    return 0;
  } catch {
    process.stderr.write("matrix policy check failed\n");
    return 1;
  }
}
if (
  process.argv[1] &&
  import.meta.url === new URL(process.argv[1], "file:").href
)
  process.exitCode = await main();
