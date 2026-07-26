# Future host-local G2 trust contract

## Status and boundary

This is a future-enable contract for the dormant, non-authoritative G2 snapshot
helpers. `prepareG2Snapshot()` remains disabled as its first action. This
runbook grants no authority, capability, or PASS result.

## Required trusted host boundary

Before any future enablement, trust the host kernel and root-owned, fixed Git,
Node, pnpm, Docker, Docker Compose, and `uname` executables. Trust the selected
Docker daemon and context, system CA roots, and only approved public
registries. Those are host-local assumptions, not properties proven by the
snapshot helper.

Reject launch-time `NODE_OPTIONS`, `NODE_PATH`, `NODE_TLS_REJECT_UNAUTHORIZED`,
`SSL_CERT_FILE`, `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS`, `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, their lowercase
proxy variants, `NO_PROXY` variants, `DOCKER_HOST`, `DOCKER_CONTEXT`,
`DOCKER_CONFIG`, `BUILDX_CONFIG`, and `BUILDKIT_HOST`. Also reject npm/pnpm
configuration, cache, store, and home overrides: this includes every key matching
`/^npm_config(?:_|$)/i` and every key matching
`/^pnpm_(?:config|home|store|cache)(?:_|$)/i`, not only known spellings.
Before any side effect, a future fixed entrypoint must call
`assertSafeG2LaunchEnv(env)` to reject every explicitly present override,
including one with an empty value. Separately, `snapshotChildEnv` always strips
ambient overrides as defense in depth, passes only its small locale allowlist,
and supplies private HOME, temporary, XDG, npm/pnpm, and Docker configuration
locations. Those child-only private values are internal after assertion;
child-environment stripping does not replace entrypoint rejection.

## Trusted-child and cleanup scope

`runBounded` owns one POSIX process group for trusted fixed commands. It
preserves bounded output and timeout handling and sends TERM then KILL while
waiting for that group to disappear. Post-KILL group verification has a fixed
poll limit: if the group remains, it fails closed with
`G2_PROCESS_GROUP_CLEANUP_UNCONTAINED`, may leave resources behind, and blocks
any G2 claim rather than polling forever. It does **not** contain hostile children
that call `setsid`, double-fork, or enter namespaces, and it cannot recover from
host loss. Do not add `/proc`-based containment claims.

Catchable cleanup paths must be verified. SIGKILL or host loss cannot provide
that guarantee: before future enablement, startup must perform exact-marker
stale-root recovery for any abandoned private root. Until that recovery exists
and is reviewed, such a failure prevents a G2 claim.
