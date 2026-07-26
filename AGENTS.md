# Agent Instructions

This repository is a TypeScript full-stack with Vite React TypeScript, Postgres,
and Docker template derived from `subculture-collective/project-template`. It
also has a separate digest-pinned local Matrix Compose topology under
`deploy/local`; its locks/provenance and policy contract must remain aligned.

## Priorities

1. Keep the template runnable and minimal.
2. Preserve Open Pilot issue and PR templates.
3. Keep generated caches, secrets, and local data out of git.
4. Update this file and `README.md` when stack conventions change.

## Verification

Run:

```bash
make verify
```

Run `make matrix-negative` when Matrix topology, routes, networks, or pinned
images change. It is an expensive live transport-isolation rehearsal and is not
part of the normal `make verify` path.

Use narrower commands only when an issue explicitly asks for a smaller check.
