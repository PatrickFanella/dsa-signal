# Security Policy

## Supported scope

dsa-signal is in development and has no supported release yet. The security boundary it aims for is described in [docs/reference/privacy-and-threat-contract.md](docs/reference/privacy-and-threat-contract.md).

## Reporting a vulnerability

Do not publish sensitive vulnerabilities in public issues.

Report privately through [GitHub private vulnerability reporting](https://github.com/subculture-collective/dsa-signal/security/advisories/new).

Include:

- affected repository and commit
- impact summary
- reproduction steps
- affected configuration or deployment path
- suggested mitigation, if known

## Secret handling

Never commit:

- `.env` or `.env.*` files, except `.env.example`
- API tokens or OAuth secrets
- SSH keys or deploy keys
- database dumps containing real data
- private certificates or signing keys
- webhook secrets

Use placeholders in docs and examples. Report only secret key names and presence, never secret values.

## Dependency and supply-chain hygiene

- The pnpm lockfile is committed and installs use `--frozen-lockfile`.
- Container images are pinned by digest in `deploy/locks/images.env`, with their review record in `deploy/locks/images.provenance.json`. A digest change needs operator approval.
- `matrix-js-sdk` and `oidc-provider` are pinned to exact versions that the tests check.
- Keep generated caches out of git.

## Open Pilot safety

Open Pilot tasks should include a deterministic `Test Command` and clear scope limits. Do not queue tasks that require secret access, production credentials, destructive data changes, or ambiguous deployment actions.

For risky work, require human review before adding `agent:queued`.
