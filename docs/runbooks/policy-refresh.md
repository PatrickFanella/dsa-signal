# Policy refresh

Bootstrap and verify an authority-policy snapshot **before** admitting API traffic. From the deployed repository root, run `umask 077; pnpm --filter '*api' refresh-policy -- --file /etc/dsa-signal/policy.jws`; the command must emit no compact policy, key material, or Foundation diagnostics. Start or un-block traffic only after it succeeds.

The policy file is owned by the refresh operator, is a regular non-symlink file, and has mode `0600` (`chown dsa-policy-refresh:dsa-policy-refresh /etc/dsa-signal/policy.jws && chmod 0600 /etc/dsa-signal/policy.jws`). Keep it outside application logs, shell history, and command output.

Schedule that command every half staleness window (for example, every 30 minutes when `POLICY_MAX_STALENESS_SECONDS=3600`) under the refresh operator. Alert immediately on the first non-zero exit; Foundation resolution has a 5-second timeout. A failed refresh leaves the prior verified snapshot active only until its freshness deadline; after that deadline authorization fails closed.

To roll back, block traffic and obtain a newly root-signed replacement encoding the desired prior content with `issuedAt` strictly greater than the active snapshot. Install that replacement with the same owner and `0600` mode, run the command and verify success, then resume traffic. An old compact-policy replay cannot work. If the signer is unavailable, keep traffic blocked; do not bypass stale-policy fail-closed behavior.

Use a secure operator-controlled policy file and retain the configured root public keys and envelope keys needed to verify and decrypt the active snapshot. Never place policy compact values or Foundation diagnostics in ordinary logs. If refresh fails and the active snapshot becomes stale, authorization fails closed; operators must restore a verified fresh snapshot before traffic resumes.

Policy/mapping erasure lifecycle is deferred to the later privacy/operational-hardening task. Exact product deletion inputs do not yet exist, so this runbook does not prescribe unsafe deletes.
