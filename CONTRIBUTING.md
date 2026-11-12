# Contributing

dsa-signal is a members-only encrypted chat app; [README.md](README.md) describes it. Keep changes small and reviewable.

## Development flow

1. Create or pick an issue before making non-trivial changes.
2. Create a branch from `main`.
3. Make the smallest change that satisfies the issue.
4. Run verification:

   ```bash
   make verify
   ```

5. Open a pull request on GitHub against `main`.
6. Link the issue with `Closes #N` when appropriate.

## Commit style

Prefer concise conventional-style subjects:

```text
feat: add encrypted direct chat
docs: update Open Pilot guidance
fix: correct make target detection
chore: refresh dependencies
```

## Open Pilot issues

Use `.gitea/ISSUE_TEMPLATE/open-pilot-task.yaml` for tasks that Open Pilot should implement.

Open Pilot requires:

- `ready-for-agent`
- `agent:queued`
- a deterministic `Test Command`

The template adds `ready-for-agent`; add `agent:queued` only after the issue is complete and ready for automation.

Good Open Pilot tasks are:

- one focused outcome
- clear context and constraints
- explicit out-of-scope notes
- verifiable from the repository root

## Verification commands

Use the narrowest deterministic command that proves the change.

Default full check:

```bash
make verify
```

Narrower examples:

```bash
pnpm --filter '*api' run test
pnpm --filter '*web' run test
node --test scripts/*.test.mjs
make compose-config
```
