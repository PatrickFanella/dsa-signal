SHELL := /usr/bin/env bash
PNPM := npm exec --yes --package=pnpm@10.33.0 -- pnpm
.DEFAULT_GOAL := help

.PHONY: help deps verify fmt lint test security-contract matrix-policy matrix-negative matrix-oauth-browser task9-local g2-encrypted-direct-chat build api-image web-image compose-config open-pilot-check

help:
	@awk 'BEGIN {FS = ":.*##"; printf "Commands:\n"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps:
	$(PNPM) install --frozen-lockfile

verify: deps fmt lint test task9-local build api-image web-image compose-config matrix-policy open-pilot-check ## Run all checks

fmt:
	$(PNPM) run format

lint:
	$(PNPM) run lint

test:
	$(PNPM) run test

security-contract:
	$(PNPM) run security-contract

matrix-policy:
	$(PNPM) run matrix-policy

matrix-negative: ## Run the expensive live Matrix negative topology rehearsal
	$(PNPM) run matrix-negative

matrix-oauth-browser: ## Run the fixture-backed Task 8 browser gate
	$(PNPM) run matrix-oauth-browser

task9-local: ## Run local Task 9 evidence contract checks
	@node scripts/test-task9-local.mjs

g2-encrypted-direct-chat: ## Run external G2 prerequisite gate
	@node scripts/test-g2-encrypted-direct-chat.mjs

build: security-contract
	$(PNPM) run build

api-image: build
	docker build --build-arg "NODE_IMAGE=$$(node scripts/read-image-lock.mjs NODE_IMAGE)" --build-arg BUILD_MARKER=local-verify --tag dsa-signal-api-verify:local --file backend/Dockerfile .
	docker run --rm --entrypoint node dsa-signal-api-verify:local -e "if (process.getuid() !== 1000 || process.getgid() !== 1000) process.exit(1)"
	test "$$(docker image inspect --format '{{ index .Config.Labels "org.dsa-signal.build-marker" }}' dsa-signal-api-verify:local)" = local-verify
	docker image rm dsa-signal-api-verify:local

web-image: build ## Build and smoke-check the locked web image
	docker build --build-arg "NODE_IMAGE=$$(node scripts/read-image-lock.mjs NODE_IMAGE)" --build-arg "NGINX_IMAGE=$$(node scripts/read-image-lock.mjs NGINX_IMAGE)" --build-arg BUILD_MARKER=local-verify --build-arg VITE_BUILD_MARKER=local-verify --tag dsa-signal-web-verify:local --file web/Dockerfile .
	test "$$(docker image inspect --format '{{ index .Config.Labels "org.dsa-signal.build-marker" }}' dsa-signal-web-verify:local)" = local-verify
	docker run --rm --network none --entrypoint nginx dsa-signal-web-verify:local -t
	docker image rm dsa-signal-web-verify:local

compose-config:
	docker compose --env-file deploy/locks/images.env --env-file .env.example config --quiet

open-pilot-check:
	@test -f .gitea/ISSUE_TEMPLATE/open-pilot-task.yaml
	@grep -q 'Test Command' .gitea/ISSUE_TEMPLATE/open-pilot-task.yaml
