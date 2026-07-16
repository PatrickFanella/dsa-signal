SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

.PHONY: help deps verify fmt lint test build compose-config open-pilot-check

help:
	@awk 'BEGIN {FS = ":.*##"; printf "Commands:\n"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps:
	pnpm install --frozen-lockfile

verify: deps fmt lint test build compose-config open-pilot-check ## Run all checks

fmt:
	pnpm run format

lint:
	pnpm run lint

test:
	pnpm run test

build:
	pnpm run build

compose-config:
	docker compose config --quiet

open-pilot-check:
	@test -f .gitea/ISSUE_TEMPLATE/open-pilot-task.yaml
	@grep -q 'Test Command' .gitea/ISSUE_TEMPLATE/open-pilot-task.yaml
