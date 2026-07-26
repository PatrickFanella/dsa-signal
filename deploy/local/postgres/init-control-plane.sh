#!/bin/sh
set -eu
read_secret() {
  test -f "$1" && test ! -L "$1" || { echo "invalid secret file" >&2; exit 1; }
  value=$(cat "$1")
  test "$(wc -c < "$1" | tr -d ' ')" = 43 && printf '%s' "$value" | grep -Eq '^[A-Za-z0-9_-]{43}$' || { echo "invalid secret" >&2; exit 1; }
  printf '%s' "$value"
}
runtime=$(read_secret /run/secrets/control-runtime-db-password)
retention=$(read_secret /run/secrets/control-retention-db-password)
revocation=$(read_secret /run/secrets/control-revocation-db-password)
runtime_role=${CONTROL_PLANE_RUNTIME_ROLE:-control_runtime}
retention_role=${CONTROL_PLANE_RETENTION_ROLE:-control_retention}
revocation_role=${CONTROL_PLANE_REVOCATION_ROLE:-control_revocation}
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v runtime_role="$runtime_role" -v retention_role="$retention_role" -v revocation_role="$revocation_role" -v runtime="$runtime" -v retention="$retention" -v revocation="$revocation" <<'SQL'
CREATE ROLE :"runtime_role" LOGIN PASSWORD :'runtime';
CREATE ROLE :"retention_role" LOGIN PASSWORD :'retention';
CREATE ROLE :"revocation_role" LOGIN PASSWORD :'revocation';
SQL
