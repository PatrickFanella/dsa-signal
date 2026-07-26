#!/bin/sh
set -eu
read_secret() {
  test -f "$1" && test ! -L "$1" || { echo "invalid secret file" >&2; exit 1; }
  value=$(cat "$1")
  test "$(wc -c < "$1" | tr -d ' ')" = 43 && printf '%s' "$value" | grep -Eq '^[A-Za-z0-9_-]{43}$' || { echo "invalid secret" >&2; exit 1; }
  printf '%s' "$value"
}
synapse=$(read_secret /run/secrets/synapse-db-password)
mas=$(read_secret /run/secrets/mas-db-password)
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -v synapse="$synapse" -v mas="$mas" <<'SQL'
CREATE ROLE synapse LOGIN PASSWORD :'synapse';
CREATE ROLE mas LOGIN PASSWORD :'mas';
CREATE DATABASE synapse OWNER synapse ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0;
CREATE DATABASE mas OWNER mas;
SQL
