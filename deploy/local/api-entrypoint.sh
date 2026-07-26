#!/bin/sh
set -eu

private=/run/private-oidc
restore_floor=/run/private-oidc-restore-floor
mkdir -p "$private"
chown node:node "$private"
chmod 0700 "$private"
for name in oidc-signing-jwks.json mas-client-secret oidc-cookie-keys.json; do
  install -m 0600 -o node -g node "/run/secrets/$name" "$private/$name"
done
mkdir -p "$restore_floor"
cp -a /var/lib/dsa-signal/oidc-restore-floor/. "$restore_floor/"
find "$restore_floor" -type d -exec chown node:node {} \; -exec chmod 0700 {} \;
find "$restore_floor" -type f -exec chown node:node {} \; -exec chmod 0600 {} \;
export OIDC_RESTORE_FLOOR_DIR="$restore_floor"
password=$(cat /run/secrets/control-runtime-db-password)
export DATABASE_URL="postgresql://${CONTROL_PLANE_RUNTIME_ROLE:-control_runtime}:${password}@control-db/${POSTGRES_DB:-control}"
exec su node -s /bin/sh -c 'exec node dist/index.js'
