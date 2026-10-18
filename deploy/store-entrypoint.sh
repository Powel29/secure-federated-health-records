#!/bin/sh
# Postgres for the federation store (ADR-0071), wrapping the image's own
# docker-entrypoint.sh.
#
# TLS_ENABLED off (the capture-plain profile): plain Postgres, unchanged.
# TLS_ENABLED on (capture-tls): serve TLS with the store certificate from
# `python -m wire.tls`, mounted at /tls/store, and refuse every non-TLS TCP
# connection in pg_hba, so a client that forgets TLS fails instead of
# talking in the clear. Clients verify the certificate (sslmode=verify-full,
# deploy/config.py). Same accepted values as deploy.config.env_flag.
set -eu

flag=$(printf '%s' "${TLS_ENABLED:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
case "$flag" in
  ""|0|false|no) exec docker-entrypoint.sh postgres "$@" ;;
  1|true|yes) ;;
  *) echo "TLS_ENABLED=$TLS_ENABLED is not one of 0/1/false/true/no/yes" >&2; exit 2 ;;
esac

if [ ! -f /tls/store/store.key ] || [ ! -f /tls/store/store.crt ]; then
  echo "TLS_ENABLED but /tls/store/store.{key,crt} missing; run python -m wire.tls" >&2
  exit 2
fi

# Postgres refuses a key readable by others; the bind mount's modes cannot
# be trusted (Windows hosts), so copy both into a private directory.
tls_dir=/run/store-tls
install -d -o postgres -g postgres -m 700 "$tls_dir"
install -o postgres -g postgres -m 600 /tls/store/store.key "$tls_dir/server.key"
install -o postgres -g postgres -m 644 /tls/store/store.crt "$tls_dir/server.crt"

auth="${POSTGRES_HOST_AUTH_METHOD:-scram-sha-256}"
cat > "$tls_dir/pg_hba.conf" <<EOF
local     all all     trust
hostssl   all all all $auth
hostnossl all all all reject
EOF
chown postgres:postgres "$tls_dir/pg_hba.conf"

exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_min_protocol_version=TLSv1.3 \
  -c "ssl_cert_file=$tls_dir/server.crt" \
  -c "ssl_key_file=$tls_dir/server.key" \
  -c "hba_file=$tls_dir/pg_hba.conf" \
  "$@"
