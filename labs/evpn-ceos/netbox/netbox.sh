#!/usr/bin/env bash
# Lab NetBox: the source of truth for the EVPN fabric (replaces the hand-written
# inventory.json). Runs on 127.0.0.1:8000. The API token and secret key are generated on first
# use and kept in var/netbox.env (gitignored); `up` seeds NetBox from the lab files, so
# load_inventory(NetBox) returns what inventory.json says.
set -euo pipefail
cd "$(dirname "$0")"
ENV_FILE=../../../var/netbox.env
if [ ! -f "$ENV_FILE" ]; then
  mkdir -p "$(dirname "$ENV_FILE")"
  umask 077
  printf 'NETBOX_TOKEN=%s\nNETBOX_SECRET_KEY=%s\n' "$(openssl rand -hex 20)" \
         "$(openssl rand -hex 32)" > "$ENV_FILE"
fi
set -a; . "$ENV_FILE"; set +a
export NETBOX_URL=${NETBOX_URL:-http://127.0.0.1:8000}
dc() { docker compose -p aos-netbox -f docker-compose.yml "$@"; }
api_ok() { curl -fsS -H "Authorization: Token $NETBOX_TOKEN" -H "Accept: application/json" \
             "$NETBOX_URL/api/status/" >/dev/null 2>&1; }

case "${1:-}" in
  up)
    dc up -d
    echo -n "waiting for NetBox (first start runs DB migrations, ~2-4 min)"
    for i in $(seq 1 90); do
      if api_ok; then echo " ready"; break; fi
      echo -n "."; sleep 5
    done
    api_ok || { echo " FAILED: $NETBOX_URL/api/status/ not answering"; dc logs --tail 30 netbox; exit 1; }
    python3 seed.py
    echo "NetBox: $NETBOX_URL (admin/admin)  NETBOX_TOKEN=$NETBOX_TOKEN" ;;
  down)
    dc down -v ;;
  seed)
    python3 seed.py ;;
  status)
    dc ps
    if api_ok; then
      curl -fsS -H "Authorization: Token $NETBOX_TOKEN" "$NETBOX_URL/api/status/" | python3 -c \
        'import json,sys; s=json.load(sys.stdin); print("netbox", s["netbox-version"], "workers", s.get("rq-workers-running"))'
    else
      echo "NetBox API not answering at $NETBOX_URL"
    fi ;;
  *) echo "usage: $0 up|down|seed|status"; exit 2 ;;
esac
