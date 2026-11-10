#!/usr/bin/env bash
# Smoke-test a published GHCR image: in-image imports/binaries, entrypoint UID,
# then boot the real container and exercise edge -> manager HTTP.
set -euo pipefail

IMAGE="${1:?usage: $0 IMAGE_REF}"
NAME="vpngate-image-smoke-$$"
TOKEN="${ADMIN_TOKEN:-image-smoke-token-0123456789abcdef}"
PROXY_PASS="image-smoke-pass-0123456789abcdef"
VLESS_UUID="11111111-2222-4333-8444-555555555555"

cleanup() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "== container logs (tail) =="
    docker logs "$NAME" 2>&1 | tail -80 || true
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== image: $IMAGE =="
docker image inspect "$IMAGE" >/dev/null

echo "== in-image layout, imports, script syntax =="
docker run --rm --entrypoint /bin/sh "$IMAGE" -c '
set -eu
for f in /app/railway_manager.py /app/vpngate_to_singbox.py /app/probe_client.py \
         /app/start.sh /app/entrypoint.sh /app/www/index.template.html \
         /usr/local/bin/vpngate-edge /usr/local/bin/vpngate-probe; do
  test -e "$f" || { echo "missing $f"; exit 1; }
done
python3 -c "import railway_manager, vpngate_to_singbox, probe_client"
bash -n /app/start.sh
sh -n /app/entrypoint.sh
echo "in-image checks OK"
'

uid="$(docker run --rm -e ENTRYPOINT_DRY_RUN=1 "$IMAGE")"
test "$uid" = "10001" || { echo "entrypoint uid=$uid (want 10001)"; exit 1; }
echo "entrypoint drops to uid 10001"

echo "== boot container (edge + manager, no VPNGate network) =="
docker run -d --name "$NAME" --publish 127.0.0.1:3000:3000 \
  -e PORT=3000 \
  -e ADMIN_TOKEN="$TOKEN" \
  -e PROXY_PASS="$PROXY_PASS" \
  -e VLESS_UUID="$VLESS_UUID" \
  -e PROBE_SERVICE=0 \
  -e EDGE_PROXY=1 \
  -e SNAPSHOT_URL=https://127.0.0.1:9/ \
  "$IMAGE" >/dev/null

ready=0
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:3000/ui || true)"
  if [ "$code" = "200" ]; then
    ready=1
    break
  fi
  if [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != "true" ]; then
    echo "container exited before /ui became ready"
    exit 1
  fi
  sleep 2
done
test "$ready" = "1" || { echo "/ui not ready after 120s"; exit 1; }
echo "/ui is reachable"

# No VPNGate snapshot is loaded on purpose (SNAPSHOT_URL points at a closed
# local port), so /healthz is expected to be 503 "not ready" rather than 200.
health_code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:3000/healthz)"
case "$health_code" in
  200) echo "healthz OK (nodes loaded)" ;;
  503) echo "healthz 503 as expected without VPNGate nodes" ;;
  *) echo "healthz returned $health_code"; exit 1 ;;
esac

echo "== HTTP/API checks through the Go edge =="
curl -fsS --max-time 5 -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:3000/api/status | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert "preferred_tag" in data and "endpoints" in data
print("status OK endpoints=%d" % len(data["endpoints"]))
'

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:3000/ui)"
test "$code" = "200" || { echo "/ui returned $code"; exit 1; }
echo "/ui OK"

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:3000/api/status)"
case "$code" in
  401|403) echo "unauthenticated /api/status rejected with $code" ;;
  *) echo "unauthenticated /api/status returned $code"; exit 1 ;;
esac

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:3000/ws-node)"
test "$code" = "400" || { echo "plain /ws-node returned $code (want 400)"; exit 1; }
echo "plain /ws-node rejected with 400 (edge WebSocket guard)"

echo "== process identity and edge presence =="
pid_uid="$(docker exec "$NAME" python3 -c '
import re
text = open("/proc/1/status", encoding="utf-8").read()
print(re.search(r"^Uid:\s+(\d+)", text, re.M).group(1))
')"
test "$pid_uid" = "10001" || { echo "PID 1 uid=$pid_uid (want 10001)"; exit 1; }
docker exec "$NAME" sh -c '
for p in /proc/[0-9]*; do
  tr "\0" " " < "$p/cmdline" 2>/dev/null | grep -q "vpngate-edge" && exit 0
done
exit 1
' || { echo "vpngate-edge process not found"; exit 1; }
echo "PID 1 runs as 10001; edge is running"

echo "IMAGE-SMOKE-OK"
