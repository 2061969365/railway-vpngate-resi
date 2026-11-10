#!/bin/bash
# Combined entrypoint: vpngate manager (sing-box + cloudflared) +
# CC Switch proxy + disguise page + optional nezha (ported from
# railway-proxy-combined; Xray replaced by sing-box VLESS+WS inbounds).
set -e

# Resolve one interpreter (R2-4-23).  The image always has python3; a source
# checkout or a different base image may only ship `python`.
if [ -z "${PYTHON:-}" ]; then
  PYTHON="$(command -v python3 || command -v python || true)"
fi
if [ -z "$PYTHON" ]; then
  echo "[ERR] no python interpreter found (set PYTHON=/path/to/python)" >&2
  exit 1
fi

is_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    0*) return 1 ;;
  esac
  [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -le 65535 ]
}

# === 0. Public port validation (R2-4-17) ===
# Railway defaults to 3000; every fixed internal listener (VLESS, disguise,
# CC Switch, mixed, resi, Clash, probe) must stay distinct from the public
# listener or the bind order decides which service dies.
PORT="${PORT:-3000}"
if ! is_port "$PORT"; then
  echo "[ERR] PORT must be an integer in 1..65535 without leading zeros: $PORT" >&2
  exit 1
fi
if [ "$((10#$PORT))" -lt 1024 ] && [ "$(id -u)" != "0" ]; then
  echo "[ERR] non-root image cannot bind privileged PORT $PORT; use >=1024 or a reverse proxy" >&2
  exit 1
fi
if [ "$PORT" != "3000" ]; then
  echo "[WARN] PORT=$PORT: the Cloudflare tunnel and TCP proxy rules in README point at 3000" >&2
fi
probe_port="${PROBE_LISTEN:-127.0.0.1:39001}"
probe_port="${probe_port##*:}"
for reserved_port in 8080 8081 8082 8084 4096 40000 \
  "${MIXED_PORT:-40000}" "${RESI_PORT:-8084}" \
  "${VLESS_DIRECT_PORT:-8080}" "${VLESS_CHAIN_PORT:-8082}" \
  "${CLASH_API_PORT:-9090}" "$probe_port"; do
  if [ "$PORT" = "$reserved_port" ]; then
    echo "[ERR] PORT=$PORT conflicts with an internal/reserved port; use 3000 or another free port" >&2
    exit 1
  fi
done

# Resolve the disguise-page paths before any Python/network work so a missing
# template fails fast (R2-4-06).  There is deliberately no fallback to
# index.html: replacing the template with a rendered page would freeze the
# previous UUID/paths on the next boot.
WWW_DIR="${WWW_DIR:-/app/www}"
if [ ! -d "$WWW_DIR" ]; then
  WWW_DIR="$(cd "$(dirname "$0")" && pwd)/www"
fi
INJECT_PY="$(cd "$(dirname "$0")" && pwd)/scripts/inject_page.py"
if [ ! -f "$INJECT_PY" ]; then
  INJECT_PY="/app/scripts/inject_page.py"
fi
TEMPLATE="$WWW_DIR/index.template.html"
if [ ! -f "$TEMPLATE" ]; then
  echo "[ERR] disguise page template missing: $TEMPLATE (expected www/index.template.html)" >&2
  exit 1
fi

# Child PIDs are initialised so signal handlers never touch an empty value.
MANAGER_PID=""
PROXY_PID=""
HTTP_PID=""
NEZHA_PID=""
# Loopback probe sidecar (optional; see section 2b below).
PROBE_PID=""
# Go edge proxy (optional; see section 2c below).
EDGE_PID=""
EDGE_PROXY="${EDGE_PROXY:-1}"
EDGE_METRICS_PORT="${EDGE_METRICS_PORT:-39002}"

safe_unzip() {
  # Validate every entry before extracting (R2-4-05/R2-5-11): reject absolute
  # paths, "..", Windows drive prefixes, and anything resolving outside the
  # destination.  Python's extractall alone does not reject zip-slip entries.
  "$PYTHON" - "$1" "$2" <<'PY'
import os
import sys
import zipfile
from pathlib import PurePosixPath

archive, target = sys.argv[1], os.path.abspath(sys.argv[2])
with zipfile.ZipFile(archive) as bundle:
    for info in bundle.infolist():
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)
        if not path.parts or path.is_absolute():
            raise SystemExit("unsafe zip entry: %r" % info.filename)
        if any(part in ("", "..") for part in path.parts):
            raise SystemExit("unsafe zip entry: %r" % info.filename)
        if ":" in path.parts[0]:
            raise SystemExit("unsafe zip entry: %r" % info.filename)
        resolved = os.path.abspath(os.path.join(target, *path.parts))
        if resolved != target and not resolved.startswith(target + os.sep):
            raise SystemExit("unsafe zip entry: %r" % info.filename)
    bundle.extractall(target)
PY
}

valid_nezha_scalar() {
  # grep -E works line by line: a value with an embedded newline can pass a
  # per-line charset regex.  Reject any whitespace (including \n/\r/\t) on the
  # whole value first; quotes/backslashes are excluded by the regex below.
  case "$1" in
    ''|*[[:space:]]*|*$'\r'*|*$'\n'*) return 1 ;;
  esac
  return 0
}

# === 1. VLESS UUID (one value for all VLESS inbounds) ===
# Unset -> random UUID; explicitly empty -> VLESS/rotation disabled.
if [ -z "${VLESS_UUID+x}" ]; then
  VLESS_UUID=$("$PYTHON" -c 'import uuid; print(uuid.uuid4())')
  echo "[init] VLESS_UUID unset: generated (fingerprint ${VLESS_UUID:0:8}...)"
elif [ -z "$VLESS_UUID" ]; then
  echo "[init] VLESS disabled (VLESS_UUID is explicitly empty)"
else
  echo "[init] VLESS UUID configured (fingerprint ${VLESS_UUID:0:8}...)"
fi
export VLESS_UUID
export VLESS_DIRECT_PATH="${VLESS_DIRECT_PATH:-/ws-node}"
export VLESS_CHAIN_PATH="${VLESS_CHAIN_PATH:-/ws-chain}"
export RESI_PATH="${RESI_PATH:-/ws-resi}"

# === 2. Dynamic IP / geo remark for the disguise page ===
valid_ip() {
  [ -n "$1" ] || return 1
  printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9A-Fa-f:.]+$' || return 1
  "$PYTHON" - "$1" <<'PY'
import ipaddress
import sys

try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
PY
}

echo "[init] probing egress IP..."
if REAL_IP=$(curl --fail --silent --show-error --max-time 5 --retry 1 \
    --proto '=https' https://ifconfig.me/ip 2>/dev/null); then
  REAL_IP=$(printf '%s' "$REAL_IP" | tr -d '\r\n')
else
  REAL_IP=""
fi
if ! valid_ip "$REAL_IP"; then
  REAL_IP="DynamicIP"
fi
if REAL_COUNTRY=$(curl --fail --silent --show-error --max-time 5 --retry 1 \
    --proto '=https' https://ipinfo.io/country 2>/dev/null); then
  REAL_COUNTRY=$(printf '%s' "$REAL_COUNTRY" | tr -d '\r\n' | tr '[:lower:]' '[:upper:]')
else
  REAL_COUNTRY=""
fi
if ! printf '%s' "$REAL_COUNTRY" | grep -Eq '^[A-Z]{2}$'; then
  REAL_COUNTRY="Cloud"
fi
export NODE_REMARK="${REAL_COUNTRY}_${REAL_IP}"
echo "[init] node remark: $NODE_REMARK"

# Render the disguise page from the read-only template on every boot.
if ! "$PYTHON" "$INJECT_PY" --template "$TEMPLATE" --output "$WWW_DIR/index.html"; then
  echo "[ERR] disguise page injection failed (template: $TEMPLATE)" >&2
  exit 1
fi
echo "[init] disguise page rendered (template: $TEMPLATE)"

_term() {
  echo "[shutdown] SIGTERM, stopping children..."
  for pid in "$MANAGER_PID" "$PROXY_PID" "$HTTP_PID" "$NEZHA_PID" "$PROBE_PID" "$EDGE_PID"; do
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "$MANAGER_PID" "$EDGE_PID" "$PROBE_PID"; do
    [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
  done
  exit 0
}
trap _term TERM INT

_cleanup() {
  # R2-4-22: any early `set -e` exit must not leave manager/proxy/httpd/nezha
  # orphans (the container reaps them at PID 1 exit, a local run does not).
  exit_code=$?
  for pid in "$MANAGER_PID" "$PROXY_PID" "$HTTP_PID" "$NEZHA_PID" "$PROBE_PID" "$EDGE_PID"; do
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null || true
  done
  for pid in "$MANAGER_PID" "$PROXY_PID" "$HTTP_PID" "$NEZHA_PID" "$PROBE_PID" "$EDGE_PID"; do
    [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
  done
  return "$exit_code"
}
trap _cleanup EXIT

# === 2b. vpngate-probe sidecar (optional, loopback only) ===
# Never fatal: the manager keeps working with its Python fallback when the
# binary is absent, disabled, or fails to start.
if [ "${PROBE_SERVICE:-1}" != "0" ] && [ -f /usr/local/bin/vpngate-probe ]; then
  export PROBE_LISTEN="${PROBE_LISTEN:-127.0.0.1:39001}"
  echo "[init] starting vpngate-probe on $PROBE_LISTEN..."
  /usr/local/bin/vpngate-probe > /tmp/probe.log 2>&1 &
  PROBE_PID=$!
  echo "[debug] vpngate-probe PID=$PROBE_PID"
  sleep 0.2 || true
  if ! kill -0 "$PROBE_PID" 2>/dev/null; then
    echo "[WARN] vpngate-probe exited immediately, continuing without it; log:"
    cat /tmp/probe.log 2>&1 || true
    PROBE_PID=""
  fi
else
  echo "[init] vpngate-probe disabled or not installed"
fi

# === 2c. Go edge proxy decision (optional) ===
# When the edge binary is present it owns the public $PORT; the manager binds
# a loopback admin port instead. Without it, boot behavior is unchanged.
EDGE_BIN="/usr/local/bin/vpngate-edge"
USE_EDGE=0
if [ "$EDGE_PROXY" != "0" ] && [ -x "$EDGE_BIN" ]; then
  USE_EDGE=1
fi
if [ "$USE_EDGE" = "1" ]; then
  probe_endpoint="${PROBE_LISTEN:-127.0.0.1:39001}"
  probe_port="${probe_endpoint##*:}"
  reserved_list="8080 8081 8082 8084 4096 40000 ${MIXED_PORT:-40000} ${RESI_PORT:-8084} ${VLESS_DIRECT_PORT:-8080} ${VLESS_CHAIN_PORT:-8082} ${CLASH_API_PORT:-9090} ${probe_port} ${PORT:-}"
  if ! is_port "$EDGE_METRICS_PORT"; then
    echo "[ERR] EDGE_METRICS_PORT must be an integer in 1..65535: $EDGE_METRICS_PORT" >&2
    exit 1
  fi
  metrics_ok=0
  while [ "$metrics_ok" = "0" ]; do
    metrics_collision=0
    for reserved_port in $reserved_list; do
      if [ "$EDGE_METRICS_PORT" = "$reserved_port" ]; then metrics_collision=1; fi
    done
    if [ "$metrics_collision" = "0" ]; then
      metrics_ok=1
    else
      if [ "$((10#$EDGE_METRICS_PORT))" -ge 65535 ]; then
        echo "[ERR] no free EDGE_METRICS_PORT at or below 65535" >&2
        exit 1
      fi
      EDGE_METRICS_PORT=$((10#$EDGE_METRICS_PORT + 1))
    fi
  done
  admin_port="${ADMIN_PORT:-3001}"
  if ! is_port "$admin_port"; then
    echo "[ERR] ADMIN_PORT must be an integer in 1..65535: $admin_port" >&2
    exit 1
  fi
  admin_ok=0
  while [ "$admin_ok" = "0" ]; do
    collision=0
    for reserved_port in $reserved_list "$EDGE_METRICS_PORT"; do
      if [ "$admin_port" = "$reserved_port" ]; then collision=1; fi
    done
    if [ "$collision" = "0" ]; then
      admin_ok=1
    else
      if [ "$((10#$admin_port))" -ge 65535 ]; then
        echo "[ERR] no free ADMIN_PORT at or below 65535" >&2
        exit 1
      fi
      admin_port=$((10#$admin_port + 1))
    fi
  done
  export ADMIN_PORT="$admin_port"
  export EDGE_METRICS_URL="http://127.0.0.1:${EDGE_METRICS_PORT}/v1/traffic"
  echo "[init] vpngate-edge enabled: public :$PORT -> admin 127.0.0.1:$ADMIN_PORT"
else
  echo "[init] vpngate-edge disabled or not installed"
  unset ADMIN_PORT EDGE_METRICS_URL
fi

# === 3. vpngate manager: admin mux in edge mode, or owns $PORT as fallback ===
# Manager serves the disguise page itself at GET / (file already has the
# UUID/remark injected above), so the tunnel catch-all /* -> $PORT keeps
# the disguise at the domain root with no extra route.
# MANAGER_IMPL is documented-only (default "py"): stages 3-6 of the Go
# manager are not implemented, so start.sh always runs the Python manager.
export DISGUISE_PATH="$WWW_DIR/index.html"
if [ "$USE_EDGE" = "1" ]; then
  echo "[init] starting railway_manager (admin 127.0.0.1:$ADMIN_PORT, edge owns \$PORT=$PORT)..."
else
  echo "[init] starting railway_manager (owns \$PORT=$PORT)..."
fi
"$PYTHON" railway_manager.py &
MANAGER_PID=$!
sleep 1
if ! kill -0 $MANAGER_PID 2>/dev/null; then
  echo "[ERR] railway_manager exited immediately"
  exit 1
fi
echo "[debug] manager PID=$MANAGER_PID"

# === 3b. Go edge proxy: public $PORT -> VLESS/admin backends ===
if [ "$USE_EDGE" = "1" ]; then
  export EDGE_LISTEN="0.0.0.0:${PORT}"
  export EDGE_ADMIN="http://127.0.0.1:${ADMIN_PORT}"
  export EDGE_NODE="127.0.0.1:${VLESS_DIRECT_PORT:-8080}"
  export EDGE_CHAIN="127.0.0.1:${VLESS_CHAIN_PORT:-8082}"
  export EDGE_METRICS_LISTEN="127.0.0.1:${EDGE_METRICS_PORT}"
  echo "[init] starting vpngate-edge on 0.0.0.0:$PORT..."
  "$EDGE_BIN" > /tmp/edge.log 2>&1 &
  EDGE_PID=$!
  echo "[debug] vpngate-edge PID=$EDGE_PID"
  sleep 0.3 || true
  if ! kill -0 "$EDGE_PID" 2>/dev/null; then
    echo "[ERR] vpngate-edge exited immediately, log:"
    cat /tmp/edge.log 2>&1 || true
    exit 1
  fi
fi

# === 4. Disguise page (8081) ===
echo "[init] starting disguise page (8081)..."
"$PYTHON" -m http.server 8081 --directory "$WWW_DIR" > /tmp/httpd.log 2>&1 &
HTTP_PID=$!
echo "[debug] httpd PID=$HTTP_PID"

# === 5. CC Switch native proxy engine (4096, unchanged) ===
# R2-4-07: run with a minimal environment so the un-audited binary does not
# inherit ADMIN_TOKEN/TUNNEL_TOKEN/NEZHA_KEY/RESI_PASS/PROXY_PASS.  Set
# CC_SWITCH_INHERIT_ENV=1 only as an escape hatch (documented in
# docs/supply-chain.md).
run_cc_switch() {
  if [ "${CC_SWITCH_INHERIT_ENV:-0}" = "1" ]; then
    PORT=4096 HOST=0.0.0.0 /usr/local/bin/cc-switch-server > /tmp/proxy.log 2>&1 &
  else
    extra_env=()
    if [ -n "${ZEN_TABLE_URL:-}" ]; then
      extra_env+=("ZEN_TABLE_URL=$ZEN_TABLE_URL")
    fi
    env -i "PATH=${PATH:-/usr/local/bin:/usr/bin:/bin}" HOME=/tmp TMPDIR=/tmp \
      "LANG=${LANG:-C.UTF-8}" PORT=4096 HOST=0.0.0.0 "${extra_env[@]}" \
      /usr/local/bin/cc-switch-server > /tmp/proxy.log 2>&1 &
  fi
  PROXY_PID=$!
}

echo "[init] starting CC Switch proxy (4096)..."
run_cc_switch
echo "[debug] CC Switch proxy PID=$PROXY_PID"

for i in $(seq 1 15); do
  sleep 2
  if curl -s --max-time 3 http://127.0.0.1:4096/health >/dev/null 2>&1; then
    echo "[debug] CC Switch proxy ready (attempt $i)"
    break
  fi
  if ! kill -0 $PROXY_PID 2>/dev/null; then
    echo "[ERR] proxy process exited, log:"
    cat /tmp/proxy.log 2>&1 || true
    break
  fi
  if [ $i -eq 15 ]; then
    echo "[ERR] proxy not ready after 15 attempts, last log:"
    cat /tmp/proxy.log 2>&1 || true
  fi
done

# === 6. Nezha probe (optional; needs all three settings) ===
NEZHA_PATH="/app/nezha-agent"
NEZHA_PID=""
if [ -n "${NEZHA_SERVER:-}" ] && [ -n "${NEZHA_KEY:-}" ] && [ -n "${NEZHA_AGENT_SHA256:-}" ]; then
  if [ ! -f "$NEZHA_PATH" ]; then
    echo "[nezha] fetching pinned agent..."
    if printf '%s' "$NEZHA_AGENT_SHA256" | grep -Eq '^[A-Fa-f0-9]{64}$' \
      && curl --fail --silent --show-error --location --max-time 60 --retry 2 \
           --proto '=https' -o /tmp/nezha-agent.zip \
           "${NEZHA_URL:-https://github.com/nezhahq/agent/releases/latest/download/nezha-agent_linux_amd64.zip}" \
      && printf '%s  %s\n' "$NEZHA_AGENT_SHA256" /tmp/nezha-agent.zip | sha256sum -c - \
      && safe_unzip /tmp/nezha-agent.zip /app \
      && chmod 700 "$NEZHA_PATH"; then
      echo "[nezha] agent verified"
    else
      echo "[nezha] download, SHA256 or archive validation failed, skipping"
      rm -f "$NEZHA_PATH"
    fi
    rm -f /tmp/nezha-agent.zip
  fi
  if [ -f "$NEZHA_PATH" ]; then
    # R2-4-05/R2-5-11: reject whitespace, quotes and newlines before writing
    # YAML, then quote the scalar values so YAML cannot re-type them either.
    nezha_server="${NEZHA_SERVER:-}"
    nezha_key="${NEZHA_KEY:-}"
    nezha_tls="${NEZHA_TLS:-true}"
    nezha_settings_ok=1
    if ! valid_nezha_scalar "$nezha_server" \
      || ! printf '%s' "$nezha_server" | grep -Eq '^(\[[0-9A-Fa-f:.]+\](:[0-9]{1,5})?|[A-Za-z0-9._~:/@-]{1,256})$'; then
      echo "[nezha] invalid NEZHA_SERVER charset, skipping" >&2
      nezha_settings_ok=0
    fi
    if ! valid_nezha_scalar "$nezha_key" \
      || ! printf '%s' "$nezha_key" | grep -Eq '^[A-Za-z0-9._~+/=-]{1,256}$'; then
      echo "[nezha] invalid NEZHA_KEY charset, skipping" >&2
      nezha_settings_ok=0
    fi
    case "$nezha_tls" in
      true|false) ;;
      *)
        echo "[nezha] invalid NEZHA_TLS (expected true|false), skipping" >&2
        nezha_settings_ok=0
        ;;
    esac
    if [ "$nezha_settings_ok" = "1" ]; then
      umask 077
      cat > /app/nezha-config.yml <<EOF
client_secret: "${nezha_key}"
server: "${nezha_server}"
tls: ${nezha_tls}
debug: false
disable_auto_update: true
disable_command_execute: true
report_delay: 3
EOF
      chmod 600 /app/nezha-config.yml
      "$NEZHA_PATH" -c /app/nezha-config.yml &
      NEZHA_PID=$!
      echo "[nezha] started"
    fi
  fi
else
  echo "[nezha] skipped (requires NEZHA_SERVER + NEZHA_KEY + NEZHA_AGENT_SHA256)"
fi

# === 7. Health monitor (15s): manager death exits (platform restarts us) ===
echo "[monitor] entering health loop..."
while true; do
  sleep 15
  if ! kill -0 $MANAGER_PID 2>/dev/null; then
    echo "[ERR] manager died, exiting to trigger restart"
    exit 1
  fi
  if [ -n "${EDGE_PID:-}" ] && ! kill -0 "$EDGE_PID" 2>/dev/null; then
    echo "[ERR] vpngate-edge died, exiting to trigger restart"
    cat /tmp/edge.log 2>&1 | tail -20 || true
    exit 1
  fi
  if ! kill -0 $PROXY_PID 2>/dev/null; then
    echo "[WARN] CC Switch proxy died, restarting once..."
    run_cc_switch
    sleep 5
    if ! kill -0 $PROXY_PID 2>/dev/null; then
      echo "[ERR] proxy restart failed, exiting to trigger restart"
      exit 1
    fi
  fi
  if ! kill -0 "$HTTP_PID" 2>/dev/null; then
    echo "[WARN] disguise page died, restarting..."
    "$PYTHON" -m http.server 8081 --directory "$WWW_DIR" > /tmp/httpd.log 2>&1 &
    HTTP_PID=$!
  elif ! curl -s --max-time 3 http://127.0.0.1:8081/ >/dev/null 2>&1; then
    echo "[WARN] disguise page not responding"
  fi
done
