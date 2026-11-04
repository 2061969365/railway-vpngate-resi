#!/bin/bash
# Combined entrypoint: vpngate manager (sing-box + cloudflared) +
# CC Switch proxy + disguise page + optional nezha (ported from
# railway-proxy-combined; Xray replaced by sing-box VLESS+WS inbounds).
set -e

# Loopback probe sidecar (optional; see section 2b below).
PROBE_PID=""
# Go edge proxy (optional; see section 2c below).
EDGE_PID=""
EDGE_PROXY="${EDGE_PROXY:-1}"
EDGE_METRICS_PORT="${EDGE_METRICS_PORT:-39002}"

# === 1. UUID (one value for both VLESS inbounds; env may override) ===
export UUID="${UUID:-a29738e5-bee1-c0fc-b484-ae7c49cbc828}"
export VLESS_UUID="${VLESS_UUID:-$UUID}"
echo "[init] VLESS UUID: $VLESS_UUID"

# === 2. Dynamic IP / geo remark for the disguise page ===
echo "[init] probing egress IP..."
REAL_IP=$(curl -s --max-time 3 --retry 1 ifconfig.me || true)
REAL_COUNTRY=$(curl -s --max-time 3 --retry 1 ipinfo.io/country || true)
[ -z "$REAL_IP" ] && REAL_IP="DynamicIP"
[ -z "$REAL_COUNTRY" ] && REAL_COUNTRY="Cloud"
NODE_REMARK="${REAL_COUNTRY}_${REAL_IP}"
echo "[init] node remark: $NODE_REMARK"

if grep -q "UUID_PLACEHOLDER" /app/www/index.html 2>/dev/null; then
  cp /app/www/index.html /tmp/index.html 2>/dev/null || true
  if [ -f /tmp/index.html ]; then
    esc_uuid=$(printf '%s' "$VLESS_UUID" | sed 's/[&/\]/\\&/g')
    esc_remark=$(printf '%s' "$NODE_REMARK" | sed 's/[&/\]/\\&/g')
    sed -i "s/UUID_PLACEHOLDER/$esc_uuid/g" /tmp/index.html
    sed -i "s/NODE_REMARK_PLACEHOLDER/$esc_remark/g" /tmp/index.html
    # Residential path: injected only when the gateway is configured, so an
    # unconfigured deployment never advertises a dead /ws-resi link.
    # Third path is on by default (VPNGate node rotation) whenever a VLESS
# UUID exists; only a VLESS-less deployment hides it.
if [ -n "${VLESS_UUID:-}" ]; then
      resi_path="${RESI_PATH:-/ws-resi}"
      esc_resi=$(printf '%s' "$resi_path" | sed 's/[&/\]/\\&/g')
      sed -i "s#RESI_PATH_PLACEHOLDER#${esc_resi}#g" /tmp/index.html
      echo "[init] residential path: $resi_path"
    fi
    cp /tmp/index.html /app/www/index.html
  fi
fi

_term() {
  echo "[shutdown] SIGTERM, stopping children..."
  kill -TERM "$MANAGER_PID" 2>/dev/null || true
  kill -TERM "$PROXY_PID" "$HTTP_PID" "$NEZHA_PID" 2>/dev/null || true
  if [ -n "${PROBE_PID:-}" ]; then
    kill -TERM "$PROBE_PID" 2>/dev/null || true
  fi
  if [ -n "${EDGE_PID:-}" ]; then
    kill -TERM "$EDGE_PID" 2>/dev/null || true
    wait "$EDGE_PID" 2>/dev/null || true
  fi
  wait "$MANAGER_PID" 2>/dev/null || true
  exit 0
}
trap _term TERM INT

_cleanup() {
  if [ -n "${PROBE_PID:-}" ]; then
    kill -TERM "$PROBE_PID" 2>/dev/null || true
    wait "$PROBE_PID" 2>/dev/null || true
  fi
  if [ -n "${EDGE_PID:-}" ]; then
    kill -TERM "$EDGE_PID" 2>/dev/null || true
    wait "$EDGE_PID" 2>/dev/null || true
  fi
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
  metrics_ok=0
  while [ "$metrics_ok" = "0" ]; do
    metrics_collision=0
    for reserved_port in $reserved_list; do
      if [ "$EDGE_METRICS_PORT" = "$reserved_port" ]; then metrics_collision=1; fi
    done
    if [ "$metrics_collision" = "0" ]; then
      metrics_ok=1
    else
      EDGE_METRICS_PORT=$((EDGE_METRICS_PORT + 1))
    fi
  done
  admin_port="${ADMIN_PORT:-3001}"
  admin_ok=0
  while [ "$admin_ok" = "0" ]; do
    collision=0
    for reserved_port in $reserved_list "$EDGE_METRICS_PORT"; do
      if [ "$admin_port" = "$reserved_port" ]; then collision=1; fi
    done
    if [ "$collision" = "0" ]; then
      admin_ok=1
    else
      admin_port=$((admin_port + 1))
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
export DISGUISE_PATH="/app/www/index.html"
if [ "$USE_EDGE" = "1" ]; then
  echo "[init] starting railway_manager (admin 127.0.0.1:$ADMIN_PORT, edge owns \$PORT=$PORT)..."
else
  echo "[init] starting railway_manager (owns \$PORT=$PORT)..."
fi
python railway_manager.py &
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
  export VLESS_DIRECT_PATH="${VLESS_DIRECT_PATH:-/ws-node}"
  export VLESS_CHAIN_PATH="${VLESS_CHAIN_PATH:-/ws-chain}"
  export RESI_PATH="${RESI_PATH:-/ws-resi}"
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
python3 -m http.server 8081 --directory /app/www > /tmp/httpd.log 2>&1 &
HTTP_PID=$!
echo "[debug] httpd PID=$HTTP_PID"

# === 5. CC Switch native proxy engine (4096, unchanged) ===
echo "[init] starting CC Switch proxy (4096)..."
PORT=4096 HOST=0.0.0.0 /usr/local/bin/cc-switch-server > /tmp/proxy.log 2>&1 &
PROXY_PID=$!
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

# === 6. Nezha probe (optional, unchanged) ===
NEZHA_PATH="/app/nezha-agent"
NEZHA_PID=""
if [ ! -f "$NEZHA_PATH" ]; then
  echo "[nezha] fetching agent..."
  curl -sL --max-time 60 --retry 2 -o /tmp/nezha-agent.zip "${NEZHA_URL:-https://github.com/nezhahq/agent/releases/latest/download/nezha-agent_linux_amd64.zip}" && \
    unzip -o /tmp/nezha-agent.zip -d /app/ && \
    chmod +x "$NEZHA_PATH" && \
    rm -f /tmp/nezha-agent.zip || echo "[nezha] download failed, skipping"
fi
if [ -f "$NEZHA_PATH" ] && [ -n "${NEZHA_SERVER:-}" ] && [ -n "${NEZHA_KEY:-}" ]; then
  cat > /app/nezha-config.yml <<EOF
client_secret: ${NEZHA_KEY}
server: ${NEZHA_SERVER}
tls: ${NEZHA_TLS:-true}
debug: false
disable_auto_update: true
disable_command_execute: true
report_delay: 3
EOF
  $NEZHA_PATH -c /app/nezha-config.yml &
  NEZHA_PID=$!
  echo "[nezha] started"
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
    PORT=4096 HOST=0.0.0.0 /usr/local/bin/cc-switch-server > /tmp/proxy.log 2>&1 &
    PROXY_PID=$!
    sleep 5
    if ! kill -0 $PROXY_PID 2>/dev/null; then
      echo "[ERR] proxy restart failed, exiting to trigger restart"
      exit 1
    fi
  fi
  if ! curl -s --max-time 3 http://127.0.0.1:8081/ >/dev/null 2>&1; then
    echo "[WARN] disguise page not responding"
  fi
done
