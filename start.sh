#!/bin/bash
# Combined entrypoint: vpngate manager (sing-box + cloudflared) +
# CC Switch proxy + disguise page + optional nezha (ported from
# railway-proxy-combined; Xray replaced by sing-box VLESS+WS inbounds).
set -e

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
    if [ -n "${RESI_GATEWAY:-}" ]; then
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
  wait "$MANAGER_PID" 2>/dev/null || true
  exit 0
}
trap _term TERM INT

# === 3. vpngate manager: owns $PORT, supervises sing-box + cloudflared ===
# Manager serves the disguise page itself at GET / (file already has the
# UUID/remark injected above), so the tunnel catch-all /* -> $PORT keeps
# the disguise at the domain root with no extra route.
export DISGUISE_PATH="/app/www/index.html"
echo "[init] starting railway_manager (owns \$PORT=$PORT)..."
python railway_manager.py &
MANAGER_PID=$!
sleep 1
if ! kill -0 $MANAGER_PID 2>/dev/null; then
  echo "[ERR] railway_manager exited immediately"
  exit 1
fi
echo "[debug] manager PID=$MANAGER_PID"

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
