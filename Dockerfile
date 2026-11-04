# syntax=docker/dockerfile:1
# railway-vpngate-combined: VPNGate(via sing-box openvpn-client, no TUN)
# behind dual VLESS+WS inbounds, fronted by Cloudflare Tunnel.
#
# Processes (all supervised, see start.sh + railway_manager.py):
#   vpngate-edge        owns public $PORT; raw-proxies /ws-node + /ws-chain
#                       to sing-box, /ws-resi + admin UI/API to the manager
#   railway_manager.py  control plane: mux /healthz /ui /api + SOCKS5,
#                       sing-box (mixed 127.0.0.1:40000, vless 8080/8082),
#                       cloudflared (soft-skipped without TUNNEL_TOKEN);
#                       binds $PORT directly only when vpngate-edge is absent
#   cc-switch-server    CC Switch AI API proxy on 4096 (unchanged from
#                       railway-proxy-combined)
#   python http.server  static disguise page on 8081 (from ./www)
#   nezha-agent         optional, only with NEZHA_SERVER + NEZHA_KEY
#
# Ports:
#   $PORT (set PORT=3000 on Railway to avoid clashing with the fixed ones):
#                       vpngate-edge public listener (manager fallback:
#                       manager mux)
#   4096: CC Switch AI API Proxy
#   8080: sing-box VLESS+WS /ws-node  -> direct (Railway-local exit)
#   8081: disguise page
#   8082: sing-box VLESS+WS /ws-chain -> chain-socks -> VPNGate exit
#
# --- Go sidecar + edge build stage ------------------------------------------
FROM golang:1.27-alpine AS probe-build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath -ldflags="-s -w" -o /out/vpngate-probe ./cmd/vpngate-probe
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/vpngate-edge ./cmd/vpngate-edge

FROM python:3.11-slim

ARG SINGBOX_VERSION=1.15.0-alpha.12
ARG CLOUDFLARED_VERSION=2026.8.3

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates unzip \
    && curl -Ls "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz" \
        | tar xz -C /tmp \
    && mv /tmp/sing-box-*/sing-box /usr/local/bin/sing-box \
    && chmod +x /usr/local/bin/sing-box \
    && sing-box version \
    && curl -Ls -o /usr/local/bin/cloudflared "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-amd64" \
    && chmod +x /usr/local/bin/cloudflared \
    && cloudflared --version \
    && rm -rf /tmp/sing-box-* /var/lib/apt/lists/*

WORKDIR /app

COPY vpngate_to_singbox.py railway_manager.py probe_client.py ./
COPY scripts/ ./scripts/
COPY cc-switch-server /usr/local/bin/cc-switch-server
COPY www ./www
COPY start.sh ./start.sh
COPY --from=probe-build /out/vpngate-probe /usr/local/bin/vpngate-probe
COPY --from=probe-build /out/vpngate-edge /usr/local/bin/vpngate-edge

RUN sed -i 's/\r$//' /app/start.sh \
 && chmod +x /app/start.sh /usr/local/bin/cc-switch-server /usr/local/bin/vpngate-probe /usr/local/bin/vpngate-edge

EXPOSE 3000 4096 8080 8081 8082 8084

ENTRYPOINT ["/app/start.sh"]
