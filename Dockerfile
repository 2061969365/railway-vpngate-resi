# syntax=docker/dockerfile:1
# railway-vpngate-combined: VPNGate(via sing-box openvpn-client, no TUN)
# behind dual VLESS+WS inbounds, fronted by Cloudflare Tunnel.
#
# Processes (all supervised, see start.sh + railway_manager.py):
#   railway_manager.py  owns $PORT (mux /healthz /ui /api + SOCKS5),
#                       sing-box (mixed 127.0.0.1:40000, vless 8080/8082),
#                       cloudflared (soft-skipped without TUNNEL_TOKEN)
#   cc-switch-server    CC Switch AI API proxy on 4096 (unchanged from
#                       railway-proxy-combined)
#   python http.server  static disguise page on 8081 (from ./www)
#   nezha-agent         optional, only with NEZHA_SERVER + NEZHA_KEY
#
# Ports:
#   $PORT (set PORT=3000 on Railway to avoid clashing with the fixed ones):
#                       manager mux
#   4096: CC Switch AI API Proxy
#   8080: sing-box VLESS+WS /ws-node  -> direct (Railway-local exit)
#   8081: disguise page
#   8082: sing-box VLESS+WS /ws-chain -> chain-socks -> VPNGate exit
FROM python:3.11-slim

ARG SINGBOX_VERSION=1.14.0
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

COPY vpngate_to_singbox.py railway_manager.py ./
COPY scripts/ ./scripts/
COPY cc-switch-server /usr/local/bin/cc-switch-server
COPY www ./www
COPY start.sh ./start.sh

RUN sed -i 's/\r$//' /app/start.sh \
 && chmod +x /app/start.sh /usr/local/bin/cc-switch-server

EXPOSE 3000 4096 8080 8081 8082 8084

ENTRYPOINT ["/app/start.sh"]
