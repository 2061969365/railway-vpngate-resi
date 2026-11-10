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
#                       railway-proxy-combined; hash-pinned, see
#                       docs/supply-chain.md)
#   python http.server  static disguise page on 8081 (from ./www)
#   nezha-agent         optional; only with NEZHA_SERVER + NEZHA_KEY +
#                       NEZHA_AGENT_SHA256
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
FROM golang:1.27-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS probe-build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath -ldflags="-s -w" -o /out/vpngate-probe ./cmd/vpngate-probe
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/vpngate-edge ./cmd/vpngate-edge

FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

ARG SINGBOX_VERSION=1.15.0-alpha.12
ARG SINGBOX_SHA256=b107528ec7d989333d986573c097d840b9ef1afa9bb177f8eb03e0767f370514
ARG CLOUDFLARED_VERSION=2026.8.3
ARG CLOUDFLARED_SHA256=f29324fe934d1e100617484c78deef803c4dc2cd351d645bbde42e96b4fccc5e
ARG CC_SWITCH_SHA256=787dafb951c6d53d2a3107aa530becb86ac23ae5e5d32ab74be4428aabaa53cb

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates unzip \
    && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        -o /tmp/sing-box.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz" \
    && printf '%s  %s\n' "$SINGBOX_SHA256" /tmp/sing-box.tar.gz | sha256sum -c - \
    && tar -xzf /tmp/sing-box.tar.gz -C /tmp \
    && install -m 0755 /tmp/sing-box-*/sing-box /usr/local/bin/sing-box \
    && sing-box version \
    && curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        -o /tmp/cloudflared \
        "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-amd64" \
    && printf '%s  %s\n' "$CLOUDFLARED_SHA256" /tmp/cloudflared | sha256sum -c - \
    && install -m 0755 /tmp/cloudflared /usr/local/bin/cloudflared \
    && cloudflared --version \
    && rm -rf /tmp/sing-box* /tmp/cloudflared /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

WORKDIR /app
# WORKDIR creates /app as root; the non-root runtime user must own it because
# DATA_DIR defaults to "." (singbox-railway.json, nodes.json, state.json,
# settings.json, stderr log, and the optional Nezha agent all live here).
RUN chown app:app /app

COPY --chown=app:app vpngate_to_singbox.py railway_manager.py probe_client.py ./
COPY --chown=app:app scripts/inject_page.py ./scripts/inject_page.py
COPY cc-switch-server /usr/local/bin/cc-switch-server
RUN printf '%s  %s\n' "$CC_SWITCH_SHA256" /usr/local/bin/cc-switch-server | sha256sum -c - \
    && chmod 0755 /usr/local/bin/cc-switch-server

COPY --chown=app:app www ./www
COPY --chown=app:app start.sh entrypoint.sh ./
COPY --from=probe-build /out/vpngate-probe /usr/local/bin/vpngate-probe
COPY --from=probe-build /out/vpngate-edge /usr/local/bin/vpngate-edge

RUN sed -i 's/\r$//' /app/start.sh /app/entrypoint.sh \
    && chmod 0755 /app/start.sh /app/entrypoint.sh \
        /usr/local/bin/vpngate-probe /usr/local/bin/vpngate-edge

EXPOSE 3000 4096 8080 8081 8082 8084

# The container starts as root so entrypoint.sh can chown a freshly mounted
# Railway volume, then drops to UID 10001 before exec'ing start.sh.  No root
# process remains after boot (R2-4-16).
ENTRYPOINT ["/app/entrypoint.sh"]
