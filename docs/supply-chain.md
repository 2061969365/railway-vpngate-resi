# Supply chain inventory and risks

Updated: 2026-11-10. This file records every non-source artifact the image
embeds or downloads, how it is verified, and what still needs work.

## `cc-switch-server` (un-audited binary)

| Field | Value |
|---|---|
| Path in repo | `cc-switch-server` (7,852,192 bytes) |
| SHA256 | `787dafb951c6d53d2a3107aa530becb86ac23ae5e5d32ab74be4428aabaa53cb` |
| Docker check | `ARG CC_SWITCH_SHA256` + `sha256sum -c` (build fails on mismatch) |
| Go module | `github.com/2061969365/zen-direct` |
| Version | `v0.3.3-0.20261014160221-1aecc571af98+dirty` |
| VCS revision | `1aecc571af989737dccc99689a9fdbbb719ad35d` |
| Build state | `vcs.modified=true` (`+dirty`): the binary was built from a dirty tree |
| Build settings | `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`, `-trimpath` |

The repository has no source, `go.sum`, vendor tree, or build script for this
module, so the binary is **not reproducible and has not been audited**. Its
strings reference `opencode.ai/zen/v1`, `opencode.ai/inference/v1`,
`api.ipquery.io`, `http://ip-api.com/json` (plaintext), `ZEN_TABLE_URL`,
`genuine_sessions.txt`, `zen-direct-400s.log`, and session-minting logic. It
runs as the `app` user (not root) and, since R2-4-07/R2-5-05, `start.sh`
launches it through `env -i` with only `PATH`, `HOME=/tmp`, `TMPDIR=/tmp`,
`LANG`, `PORT=4096`, `HOST=0.0.0.0`, plus `ZEN_TABLE_URL` when the operator
sets it. `ADMIN_TOKEN`, `TUNNEL_TOKEN`, `NEZHA_KEY`, `RESI_PASS` and
`PROXY_PASS` are no longer inherited.

Escape hatch: `CC_SWITCH_INHERIT_ENV=1` restores the old full-environment
inheritance for debugging. Do not enable it in production; it re-exposes every
container secret to this un-audited binary.

The duplicate `zen-direct-linux-amd64` (same blob and SHA256, no build/start
reference) was deleted.

**Recommendation:** either drop the component, or pin and vendor the
`zen-direct` source at `1aecc571af989737dccc99689a9fdbbb719ad35d`, build it in
CI from source, publish SBOM/signature, and run it as a separate least-
privilege sidecar. Until then treat it as untrusted third-party code and do
not expose its port beyond the container.

## `sing-box`

| Field | Value |
|---|---|
| Version | `1.15.0-alpha.12` |
| Download | GitHub Releases tarball |
| SHA256 | `b107528ec7d989333d986573c097d840b9ef1afa9bb177f8eb03e0767f370514` |
| Docker check | `ARG SINGBOX_SHA256` + `sha256sum -c` |
| CI check | `unit-tests.yml` verifies the same SHA256 before running `sing-box check` |

This is an **alpha** release, kept because the rotate/self-heal tests depend on
its `on_demand` behaviour. Move to a stable 1.15.x once available and update
the ARG and this file together.

## `cloudflared`

| Field | Value |
|---|---|
| Version | `2026.8.3` |
| SHA256 | `f29324fe934d1e100617484c78deef803c4dc2cd351d645bbde42e96b4fccc5e` |
| Docker check | `ARG CLOUDFLARED_SHA256` + `sha256sum -c` |

## Base images

| Image | Digest (retrieved 2026-11-10) |
|---|---|
| `golang:1.27-alpine` | `sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18` |
| `python:3.11-slim` | `sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535` |

Both are multi-arch index digests. Refresh them deliberately (and record the
new digest here) rather than letting a mutable tag drift.

## Nezha agent

The agent is **not downloaded by default**. `start.sh` downloads it only when
all three variables are present:

- `NEZHA_SERVER`
- `NEZHA_KEY`
- `NEZHA_AGENT_SHA256` (64 hex characters)

The downloaded zip is verified with `sha256sum -c`; extraction goes through
Python `zipfile` with a per-entry check that rejects absolute paths, `..`,
Windows drive prefixes and any path resolving outside `/app` (zip-slip), then
the binary is installed mode `700`, and `nezha-config.yml` is written with
mode `600`.

Before writing YAML, `start.sh` validates the settings (R2-4-05/R2-5-11):

| Variable | Accepted values |
|---|---|
| `NEZHA_SERVER` | hostname/`host:port`/bracketed IPv6, no whitespace/quotes/newlines |
| `NEZHA_KEY` | `^[A-Za-z0-9._~+/=-]{1,256}$` |
| `NEZHA_TLS` | `true` or `false` |

Values are additionally emitted as quoted YAML scalars, so a value such as
`true` cannot be re-typed as a boolean. Invalid settings skip the agent with a
message instead of writing a config.

The default `NEZHA_URL` still points at the upstream `releases/latest` asset,
so pin a versioned URL and its SHA256 for repeatable deployments.

## GitHub Actions

Every `uses:` in `.github/workflows/*.yml` is pinned to a 40-character commit
SHA (version tags in comments). Update them through Dependabot/Renovate and
re-run `tests/test_workflow.py`.

## Remaining work

- Remove or vendor `cc-switch-server` and rebuild it from a pinned source.
- Replace the Nezha download/extract path with Python stdlib (`urllib` +
  `zipfile`) so the runtime image no longer needs `curl`/`unzip`; until then
  both remain installed and their apt package versions are not pinned
  (R2-4-11).  `curl` is also used by the cc-switch/disguise-page health checks.
- Move sing-box to a stable release.
- Generate SBOM/provenance for the Python image layer as well (the publish
  workflow now enables BuildKit `provenance` and `sbom`).
- Add image signing (cosign) and an admission policy that requires it.
- Put Cloudflare Access in front of `/ui` and `/api/*` as defence in depth.
