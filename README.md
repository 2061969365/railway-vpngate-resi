# railway-vpngate-combined

VPNGate 免费节点（sing-box `openvpn-client`，免 TUN/免特权）+ 三路 VLESS+WS 入站
（直连 / VPNGate / 旋转住宅 SOCKS5），经 Cloudflare Tunnel 对外提供。
CC Switch / 伪装页 / 哪吒探针从 `railway-proxy-combined` 全量搬运
（Xray 由 sing-box 原生 VLESS 入站替代）。

## 三路出口（冻结方案）

| 入站 | 路径 | 出口 |
|---|---|---|
| `:8080` `/ws-node` | `vless-direct` → `direct` | Railway 本机出口（复刻 combined 行为） |
| `:8082` `/ws-chain` | `vless-chain` → `chain`/`auto` → openvpn endpoint | VPNGate 节点出口 |
| `:8084` `/ws-resi` | 管理器轮换监听 → 每个有效节点一条 loopback `resi-rot-i` 入站 | **轮换出口**：每条新连接换一个有效 VPNGate 节点（默认开启；配了 `RESI_GATEWAY` 则改为住宅网关） |

三个入站共用同一个 `UUID`（`VLESS_UUID`）。未设置 `VLESS_UUID` 时启动会随机生成，
日志只打印前 8 位指纹；**每次容器重启/重新部署都会换新 UUID**，已有客户端订阅会全部
失效，生产请显式设置固定 `VLESS_UUID`。显式设置 `VLESS_UUID=`（空值）表示禁用
VLESS 与节点轮换（伪装页会隐藏三张 VLESS 卡并显示“未启用”）。
`route.rules` 按 inbound tag 分流，三条路互不串扰。有 `VLESS_UUID` 时默认开启
「节点轮换」（面板第三张卡显示节点数与当前游标）。

公网侧默认由 Go `vpngate-edge` 接 `$PORT` 并分流到上述 loopback 入站；没有 edge 时由管理器
自己在 `$PORT` 分流（旧行为不变）。

## 架构：Python 控制面 + Go 数据面/探测边车

- `railway_manager.py` 是控制面：生成/重写 sing-box 配置、管理 `chain`/`auto` pin、节点
  轮换、Clash API 热切换与 `/api/status`，并继续提供 `/ui`、`/api`、`/healthz` 与伪装页
  （由 edge 反代）。edge 模式下它只绑 `127.0.0.1:ADMIN_PORT`，不再直接监听公网。
  `MANAGER_IMPL` 只是文档预留（默认/唯一实现是 `py`）：`start.sh` 始终运行
  `railway_manager.py`，镜像不构建 `vpngate-manager`，Go manager 的 stage 3-6
  未实现，设置 `MANAGER_IMPL=go` 不会生效，见
  [`docs/go-manager.md`](docs/go-manager.md)。
- `vpngate-edge`（`cmd/vpngate-edge`，纯标准库 Go，`CGO_ENABLED=0` 静态编译）是公网数据面：
  拥有 `$PORT`，把 `/ws-node`、`/ws-chain` 原样 TCP 转发到 `127.0.0.1:8080/8082`（并统计
  字节/连接），`/ws-resi` 原样转给 Python 管理端（由 Python 计数），其余请求反代给管理端。
- `vpngate-probe`（`cmd/vpngate-probe`，纯标准库 Go，`CGO_ENABLED=0` 静态编译）是**只监听
  回环**的测量边车，只读不写：`GET /v1/health`、`POST /v1/exit`、`POST /v1/delay`。它不选
  节点、不改配置、不启动 sing-box；完整契约见 [`docs/probe-sidecar.md`](docs/probe-sidecar.md)。
- `probe_client.py` 是它的 fail-open 客户端：任何传输错误、超时、401/503 或畸形响应都返回
  `None` 并短暂熔断，调用方随即回退到 `vpngate_to_singbox.measure_mixed_exit_ip()`
  （HTTP CONNECT + TLS，纯 Python，无子进程）。
- Docker 是两段式：`golang:1.27-alpine` 构建 `vpngate-edge` 与 `vpngate-probe`，两个静态
  二进制拷进 `python:3.11-slim` 运行镜像（见 `Dockerfile`）。

### Go edge（公网数据面）

**启动与回退**：`start.sh` 默认 `EDGE_PROXY=1`；二进制存在且未禁用时，edge 监听
`0.0.0.0:$PORT`，管理器改绑 `127.0.0.1:ADMIN_PORT`（默认 `3001`，自动跳过 `$PORT`、
8080/8081/8082/8084/4096/40000 与 metrics 端口）。二进制缺失或 `EDGE_PROXY=0` 时
`start.sh` 会 unset `ADMIN_PORT`/`EDGE_METRICS_URL`，管理器照旧绑 `$PORT` 并自己做路径
mux。edge 日志 `/tmp/edge.log`。

| 变量 | 默认 | 说明 |
|---|---|---|
| `EDGE_PROXY` | `1` | `0` 关闭 edge（回到 manager 直接监听 `$PORT`） |
| `ADMIN_PORT` | `3001` | edge 模式下 manager 的回环管理端口；`start.sh` 冲突时自动递增 |
| `EDGE_LISTEN` | `0.0.0.0:3000` | 公网监听；`start.sh` 实际设为 `0.0.0.0:$PORT` |
| `EDGE_ADMIN` | `http://127.0.0.1:3001` | 管理端 base URL（反代与 `/ws-resi` 的目标） |
| `EDGE_NODE` | `127.0.0.1:8080` | `/ws-node` 的原始 TCP 后端 |
| `EDGE_CHAIN` | `127.0.0.1:8082` | `/ws-chain` 的原始 TCP 后端 |
| `EDGE_METRICS_LISTEN` | `127.0.0.1:39002` | 指标监听，**必须回环**（启动校验） |
| `EDGE_METRICS_PORT` | `39002` | `start.sh` 只读；拼出 `http://127.0.0.1:<port>/v1/traffic` |
| `EDGE_METRICS_URL` | 由上一行生成 | manager 读取的指标地址；edge 启用时导出，关闭时 unset |
| `EDGE_IDLE_TIMEOUT_MS` | `120000` | 原始隧道每块读/写的空闲超时 |
| `EDGE_DIAL_TIMEOUT_MS` | `5000` | 连接后端的超时 |
| `VLESS_DIRECT_PATH` | `/ws-node` | 直连 VLESS WS 路径 |
| `VLESS_CHAIN_PATH` | `/ws-chain` | chain VLESS WS 路径 |
| `RESI_PATH` | `/ws-resi` | 第三路路径 |

**路由**：只有“无 body 的 GET”且路径**精确相等**才走原始 TCP；`/ws-node`、`/ws-chain` 还
要求 `VLESS_UUID` 非空。原始模式用 `http.Hijacker` 接管连接，重放原请求后由两个 goroutine
做双向 copy，并用 `CloseWrite` 半关闭；连接后端失败返回 502。其它请求（包括带 body 的同
路径请求）一律反代到 `EDGE_ADMIN`。

**流量口径**：edge 只统计 `/ws-node`、`/ws-chain` 的 `bytes_up`/`bytes_down`/`connections`/
`active`；`/ws-resi` 与测量流量仍由 Python 统计。`/api/status` 生成快照时以 0.3 秒超时拉
`EDGE_METRICS_URL`，把 edge 的 `bytes_up`/`bytes_down` 加进返回的 `traffic`；拉取失败静默
忽略（fail-open），管理页其它数据不受影响。

**为什么用 Go**：旧 mux 在 Python 里对每个客户端起一个线程（`_accept_loop` →
`_handle_client`）并在线程里搬字节，VLESS 热路径受 GIL/线程栈限制；edge 用 `net/http`
hijack + 每连接两个 goroutine，减少了 Python 线程模型的 header、半关闭与超时边界问题，
同时控制面（配置、pin、轮换、健康）仍完全留在 Python。

**edge 故障排查**：

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 日志 `vpngate-edge disabled or not installed` | `EDGE_PROXY=0`，或镜像里没有可执行的 `/usr/local/bin/vpngate-edge` | 走回退模式；重建镜像或去掉 `EDGE_PROXY=0` 后重启 |
| edge 启动即退出 | `$PORT` 被占、`EDGE_ADMIN` 非法、metrics 非回环 | 看 `/tmp/edge.log`；`start.sh` 会直接退出让平台重启 |
| 运行中 edge 死了 | 进程崩溃/端口异常 | 15 秒健康循环发现后让容器退出，平台重启即恢复 |
| 管理端口冲突 | 手动把 `ADMIN_PORT` 设成 `$PORT`、8080/8081/8082/8084/4096/40000 或 metrics 端口 | 不要手填，交给 `start.sh` 自动挑；直接给 manager 设冲突值会拒绝启动 |
| metrics 连不上 / 流量总数偏小 | edge 未运行，或 `EDGE_METRICS_URL` 未设/指错 | `curl 127.0.0.1:39002/v1/traffic` 自检；拉取失败是 fail-open |
| 回退模式 | `EDGE_PROXY=0` 或无 edge 二进制 | 预期行为：manager 绑 `0.0.0.0:$PORT` 并执行原来的路径 mux |

### 探测边车环境变量（全部有默认值，`PROBE_SERVICE=0` 可关闭）

| 变量 | 默认 | 说明 |
|---|---|---|
| `PROBE_SERVICE` | `1` | `0` 关闭（`start.sh` 只认 `0`；Python 客户端还接受 `false`/`no`/`off`） |
| `PROBE_LISTEN` | `127.0.0.1:39001` | 边车监听地址，**必须是回环**（启动时校验，非回环直接退出）；客户端也用它拼 base URL |
| `PROBE_TOKEN` | 空 | 设置后 `/v1/*` 都要 `Authorization: Bearer <token>` |
| `CLASH_URL` | `http://127.0.0.1:9090` | sing-box Clash API（边车只读） |
| `CLASH_SECRET` | 空 | Clash API secret |
| `PROBE_DEFAULT_TIMEOUT_MS` | `8000` | `/v1/exit`、`/v1/delay` 的默认超时预算（请求可覆盖，上限 120000ms） |
| `PROBE_CONCURRENCY` | `8` | `/v1/delay` 并发上限 |

边车日志写到 `/tmp/probe.log`；二进制缺失、`PROBE_SERVICE=0` 或启动失败都只告警，不阻塞
管理器（fail-open）。代码没有单独的 `PROBE_URL`：监听与客户端地址都读 `PROBE_LISTEN`。

## Railway 部署

1. 新建 Service，指向本仓库，Region 建议新加坡（离 VPNGate 亚洲节点近）。
2. Variables（必填）：
   - `PORT`（默认 3000 即正确值，不填即可；edge 模式下这是 edge 的公网端口，manager 改绑回环 `ADMIN_PORT`。填 8080/8081/8082/4096/混入端口会拒绝启动，非 3000 会告警，因隧道与 TCP 代理规则都指向 3000）
     - `PROXY_USER`（默认 `u`）/ `PROXY_PASS`（可选；不填则每次启动自动生成随机 `PROXY_PASS`，
       `PROXY_USER` 保持 `u`。走 VLESS+tunnel 时用不到；只有直连 SOCKS5 调试时才需要。
       显式填写的话 `PROXY_PASS` 须 ≥ 16 位，否则拒绝启动）
     - `ADMIN_TOKEN`（未设置时随机生成并在启动日志打印一次；显式设置为 `vpn`
       或长度 < 16 位会拒绝启动，只有 `ALLOW_INSECURE_ADMIN=1` 才放行。
       `/ui` 登录门输入该 token）
   - `TUNNEL_TOKEN`（Cloudflare tunnel token；缺失则 tunnel 软跳过，
     代理本身照常工作，`status["tunnel"] == "no-token"`）
     - 可选：`VLESS_UUID`（未设置则随机生成并打印前 8 位指纹；显式空值则禁用
       VLESS/轮换，直接 `python railway_manager.py` 会无 VLESS）、
       `NEZHA_SERVER`/`NEZHA_KEY`/`NEZHA_AGENT_SHA256`（三者齐全才下载并校验 agent；
       `NEZHA_SERVER`/`NEZHA_KEY`/`NEZHA_TLS` 写 YAML 前做字符集校验，换行/空白/引号会被拒绝）、
       `LIMIT`（默认 100，0=全量、上限 100）、`REAL_TOPK`（默认 30，真拨 TopK）、
       `DIAL_WORKERS`（默认 2，真测并发；1GB 内存够用，OOM 就往小调）、`FULL_PROBE_WORKERS`（默认 3，
       全量真测并发；和 DIAL_WORKERS 叠加受全局 dial gate 上限 10 约束）、`REFRESH_SECONDS`（默认 3600，每小时拉新快照并补测新/被踢节点）、`PROBE_WORKERS`（默认 15，握手并发）、`DIAL_TIMEOUT`（默认 15，真拨超时秒）、`AUTO_REPIN`（默认开，每小时自动重 pin 最优）、`AUTO_RESCUE`（默认开，手动 pin 挂了自动救最优）、`HEALTH_CHECK_INTERVAL`（默认 20s，无 probe sidecar 时的全量探活；有 sidecar 时改用 `FAST_HEALTH_INTERVAL` 默认 5s 快探 + `DEEP_HEALTH_INTERVAL` 默认 30s 真出口深探，固定节拍、检查超时不补跑；快探超时由 `FAST_DELAY_TIMEOUT_MS` 控制，默认 2500ms、钳制 500..5000）、`CHAIN_SETTLE_GRACE`（默认 20s，新 pin 预热宽限，钳制 5..120）、`OPENVPN_PERSIST_PINNED`（默认 1，preferred/backup 端点空闲也保持 OpenVPN 会话；0 恢复按需释放）、`MAX_MUX_CONNECTIONS`（默认 100）、`NEZHA_URL`（可选；自定义地址仍需配合 `NEZHA_AGENT_SHA256`）、`SNAPSHOT_URLS`（可选，逗号分隔的快照镜像，主源失败自动顺延）
     - 第三出口（默认开启、节点轮换、零配置；只有要接外部住宅网关才需要下面这些）：
       `RESI_GATEWAY`（`host:port`，固定 backconnect 网关，**永远只连这个地址**；填了就切到住宅模式）、
       `RESI_USER`、`RESI_PASS`、
       `RESI_SESSION_TTL`（默认 0 = 每次连接换 IP；>0 = 粘性窗口秒数）、
       `RESI_USER_TEMPLATE`（粘性模式必填，见下节）、`RESI_PORT`（默认 8084）、
       `RESI_PATH`（默认 `/ws-resi`）、`RESI_PROBE_INTERVAL`（默认 300 秒）
       以上运行参数也可在控制台「设置」页直接改（`GET/POST /api/settings`，带范围校验），保存进 `settings.json`，重启不丢失，会覆盖 env。住宅的网关地址与凭据**只能走 env**，不进 `settings.json`（该文件会被 `/api/settings` 原样返回）。
3. 健康检查：`/` 路径填 `/healthz`（部署时需 200，冷启动靠 last-good 秒回）。
4. 另加一个 TCP Proxy 指向内部 `3000` 端口（可选，给 SOCKS5 用）。
5. 持久化（强烈建议）：service → Volumes → Add Volume，加完即可，
   无需配任何变量，也**不需要手动改卷属主**。容器入口 `entrypoint.sh` 以 root
   启动，自动 `mkdir -p` 并对 `DATA_DIR`（`DATA_DIR` → `RAILWAY_VOLUME_MOUNT_PATH`
   → `/app`）执行 `chown -R app:app`，随后立即 setuid 到 UID 10001 运行
   `start.sh`，运行期没有 root 进程。代码用该目录存 sing-box 配置/节点存档/last-good。
   不挂卷的话每次重部署全量握手发现后冷启动（last-good 先顶住健康检查）。

> 合规警告：Railway AUP 明文禁止 proxy/anonymization 服务，
> 长期运行有封号风险，仅适合临时演示/调试。

## 从旧版本升级（破坏性变更）

从 `79de9fe` 之前的部署直接升级时，逐项确认（否则会出现“客户端全失效 / 管理端 401 /
探针不启动 / 容器重启循环”）：

1. **`VLESS_UUID`**：旧版本有固定默认 UUID；现在未设置时每次容器重启/重新部署都会生成
   新的随机 UUID，客户端订阅随之失效。升级前显式设置一个固定的 `VLESS_UUID`（合法
   UUID）；确实要关闭 VLESS 才设空值。
2. **`ADMIN_TOKEN`**：未设置时随机生成并只在启动日志打印一次；显式 `vpn` 或短于 16 位
   会拒绝启动。升级后设置 ≥16 位的随机 token，并更新 `/ui` 登录与所有 Bearer 调用。
3. **Nezha**：现在必须同时提供 `NEZHA_SERVER` + `NEZHA_KEY` + `NEZHA_AGENT_SHA256`
   才会下载/启动 agent；只有前两个变量时 agent 会被跳过。`NEZHA_TLS` 只接受
   `true|false`，三个值都会做字符集校验。
4. **非 root / 卷属主**：镜像不再以 `USER app` 启动，而是 root 入口 `entrypoint.sh`
   对 `DATA_DIR` 自动 `mkdir -p` + `chown -R app:app`，再 setuid 到 UID 10001 运行。
   Railway 卷不需要手动改属主；自定义 `DATA_DIR` 时确认该路径在容器内可写。
5. **`PORT`**：默认 3000。`8080/8081/8082/8084/4096/40000`（以及 `MIXED_PORT`/
   `RESI_PORT`/VLESS/Clash/probe 端口）会拒绝启动；其它非 3000 值会告警（Cloudflare
   tunnel 与 TCP Proxy 规则仍指向 3000）。小于 1024 的端口在非 root 下明确报错。
6. **订阅**：升级后在伪装页重新复制三路链接（若启用 VLESS），并确认
   `/ws-node`、`/ws-chain`、`/ws-resi` 的实际出口符合预期。

### 供应链与访问控制

- 镜像包含未审计的 `cc-switch-server`（模块 `github.com/2061969365/zen-direct`，
  `+dirty` 构建）。Dockerfile 只做 SHA256 固定，来源、哈希与风险见
  [`docs/supply-chain.md`](docs/supply-chain.md)；建议后续从源码重建或移除。
- 基础镜像固定到 digest；`sing-box`/`cloudflared` 下载带 `--fail` 和 SHA256
  校验；Nezha agent 仅在 `NEZHA_SERVER` + `NEZHA_KEY` + `NEZHA_AGENT_SHA256`
  三条件齐全时下载并校验。
- 容器入口以 root 启动，对 `DATA_DIR`（卷）执行 `mkdir -p` + `chown -R app:app`
  后立即 `setuid(10001)` 运行 `start.sh`；业务进程以非 root `app` 运行，只写
  `DATA_DIR` 与 `/tmp`，运行期没有常驻 root 进程。
- `cc-switch-server`（未审计）通过 `env -i` 以最小环境启动，只拿
  `PATH`/`HOME`/`TMPDIR`/`LANG`/`PORT`/`HOST`（可选 `ZEN_TABLE_URL`），不再继承
  `ADMIN_TOKEN`/`TUNNEL_TOKEN`/`NEZHA_KEY`/`RESI_PASS`/`PROXY_PASS`。
  `CC_SWITCH_INHERIT_ENV=1` 是仅用于排障的逃生开关，见
  [`docs/supply-chain.md`](docs/supply-chain.md)。
- 强烈建议在 Cloudflare 侧对 `/ui`、`/api/*` 加 Access 策略（或至少 WAF +
  速率限制），不要只依赖 `ADMIN_TOKEN`。

## Cloudflare Tunnel 路由（Dashboard 配置）

tunnel 只管把外网域名打到容器端口，token 方式运行，
ingress 规则在 Cloudflare Dashboard 的 tunnel 配置里加。

**最省事的配法（推荐）：一条兜底规则就够**

- `node.example.com` + Path `/*` → `http://localhost:3000`

`$PORT`（3000）由 Go edge 统一按路径分流三条 VLESS+WS：
`/ws-node` → 本机 `8080`、`/ws-chain` → 本机 `8082`、`/ws-resi` → 管理端的轮换监听器
（无 edge 时由管理器做同样的分流）。因此**新增第三路不需要动 ingress**，
`/ws-node`、`/ws-chain` 也不会因为忘了加规则而失效。

**按端口分流的老配法（也仍然支持，规则必须按顺序）**

- `node.example.com` + Path `/ws-node*` → `http://localhost:8080`
- 同一 hostname + Path `/ws-chain*` → `http://localhost:8082`
- 同一 hostname + Path `/ws-resi*` → `http://localhost:8084`
- 同一 hostname + Path `/*` → `http://localhost:3000`（兜底，必须排在上面几条**之后**）

两种配法可以混用：按端口分流的规则命中后直连 sing-box/轮换监听器，
没命中的路径落到 3000 再由 edge（回退模式下是管理器）反代给管理端。管理端剥离 query 后
路由：`/ui` 进控制台登录门，
`/api/*` 为数据接口（需 Bearer token），`/` 直接 serve 伪装页文件
（`start.sh` 每次启动都从只读模板 `www/index.template.html` 重新渲染
UUID/remark/路径后经 `DISGUISE_PATH` 接线，同容器重启不会残留旧值），
其余路径 404 或 401。

> 如果第三路连不上而前两路正常：先确认 ingress 里有 `/ws-resi` 的规则**或**一条
> `/*` → `http://localhost:3000` 的兜底规则。用
> `curl -i https://<域名>/ws-resi` 看返回码即可判断——`401`/`404` 且来自容器
> 说明请求已到容器（老镜像没有端口分流），`502`/`404` 且带 `cf-ray` 说明隧道规则没放行。

（同一 hostname 配两个 path 也可。）本地都是明文 `http://`，
TLS 由 Cloudflare 边缘终结。

客户端：

```
vless://<UUID>@node.example.com:443?security=tls&sni=node.example.com&type=ws&path=/ws-node#direct
vless://<UUID>@chain.example.com:443?security=tls&sni=chain.example.com&type=ws&path=/ws-chain#vpngate
vless://<UUID>@node.example.com:443?security=tls&sni=node.example.com&type=ws&path=/ws-resi#resi
```

验证：`/ws-node` 出口 IP == Railway 本机 IP；
`/ws-chain` 出口 IP == VPNGate 节点 IP（两者不同即分流正常）；
`/ws-resi` 出口 IP 属于住宅池，且连续新连接会变化（见下节）。

## 第三出口：节点轮换 / 住宅（默认开启）

第③路有两种后端，**优先住宅网关，未配置就是 VPNGate 节点轮换**：

- **轮换模式（默认，零配置）**：没填 `RESI_GATEWAY` 时，出口从当前所有**实测有效节点**
  （真拨通过、且没有被判死踢出池子）里
  按连接环形轮换——第 1 条连接走节点 1、第 2 条走节点 2……用完一圈回到第 1 个。
  出口 IP 就是该节点的 VPNGate IP（机房 IP，不是家宽）。
  首启只用 `REAL_TOPK`（默认 30）真拨一批好让服务先起来，**服务起来后自动在后台把剩余节点
  全部真拨一遍**，池子随之涨到全部可用节点（100 个快照通常 60~70 个）；之后每次刷新（默认
  每小时）只补测**新出现**和**已被踢出池子**的节点——正在服务的节点不会重拨，因为
  VPNGate 每节点只允许一个会话，重拨会把用户正在用的连接踢掉（见
  `docs/rotate-design.md` §12.9e D13）。服务中节点的健康由真实流量判定（连续失败即临时踢出）。
  没有「凑不够就随便拿没验证的节点顶上」的兜底：池子空时面板会写明
  `rotation pool empty (waiting for a verified node)`，等验证通过即自动恢复。
  某个节点连续 3 次「刚连上就被它掐断、还没传过数据」会被**临时踢出轮换**
  （2 分钟起、最长 15 分钟指数退避），到期自动回池，不需要重启或改配置；
  客户端自己先关（空闲回收、测活）不算失败；节点**吃下请求却 20 秒一个字节都不回**
  也算失败（sing-box 会在 endpoint 没就绪时 hold 住连接），连接当场被砍掉让客户端重试，
  不会像以前那样卡满 120 秒。
  所有节点都被踢出时会继续试最久没试的那个，
  不会出现「面板有节点、实际全不通」。
  **chain 正在用的那个节点不会进轮换池**（面板显示「N 个留给 chain」）：VPNGate 一个节点
  只允许一个 OpenVPN 会话，轮换如果也在上面建会话，会把 chain 挤掉——第三路正常、第二路
  静默失效，正是「一个死两个一起死」。
  这些健康决策只影响 mux 把连接拨到哪条 loopback 入站，**不会重写配置、不会重启 sing-box**，
  所以第三路节点抖动不会波及 `/ws-node`、`/ws-chain` 的现有连接。
  **chain 自己有主备两个预留节点**：rotate 模式下 `chain` 是一个 `urltest[主, 备]` 组，
  主节点的会话死掉后会在一个探测周期内自动切到备节点——不写配置、不重启；只有两个都死
  才由健康检查重 pin（日志 `chain rescue: … -> …`），而且重 pin 优先选"最近真的从它传过
  payload"的节点，而不是延迟数字最小但可能早已死掉的那个。所以不会再出现「`/ws-resi`
  可用、`/ws-chain` 挂了、只能手动切节点」的情况（见 `docs/rotate-design.md` §12.9f D14）。
- **住宅模式**：填了 `RESI_GATEWAY` + 账号密码时，改为连固定的 backconnect 网关，
  真实家宽 IP 由网关按连接分配，本服务永远不知道也不需要知道它。

两种模式的「旋转」都指**每次新 TCP 连接换一个出口**；住宅模式下粘性靠用户名里的 session。

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `RESI_GATEWAY` | 空 | `host:port`。为空则整条路径关闭 |
| `RESI_USER` / `RESI_PASS` | 空 | 网关凭据（必填，env only） |
| `RESI_SESSION_TTL` | `0` | `0` = 旋转；`>0` = 粘性窗口秒数（设置页也可改） |
| `RESI_USER_TEMPLATE` | `{user}` | 粘性模式用；占位符仅 `{user}` `{session}` `{ttl}` |
| `RESI_PORT` / `RESI_PATH` | `8084` / `/ws-resi` | 入站端口 / WS 路径 |
| `RESI_PROBE_INTERVAL` | `300` | 住宅出口自动探测间隔（秒） |
| `CLASH_API_PORT` | `9090` | sing-box Clash API 的**回环**端口，换 pin 走 `PUT /proxies/chain`（不写配置、不重启）。`0` = 关闭热切换，退回"改配置+重启" |

**粘性（Sticky）**：`RESI_SESSION_TTL>0` 且 `RESI_USER_TEMPLATE` 里包含 `{session}`
才会渲染 session 参数。格式必须按代理商官方文档填写，本仓库不猜格式：

```bash
RESI_USER_TEMPLATE='{user}-session-{session}-ttl-{ttl}'
```

不填模板（或模板里没有 `{session}`）会**降级为旋转并打印告警**——宁可不变，也不拼错。
Session id 在一个进程生命周期内固定；要换 session 调
`POST /api/resi_session`（会重建配置，连接会短暂中断）。

### 换 IP 的三个前提（不满足会看起来"旋转失效"）

1. **客户端必须关闭 multiplex/mux**。开了 mux 后所有流复用一条 WS 连接，
   网关只看到一次 SOCKS5 握手 → 出口 IP 全程不变。
2. **HTTP keep-alive 会让同一连接承载多个请求**，同连接内 IP 不变是正常的。
   要"每请求一个 IP"就每请求新建连接，或发 `Connection: close`。
3. **DNS 要交给代理**：客户端用 `socks5h` 语义（`curl --socks5-hostname`、
   `requests` 的 `socks5h://`、`aiohttp_socks` 的 `rdns=True`），不要在本地先解析。
   走 VLESS 时只要客户端传域名，sing-box 会以域名（ATYP=3）转给网关，DNS 在网关侧解析。

UDP 默认**关闭**（`network: "tcp"`）：住宅网关基本不支持 UDP ASSOCIATE。

### 客户端样例

curl（每次调用都是新连接）：

```bash
curl -s --socks5-hostname "$RESI_USER:$RESI_PASS@$RESI_GATEWAY" https://api.ipify.org; echo
```

Python requests：

```python
import requests
PROXY = f"socks5h://{user}:{password}@{host}:{port}"
with requests.Session() as s:          # 每次新 Session，避免连接复用
    r = s.get("https://api.ipify.org", proxies={"http": PROXY, "https": PROXY},
              headers={"Connection": "close"}, timeout=(10, 20))
    print(r.text)
```

httpx / aiohttp：

```python
import httpx
with httpx.Client(proxy=PROXY, timeout=httpx.Timeout(20, connect=10)) as c:
    print(c.get("https://api.ipify.org").text)

from aiohttp_socks import ProxyConnector
conn = ProxyConnector.from_url(PROXY, rdns=True)   # rdns=True 等价 socks5h
```

sing-box（客户端侧独立使用）：

```json
{"type": "socks", "tag": "resi", "server": "gw.example.com", "server_port": 1080,
 "version": "5", "username": "USER", "password": "PASS", "network": "tcp"}
```

Clash / Mihomo：

```yaml
proxies:
  - {name: resi-rot, type: socks5, server: gw.example.com, port: 1080,
     username: USER, password: PASS, udp: false}
```

### 验证 IP 是否变化

```bash
# 直连网关：5 次独立 curl = 5 条新连接
for i in 1 2 3 4 5; do
  curl -s --socks5-hostname "$RESI_USER:$RESI_PASS@$RESI_GATEWAY" https://api.ipify.org; echo
done | sort -u | wc -l      # 旋转模式期望 >= 2；粘性模式期望 1

# 经本项目（容器内 / 本机，走线上同一条 sing-box 出站）
for i in 1 2 3; do
  curl -s --socks5-hostname 127.0.0.1:40001 https://api.ipify.org; echo
done
```

控制台：`POST /api/resi_probe {"count":3}`（需 Bearer），返回的
`status.resi.last_probe` 含 `{ips, distinct, rotating}`；`/ui` 的「住宅出口」卡片
会显示 IP 序列与「轮换正常 / 未轮换」判定。判定标准：旋转模式 `distinct >= 2`
（住宅池可能连续命中同一节点，不苛求 100% 不同），粘性模式同一 session 下 `distinct == 1`。

回滚：删掉 `RESI_GATEWAY` 重启即可，第三条路径及其入站自动消失，另两条不受影响。


## 本地试运行

```bash
docker build -t combined:test .
docker run -d --name combined -p 3000:3000 -p 8080:8080 -p 8082:8082 -p 8084:8084 \
  -e PORT=3000 -e PROXY_USER=u -e PROXY_PASS=0123456789abcdef \
  -e ADMIN_TOKEN=local-admin-token-0123456789 \
  -e LIMIT=12 -e REAL_TOPK=2 \
  combined:test
curl http://127.0.0.1:3000/healthz   # ok
```

默认走 edge（3000 → 回环 admin）。要验证旧的无 edge 回退路径，在 `docker run` 里加
`-e EDGE_PROXY=0`，此时管理器直接绑 `$PORT`。

要一起试住宅出口，再加：

```bash
  -e RESI_GATEWAY=gw.example.com:1080 -e RESI_USER=USER -e RESI_PASS=PASS
```

管理页：`http://127.0.0.1:3000/ui`（粘贴 ADMIN_TOKEN）。节点列表显示出口 IP（`tag` 只留在 API 参数里）；搜索框＋范围下拉＋排序同一行；右上可切 Google 白浅色主题；底部显示真机 CPU 型号与实时占用（`GET /api/status` 的 `cpu{model,cores,pct}`、`memory.pct`，Linux 下读 `/proc`，取不到为 `None`）。
全量真测：管理页按钮或 `POST /api/full_probe`（需 `Authorization: Bearer`）。每次刷新成功（开机/每小时/手动）都会自动在后台真测，按握手延迟从小到大 5 并发拨号，超时 20 秒；轮换模式下只拨"当前不在服务中"的节点（新节点、被踢出池子的节点、预留之外未被验证的节点），绝不重拨正在服务的节点和 chain 的主/备节点（重拨会抢走它唯一的 VPNGate 会话）。自动轨道每轮跑完都重 pin 到实测最低（主）＋次低（保底），chain 出 `[best, second, auto]`，相同不重启；手动切换的不覆盖，手动挂了（连续 3 次握手失败）自动救到实测最优并回到自动轨道。状态条节点 title 显示主备。
单节点测速：节点列表每行“测速”按钮，或 `POST /api/probe {"tag":"vpngate-N"}`；
测通的节点自动可切换（全部存活节点本就在 sing-box 配置里，无需重建）。切换即切即换，成功后总览出现 15 秒「撤销换回」按钮（键盘可达，过期焦点自动回到当前节点）；成功的操作只在行内确认，失败才右下角弹窗。表头按钮可键盘排序，状态条圆点三态（绿=已验证新鲜/黄=未验证或数据旧/红=刷新失败），token 失效自动回登录页，全量真测可中途取消并显示中文进度＋预计剩余时间。日志支持搜索＋自动滚动开关；订阅行标注直连/经 VPN 用途，切换失败提示取后端 detail；统计卡自适应列、流量带单位、时长人性化显示，移动端保留导航并冻结首末列。

## 链路健康：真实出口验证与 pin_health

**验证方式**：对正在服务的 pin/chain 的出口判定，一律走**正在服务的 mixed inbound**
（`127.0.0.1:40000`，HTTP CONNECT + TLS + 出口 IP 回显），优先用边车，边车不可用则用
Python 回退。sing-box 运行时**绝不再起临时客户端去拨第二个会话**——VPNGate 每节点只允许
一个会话（`duplicate-cn`），第二个会踢掉正在服务的那条。没有验证器、或 mixed 正在重启时
结果是 **unknown，不是死亡**，不会触发救援。

`status.pin_health`（`GET /api/status`）：

| 字段 | 含义 |
|---|---|
| `state` | `ok` / `degraded` / `dead` / `unknown` / `unpinned` |
| `fail_streak` | 握手连败与隧道连败中的较大值 |
| `checked_at` | 最后一次健康判定时间 |
| `exit_ip` / `error` | 最近一次真实出口 IP / 错误 |
| `chain_switch` | `{mode, ready, switches}`，热切换通道状态 |

`status.endpoints[]` 的验证字段：`alive`、`exit_ip`、`verified_at`、`verify_ms`、
`verify_error`、`verify_fresh`（`VERIFY_STALE_AFTER_SEC=600` 秒内算新鲜）。

**阈值与救援**：

- 握手连续 **3** 次失败（`PINNED_FAIL_THRESHOLD=3`）才把 pin 判死；隧道端到端探针连续
  **2** 次失败（`CHAIN_FAIL_THRESHOLD=2`）才救援；新 pin 有 20 秒
  （`CHAIN_SETTLE_GRACE`，默认 20、钳制 5..120）预热宽限，宽限内失败不判死。
- 救援只切到**当下真实出口验证通过**的候选（最多试 6 个、60 秒预算）；失败候选进
  900 秒死记忆，连续救援会沿池子往下走。没有候选通过时**保留原 pin**、标 `degraded`，
  并触发后台刷新——绝不拿没验证的节点顶上。
- 候选预检（有 sidecar 时）：救援前先对最多 6 个候选做一次批量 delay；只有明确返回
  `alive=false` 的候选才跳过，`unknown`/缺失/无 sidecar 仍照常尝试。全部候选都明确
  delay-dead 时保留原 pin、触发后台刷新，不写配置、不记死记忆——delay 失败本身从不判死。
- 健康循环是固定节拍：有 sidecar 时每 5 秒 fast tick、每 30 秒 deep 真出口；某次检查
  超时不会补跑，只从当前时刻重新计时。实际发现时间仍受 delay/exit 探针超时约束
  （快探默认 2500ms，`FAST_DELAY_TIMEOUT_MS` 可调 500..5000）。
- `OPENVPN_PERSIST_PINNED=1`（默认）让 preferred/backup 端点带 `on_demand=false`，
  空闲时也保持各自的 OpenVPN 会话；其余节点仍是 `on_demand=true`。设 `0` 则全部按需释放。
- 握手已死但链路仍能真实出口：视为 `ok`（热切换已经把 selector 移走），不重写配置。
- 手动 pin 在刷新/自动测速后保持不变；`AUTO_REPIN` 只重 pin 自动轨道。
- 轮换模式（未配 `RESI_GATEWAY`）在所有候选握手都死时**保留死 pin**并标 `dead`
  （丢掉 pin 会让 urltest 和轮换抢同一会话，变成“一个死两个一起死”）；住宅网关模式
  （配了 `RESI_GATEWAY`）则在连续 3 次握手失败后解 pin 回 `auto`（`unpinned`）。

### 故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 日志 `vpngate-probe disabled or not installed` / 边车缺失 | `PROBE_SERVICE=0`、镜像里没二进制或启动即崩 | 管理器会回退 Python 验证；看 `/tmp/probe.log`，确认 `PROBE_LISTEN` 是回环且端口空闲 |
| `pin_health=degraded` | 握手/隧道连败未到阈值、serving 短暂不可达、或无候选通过验证 | 有 sidecar 时快探每 5 秒重试（无 sidecar 每 20 秒）；看 `/api/status` 的 `pin_health.error` 与 `/tmp/probe.log` |
| `pin_health=dead` | 轮换模式下所有候选握手都死，按设计保留 pin | 不是崩溃；等刷新补测或手动切换，必要时 `POST /api/full_probe` |
| 所有节点 `alive`/`exit_ip` 为 `null`、`verify_fresh=false` | 冷启动尚未测完，或没有验证器 | 等全量真测；确认边车/回退可用，或 `POST /api/full_probe` |
| 面板提示「服务出口探测不可用」 | 没有验证器（边车与 Python 回退都不可用）或 mixed 正在重启 | 恢复边车/等待 sing-box 起来；`unknown` 不会触发救援，勿据此判死 |

## CI

仓库共有 4 个 workflow，所有 action 都固定到 commit SHA：

- `publish-image.yml`：`main` push / `workflow_dispatch`；先跑 `pytest tests -q`
  与 `go test ./...`，通过后先构建 `--platform linux/amd64` 镜像并做入口冒烟
  （`bash -n start.sh` + `sh -n entrypoint.sh` + `import railway_manager` +
  `ENTRYPOINT_DRY_RUN=1` 输出 `10001`），只有冒烟通过才推 GHCR
  （`ghcr.io/<owner>/<repo>`），同时推不可变 `sha-<commit>` 与 `latest`
  （`latest` 仅默认分支）、启用 provenance/SBOM；同一 ref 的发布串行执行。
- `unit-tests.yml`：push/PR 上跑 Python 3.12/3.13 × 3 次，并用真实 sing-box
  校验生成配置；PR 还会 `docker build`（不推送）并执行同样的入口冒烟。
- 两个 workflow 都用固定版本的 `requirements-test.txt`（当前 `pytest==9.0.3`），
  不再在 CI 里安装浮动最新版。
- `test-combined.yml`：push/PR 上跑 `go test ./...` + `go vet ./...`。
- `test-chain-acceptance.yml`：仅手动触发，真实 VPNGate 冷启动/自愈验收
  （约 25–45 分钟）。

本地等价验证：

```bash
go test ./...                                     # 边车单测
go vet ./...                                      # 边车静态检查（Dockerfile 用 CGO_ENABLED=0 静态构建）
python -m pytest -q                               # 管理器/转换器测试
python vpngate_to_singbox.py \
  --input tests/fixtures/vpngate_tcp_sample.ovpn --output /tmp/singbox.json
sing-box check -c /tmp/singbox.json              # 配置形状（含三路入站）校验
```

住宅网关的真连验证同样在本地：配好 `RESI_*` 后 `POST /api/resi_probe {"count":3}`
要求 `distinct >= 2`，或直接 `curl --socks5-hostname` 连打几次 `https://api.ipify.org`
看出口 IP 是否变化。住宅流量按 GB 计费，不要放进自动流水线。
