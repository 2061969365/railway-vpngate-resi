# 旋转型住宅 SOCKS5 出口改造设计（草案 v1）

> 状态：**待确认**，未落地任何代码。
> 目标仓库：`2061969365/railway-vpngate-combined` @ `c389fba`
> 基线：现有两条出口 `/ws-node`（Railway 本机）与 `/ws-chain`（VPNGate）。

---

## 1. 目标与硬约束

在现有两条出口之外，**并列**增加第三条出口：客户端 → VLESS+WS → sing-box → **旋转型住宅 SOCKS5 网关（backconnect）** → 目标站点。

硬约束（来自需求，实施时逐条对照）：

| # | 约束 | 在本设计中的落点 |
|---|---|---|
| C1 | 只连**固定网关地址** `host:port`，永不直连真实家宽 IP | 出站只有 `server=RESI_GATEWAY` 一个地址 |
| C2 | 网关背后是住宅节点池，新连接自动换出口 | 依赖"每条 SOCKS5 连接 = 新出口"，见 §5.3 |
| C3 | 默认**旋转**：用户名不带 session | `RESI_SESSION_TTL=0` → 注册原样用户名 |
| C4 | **粘性**：用户名带 session + ttl，按代理商文档格式 | 模板渲染 + 占位符，格式由用户提供，不猜测 |
| C5 | 优先 `socks5h`（DNS 也走代理） | 见 §5.4：VLESS 携带域名时 sing-box 直接以 ATYP=3 转发，等价 socks5h |
| C6 | 连接复用会导致 IP 不换，必须明确告知 | 见 §5.3 与 §9：**multiplex 必须关** |
| C7 | 住宅节点不稳，需超时/重试/错误处理 | 见 §8 |
| C8 | 不假设可直连真实家宽 IP、不编造代理商参数格式 | 模板默认 `{user}`，粘性需用户指定格式 |
| C9 | 不把住宅出口放进 urltest（会持续探测、烧流量） | 见 §4.3：`auto`/`chain` 组只含 VPNGate endpoint |

**明确不做**：不做双跳（VPNGate → 住宅 或 反向）。理由：openvpn endpoint 作为 `detour` 目标的兼容性需要额外验证，且延迟翻倍；本轮先做并列第三条。

---

## 2. 拓扑与端口

```
客户端 ──VLESS+WS──> :8080 /ws-node  ──> direct            (Railway 本机出口)
        ──VLESS+WS──> :8082 /ws-chain ──> chain|auto        (VPNGate 出口)
        ──VLESS+WS──> :8084 /ws-resi  ──> resi              (住宅旋转出口)   ← 新增
                                    └─> socks5 gw:port      (固定 backconnect 网关)

本机 127.0.0.1:40000 mixed-in   ──> route.final (chain|auto)   (调试 SOCKS5，不变)
本机 127.0.0.1:40001 resi-in    ──> resi                        (新增，仅本机，测轮换用)
```

端口占用表（`build_config_from_env` 里的冲突检查必须同步扩充）：

| 端口 | 用途 | 来源 |
|---|---|---|
| `$PORT`(3000) | manager mux（HTTP/SOCKS5/CONNECT） | 现有 |
| 4096 | cc-switch-server | 现有 |
| 8080 | `vless-direct` | 现有 |
| 8081 | 伪装页静态服务 | 现有 |
| 8082 | `vless-chain` | 现有 |
| **8084** | **`vless-resi`** | **新增** |
| 40000 | `mixed-in`（loopback） | 现有 |
| **40001** | **`resi-in`（loopback，仅本机）** | **新增** |
| **53000** | **占位：无，不需要额外端口** | — |

Cloudflare Tunnel ingress 需要新增一条（顺序在 `/*` 之前）：

```yaml
- hostname: node.example.com
  path: /ws-resi*
  service: http://localhost:8084
```

---

## 3. 配置模型（env 优先，密钥不进 settings.json）

新增环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `RESI_GATEWAY` | 空 | `host:port`，**唯一出口地址**。为空则不启用整条路径 |
| `RESI_USER` | 空 | 基础用户名（旋转模式下原样使用） |
| `RESI_PASS` | 空 | 密码 |
| `RESI_SESSION_TTL` | `0` | 秒。`0`=纯旋转；`>0`=粘性窗口 |
| `RESI_USER_TEMPLATE` | `{user}` | 仅粘性模式使用（见 §5.2） |
| `RESI_PORT` | `8084` | `vless-resi` 监听端口 |
| `RESI_PATH` | `/ws-resi` | WS 路径 |
| `RESI_UDP` | `false` | 是否允许 UDP（多数网关不支持，默认关） |
| `RESI_PROBE_INTERVAL` | `300` | 住宅出口健康探测间隔（秒），不参与重启决策 |

启动校验（`build_config_from_env`，与现有 `refusing to start: ...` 风格一致）：

- `RESI_GATEWAY` 非空但 `RESI_USER` 或 `RESI_PASS` 为空 → 拒绝启动（避免"看起来启用了其实 401"）
- `host:port` 解析失败（含 IPv6 需方括号）→ 拒绝启动
- `RESI_PORT` 与 `{3000, 4096, 8080, 8081, 8082, MIXED_PORT, VLESS_*}` 任一冲突 → 拒绝启动
- `RESI_SESSION_TTL > 0` 但模板里没有 `{session}` 占位符 → **只告警并降级为旋转**（不猜测代理商格式，也不静默改变语义，见 §5.2）

**为什么不把用户名/密码放进 `SETTINGS_SPEC`**：`update_settings()` 会把值 `_write_private_json` 到 `settings.json`，且 `settings_snapshot()` 会在 `/api/settings` 里**明文返回**。代理凭据如果进这里，等于在控制台接口里回显。`RESI_SESSION_TTL` 是纯整数，可以进设置页（见 §6.2）。

---

## 4. sing-box 配置生成

### 4.1 新增 outbound

`build_singbox_config()` 增加参数 `resi: dict | None = None`，值为：

```python
{
    "type": "socks",
    "tag": "resi",
    "server": gateway_host,
    "server_port": gateway_port,
    "version": "5",
    "username": rendered_username,
    "password": resi_password,
    "network": "tcp",          # UDP 默认关闭
    # "udp_over_tcp": False,   # 只有 RESI_UDP=true 时才考虑，见 §8
}
```

要点：

- **不加 `detour`**：并列路径，直接出网。`detour` 留给以后的"住宅→VPNGate"双跳。
- **`network: "tcp"`**：住宅网关普遍不支持 UDP ASSOCIATE。不写 `tcp` 的话，UDP 流量会先在网关侧超时再失败，表现为"网页能开、视频/语音一直转圈"。
- **不进 `auto` / `chain`**：urltest 默认 15s 探测一次，住宅流量按 GB 计费，把 resi 放进 urltest 会 24 小时烧钱且探测本身就消耗节点。

### 4.2 新增入站与路由

在现有 `vless_uuid` 分支追加（仅当 `resi` 非空时）：

```python
config["inbounds"].extend([
    {"type": "vless", "tag": "vless-resi",
     "listen": "0.0.0.0", "listen_port": resi_port,
     "users": [{"uuid": vless_uuid}],
     "transport": {"type": "ws", "path": resi_path}},
])
config["route"]["rules"].append({"inbound": "vless-resi", "outbound": "resi"})
```

以及仅本机的测轮换入口：

```python
config["inbounds"].append(
    {"type": "mixed", "tag": "resi-in", "listen": "127.0.0.1", "listen_port": 40001})
config["route"]["rules"].append({"inbound": "resi-in", "outbound": "resi"})
```

> `resi-in` 是给运维/CI 用的：`curl --socks5-hostname 127.0.0.1:40001 https://api.ipify.org` 走的是**和线上完全一致的 sing-box socks 出站**，比另写一套 SOCKS5 客户端更能反映真实行为。它只监听 loopback，不经 mux、不经 CF Tunnel。

### 4.3 与现有 selector 的关系

`proxy` selector 的候选列表保持 `tags + ["direct"]` **不变**，不加入 `resi`。理由：`proxy` 是手动兜底选择器，住宅出口按流量计费，误选一次就可能跑掉几十 GB。要住宅出口请用 `/ws-resi`。

---

## 5. 用户名渲染：旋转 vs 粘性

### 5.1 旋转（默认）

`RESI_SESSION_TTL=0` → 用户名 = `RESI_USER` 原样，**不追加任何参数**。每次新连接由网关换出口。

### 5.2 粘性

`RESI_SESSION_TTL>0` 且模板含 `{session}` 时：

```
template = RESI_USER_TEMPLATE           # 用户按代理商文档填写
rendered = template.format(user=RESI_USER, session=sid, ttl=RESI_SESSION_TTL)
```

- `sid` 由 `secrets.token_hex(4)` 生成，**在一个 ttl 窗口内保持不变**，窗口到期后换新 `sid`（网关侧重新分配出口）。
- 支持占位符：`{user}`、`{session}`、`{ttl}`。**不提供** `{country}`/`{city}`/`{sid}` 等未定义的写法，避免臆造。
- 默认模板是 `{user}`；因此**不填模板就永远不会进入粘性**，只会告警。这是刻意的：宁可降级为旋转，也不按猜测的格式拼串。

渲染实现（纯函数，便于测试）：

```python
def render_resi_username(user: str, template: str, ttl: int, session_id: str) -> str:
    if ttl <= 0:
        return user
    if "{session}" not in template:
        return user                      # 降级为旋转，调用方已告警
    return template.format(user=user, session=session_id, ttl=ttl)
```

未知占位符（`KeyError`）→ 拒绝启动并打印模板，错误信息里不打印已渲染的用户名（可能含凭据）。

### 5.3 "换 IP" 的真实前提（必须写进 README）

住宅网关的轮换粒度是**一次新的 TCP 连接**。所以：

1. **sing-box 客户端的 `multiplex` 必须关**。开 mux 后所有流复用一条 WS 连接，网关只看到一次 SOCKS5 握手 → 出口 IP 全程不变。
2. **HTTP keep-alive 会让同一个 TCP 连接承载多个请求**。浏览器/`requests.Session` 复用连接时，同一连接内 IP 不变是正常行为，不是故障。
3. 想要"每个请求一个 IP"，必须：关 mux + 每个请求新建连接（或发 `Connection: close`）。
4. 服务端不做连接池：sing-box `socks` outbound 每条入站流独立建 TCP，这一点无需额外配置。

> 附注：整条 `/ws-resi` 共用同一份凭据，因此**粘性模式下整个部署同一时刻共用一个住宅出口 IP**。要做"每用户独立粘性"需要按用户下发不同凭据，本轮不做，写进限制。

### 5.4 DNS 泄露（socks5h 等价物）

- 客户端（浏览器/curl）如果自己先解析域名，请求到达 sing-box 时已经是 IP，DNS 已经泄露了，服务端无法补救。
- 只要客户端把**域名**交给 VLESS（sing-box/mihomo 默认行为），sing-box 就会以 `ATYP=3`（域名）转发给 SOCKS5 网关，**DNS 在网关侧解析**，等价 `socks5h`。
- 因此我们的责任是：文档里明确要求客户端使用 `socks5h://` 语义（`curl --socks5-hostname`、`requests` 的 `socks5h://`、`aiohttp_socks` 的 `rdns=True`），并且不要把域名在本地解析后再转发。

---

## 6. 管理器改动清单

### 6.1 `vpngate_to_singbox.py`

| 位置 | 改动 |
|---|---|
| `build_singbox_config()` | 新增 `resi: dict \| None`、`resi_port`、`resi_path` 参数；按 §4 生成 outbound/inbound/rule |
| 新增 `render_resi_username()` | §5.2 的纯函数 |
| 新增 `measure_resi_exit_ip(resi, singbox_bin, timeout)` | 复用现有"临时 sing-box + mixed 入站 + SOCKS5 GET"骨架，返回 `(ip, ms)` |
| 新增 `measure_resi_rotation(resi, count, ...)` | 同上，但在**同一个**临时 sing-box 上连续建 `count` 条 SOCKS5 连接，收集出口 IP 序列 → `{"ips": [...], "distinct": n}` |
| 重构（可选） | 现有 `measure_real_latency` / `measure_exit_ip` 与新函数共 70 行同构代码，建议抽 `_throwaway_dial(outbound_cfg, probes)` |

### 6.2 `railway_manager.py`

| 位置 | 改动 |
|---|---|
| 模块常量 | `RESI_TAG = "resi"`、`RESI_IN_PORT = 40001`、`RESI_PROBE_INTERVAL` |
| `SETTINGS_SPEC` | 追加 `"resi_session_ttl": {"type":"int","min":0,"max":86400}`、`"resi_enabled": {"type":"bool"}`（`_coerce_setting` 无需改，已支持 int/bool） |
| `build_config_from_env()` | §3 的解析与校验，返回 `resi` 子字典；端口冲突表加入 `resi_port` |
| `RailwayManager.__init__` | 保存 `self.resi`、`self.resi_port/path/udp`、`self._resi_session`、`self._resi_session_started`；`status["resi"]` 初值 |
| `status_snapshot()` | 追加 `resi` 块（**不含 username/password**） |
| `_apply_config()` | 把 `self.resi` 传给 `build_singbox_config`；`_serving_config_unchanged()` 已比较 `inbounds/outbounds/route`，无需改 |
| 新增 `_resi_session_id()` | 按 ttl 窗口生成/复用 session id（`threading.Lock` 保护） |
| 新增 `_resi_config()` | 调 `render_resi_username()` 产出 outbound dict；ttl 变更时换新 session |
| 新增 `_resi_probe_loop()` / `_run_resi_probe()` | 每 `RESI_PROBE_INTERVAL` 走一次 `measure_resi_exit_ip`；单飞；**只更新状态，绝不重启 sing-box** |
| `_route_post()` | 新增 `POST /api/resi_probe`（body `{"count": 3}`，2..5，单飞 409） |
| `_handle_http()` | `POST /api/verify` 支持 `?path=resi`（走 `measure_resi_rotation` 或 `measure_resi_exit_ip`） |
| `main()` | 把 `cfg["resi"]` 等传进构造函数 |
| 健康语义 | `_serving_ok()` **不**把 resi 算作健康条件：住宅网关挂了不能拖垮 `/healthz` 与另外两条路径 |

### 6.3 `start.sh`

- 现有 `sed` 注入保留；追加 `RESI_PATH_PLACEHOLDER` 注入（供 `www/index.html` 的第三个订阅卡）。
- 不做别的改动：manager 自己从 env 读 `RESI_*`。

### 6.4 `www/index.html`

- `#realPage` 增加第三张卡：住宅出口，含"旋转/粘性"徽章、`复制` 按钮、`id="nodeLinkResi"`。
- 生成 `vless://<UUID>@<host>:443?security=tls&sni=<host>&type=ws&path=/ws-resi#resi`。
- 若 `RESI_PATH_PLACEHOLDER` 未替换则隐藏该卡（未启用住宅出口时不留死链）。

### 6.5 `railway_manager.py` 内嵌 `UI_HTML`

- 总览页 `#route-strip` 增加第三行 `/ws-resi → 住宅出口 <exit ip>`。
- 新增"住宅出口"卡片：模式徽章（旋转/粘性 ttl）、当前出口 IP、`探测` 按钮（调 `/api/resi_probe`）、IP 序列（`1.2.3.4 → 5.6.7.8 ...`，全不同显示绿色"轮换正常"，全相同显示黄色提示"疑似未轮换"）。
- 设置页追加两个字段（ttl、启用开关）。
- 复用现有 `esc()`/`safeTag()`，**新增字段一律过 `esc()`**。

---

## 7. HTTP API 变更

| 方法 | 路径 | 变更 |
|---|---|---|
| GET | `/api/status` | `status.resi = {enabled, host, port, mode:"rotation"\|"sticky", sticky_ttl, session_age, state, exit_ip, ms, checked_at, error, last_probe:{ips,distinct,rotating}}`；**无凭据字段** |
| GET | `/api/settings` | 增加 `resi_session_ttl`、`resi_enabled` |
| POST | `/api/settings` | 同上 |
| POST | `/api/verify?path=resi` | 202/409，语义与现有一致 |
| POST | `/api/resi_probe` | **新增**。body `{"count":3}`；202 `{accepted:true}`；409 单飞；503 未启用 |

兼容性：`/api/verify` 不带 `path` 时行为完全不变（默认 `node`）。

---

## 8. 超时 / 重试 / 错误处理

| 场景 | 策略 |
|---|---|
| 连网关超时 | 客户端侧建议 10 s；服务端探测 `RESI_DIAL_TIMEOUT` 默认 15 s（复用 `dial_timeout` 会让住宅探测被 VPNGate 的 15s 拖长，单独给一个更合适） |
| 网关 401/407（凭据错） | 探测状态置 `error="auth failed"`，**不重启 sing-box**，不重试轰炸（间隔内最多 1 次） |
| 网关可用但目标站失败 | 区分 `dial` 失败与 `http` 失败（`summarize_probe.py` 已有该区分，沿用） |
| 住宅节点抖动 | 单次失败不改变状态机；连续 3 次失败才置 `state="down"`，下次探测自动恢复 |
| 重试 | 探测内部 1 次重试（间隔 2 s）；**不做无限重试**，避免把网关打成风控 |
| 流量 | 探测只打 `api.ipify.org`（几十字节），间隔 ≥300 s；轮换测试 `count` 上限 5 |
| UDP | 默认 `network:"tcp"`；`RESI_UDP=true` 时改用 `udp_over_tcp: true`（仍取决于网关是否支持，文档标注"不保证"） |

---

## 9. 客户端配置样例（README 用）

### curl

```bash
# 旋转：每次独立调用 = 新 TCP 连接 = 新出口 IP
curl -s --socks5-hostname "$RESI_USER:$RESI_PASS@$RESI_GATEWAY" https://api.ipify.org; echo

# 粘性：用户名里带 session（格式以代理商文档为准，下面只是占位示意）
curl -s --socks5-hostname "$RENDERED_STICKY_USER:$RESI_PASS@$RESI_GATEWAY" https://api.ipify.org
```

### Python requests

```python
import requests
PROXY = "socks5h://{u}:{p}@{h}:{port}".format(**cfg)   # socks5h = 远端解析 DNS
for _ in range(3):
    with requests.Session() as s:            # 每次新 Session，避免连接复用
        r = s.get("https://api.ipify.org", proxies={"http": PROXY, "https": PROXY},
                  headers={"Connection": "close"}, timeout=(10, 20))
        print(r.text)
```

### httpx

```python
import httpx
with httpx.Client(proxy=PROXY, timeout=httpx.Timeout(20, connect=10),
                  headers={"Connection": "close"}) as c:
    print(c.get("https://api.ipify.org").text)
```

### aiohttp

```python
import aiohttp
from aiohttp_socks import ProxyConnector
conn = ProxyConnector.from_url(PROXY, rdns=True)      # rdns=True 等价 socks5h
async with aiohttp.ClientSession(connector=conn) as s:
    async with s.get("https://api.ipify.org") as r:
        print(await r.text())
```

### sing-box（客户端）

```json
{
  "outbounds": [
    {
      "type": "socks",
      "tag": "resi",
      "server": "gw.example.com",
      "server_port": 1080,
      "version": "5",
      "username": "USER",
      "password": "PASS",
      "network": "tcp"
    }
  ],
  "route": { "final": "resi" }
}
```

链式（本地规则 → 住宅出口）时，用 selector 或 `detour` 指向 `resi` 即可；**不要**开 `multiplex`。

### Clash / Mihomo

```yaml
proxies:
  - name: resi-rot
    type: socks5
    server: gw.example.com
    port: 1080
    username: USER
    password: PASS
    udp: false
proxy-groups:
  - name: resi
    type: select
    proxies: [resi-rot, DIRECT]
rules:
  - MATCH,resi
```

Mihomo 侧同样关闭 `smux`（`smux: {enabled: false}`）。

### 通过本项目的隧道使用

```
vless://<UUID>@node.example.com:443?security=tls&sni=node.example.com&type=ws&path=/ws-resi#resi
```

客户端 rema​rk 里的 `multiplex` 保持关闭。

---

## 10. 如何验证 IP 在变化

**A. 直连网关（最快，验证代理商本身）**

```bash
for i in 1 2 3 4 5; do
  curl -s --socks5-hostname "$RESI_USER:$RESI_PASS@$RESI_GATEWAY" https://api.ipify.org; echo
done | sort -u | wc -l      # 旋转模式期望接近 5；粘性模式期望 1
```

> 必须是 5 次独立 `curl` 调用。一次 `curl url1 url2` 会复用连接。

**B. 经本项目隧道（验证服务端整条链路）**

```bash
# 在容器内/本机通过 resi-in
for i in 1 2 3; do
  curl -s --socks5-hostname 127.0.0.1:40001 https://api.ipify.org; echo
done
```

**C. 控制台**：`POST /api/resi_probe {"count":3}`，返回 `{ips:[...], distinct:3, rotating:true}`；UI 卡片会给出"轮换正常/疑似未轮换"。

判定标准：
- 旋转模式：`distinct >= 2`（不苛求 100% 不同，住宅池可能回退到同一节点）
- 粘性模式：同一 `session` 下 `distinct == 1`，换 `session` 后 IP 应变化

---

## 11. 测试计划

| 层级 | 用例 |
|---|---|
| 单元 | `render_resi_username`：ttl=0 原样；ttl>0 含 `{session}`；模板缺 `{session}` 降级 + 告警；未知占位符报错且**错误信息不含渲染结果** |
| 单元 | `build_singbox_config(resi=...)`：outbound 字段、`network=="tcp"`、两个新入站、两条 route rule、`resi` 不在 `auto`/`chain` 组里 |
| 单元 | `build_config_from_env`：网关缺凭据/端口冲突/非法 host:port → `SystemExit(2)` 且日志含 `refusing to start` |
| 集成 | `_fake_singbox()` 起 manager（`start_singbox=False`）→ `/api/status` 有 `resi` 且**不含** `username`/`password` |
| 集成 | `POST /api/resi_probe` 注入 fake `rotation_fn` → 202，随后 status 出现 `last_probe`；并发第二次 → 409 |
| 集成 | 网关不可达 → `state="down"`，`/healthz` 仍 200，`/ws-chain` 配置不受影响（防止把 resi 故障升级成全局故障） |
| 协议 | 扩展 `tests/` 里的 `FakeSocks5Server`：支持 RFC1929 用户名密码协商，返回可轮换的出口 IP，供 `measure_resi_rotation` 直接跑 |
| CI | `sing-box check` 对"含 resi outbound + vless-resi + resi-in"的配置跑一次；真实网关**不进 CI**（需要账号，且按流量计费） |

---

## 12. 部署步骤（Railway + CF Tunnel）

1. Variables 增加：`RESI_GATEWAY`、`RESI_USER`、`RESI_PASS`（可选 `RESI_SESSION_TTL`、`RESI_USER_TEMPLATE`）
2. Cloudflare Tunnel ingress 增加 `/ws-resi*` → `http://localhost:8084`（必须在 `/*` 之前）
3. 部署后 `curl https://<host>/healthz` 应为 `ok`
4. `POST /api/resi_probe` 验证轮换
5. 客户端导入 `/ws-resi` 订阅

回滚：删除 `RESI_GATEWAY` 并重启即可，第三条路径与相应入站自动消失，另两条不受影响。

---

## 13. 风险与边界

| 风险 | 说明 / 缓解 |
|---|---|
| 按流量计费 | 探测间隔 ≥300 s、`count ≤ 5`、不进 urltest、不进 `proxy` selector |
| 凭据落盘 | 只出现在 env 与 sing-box 配置（0600）；`/api/status`、`/api/settings`、日志均不输出 |
| 粘性影响全站 | 所有客户端共用同一凭据 → 同一时刻同一出口 IP；文档明示 |
| 网关风控 | 不做高频重试；`RESI_PROBE_INTERVAL` 可调大 |
| UDP 不可用 | 默认 `network:"tcp"`；文档标注"住宅网关通常不支持 UDP" |
| 与现有 `_DIAL_GATE` 抢名额 | resi 探测走独立开关与独立信号量，不占 `_DIAL_GATE`（否则会挤掉 VPNGate 的 TopK 拨号） |
| 抄错代理商格式 | 模板默认 `{user}`，粘性需显式配置；文档要求对照官方文档 |

---

## 14. 实施顺序（确认后执行）

1. `vpngate_to_singbox.py`：`render_resi_username` + `build_singbox_config(resi=...)` + 单元测试
2. `vpngate_to_singbox.py`：`measure_resi_exit_ip` / `measure_resi_rotation` + FakeSocks5Server 鉴权扩展
3. `railway_manager.py`：env 解析/校验 → 构造器 → `_apply_config` 透传
4. `railway_manager.py`：status / 探测循环 / 两个 API
5. `UI_HTML` + `www/index.html` + `start.sh`
6. `README.md`（§9/§10 内容）+ CI 的 `sing-box check`
7. 本地 `python -m unittest discover -s tests` + `sing-box check` + 用假网关跑一遍端到端

---

## 15. 已确认决议（2026-10-19）

| 待定项 | 决定 |
|---|---|
| 凭据存放 | **env only**；`settings.json` 只存 `resi_session_ttl`；`/api/status` 不含凭据 |
| 粘性入口 | **单一 `/ws-resi`**，由 `RESI_SESSION_TTL` 决定旋转/粘性；另提供 `POST /api/resi_session` 显式换 session |
| UDP | **彻底关闭**，出站硬编码 `network: "tcp"` |
| CI | **真连网关**：`live-resi` job，靠 `RESI_GATEWAY/RESI_USER/RESI_PASS` secrets，缺 secret 自动跳过，日志 `::add-mask::` |

### 实施时的两处修正（推翻本草案早期假设）

1. **拨号闸门共用而非独立**。草案 §13 曾写"resi 探测走独立信号量、不占 `_DIAL_GATE`"。
   实际改为**共用 `_DIAL_GATE`**：该闸门保护的是"同时存在的 sing-box 进程数 ≤ 10"，
   与流量语义无关；另开闸门会让 1 GB 机器重新回到 OOM 风险。resi 探测间隔 ≥300 s、
   每次只起 1 个进程，占用一个名额是正确取舍。
2. **「配置未变则不重启 sing-box」确实存在**（`_serving_config_unchanged()` 比较
   `endpoints/outbounds/route/inbounds`）。因此只有 TTL 变化导致用户名变化、
   或节点重排时才会重启；session id 在进程生命周期内固定，避免每个粘性窗口
   重启一次把长连接全部打断。

