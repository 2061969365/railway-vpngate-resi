# 第③路：VPNGate 节点自动轮换（设计，已实现）

> 状态：**已实现并合入**（2026-10-19）。实现记录见文末 §11。
> 前置：现有第③路是"外部住宅 SOCKS5 网关"（见 `docs/resi-design.md`），本设计把它扩展为两种模式，
> 默认模式改为"VPNGate 节点轮换"，住宅模式保留。

## 1. 目标

- 入口仍然只有一个：`:8084` + path `/ws-resi`（VLESS+WS），客户端配置不变。
- **每条新连接自动换一个节点**，出口 IP 即该节点 IP；连接序号用尽后**环形回到第一个**继续轮换。
- 轮换范围 = **当前所有实测有效节点**（即 `auto` 组里 `real_latency_ms` 有值的那批），**不设上限**。
- **零新增必填变量**：不填任何 `RESI_*` 也能用。
- 第①路 `/ws-node`、第②路 `/ws-chain` 行为完全不变；第三路坏了不影响它们。

## 2. 术语与行为定义

| 概念 | 定义 |
|---|---|
| 有效节点集合 `S` | 当前 serving 配置里的 endpoints，且 `real_latency_ms is not None`（真拨通过） |
| 轮换序号 | 单调递增计数器 `cursor`，第 k 条新连接取 `i = (cursor + k) mod |S|` |
| 后端端口 | `RESI_ROTATE_BASE + i`，默认 `41000`；`RESI_ROTATE_BASE` 为内部常量，不对外暴露 |
| 环形回绕 | `|S|` 条用完后从 0 重新开始，不等待、不排空 |

- 并发连接各自取不同 `i`（线程安全自增），因此并发下也是分散的。
- `S` 每次刷新/切换/健康剔除后重建；重建后 `cursor` 归零，端口表随之更新。
- 一条连接一旦建立，就固定走那个节点，不会中途跳节点。

## 3. sing-box 配置（`build_singbox_config` 的 rotate 分支）

对 `S` 中第 `i` 个节点生成：

```json
{"type": "vless", "tag": "resi-rot-<i>", "listen": "127.0.0.1",
 "listen_port": 41000,
 "users": [{"uuid": "<VLESS_UUID>"}],
 "transport": {"type": "ws", "path": "/ws-resi"}}
```

并追加路由：

```json
{"inbound": "resi-rot-<i>", "outbound": "<该节点的 endpoint tag>"}
```

- **不再**生成 `vless-resi` 入站（8084 改由管理器监听）、**不再**生成 `resi` socks 出站。
- 8084 不再出现在 `singbox-railway.json` 的 listen 列表里（由 `status.resi.listen` 说明）。
- 入站数量 = `|S|`；端口区间 `41000 .. 41000+|S|-1`，需与 `40000`（mixed）、`40001`（residential 模式回环）避开。

## 4. manager 侧

### 4.1 轮换监听器
- `0.0.0.0:RESI_PORT`（默认 8084），`SO_REUSEADDR`，listen(128)。
- 每条 accept：
  1. `i = cursor % len(ports)`，`cursor += 1`；
  2. 连 `127.0.0.1:ports[i]`；
  3. 双向 pipe，复用现有 `_mux_inflight` 计数、`_drain()` 与空闲超时逻辑（保证 `docker stop` 仍能优雅 drain）。
- 后端连接失败：顺延到下一个下标重试一次；仍失败则关掉该客户端连接并计数。

### 4.2 状态
`status["resi"]` 在 rotate 模式下：

```json
{"enabled": true, "mode": "rotate", "path": "/ws-resi", "port": 8084,
 "nodes": 27, "cursor": 13, "state": "up", "last_probe": {...}}
```

面板第三张卡标题改为「轮换出口（VPNGate）」，显示：节点数、当前游标、最近 3 次出口 IP、`distinct`。

### 4.3 探活
每 `RESI_PROBE_INTERVAL`（默认 300s）通过 `127.0.0.1:8084` 连续建 3 条**独立**连接请求 `https://api.ipify.org`，
记录 `{ips, distinct, rotating}`；`distinct >= 2` 视为轮换正常。探活失败只更新 `last_probe.error`，不改 `enabled`。

## 5. 模式选择（不新增必填变量）

```
填了 RESI_PROXY 或 RESI_GATEWAY(+USER/PASS) → mode = "gateway"（原住宅 SOCKS5 模式）
否则                                        → mode = "rotate"（本次新增，默认）
```

- `RESI_ROTATE=0` 可显式关闭第③路（不生成任何入站/监听），用于"只要两路"的部署。
- `RESI_ROTATE=1` 与住宅变量同时给 → 拒绝启动（避免语义冲突）。
- 端口/路径沿用 `RESI_PORT=8084`、`RESI_PATH=/ws-resi`。

## 6. 不变量（实现时必须守住）

1. `/healthz`、`_serving_ok()` 不依赖第③路；轮换器异常不影响第①②路。
2. 配置未变化时**不重启** sing-box（沿用 `_serving_config_unchanged`）。
3. `S` 为空（没有有效节点）→ 关闭第③路监听、`status.resi.state = "down"`，日志告警一次，不循环刷屏。
4. `/api/status` 永不包含任何凭据（rotate 模式本来就没有凭据）。
5. 订阅里 `/ws-resi` 链接格式不变。

## 7. 风险与取舍

| 风险 | 说明 |
|---|---|
| 配置体积 | 有效节点数 = 入站数，配置线性增长（40 个活节点 ≈ 40 条入站 + 40 条路由）。纯静态，可接受 |
| 出口性质 | 出口是 VPNGate 的机房 IP，目标站可能识别为代理；这与"住宅 IP"是两回事，文案需说明 |
| 连接粒度 | 轮换单位是 TCP 连接；客户端开 mux / HTTP keep-alive 会钉住同一节点（沿用原提示，需在 README 强调） |
| 配置重建 | 刷新后 `S` 变化会重建配置并重启 sing-box（现有机制），在途连接短暂中断 |

## 8. 测试计划

| 层 | 用例 |
|---|---|
| 单元 | rotate 分支生成 `|S|` 条 `vless` 入站 + `|S|` 条路由；端口从 41000 连续；无 8084 入站、无 `resi` socks 出站 |
| 单元 | 轮换器 round-robin：对 3 个假后端各发一条连接，命中顺序 0,1,2，第 4 条回到 0 |
| 单元 | `S` 变化后端口表重建、`cursor` 归零 |
| 单元 | `RESI_ROTATE=0` 不生成第三路；与住宅变量冲突时拒绝启动 |
| 集成 | `_fake_singbox()` + 假后端：连 3 次 `/ws-resi` 得到 3 个不同后端标记 |
| 集成 | 第③路后端全挂 → `/healthz` 仍 200，第①②路配置不变 |

## 9. 已确认 / 待确认

- 已确认：轮换范围 = 全部有效节点；不设池子上限；用尽后环形回绕；默认开启。
- 待确认：
  1. `RESI_ROTATE=0` 这个"关闭开关"要不要保留？
  2. 面板文案用「轮换出口（VPNGate）」是否可以？
  3. 刷新后配置重建会短暂断开在途连接，是否接受（现有机制如此）。

## 10. 实施顺序（评审通过后）

1. `vpngate_to_singbox.py`：rotate 分支与端口推导（纯函数，先写测试）
2. `railway_manager.py`：轮换监听器 + 状态 + 探活改造 + 模式解析
3. `UI_HTML` / `www/index.html`：第三张卡文案与指标
4. `docs/resi-design.md` 增补 rotate 模式；`README.md` 更新第③路说明与限制
5. 本地跑单测 + 假后端端到端；推新仓库，只走 `publish-image.yml`


## 11. 实现记录

按评审结论落地，与 §9「已确认」一致：

- **不设池子上限**：轮换对象就是 serving 配置里的全部有效节点（`MAX_SERVING_ENDPOINTS`
  默认 100，与 `LIMIT` 对齐），有几个生成几条 loopback 入站。
- **环形回绕**：`_resi_cursor` 单调递增取模，用完一圈自动回到 0；重建端口表时游标归零。
- **默认开启、无开关**：`VLESS_UUID` 非空即开启 rotate 模式；填了住宅网关变量则切回 gateway 模式。
- **8084 归管理器**：新增 `_resi_accept_loop` / `_handle_resi_client` / `_resi_next_port` /
  `_set_resi_ports`，复用 `_forward`、`_mux_inflight`、`_drain`、`PIPE_IDLE_TIMEOUT`，
  所以 `docker stop` 仍会优雅排空。
- **探活改走监听器**：新增 `measure_resi_rotate()`（throwaway sing-box 作为 VLESS 客户端连
  127.0.0.1:8084），每条样本一条新连接，`distinct >= 2` 判定旋转正常。
- 配置生成：`build_singbox_config(..., resi_rotate=True)` → `resi-rot-<i>` 入站
  （`127.0.0.1:41000+i`）+ `inbound → 该节点 tag` 路由；与 gateway 模式互斥。
- `Dockerfile` 增加 `EXPOSE 8084`；`start.sh` 在 `VLESS_UUID` 存在时注入订阅占位符；
  面板/伪装页文案改为「第三出口（轮换）」。
- 测试：`tests/test_resi.py` 47 条（新增 rotate 配置形状、轮换游标、端口表、真实 balancer
  连接级轮转、rotate 探活），`tests/test_vpngate_to_singbox.py` 全过。

### 11.1 云端验收发现与修正（GitHub Actions 真容器，2026-10-19）

`.github/workflows/test-rotate.yml` 在 runner 上真构建、真跑容器、真拨 VPNGate，并用本地
sing-box 当终端客户端经 `/ws-resi` 每条新连接采样。四个问题当场暴露并已修：

1. **`/api/resi_probe` 与 `/api/verify?path=resi` 误报 503 `resi disabled`。**
   rotate 模式没有网关凭据（`self.resi is None`），处理函数却只按 `self.resi` 判定，
   默认零配置部署下控制台的「探测 / 验证」按钮全挂。改为按「第三路是否启用」
   （`resi or resi_rotate`）判定；`/api/resi_session` 在 rotate 模式改回 400 并说明
   粘性会话属于住宅网关，轮换模式没有会话概念。
2. **探活被单个死节点打断，误报「未轮换」。** 节点池来自 VPNGate 快照，必然混有死节点；
   旧实现在第 2 条样本失败时直接 `break`，于是 `distinct=1`、`rotating=false`，面板显示
   「未轮换（请确认客户端已关闭 mux）」——把死节点说成了客户端配置问题。抽出
   `_collect_rotate_samples()`：每条样本一条新连接，失败只记录并继续走下一个节点
   （`count * 4` 次尝试或时间预算封顶），全部失败才返回 None。
3. **轮换池没有按 §1/§2 过滤「实测有效节点」。** `_apply_config` 之前把全部 serving 节点
   都塞进池子（含从未真拨过的），与 §2 的 `S` 定义不符，也让第三路首次连接有较大概率
   落到未验证的死节点上。新增 `RailwayManager._rotate_nodes()`：只取
   `real_latency_ms is not None` 的节点（按排名顺序），并把选中的 tag 顺序传给
   `build_singbox_config(..., resi_rotate_tags=[...])`，保证 `端口 41000+i ↔ 轮换顺序 i`
   一一对应；**实测节点不足 2 个时兜底用全部 serving 节点**（冷启动、探活未跑完、
   或 `REAL_TOPK=0` 时第三路不会因为没数据而变死）。
4. **§4.1 的「后端连接失败顺延下一个节点」没实现。** 补齐：loopback 入站连不上时取下一个
   下标重试一次，仍失败才放弃该客户端连接。

测试：`tests/test_resi.py` 59 条（新增：rotate 探针容错 5 条、tag 选择与顺序 2 条、
轮换池过滤与兜底 2 条、`_apply_config` 池子落盘 1 条、后端顺延 1 条、API 回归 3 条）。

### 11.2 池子只有 REAL_TOPK 大（回归修复）

按 §11.1 第 3 条把池子收窄成「实测有效节点」后暴露了真问题：**默认池子只有 30 个节点**，
用户预期「100 个节点里 60~70 个可用」全都在池里。

根因是 manager 重写时丢掉了一步：仓库自带的 `RefreshAutoProbeTests` 要求
「刷新成功后启动全量真拨」（`refresh_once` → `_start_full_probe()`），而重写后的
`_refresh_once_inner` 只做 `real_topk` 个真拨就返回，全量真拨只剩手动按钮——
于是除了 TopK，其余节点永远没有 `real_latency_ms`，进不了池子。
（该测试在重写后一直是红的，属于既有回归；本次一并修好。）

修复：

- `_refresh_once_inner` 成功收尾时调用 `_start_full_probe()`：启动/刷新只用 `REAL_TOPK`
  保证第一份 serving 配置快速落地，服务起来后由后台线程把**剩余节点全部真拨**一遍。
  默认 `FULL_PROBE_WORKERS` 2 → 3，100 节点全量真拨约 4~6 分钟跑完。
- 新增 `_republish_config()`：探针跑完后无论 auto-pin 是否改变都重新落一次配置，
  否则池子不会因为「新验证了一批节点」而更新（auto-pin 通常会跳过，因为它只在
  `preferred_tag is None` 时才 pin）。
- 效果：一次全量真拨后，轮换池 = 全部真拨通过的节点。

云端验收（run 39286586742，`LIMIT=40` / `REAL_TOPK=5`，单次真跑容器）：

| 阶段 | serving | 实测通过 | 轮换池 |
|---|---|---|---|
| 启动后（第一份配置落地，约 60s） | 40 | 5 | **5**（= REAL_TOPK），且 `full_probe` 已在 `running` |
| 后台全量真拨跑完（40/40，约 1 分钟） | 40 | 29 | **29** |
| 复查 | 29 条 loopback 入站 `41000..41028`，`sing-box check` 通过 | | |
| 轮换 | 5 条新连接 → **5 个不同出口 IP**，`rotating=true` | | |

即 40 个节点里 72.5% 可拨通，与「100 个节点约 60~70 个可用」的预期一致，且这些节点现在全部进池。

仍然已知的取舍：池中节点随后死掉时，那一条连接会失败（客户端重试即换下一个节点），
不做实时健康剔除——与 §4.1「不等待、不排空」一致；每次刷新都会重跑一次全量真拨
（与原设计一致，代价是每小时几分钟的后台真拨）。

### 11.3 Cloudflare 临时隧道端到端验收（run 39292087377）

生产用 Cloudflare Tunnel 按路径分流（`/ws-resi*` → `localhost:8084`），所以只测 localhost
不算数。临时工作流用镜像里同一版本的 `cloudflared` 直接开 **quick tunnel**（`trycloudflare.com`，
无需账号），把 `:8084` 暴露到公网，再用真实终端客户端验证：

| 检查 | 结果 |
|---|---|
| 轮换池（`LIMIT=30` / `REAL_TOPK=5`） | `full_probe=done`，池子 **26/30** 个实测节点 |
| 面板/伪装页经隧道 | `GET /` → 200，页面含 `ws-node` 与 `ws-resi` 链接；`/healthz` → 200 |
| `/ws-resi` 握手 | `https://<随机>.trycloudflare.com/ws-resi` 返回 **101** |
| 真实客户端（vless+ws+tls，与面板给的链接同构） | 5 条成功连接 → **5 个不同 VPNGate 出口 IP**（`118.105.78.215` / `118.156.149.7` / `120.74.8.14` / `216.251.205.242` / `27.84.184.174`），均不是 runner 自身 IP |

结论：第三路经 Cloudflare 边缘真实可用，且逐连接轮换生效。

两个踩坑记录（都属测试脚本本身，与产品无关）：

1. quick tunnel 刚建立时新 hostname 在边缘/DNS 还没生效，首个请求会 `000`，需要带退避重试；
2. WebSocket 升级检查必须 `--http1.1`——curl 默认走 h2，而 h2 里 `Connection:` 头非法，
   Cloudflare 会直接回 400（localhost 直连时看不出来）。

采样中有 2 条连接失败：正是「池内节点后来死掉」的情形，客户端重试即换下一个节点，
与上面的取舍一致。

### 11.4 线上事故：`/ws-resi` 连不上而前两路正常（run 39351138543）

线上反馈：同一域名/同一优选 IP 下 `/ws-node`、`/ws-chain` 正常，只有 `/ws-resi` 连不上。

根因**不在第三路实现**，在 tunnel 分流：线上 ingress 只给前两路配了
`/ws-node*`、`/ws-chain*` 规则，第三路是后加的，请求落到兜底 `/*` → `http://localhost:3000`；
管理器 mux 只服务 `/`、`/ui`、`/healthz`、`/api/*`，把 VLESS 的 `GET /ws-resi` 当普通
HTTP 处理，返回 401/404，握手自然失败。也就是说「加一条新路径 = 必须同时改 tunnel 配置」
这个隐含前提，正是最容易忘的地方。

修复（不要求用户改 tunnel 配置）：管理器在 `$PORT` 上**按路径分流**三条 VLESS+WS
（`_vless_path_route`）：`/ws-node` → 本机 8080、`/ws-chain` → 本机 8082、
`/ws-resi` → 轮换监听器（rotate）或 8084（住宅网关）。分流发生在鉴权之前（这些是
UUID 保护的公开端点，不是 API），并把 mux 已经读到的握手字节 `prefix` 一起送进后端，
保证不丢字节。老的按端口分流规则继续有效。

云端验收（run 39351138543，**只发布 3000、只开一条 catch-all quick tunnel**）：

| 检查 | 结果 |
|---|---|
| `/ws-node`、`/ws-chain`、`/ws-resi` 经 catch-all 升级 | 三条全部 **101** |
| `/ws-node` 出口 | `52.156.141.4` == runner 直连 IP（走本地直出） |
| `/ws-chain` 出口 | `72.180.13.9`（VPNGate） |
| `/ws-resi` 出口 | 5 条连接 → **5 个不同 VPNGate IP**（`216.189.136.50` / `73.251.85.171` / `219.100.37.236` / `.238` / `.239`） |

附带加固：`_pipe_to_backend` / `_handle_resi_client` 在拆连接前给另一方向 1 秒 flush
宽限——WS 在数据帧之后紧跟 close 时，原来的立即 `shutdown(SHUT_RDWR)` 可能截断末帧。

## 12. 轮换死节点事故复盘 + 设计修订（2026-10-20）

用户反馈（原话）：「旋转切换节点的时候，会旋转切换到失效的未被真测的节点，并且把 chain
本来能用的也拖累产生，产生矛盾，一个死两个一起死。然后就一直死在失效的节点那里，失效了
也不会换节点，就一直卡死在那里。」

这三句各自对应一个真实缺陷，而且互相放大。下面按「症状 → 根因 → 修法 → 证据」逐条列，
不修的也写清楚为什么。

### 12.1 D1：池子写进配置 ⇒ 一个节点死，三条路一起断

- 症状：第三路节点波动时，`/ws-node`、`/ws-chain` 的现有连接成批掉线；日志里能看到
  sing-box 被反复重启。
- 根因：旧实现里 rotate 入站**只为「已验证池」生成**（`_rotate_nodes`）。池子一变
  （探针结果、全量真拨、健康剔除）→ 生成的 JSON 变 → `_apply_config` 判定配置变化 →
  `_restart_singbox()`。sing-box 是三条路共用的进程，重启等于三条路一起清零。
  这就是「一个死两个一起死」。
- 修法：**配置只描述拓扑，不描述健康**。
  - `_rotate_routes(serving)`：serving 里**每个**节点都拿一条入站（`127.0.0.1:41000+i`，
    tag `resi-rot-<i>`），与验证结果无关；上限 `MAX_SERVING_ENDPOINTS=100`。
  - 池子/剔除/游标全部是**运行时状态**（`_resi_routes` + `_resi_health`），只影响
    mux 把连接拨到哪条 loopback 入站，不落盘。
  - `_republish_config()` 只在**端点集合**变化时被调用，不再因探针结果触发。
- 证据：`test_probe_results_do_not_rewrite_the_config`（节点从"活着"变"死"、另一个延迟
  从 20 变 999，配置文件字节完全相同、`_restart_singbox` 调用次数 0）、
  `test_full_probe_grows_the_pool_without_touching_the_config`（池 2→4，配置不变）。

### 12.2 D2：从未真拨过的节点也进池（"失效的未被真测的节点"）

- 症状：轮换到某个节点，连上去立刻断；客户端重试又撞上另一批同样没验证过的节点。
- 根因：旧 `_rotate_nodes` 有个"兜底"：真拨通过数 `< 2` 时**回退到整个 servings 集合**，
  于是「一个都没验证」「刚刷新完还没拨」这些时刻，池子里全是没验证过（甚至已经挂了）的
  节点。加上 §11.2 的池子 bug，这个兜底被触发得非常频繁。
- 修法：兜底删除。池成员唯一来源 = `real_latency_ms is not None`（真拨通过）且未 park。
  池空时不做"随便拿一个试试"，而是 `_set_resi(state="down", error="rotation pool empty
  (waiting for a verified node)")`，面板/`/healthz` 直接显示原因。
- 证据：`test_rotation_pool_keeps_verified_nodes_only`、
  `test_rotation_pool_is_empty_until_a_node_is_verified`（返回 `[]`、`_resi_next_route()` 为 `None`）。

### 12.3 D3：没有健康状态 ⇒ 死节点永远在池里，且不换（"一直卡死在失效节点"）

- 症状：某个节点在池子里但已经不通，轮换每次轮到它都失败，而且下一轮还会轮到；严重时
  所有连接都失败但池子看起来还有几十个节点。
- 根因：旧实现完全没有每节点状态：既不记失败，也不剔除，更不会自动恢复。同时
  §12.4 的长挂起让每条失败连接要占 120 秒，观感就是"卡死"。
- 修法（新增运行时健康表 `_resi_health[tag]`）：
  - `_resi_mark_fail(tag)`：**连续 3 次**（`RESI_NODE_STRIKES_DOWN`）失败才 park，
    park 时长指数退避 `120s → 240s → 480s → 900s`（`RESI_NODE_DOWN_BASE/MAX`）。
  - park 到期自动回池（`down_until` 过期），不需要任何配置/重启；`_resi_health`
    在路由表重建时清理已消失的 tag。
  - 池子按游标轮转，被 park 的节点直接从候选里去掉——**换节点是即时的**，不等重连。
  - 全池 park 时**不摆烂**：退化为"挑最早该重试的那个"（`down_until` 最小）继续服务，
    避免「全死 → 一个都不用 → 面板还是绿的」。
  - 什么算一次失败（故意保守，避免误伤）：连接由**节点侧先关**、下行 < 1KB
    （`RESI_PAYLOAD_BYTES`）且发生在 **30 秒内**（`RESI_FAIL_MAX_SECONDS`）——
    这覆盖了「立刻 RST」和「拨号黑洞卡十几秒后关闭」两种死法。超过 30 秒才被关的
    连接视为健康（那是空闲 NAT 回收，不是死节点）；客户端自己先关（keep-alive 回收、
    tcping、测活）**不计**失败；任何传过 1KB 以上下行数据的连接即使随后被关，
    立即算健康并清零 strikes。
  - 另一种死法：节点侧**整整 120 秒一个字节都没下行**（`PIPE_IDLE_TIMEOUT` 空闲超时，
    `down_idle`）——这不算"活得久"，记一次失败，避免客户端被按在死节点上两分钟。
  - 第三种死法（云端实测才发现）：节点**吃掉了客户端的请求但一个字节都不回**，也
    **不主动关**。sing-box 在 endpoint "not ready yet" 时会 hold 住入站连接、后台继续
    dial-probe 一个 RST/黑洞的 IP，这条连接既不下行也不结束，于是上面的三条规则全都不
    触发（没关、没满 120 秒、下行 0 但不算 payload）。加了**首字节预算**
    `RESI_FIRST_BYTE_TIMEOUT = 20s`：客户端已经写过字节、节点 20 秒内没有任何下行 ⇒
    看门狗砍连接 + 记一次失败。20 秒是在 endpoint dial-probe 预热（约 5 秒）之上留的余量。
- 证据：`test_a_failing_node_is_parked_then_returns`（3 次 → 只剩另一个；窗口过期 →
  回池；成功一次 → 计数清零）、`test_client_side_closes_never_count_as_strikes`、
  `test_an_all_parked_pool_still_serves_the_least_recent_failure`、
  `test_a_fast_node_drop_is_counted_as_a_strike`（真 socket 拨号，节点 accept 后立刻关）、
  `test_a_slow_node_side_failure_also_counts_as_a_strike`（10 秒后才关也算失败）、
  `test_a_long_idle_close_is_not_a_strike`（45 秒空闲关闭不算失败）、
  `test_a_silent_node_side_strikes_even_after_the_idle_window`、
  `test_a_node_that_swallows_the_request_is_struck`、
  `test_a_node_that_answered_is_not_struck_for_a_stall`（回过了就来算 payload，不误杀）。

### 12.4 D4：上游先死时挂满 120 秒（"卡死在那里"的直接原因）

- 症状：轮换到死节点，客户端不是"快速失败后重试"，而是**画面卡住两分钟**。
- 根因：`_pipe_to_backend` / `_handle_resi_client` 用 `first.join()` 等客户端→后端
  方向结束；节点先断时这个方向永远不会结束（客户端还在等响应），于是一条连接占满
  `PIPE_IDLE_TIMEOUT=120s`，期间还占着 `MAX_CONCURRENT_DIALS=10` 的并发槽。10 条这样的
  连接就能让第三路整体"假死"。
- 修法：新增 `_pump_pair(a, b, started)`：
  - 任一方向结束 ⇒ 立刻拆另一端（`shutdown(SHUT_RDWR)`），不再等另一个方向；
  - 两个方向都没结束时，看门狗按 `RESI_FIRST_BYTE_TIMEOUT` 结束"只有上行、没有下行"
    的连接（见 §12.3 第三种死法），并把这种情形标成 `first_byte_stalled` 交给健康表；
  - 有结束事件时才保留 1 秒 flush 宽限（避免截断紧跟数据的 close 帧）；看门狗路径
    没有东西可 flush，立刻拆；
  - 有界 join（2s），极端平台（`shutdown` 唤不醒阻塞 `recv`）再补一次 close 兜底，
    不泄漏线程。
  - 返回值带 `upstream_first` / `timed_out` / `first_byte_stalled` / `elapsed`，
    供健康表判断"是不是节点先关的"。
- 证据：`test_node_close_tears_the_connection_down_at_once`（节点 0.2s 后关闭，客户端
  < 4s 收到 EOF，线程不残留）、`test_the_pump_gives_a_silent_node_only_the_first_byte_budget`
  （节点收下字节但不回也不关，客户端在预算内收到 EOF）。

### 12.5 D5：配置顺序跟着延迟排名走 ⇒ 每次探针都"看起来变了"

- 根因：旧实现按延迟排序生成入站，探针结果一动，顺序就变，JSON 文本不同 →
  `_serving_config_unchanged()` 认为变了 → 重启。
- 修法：`_ordered_serving()`：serving 按 endpoint tag 排序后再生成配置（拓扑稳定）；
  延迟只用于选 serving 集合（超过 100 个节点时的截断）和链路的 auto-pin。
- 残留风险（诚实记录）：`MAX_SERVING_ENDPOINTS=100` 截断边界附近的节点排名互换时，
  serving 集合会变 → 配置变化 → 重启。这属于"拓扑真的变了"，无法避免；已通过
  tag 排序 + 只在刷新时重算，把频率降到每小时最多一次。

### 12.6 D6：仍会重启 sing-box 的路径（明确边界）

只有两类，且都不是健康/池子驱动的：

| 触发 | 为什么必须重启 | 频率 |
|---|---|---|
| 端点集合变化（定时刷新、`LIMIT` 变化、快照里节点消失） | 入站/出站的拓扑变了 | 每小时一次 + 手动刷新 |
| pin 变化（`auto-rescue`、`auto-pin`、手动 switch） | chain 路的 outbound 顺序变了 | 节点死亡/更优节点出现时 |

`/ws-resi` 的健康表、park、游标、池子**永不**在此列表里（有 §12.1 的回归测试守着）。

### 12.7 D7：游标在路由表变化时被清零 ⇒ 头部节点被反复使用

- 旧行为：任何路由表重建（`_set_resi_routes`）都把 `_resi_cursor` 归零，等于永远从
  0 号开始轮，尾部节点实际吃不到流量。
- 修法：游标只在**路由表内容真的变化**时归零（节点集合变了，从头轮起是合理的），
  健康/池子变化不碰它；每取一个候选 `cursor += 1`，天然 round-robin，遍历一遍池子才回头。
  旧实现的归零发生在「池子一变就重建路由表」的路径上，等价于每次探针后都从头开始。
- 证据：`test_cursor_cycles_and_wraps`（旧测试保留）、`test_rebuilding_the_table_resets_the_cursor`
  （表内容变化才重置）。

### 12.8 D8：空池/全 park 时的对外表现

- `/ws-resi` 的 VLESS 握手仍然成功（101），随后立即关闭：客户端（v2rayN/sing-box）
  会自然重试，比"握手失败"更容易被客户端正确归类。
- 状态里 `mode=rotate` 不变，但 `pool=0` 且 `error` 写明原因；面板第三路卡片显示
  `池 0/N 可用`，不再误导成"正常"。

### 12.9 D9：轮换抢走了 chain 自己的节点会话（"一个死两个一起死"）

- 症状（云端验收 run 39432025613 实测）：容器池里 5 个有效节点、`/ws-resi` 工作正常，
  但 `/ws-chain` 连续 90 秒拿不到任何出口 IP（`chain exit=` 为空），基线断言直接失败。
  容器日志同一时刻刷满 `endpoint/openvpn-client[dial-probe]: client terminated:
  authentication failed: terminal (auth-retry none)` 和 `dial failed for <节点>:443`。
- 根因：VPNGate 一个节点只允许**一个** OpenVPN 会话（duplicate-cn 关闭）。轮换模式在
  **每个** serving 节点上都建了 endpoint 并持续 dial-probe，而 chain 路径的
  `preferred_tag`/`backup_tag` 也在这批节点里——同一节点两个会话，谁后连谁把对方踢掉。
  被踢的如果是 chain，chain 看起来"死了"；而 `check_pinned_health` 只做 TCP 握手探测
  （节点端口还是通的），所以**永远不会触发 rescue**，第三路却一切正常：典型的「一个死、
  另一个也没了」，而且用户会以为是 chain 坏了。
- 修法：`_resi_pool_locked()` 把 `preferred_tag`/`backup_tag` 从轮换候选里**排除**，
  并在 `status.resi.reserved` 里报数（面板显示「N 个留给 chain」）。这只是路由选择层的
  过滤——那两条 loopback 入站还在配置里，pin 变了立刻回到池子里，不需要重写配置、不重启。
- 修法（第二半，同样关键）：轮换模式下 chain **永远保持 pin**。
  - `check_pinned_health()`：pin 的节点死了且没有别的已验证节点时，不再 `unpin → final=auto`，
    而是保留 pin（历史记 `auto-pin-kept`）。
  - `_auto_pin_best()`：exit 探测全失败时不再留空 pin，而是钉住真拨评分最好的节点
    （历史记 `auto-pin-unverified`），且**不编造**未验证的 standby。
  - 为什么必须这样：unpin 之后 chain 走的是 `auto`（urltest over 全部 endpoint），
    而轮换拨的正是同一批 endpoint —— 两条路抢同一节点唯一会话，"一个死两个一起死"
    照样复现（云端 run 39432025613 的 `refreshed 12 endpoints, final=auto` 就是这个状态）。
  - 代价：pin 的节点死掉时，chain 要等它复活或等下一轮 refresh 才可能换（这期间轮换仍在
    其它节点上正常服务）；这是有意的取舍，避免两条路互相踩。
- 证据：`test_the_chain_nodes_stay_out_of_the_rotation`、`test_an_unpinned_node_returns_to_the_rotation`、
  `test_a_pool_that_only_holds_the_chain_node_is_empty`、`test_rotate_mode_never_leaves_the_chain_unpinned`、
  `test_rotate_mode_never_unpins_a_dead_chain_node`。
- 边界：pin 本身变化（rescue/refresh）仍会重启 sing-box，见 D6；这不是本条的回归。

### 12.10 不变量（后续改动必须守住）

1. **健康/池子决策不得写配置文件、不得重启 sing-box**（`/ws-resi` 的抖动不能影响
   前两路）。回归测试：`test_probe_results_do_not_rewrite_the_config`。
2. **池成员 = 真拨通过 且 未 park**；没有"猜一个"的兜底。
3. **任一方向的连接结束 ⇒ 另一方向在 5 秒内拆掉**（不得挂到 `PIPE_IDLE_TIMEOUT`）；
   **只有上行没有下行时，`RESI_FIRST_BYTE_TIMEOUT` 内必须砍掉**。
4. **配置稳定**：同样的节点集合 → 同样的 JSON 字节（顺序按 tag，不带延迟字段）。
5. **轮换永远不碰 chain 的节点**：`preferred_tag`/`backup_tag` 不在轮换路由里，
   否则 VPNGate 的单会话限制会让 chain 静默失效。
6. **轮换模式下 chain 永不 unpin**：unpinned 的 chain 会用轮换正在拨的 endpoint，
   等于把 D9 重新打开。

### 12.11 测试矩阵（`tests/test_resi.py`，79 项全绿）

| 场景 | 测试 |
|---|---|
| 池只含真拨通过的节点 | `test_rotation_pool_keeps_verified_nodes_only` |
| 没有验证过 → 池空、不兜底 | `test_rotation_pool_is_empty_until_a_node_is_verified` |
| 每个 serving 节点一条入站 | `test_apply_config_creates_one_inbound_per_serving_node` |
| 健康变化不重写配置/不重启 | `test_probe_results_do_not_rewrite_the_config` |
| 全量真拨只扩池不改配置 | `test_full_probe_grows_the_pool_without_touching_the_config` |
| 三振 park + 到期回池 + 成功清零 | `test_a_failing_node_is_parked_then_returns` |
| 客户端先关不算失败 | `test_client_side_closes_never_count_as_strikes` |
| 全 park 仍有兜底 | `test_an_all_parked_pool_still_serves_the_least_recent_failure` |
| 节点快速掉线 → 连接快速拆 | `test_node_close_tears_the_connection_down_at_once` |
| 节点快速掉线 → 记一次 strike | `test_a_fast_node_drop_is_counted_as_a_strike` |
| 慢失败（拨号黑洞十几秒）也算 | `test_a_slow_node_side_failure_also_counts_as_a_strike` |
| 长时间空闲后关闭不算失败 | `test_a_long_idle_close_is_not_a_strike` |
| 节点侧 120 秒无下行算失败 | `test_a_silent_node_side_strikes_even_after_the_idle_window` |
| 节点吞下请求不回也不关 → 首字节预算砍连接 + 记失败 | `test_a_node_that_swallows_the_request_is_struck`、`test_the_pump_gives_a_silent_node_only_the_first_byte_budget` |
| 回过了就不算 stall | `test_a_node_that_answered_is_not_struck_for_a_stall` |
| 握手重放失败也不漏 backend socket | `test_a_failed_handshake_replay_still_closes_the_backend` |
| chain 的节点不参与轮换 | `test_the_chain_nodes_stay_out_of_the_rotation`、`test_an_unpinned_node_returns_to_the_rotation`、`test_a_pool_that_only_holds_the_chain_node_is_empty` |
| 轮换模式永远留 pin（无 exit 探测也钉） | `test_rotate_mode_never_leaves_the_chain_unpinned` |
| 轮换模式不把死 pin 丢给 urltest | `test_rotate_mode_never_unpins_a_dead_chain_node` |
| 环回入站被拒不算节点失败 | `test_a_refused_loopback_dial_never_strikes_the_node` |
| 拨号失败自动换下一个 | `test_backend_dial_failure_steps_to_the_next_node` |
| 真连接 round-robin | `test_balancer_round_robins_real_connections` |

另外用真 sing-box 1.14.0 校验了 100 节点静态入站的配置（不是 mock）：

```
$ sing-box check -c .check-rotate100.json     # rc=0，无告警
endpoints: 100  inbounds: 103  rotate: 100
ports ok: True [41000, 41001, 41002] ... 41099
route rules: 100 {'inbound': 'resi-rot-0', 'outbound': 'vpngate-0'} ... 'resi-rot-99'
```

### 12.12 已知限制（不打算修）

- **一条 TCP 连接只轮换一次**：mux 的"轮换单位"是一条连接，sing-box 的 VLESS 入站会把
  同一连接上的所有目标复用同一条出站。要按请求轮换，得在最前面挂一个真正的
  socks/http 代理（第三路原本的设计），代价见 §2/§7。客户端多开连接即可获得轮换。
- **出口是 VPNGate 的机房 IP**，不是住宅 IP；文案统一写「轮换出口」。
- **park 阈值是启发式的**：3 次 + 30 秒 + 1KB(+20 秒首字节) 的规则来自线上样本，真正误判也需要 3 次
  连续快速失败，且 2 分钟后自动重试，不会永久拉黑。
- 峰值并发仍受 `MAX_CONCURRENT_DIALS=10` 限制：这是 1 进程 400 连接场景下的保护，
  第三路的重连风暴不会把 sing-box 拖死（代价是并发拨号排队）。

### 12.13 上线后自查清单

1. `GET /api/status` → `resi.pool`（可用节点数）、`resi.down`（临时剔除数）、
   `resi.reserved`（留给 chain 的节点数）、`resi.inbounds`（= serving 节点数）。
   应满足 `pool + down + reserved <= inbounds`。
2. 面板第三路卡片显示 `节点池 24/30 可用 · 每连接轮换 · 3 个临时剔除 · 1 个留给 chain`；
   池为 0 时状态是「不可用」并写明 `rotation pool empty` 或 `every rotation node is parked`。
3. 节点死亡时历史里出现 `resi-node-parked`，`error` 形如
   `vpngate-7 parked for 120s after 3 fast failures`。
4. 该时段**不应**出现 sing-box 重启 / 配置写入：容器日志里没有新的
   `wrote config`、`sing-box restarted`，前两路的现有连接不掉。
5. 客户端体感：撞到坏节点应在 1~2 秒内失败（被 REJECT/RST 的情况）或最迟二十几秒
   （节点吞包不回，撞 `RESI_FIRST_BYTE_TIMEOUT=20s` 看门狗），**不再是 120 秒**；
   重试即落到健康节点。
6. 每小时的全量真拨把死掉的节点写成 `real_latency_ms=null`，它们会**自动退出池子**
   且不触发重启——面板上 `pool` 会掉、`inbounds` 不变。
7. **chain 不许被轮换拖死**：`/ws-resi` 在换节点时，`/ws-chain` 仍要能出出口 IP；
   同一时刻容器日志里不应出现针对 chain 那个节点的
   `authentication failed: terminal`（说明轮换又在抢它的唯一会话）。
