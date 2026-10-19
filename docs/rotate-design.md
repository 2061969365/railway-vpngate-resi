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

仍然已知的取舍：轮换池按 `REAL_TOPK`（默认 30）决定大小，未验证节点不入池；池中节点随后
死掉时，那一条连接会失败（客户端重试即换下一个节点），不做实时健康剔除——与 §4.1
「不等待、不排空」一致。
