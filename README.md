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
| `:8084` `/ws-resi` | `vless-resi` → `resi`（socks5）→ 固定 backconnect 网关 | 旋转住宅出口（可选，需 `RESI_GATEWAY`） |

三个入站共用同一个 `UUID`（`VLESS_UUID`，默认与 combined 一致：
`a29738e5-bee1-c0fc-b484-ae7c49cbc828`）。`route.rules` 按 inbound tag 分流，
三条路互不串扰。`/ws-resi` 未配置 `RESI_GATEWAY` 时整条路径（入站 + 出站 + 订阅）
都不会生成。

## Railway 部署

1. 新建 Service，指向本仓库，Region 建议新加坡（离 VPNGate 亚洲节点近）。
2. Variables（必填）：
   - `PORT`（默认 3000 即正确值，不填即可；填 8080/8081/8082/4096/混入端口会拒绝启动，非 3000 会告警，因隧道与 TCP 代理规则都指向 3000）
     - `PROXY_USER`（默认 `u`）/ `PROXY_PASS`（可选；不填则每次启动自动生成随机 `PROXY_PASS`，
       `PROXY_USER` 保持 `u`。走 VLESS+tunnel 时用不到；只有直连 SOCKS5 调试时才需要。
       显式填写的话 `PROXY_PASS` 须 ≥ 16 位，否则拒绝启动）
     - `ADMIN_TOKEN`（可选；不填则默认为 `vpn`，`/ui` 登录门输入 `vpn` 即可进入；
       若显式填写且长度 < 16 位，会被静默替换为随机值并在日志打印）
   - `TUNNEL_TOKEN`（Cloudflare tunnel token；缺失则 tunnel 软跳过，
     代理本身照常工作，`status["tunnel"] == "no-token"`）
     - 可选：`VLESS_UUID`（默认与 combined 一致；`VLESS_UUID` 为空则不注册 VLESS 入站，
       直接 `python railway_manager.py` 会无 VLESS）、`NEZHA_SERVER`/`NEZHA_KEY`、
       `LIMIT`（默认 100，0=全量、上限 100）、`REAL_TOPK`（默认 30，真拨 TopK）、
       `DIAL_WORKERS`（默认 2，真测并发；1GB 内存够用，OOM 就往小调）、`FULL_PROBE_WORKERS`（默认 2，
       全量真测并发；和 DIAL_WORKERS 叠加受全局 dial gate 上限 10 约束）、`REFRESH_SECONDS`（默认 3600，每小时拉新快照并自动全量真测）、`PROBE_WORKERS`（默认 15，握手并发）、`DIAL_TIMEOUT`（默认 15，真拨超时秒）、`AUTO_REPIN`（默认开，每小时自动重 pin 最优）、`AUTO_RESCUE`（默认开，手动 pin 挂了自动救最优）、`HEALTH_CHECK_INTERVAL`（默认 20s）、`MAX_MUX_CONNECTIONS`（默认 100）、`NEZHA_URL`（可选）、`SNAPSHOT_URLS`（可选，逗号分隔的快照镜像，主源失败自动顺延）
     - 旋转住宅（可选，不填则整条路径关闭）：`RESI_GATEWAY`（`host:port`，固定
       backconnect 网关，**永远只连这个地址**）、`RESI_USER`、`RESI_PASS`、
       `RESI_SESSION_TTL`（默认 0 = 每次连接换 IP；>0 = 粘性窗口秒数）、
       `RESI_USER_TEMPLATE`（粘性模式必填，见下节）、`RESI_PORT`（默认 8084）、
       `RESI_PATH`（默认 `/ws-resi`）、`RESI_PROBE_INTERVAL`（默认 300 秒）
       以上运行参数也可在控制台「设置」页直接改（`GET/POST /api/settings`，带范围校验），保存进 `settings.json`，重启不丢失，会覆盖 env。住宅的网关地址与凭据**只能走 env**，不进 `settings.json`（该文件会被 `/api/settings` 原样返回）。
3. 健康检查：`/` 路径填 `/healthz`（部署时需 200，冷启动靠 last-good 秒回）。
4. 另加一个 TCP Proxy 指向内部 `3000` 端口（可选，给 SOCKS5 用）。
5. 持久化（强烈建议）：service → Volumes → Add Volume，加完即可，
   无需配任何变量。代码会自动用 Railway 注入的
   `RAILWAY_VOLUME_MOUNT_PATH` 存 sing-box 配置/节点存档/last-good
   （`DATA_DIR` 显式设置会优先）。不挂卷的话每次重部署全量握手发现后冷启动（last-good 先顶住健康检查）。

> 合规警告：Railway AUP 明文禁止 proxy/anonymization 服务，
> 长期运行有封号风险，仅适合临时演示/调试。

## Cloudflare Tunnel 路由（Dashboard 配置）

tunnel 只管把外网域名打到容器端口，token 方式运行，
ingress 规则在 Cloudflare Dashboard 的 tunnel 配置里加：

- `node.example.com` + Path `/ws-node*` → `http://localhost:8080`
- 同一 hostname + Path `/ws-chain*` → `http://localhost:8082`
- 同一 hostname + Path `/ws-resi*` → `http://localhost:8084`（仅启用住宅出口时）
- 同一 hostname + Path `/*` → `http://localhost:3000`（兜底，必须排在上面几条**之后**）

顺序即优先级：`/ws-node`、`/ws-chain`、`/ws-resi` 先命中走 sing-box，其余一切都落到
3000 的 manager。manager 剥离 query 后路由：`/ui` 进控制台登录门，
`/api/*` 为数据接口（需 Bearer token），`/` 直接 serve 伪装页文件
（`start.sh` 注入 UUID 后经 `DISGUISE_PATH` 接线，`start.sh` 幂等，
容器重启不会残留旧值），其余路径 404。规则一次配完，不用再为伪装页加端口。

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

## 旋转住宅 SOCKS5 出口（可选）

只连**固定的 backconnect 网关**（`RESI_GATEWAY`），真实家宽 IP 由网关按连接分配，
本服务永远不知道也不需要知道它。默认**旋转**：每次新 TCP 连接换一个出口。

### 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `RESI_GATEWAY` | 空 | `host:port`。为空则整条路径关闭 |
| `RESI_USER` / `RESI_PASS` | 空 | 网关凭据（必填，env only） |
| `RESI_SESSION_TTL` | `0` | `0` = 旋转；`>0` = 粘性窗口秒数（设置页也可改） |
| `RESI_USER_TEMPLATE` | `{user}` | 粘性模式用；占位符仅 `{user}` `{session}` `{ttl}` |
| `RESI_PORT` / `RESI_PATH` | `8084` / `/ws-resi` | 入站端口 / WS 路径 |
| `RESI_PROBE_INTERVAL` | `300` | 住宅出口自动探测间隔（秒） |

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
  -e VLESS_UUID=a29738e5-bee1-c0fc-b484-ae7c49cbc828 \
  -e LIMIT=12 -e REAL_TOPK=2 \
  combined:test
curl http://127.0.0.1:3000/healthz   # ok
```

要一起试住宅出口，再加：

```bash
  -e RESI_GATEWAY=gw.example.com:1080 -e RESI_USER=USER -e RESI_PASS=PASS
```

管理页：`http://127.0.0.1:3000/ui`（粘贴 ADMIN_TOKEN）。节点列表显示出口 IP（`tag` 只留在 API 参数里）；搜索框＋范围下拉＋排序同一行；右上可切 Google 白浅色主题；底部显示真机 CPU 型号与实时占用（`GET /api/status` 的 `cpu{model,cores,pct}`、`memory.pct`，Linux 下读 `/proc`，取不到为 `None`）。
全量真测：管理页按钮或 `POST /api/full_probe`（需 `Authorization: Bearer`）。每次刷新成功（开机/每小时/手动）都会自动在后台全量真测，按握手延迟从小到大 5 并发拨号，超时 20 秒。自动轨道每轮跑完都重 pin 到实测最低（主）＋次低（保底），chain 出 `[best, second, auto]`，相同不重启；手动切换的不覆盖，手动挂了（连续 3 次握手失败）自动救到实测最优并回到自动轨道。状态条节点 title 显示主备。
单节点测速：节点列表每行“测速”按钮，或 `POST /api/probe {"tag":"vpngate-N"}`；
测通的节点自动可切换（全部存活节点本就在 sing-box 配置里，无需重建）。切换即切即换，成功后总览出现 15 秒「撤销换回」按钮（键盘可达，过期焦点自动回到当前节点）；成功的操作只在行内确认，失败才右下角弹窗。表头按钮可键盘排序，状态条圆点三态（绿=已验证新鲜/黄=未验证或数据旧/红=刷新失败），token 失效自动回登录页，全量真测可中途取消并显示中文进度＋预计剩余时间。日志支持搜索＋自动滚动开关；订阅行标注直连/经 VPN 用途，切换失败提示取后端 detail；统计卡自适应列、流量带单位、时长人性化显示，移动端保留导航并冻结首末列。

## CI

`.github/workflows/test-combined.yml`：单测 → sing-box check →
真实快照转换 → 真拨号 → 稳定性探针 → 镜像构建冒烟 →
trial-run（含双 VLESS 路径拨号验证：chain 出口 ≠ direct 出口，
direct 出口 == runner 本机 IP）。

另有 `live-resi` job：仓库配了 `RESI_GATEWAY` / `RESI_USER` / `RESI_PASS`
三个 secret 时，真连住宅网关跑 3 次出口 IP 采样并要求 `distinct >= 2`；
没配 secret（fork / PR / 未开通住宅）时自动跳过，日志里凭据会被 `::add-mask::`。
该 job 只在 `push` 与 `workflow_dispatch` 上有意义，住宅流量按 GB 计费，
不要在 PR 上依赖它。
