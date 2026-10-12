# VPNGATE

日本家宽出口网关：在日本 VPS 上自动挑选延迟最低的 VPNGate **日本家宽**节点，通过原生 UDP 隧道连接；客户端用 **Shadowsocks** 接入（加密，TCP + UDP）。配合沪日专线，得到“专线低延迟 + 日本住宅 IP 出口”。

- **单个静态二进制**（约 7 MB，Go 标准库，零依赖），系统只需 `openvpn` 和 `iproute2`
- **一个入口**：Shadowsocks（`aes-128-gcm`）同一端口承载 TCP 和 UDP，游戏、语音、QUIC 都能走；带重放保护，错误密码和探测请求得不到任何响应
- **原生 UDP 隧道**：VPNGate API 只下发 TCP 配置，程序从 vpngate.net 读出每个节点的 UDP 端口，改走原生 UDP。实测比 TCP 延迟低 5–10ms，抖动从 15–20ms 降到 1–2ms
- **只选家宽**：按 ip-api.com 的归属信息排除机房、移动网络和筑波大学学术节点
- **两阶段测速**：先对全部节点测 VPS 直连延迟，再对前 N 名建立真实隧道，测隧道内延迟、抖动、丢包和下载速度
- **热备秒切**：第二条隧道常驻待命，主节点故障时新连接立即走备用隧道，不用重新握手
- **DNS 走日本**：域名通过隧道解析，CDN 按日本出口调度；结果缓存 30 分钟，过了 2 分钟就在后台刷新，同一个域名再次访问不用等 DNS
- **出口 IP 稳定**：选中的节点保持 90 分钟，到期后再按“速度 ≥ 50 Mbps 且丢包 ≤ 5%、延迟最低”重选；重启后优先连回上次的节点；手动锁定的节点故障恢复后自动切回
- **不动 VPS 自身路由**：每条隧道独立网卡（`vgN`）+ 独立路由表 + `oif` 策略规则，SSH 不受影响

```
客户端 ──Shadowsocks (TCP+UDP)──▶ 日本 VPS :7929 ──(vg0 UDP 隧道)──▶ VPNGate 日本家宽节点 ──▶ 目标网站
                                       │
                                       └──(vg1 热备隧道)──▶ 另一个家宽节点
```

## 安装

需要：systemd Linux（Debian / Ubuntu / RHEL 系）、root、VPS 已开启 TUN/TAP。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/GHUNLIL/vpngate/main/install.sh)
```

离线安装：把 `vpngate-linux-amd64`（或对应架构）和 `install.sh` 放在同一目录，执行 `bash install.sh`。

安装完成后会打印后台地址和 Shadowsocks 连接信息，之后随时可用 `vpngate info` 查看。

## 连接

| 项目 | 默认值 |
| --- | --- |
| Shadowsocks | `VPS:7929`（TCP + UDP），`aes-128-gcm` |
| 管理后台 | `http://VPS:54345/`（HTTP Basic 认证，连续失败 10 次锁定 10 分钟） |

`vpngate info` 会打印 `ss://` 链接和 Clash 配置，后台页面也能直接复制。Clash / Mihomo 写法：

```yaml
proxies:
  - {name: 日本家宽, type: ss, server: VPS地址, port: 7929, cipher: aes-128-gcm, password: "密码", udp: true}
```

Shadowrocket、Surge、v2rayN 等客户端直接导入 `ss://` 链接即可，记得打开 UDP。主节点故障切换或定时重选后，正在进行的 UDP 会话会自动迁到新的隧道上。

### 配合沪日专线

1. 专线入口（上海）转发到 `日本 VPS IP:7929`，TCP 和 UDP 都要转发。
2. 在 `/etc/vpngate/vpngate.env` 里设置 `SS_ALLOW=专线落地机IP/32`，只允许专线来源连接。
3. 客户端把 Shadowsocks 服务器地址填成专线入口地址和端口。

## 命令

```
vpngate info       后台地址、账号和 Shadowsocks 连接信息
vpngate status     服务状态
vpngate logs       实时日志
vpngate restart    重启 (start / stop 同理)
vpngate config     编辑配置并重启
vpngate passwd     重新生成后台和 Shadowsocks 密码
vpngate update     从 GitHub Release 更新
vpngate uninstall  卸载
```

## 配置

配置文件是 `/etc/vpngate/vpngate.env`，修改后执行 `vpngate restart` 生效。常用项：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `WEB_PORT` | `54345` | 管理后台端口 |
| `SS_PORT` / `SS_PASSWORD` / `SS_METHOD` | `7929` / 随机 / `aes-128-gcm` | Shadowsocks 入口；可选 `aes-256-gcm` |
| `SS_ALLOW` | 空 | 允许连接的来源 IP/CIDR，逗号分隔；留空不限制 |
| `WEB_ALLOW` | 空 | 允许访问管理后台的 IP/CIDR；不在列表里的来源直接返回 403，连登录框都看不到 |
| `NOTIFY_WEBHOOK` | 空 | 出口 IP 变化、无可用节点、恢复时 POST JSON 到此地址 |
| `TG_BOT_TOKEN` / `TG_CHAT_ID` | 空 | 同样的事件发到 Telegram |
| `COUNTRIES` | `JP` | 节点国家 |
| `TRANSPORT` | `udp` | 隧道协议：`udp` 只用原生 UDP（没有可用 UDP 节点时才退回 TCP），`tcp`，或 `auto` 两者一起比 |
| `RESIDENTIAL_ONLY` | `1` | 只用家宽节点（没有可用家宽时临时放宽） |
| `DEEP_TEST_COUNT` | `6` | 每轮建立真实隧道测试的候选数 |
| `MIN_MBPS` | `50` | 合格速度线：达到的节点中延迟最低者胜出 |
| `HOLD_MINUTES` | `90` | 出口 IP 保持时间，到期后重新测速、按规则重选 |
| `SPEEDTEST_BYTES` | `4000000` | 测速下载量（4 MB：前 1 MB 让 TCP 提速不计时，只对后 3 MB 计时），`0` 表示关闭 |
| `STANDBY` | `1` | 热备隧道 |
| `MONITOR_INTERVAL` | `2` | 实时监测间隔（秒），每轮对主备各发 5 个 1200 字节探测包 |
| `FAIL_LOSS_PCT` | `5` | 主节点最近 30 秒丢包超过此值、且备用明显更干净时立即切换 |
| `DNS_SERVERS` | `1.1.1.1,8.8.8.8` | 通过隧道查询的 DNS |
| `SOURCES` | VPNGate 官方 API | 节点列表源，可追加镜像 |

## 通知

出口 IP 变化（90 分钟重选、故障切换、手动切换、重启后没能连回原节点）、完全没有可用节点、恢复时，会发通知到 Webhook 和/或 Telegram。Webhook 收到的 JSON：

```json
{"event": "exit_ip_changed", "old_ip": "60.149.136.130", "new_ip": "58.87.159.9",
 "reason": "实时丢包 5.3%，切到备用 (丢包 0.0%)", "node": "58.87.159.9 Sony Network Communications Inc UDP",
 "text": "出口 IP 变更 60.149.136.130 → 58.87.159.9，原因: ...", "time": 1791790423}
```

`event` 取值：`exit_ip_changed`、`no_node`（服务中断）、`recovered`（恢复，带新 IP）。发送是异步的，失败只记日志，不影响切换。

## 选点规则

1. 拉取 VPNGate 节点列表（失败时用本地缓存），保留日本节点，并通过 ip-api.com 识别归属（结果缓存 7 天）。
2. 从 vpngate.net 网站读出每个节点的 UDP 端口，生成原生 UDP 配置（`TRANSPORT=udp` 时只用这些）。
3. **第一阶段**：从 VPS 直连测每个节点的延迟。TCP 节点测握手时间；UDP 节点发一个 OpenVPN 握手包并计时（家宽节点大多不回 ping），顺便排除 UDP 端口不通的节点。
4. **第二阶段**：对前 `DEEP_TEST_COUNT` 个节点并行建立真实隧道，在隧道内向 `1.1.1.1` 发 20 个 1200 字节的 ping。然后按“零丢包优先、延迟从低到高”依次测速，凑够主备两个合格节点就停。每次测速下载 4 MB：前 1 MB 让 TCP 提速不计时，只对后 3 MB 计时，结果更准、流量更省。
5. 按规则排名：**速度 ≥ `MIN_MBPS`（默认 50 Mbps）且丢包 ≤ 5% 为合格，合格节点里延迟最低的胜出**；全都不合格时选速度最快的。
6. 第一名作为主节点，第二名保持连接作为热备，其余隧道关闭。
7. 主节点保持 `HOLD_MINUTES`（默认 90 分钟）不变，出口 IP 稳定。到期后当前主节点、热备和新候选一起重测（含测速），按同一规则重选：当前节点仍是第一就继续保持；被替换的旧隧道再保留 1 分钟，让已有连接收尾。手动锁定的节点不参与轮换。
8. **实时监测**：每 2 秒对主备两条隧道同时各发 5 个小探测包，保留最近 30 秒的数据。只丢大包的线路由 MTU 探测发现（建隧道时测一次，之后每 10 分钟复查）。监测本身每天只消耗约 0.1 GB：
   - 主节点丢包超过 5%、且热备丢包不到主节点的一半 → 立即切到热备（热备已连好，不用重新握手）；
   - 主节点连续 3 轮无响应 → 立即切换；
   - 热备自身丢包超标或失联 → 换掉，后台补充一个干净的；主节点有丢包但暂时没有好的热备时，立刻去找；
   - 至少攒够 12 秒（30 个探测包）才按丢包切换，避免偶发抖动误切；手动锁定的节点只在完全无响应时才切。

## OpenVPN 与内核调优

- **OpenVPN**：
  - `--route-nopull`：不改 VPS 默认路由。
  - `--mssfix 1360`：适配日本 PPPoE 线路的 1454 MTU。
  - UDP 节点加 `--fast-io` 和 4 MB 收发缓冲。
  - 优先协商 AES-GCM，回退 AES-128-CBC。
  - `--ping-exit 25`：隧道失联时快速退出，交给热备接管。
  - UDP 隧道加 `--explicit-exit-notify`：断开时通知服务器立即释放会话。否则重启后马上重连会被拒（`AUTH_FAILED`），也会在志愿者服务器上留下僵尸会话。
  - `--tun-mtu 1400`，并且每条隧道建好后**逐个探测实际能通过的最大包**（1400 → 1280），把网卡 MTU 设成这个值。实测不同家宽线路差别很大（有的 1400 能过，有的 1400 全丢），超大的包会被线路直接丢掉；MTU 合适后，内核会自动把 TCP 分段和 UDP 包控制在能通过的大小。
- **内核**（`/etc/sysctl.d/98-vpngate.conf`）：
  - BBR + fq 拥塞控制。
  - `tcp_notsent_lowat`，降低排队延迟。
  - `tcp_mtu_probing`，防止大包被黑洞丢弃。
  - 关闭空闲后慢启动。
  - 文件名用 `98-` 开头：服务器原有的 `99-*` 调优遇到相同参数时优先生效，不会被覆盖。
  - `rp_filter` 只对隧道网卡设置，不改全局。

## 流量开销

没有客户端使用时，程序自身每天约消耗 0.2–0.3 GB：

| 来源 | 每天约 | 说明 |
| --- | --- | --- |
| 实时监测 | 0.07 GB | 每 2 秒对主备各发 5 个小探测包 |
| 测速 | 0.13 GB | 每 90 分钟重选时通常测 2 个节点，每次 4 MB |
| 节点列表 | 0.02 GB | 只在需要选节点或距上次超过 3 小时才下载 |

另外，有些 VPNGate 节点上连着很多其他用户，节点服务器（SoftEther）会把内部 DHCP 广播（`10.211.254.254 → 255.255.255.255`）推给所有连接者，人多的节点每天可达约 0.4 GB。这部分是对方主动发来的入站流量，客户端无法阻止，只能收下丢弃。

## 构建

```bash
make test       # go vet + race 测试
make release    # dist/ 下生成 linux amd64 / arm64 / armv7 / 386 静态二进制
```

推送 `v1.0.0` 这样的 tag 后，GitHub Actions 会自动构建二进制并发布 Release。

## 许可

GPL-3.0。本项目基于 [aimili-vpngate](https://github.com/OpenMili/aimili-vpngate)（GPL-3.0）用 Go 重写，并做了修改。

请确认所在地法律和 VPS 服务商条款允许使用 VPN。VPNGate 是筑波大学的学术实验项目，节点由志愿者提供，请合理使用。
