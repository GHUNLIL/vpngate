# VPNGATE

日本家宽出口网关：在日本 VPS 上自动挑选延迟最低、丢包最少的 VPNGate **日本家宽**节点，对外提供 HTTP / HTTPS / SOCKS5 代理（同一端口），以及加密、支持 UDP 的 Shadowsocks 入口。配合沪日专线，得到“专线低延迟 + 日本住宅 IP 出口”。

- **单个静态二进制**（约 7 MB，Go 标准库，零依赖），系统只需 `openvpn` 和 `iproute2`
- **零拷贝转发**：握手后两端都是 TCP 套接字，Linux 上走 `splice(2)`，数据不经过用户态
- **只选家宽**：按 ip-api.com 的归属信息排除机房、移动网络和筑波大学学术节点
- **两阶段测速**：先对全部节点测 VPS 直连延迟，再对前 N 名建立真实隧道，测隧道内延迟、抖动、丢包和下载速度
- **热备秒切**：第二条隧道常驻待命，主节点故障时新连接立即走备用隧道，不用重新握手
- **新连接更快**：`FAST_CONNECT` 先回复“连接成功”，再并行连接上游。DNS 结果缓存 30 分钟，过了 2 分钟就在后台刷新，同一个域名再次访问不用等 DNS
- **出口 IP 稳定**：选中的节点保持 90 分钟，到期后再按“速度 ≥ 50 Mbps、延迟最低”重选；重启后优先连回上次的节点；手动锁定的节点故障恢复后自动切回
- **不动 VPS 自身路由**：每条隧道独立网卡（`vgN`）+ 独立路由表 + `oif` 策略规则，SSH 不受影响

```
客户端 ──沪日专线──▶ 日本 VPS :7928 ──(vg0 隧道)──▶ VPNGate 日本家宽节点 ──▶ 目标网站
                         │
                         └──(vg1 热备隧道)──▶ 另一个家宽节点
```

## 安装

需要：systemd Linux（Debian / Ubuntu / RHEL 系）、root、VPS 已开启 TUN/TAP。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/GHUNLIL/vpngate/main/install.sh)
```

离线安装：把 `vpngate-linux-amd64`（或对应架构）和 `install.sh` 放在同一目录，执行 `bash install.sh`。

安装完成后会打印后台地址、账号和代理连接串，之后随时可用 `vpngate info` 查看。

## 连接

| 项目 | 默认值 |
| --- | --- |
| 管理后台 | `http://VPS:54345/`（HTTP Basic 认证，连续失败 10 次锁定 10 分钟） |
| 代理 | `VPS:7928`，HTTP / HTTPS CONNECT / SOCKS5 共用，需要账号密码，仅 TCP |
| Shadowsocks | `VPS:7929`（TCP + UDP），`aes-128-gcm`，加密，**支持 UDP**（游戏、语音、QUIC） |

需要 UDP 或者想让客户端到服务器这段加密，就用 Shadowsocks。`vpngate info` 会打印 `ss://` 链接和 Clash 配置，后台页面也能直接复制：

```yaml
proxies:
  - {name: 日本家宽, type: ss, server: VPS地址, port: 7929, cipher: aes-128-gcm, password: "密码", udp: true}
```

UDP 同样从日本家宽出口出去。主节点故障切换或定时重选后，正在进行的 UDP 会话会自动迁到新的隧道上。

**延迟最低的用法**：客户端优先用 **HTTP 代理**（HTTPS 走 CONNECT）。带账号密码的 SOCKS5 在发出数据前要经专线来回 3 次，HTTP CONNECT 只要 1 次。如果设置了 `PROXY_ALLOW` 白名单，还可以把 `PROXY_USER` 和 `PROXY_PASS` 留空，免去认证。

用 SOCKS5 时请用 **`socks5h://`**（由网关解析域名）。域名通过隧道交给日本 DNS 解析，CDN 会按日本出口调度。用 `socks5://` 时，域名会在国内本地解析，可能被调度到非日本的 CDN 节点。

### 配合沪日专线

1. 专线入口（上海）转发到 `日本 VPS IP:7928`。
2. 在 `/etc/vpngate/vpngate.env` 里设置 `PROXY_ALLOW=专线落地机IP/32`，只允许专线来源访问代理。
3. 客户端连接 `socks5h://用户:密码@专线入口:端口`。

## 命令

```
vpngate info       后台地址、账号和代理连接串
vpngate status     服务状态
vpngate logs       实时日志
vpngate restart    重启 (start / stop 同理)
vpngate config     编辑配置并重启
vpngate passwd     重新生成后台和代理密码
vpngate update     从 GitHub Release 更新
vpngate uninstall  卸载
```

## 配置

配置文件是 `/etc/vpngate/vpngate.env`，修改后执行 `vpngate restart` 生效。常用项：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `WEB_PORT` | `54345` | 管理后台端口 |
| `PROXY_PORT` | `7928` | 代理端口 |
| `PROXY_ALLOW` | 空 | 允许访问代理的来源 IP/CIDR，逗号分隔 |
| `SS_PORT` / `SS_PASSWORD` / `SS_METHOD` | `7929` / 随机 / `aes-128-gcm` | Shadowsocks 入口，密码留空则关闭；可选 `aes-256-gcm` |
| `FAST_CONNECT` | `1` | 先回复“连接成功”再连上游，每个新连接省一次隧道往返 |
| `COUNTRIES` | `JP` | 节点国家 |
| `RESIDENTIAL_ONLY` | `1` | 只用家宽节点（没有可用家宽时临时放宽） |
| `DEEP_TEST_COUNT` | `6` | 每轮建立真实隧道测试的候选数 |
| `MIN_MBPS` | `50` | 合格速度线：达到的节点中延迟最低者胜出 |
| `HOLD_MINUTES` | `90` | 出口 IP 保持时间，到期后重新测速、按规则重选 |
| `SPEEDTEST_BYTES` | `10000000` | 测速下载量（10 MB，足够让 TCP 跑满），`0` 表示关闭 |
| `STANDBY` | `1` | 热备隧道 |
| `MONITOR_INTERVAL` | `5` | 健康检查间隔（秒） |
| `FAIL_LOSS_PCT` | `30` | 1 分钟平均丢包超过此值即切换 |
| `DNS_SERVERS` | `1.1.1.1,8.8.8.8` | 通过隧道查询的 DNS |
| `SOURCES` | VPNGate 官方 API | 节点列表源，可追加镜像 |

## 选点规则

1. 拉取 VPNGate 节点列表（失败时用本地缓存），保留日本节点，并通过 ip-api.com 识别归属（结果缓存 7 天）。
2. **第一阶段**：从 VPS 直连测每个节点的延迟（TCP 节点测握手时间，UDP 节点用 ICMP）。
3. **第二阶段**：对前 `DEEP_TEST_COUNT` 个节点并行建立真实隧道，在隧道内向 `1.1.1.1` 发 10 个 ping，并下载 10 MB 测速。UDP 节点常常不响应 ping，第一阶段没法给它们排名，所以每轮至少放 2 个 UDP 节点进来做真实测试。
4. 按规则排名：**速度 ≥ `MIN_MBPS`（默认 50 Mbps）为合格，合格节点里延迟最低的胜出**；全都不合格时选速度最快的。
5. 第一名作为主节点，第二名保持连接作为热备，其余隧道关闭。
6. 主节点保持 `HOLD_MINUTES`（默认 90 分钟）不变，出口 IP 稳定。到期后当前主节点、热备和新候选一起重测（含测速），按同一规则重选：当前节点仍是第一就继续保持；被替换的旧隧道再保留 1 分钟，让已有连接收尾。手动锁定的节点不参与轮换。
7. 每 5 秒在主隧道内检查一次。连续 3 次无响应，或 1 分钟平均丢包超过阈值，就立即切到热备，并在后台补充新的热备。

## OpenVPN 与内核调优

- **OpenVPN**：
  - `--route-nopull`：不改 VPS 默认路由。
  - `--mssfix 1360`：适配日本 PPPoE 线路的 1454 MTU。
  - UDP 节点加 `--fast-io` 和 4 MB 收发缓冲。
  - 优先协商 AES-GCM，回退 AES-128-CBC。
  - `--ping-exit 25`：隧道失联时快速退出，交给热备接管。
- **内核**（`/etc/sysctl.d/98-vpngate.conf`）：
  - BBR + fq 拥塞控制。
  - `tcp_notsent_lowat`，降低排队延迟。
  - `tcp_mtu_probing`，防止大包被黑洞丢弃。
  - 关闭空闲后慢启动。
  - 文件名用 `98-` 开头：服务器原有的 `99-*` 调优遇到相同参数时优先生效，不会被覆盖。
  - `rp_filter` 只对隧道网卡设置，不改全局。

## 构建

```bash
make test       # go vet + race 测试
make release    # dist/ 下生成 linux amd64 / arm64 / armv7 / 386 静态二进制
```

推送 `v1.0.0` 这样的 tag 后，GitHub Actions 会自动构建二进制并发布 Release。

## 许可

GPL-3.0。本项目基于 [aimili-vpngate](https://github.com/OpenMili/aimili-vpngate)（GPL-3.0）用 Go 重写，并做了修改。

请确认所在地法律和 VPS 服务商条款允许使用 VPN。VPNGate 是筑波大学的学术实验项目，节点由志愿者提供，请合理使用。
