#!/usr/bin/env bash
# sudo bash <(curl -fsSL https://raw.githubusercontent.com/GHUNLIL/vpngate/main/install.sh)
set -Eeuo pipefail
umask 077
REPO=${VPNGATE_REPO:-GHUNLIL/vpngate}
VERSION=${VPNGATE_VERSION:-}
die() { printf '错误: %s\n' "$*" >&2; exit 1; }
step() { printf '==> %s\n' "$*"; }
[ "$(id -u)" = 0 ] || die '请使用 root 运行'
[ "$(uname -s)" = Linux ] || die '需要 Linux'
command -v systemctl >/dev/null || die '需要 systemd'
[ -c /dev/net/tun ] || die '/dev/net/tun 不存在，请在 VPS 控制面板开启 TUN/TAP'
case "$REPO" in *[!a-zA-Z0-9_./-]*|*..*|/*) die '仓库名称无效' ;; esac
case "$(uname -m)" in
 x86_64|amd64) ARCH=amd64 ;;
 aarch64|arm64) ARCH=arm64 ;;
 armv7l|armv7) ARCH=armv7 ;;
 i386|i686) ARCH=386 ;;
 *) die "不支持的架构 $(uname -m)" ;;
esac
step '安装依赖 (openvpn, iproute2, curl, CA certificates)'
if command -v apt-get >/dev/null; then
 export DEBIAN_FRONTEND=noninteractive
 apt-get update -qq
 apt-get install -y -qq openvpn iproute2 ca-certificates curl coreutils >/dev/null
elif command -v dnf >/dev/null || command -v yum >/dev/null; then
 PM=$(command -v dnf || command -v yum)
 "$PM" install -y -q epel-release >/dev/null 2>&1 || true
 "$PM" install -y -q openvpn iproute ca-certificates curl coreutils
else
 die '不支持的发行版 (需要 apt / dnf / yum)'
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
SRC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)
BIN=''
for f in "$SRC_DIR/vpngate-linux-$ARCH" "$SRC_DIR/dist/vpngate-linux-$ARCH"; do
 if [ -f "$f" ]; then BIN=$f; break; fi
done
if [ -z "$BIN" ]; then
 if [ -z "$VERSION" ]; then
  url=$(curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")
  VERSION=${url##*/}
 fi
 case "$VERSION" in v[0-9]*|[0-9]*) ;; *) die '未找到有效 Release 版本' ;; esac
 case "$VERSION" in *[!a-zA-Z0-9_.-]*|*..*) die 'Release 版本无效' ;; esac
 base="https://github.com/$REPO/releases/download/$VERSION"
 step "下载并验证 $VERSION / $ARCH"
 curl -fSL --retry 3 --proto '=https' --tlsv1.2 "$base/vpngate-linux-$ARCH" -o "$tmp/vpngate-linux-$ARCH"
 curl -fsSL --retry 3 --proto '=https' --tlsv1.2 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
 awk -v name="vpngate-linux-$ARCH" '$2 == name { print; found=1 } END { if (!found) exit 1 }' "$tmp/SHA256SUMS" > "$tmp/selected.sha256" || die '校验文件缺少本机架构'
 (cd "$tmp" && sha256sum -c selected.sha256) || die 'SHA256 校验失败，未安装'
 BIN=$tmp/vpngate-linux-$ARCH
fi
chmod +x "$BIN"
"$BIN" version
if [ -f /usr/local/bin/vpngate ]; then cp -p /usr/local/bin/vpngate "$tmp/previous"; fi
if [ -f /etc/vpngate/vpngate.env ]; then cp -p /etc/vpngate/vpngate.env "$tmp/previous.env"; fi
step '安装并启动服务（保留已有配置与密码）'
if "$BIN" install && systemctl is-active --quiet vpngate; then
 step 'VPNGATE 服务已启动；首次筛选 VPN 节点需要一些时间'
else
 if [ -f "$tmp/previous" ]; then
  cp -p "$tmp/previous" /usr/local/bin/vpngate
  if [ -f "$tmp/previous.env" ]; then cp -p "$tmp/previous.env" /etc/vpngate/vpngate.env; fi
  systemctl restart vpngate || true
  die '新版本启动失败，已恢复旧二进制，请检查 journalctl -u vpngate'
 fi
 die '启动失败，请检查 journalctl -u vpngate'
fi
