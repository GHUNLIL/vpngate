#!/usr/bin/env bash
# VPNGATE installer (systemd Linux, root):
#   bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_GITHUB_USER/vpngate/main/install.sh)
# Or offline: put the vpngate binary next to this script and run `bash install.sh`.
set -euo pipefail

REPO="${VPNGATE_REPO:-YOUR_GITHUB_USER/vpngate}"

die() { printf '\033[31m错误: %s\033[0m\n' "$*"; exit 1; }
step() { printf '\033[36m==>\033[0m %s\n' "$*"; }

[ "$(id -u)" = 0 ] || die "请使用 root 运行"
command -v systemctl >/dev/null || die "需要 systemd"
[ -c /dev/net/tun ] || die "/dev/net/tun 不存在，请在 VPS 控制面板开启 TUN/TAP"

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    armv7l|armv7) ARCH=armv7 ;;
    i386|i686) ARCH=386 ;;
    *) die "不支持的架构 $(uname -m)" ;;
esac

step "安装依赖 (openvpn, iproute2)"
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq openvpn iproute2 ca-certificates curl >/dev/null
elif command -v dnf >/dev/null || command -v yum >/dev/null; then
    PM=$(command -v dnf || command -v yum)
    $PM install -y -q epel-release >/dev/null 2>&1 || true
    $PM install -y -q openvpn iproute ca-certificates curl
else
    die "不支持的发行版 (需要 apt / dnf / yum)"
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
BIN=""
for f in "$SRC_DIR/vpngate-linux-$ARCH" "$SRC_DIR/dist/vpngate-linux-$ARCH" "$SRC_DIR/vpngate"; do
    [ -f "$f" ] && [ "$f" != /usr/local/bin/vpngate ] && BIN="$f" && break
done
if [ -z "$BIN" ]; then
    [[ "$REPO" == YOUR_GITHUB_USER/* ]] && die "请把 install.sh 里的 REPO 改成你的 GitHub 仓库，或把二进制放在脚本旁边"
    step "下载 vpngate-linux-$ARCH"
    BIN=$(mktemp)
    trap 'rm -f "$BIN"' EXIT
    curl -fL --progress-bar -o "$BIN" "https://github.com/$REPO/releases/latest/download/vpngate-linux-$ARCH"
fi
chmod +x "$BIN"

step "安装服务"
"$BIN" install
