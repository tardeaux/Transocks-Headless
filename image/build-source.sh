#!/bin/sh
set -eu

# Prevent WSL-imported Windows PATH entries with spaces/parentheses from
# corrupting OpenWrt's nested shell command lines.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

: "${OPENWRT_DIR:?Set OPENWRT_DIR to an OpenWrt 25.12.5 source tree}"

REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}"
FEEDS_FILE="$OPENWRT_DIR/feeds.conf"

if [ ! -f "$FEEDS_FILE" ]; then
	cp "$OPENWRT_DIR/feeds.conf.default" "$FEEDS_FILE"
fi
if ! grep -q '^src-link transocks ' "$FEEDS_FILE"; then
	printf '\nsrc-link transocks %s\n' "$REPO_DIR" >>"$FEEDS_FILE"
fi

cd "$OPENWRT_DIR"
./scripts/feeds update -a
./scripts/feeds install -a
./scripts/feeds install -p transocks transocks-headless

if [ -n "${TARGET_CONFIG:-}" ]; then
	cp "$TARGET_CONFIG" .config
fi
cat "$REPO_DIR/image/configs/packages.config" >>.config
make defconfig
make download -j"$JOBS"
make -j"$JOBS"
