#!/bin/sh
set -eu

# Keep WSL-imported Windows PATH syntax out of ImageBuilder command lines.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

: "${IMAGEBUILDER_DIR:?Set IMAGEBUILDER_DIR to an OpenWrt 25.12.5 ImageBuilder}"
: "${PROFILE:?Set PROFILE to the target device profile}"
: "${PACKAGE_FILE:?Set PACKAGE_FILE to the built transocks-headless .apk package}"

JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)}"

cp "$PACKAGE_FILE" "$IMAGEBUILDER_DIR/packages/"
cd "$IMAGEBUILDER_DIR"
set -- PROFILE="$PROFILE" \
	PACKAGES="transocks-headless sing-box ca-bundle firewall4 ip-full kmod-tun ${EXTRA_PACKAGES:-}"

if [ -n "${FILES_DIR:-}" ]; then
	set -- "$@" FILES="$FILES_DIR"
fi

make image \
	"$@" \
	-j"$JOBS"
