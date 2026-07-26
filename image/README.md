# OpenWrt image integration

Target baseline: OpenWrt `v25.12.5`.

## Full source build

Use a Linux build host and a clean OpenWrt source tree:

```sh
git clone --branch v25.12.5 --depth 1 https://github.com/openwrt/openwrt.git
export OPENWRT_DIR="$PWD/openwrt"
export TARGET_CONFIG=/absolute/path/to/device.config
/absolute/path/to/TransocksHeadless/image/build-source.sh
```

The script adds this repository as a linked feed, installs the package, enables
the package set, and builds the selected target.

## ImageBuilder

First build `transocks-headless` with the matching 25.12.5 SDK. Then:

```sh
export IMAGEBUILDER_DIR=/absolute/path/to/openwrt-imagebuilder
export PROFILE=your_device_profile
export PACKAGE_FILE=/absolute/path/to/transocks-headless-0.1.0-r2.apk
/absolute/path/to/TransocksHeadless/image/build-imagebuilder.sh
```

OpenWrt 25.12 uses apk-tools v3. Distribution feeds must publish signed `.apk`
packages and a signed `packages.adb` index. Build package and index artifacts
with the matching release SDK/build system and keep the signing private key
offline. Embed only the public verification key in images.
