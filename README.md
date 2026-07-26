# Transocks Headless for OpenWrt

Clean-room headless client derived from static behavioral analysis of the
official Transocks Android 4.4.4 APK.

Target: OpenWrt 25.12.5. Data plane: OpenWrt's maintained `sing-box` package.
Control plane: portable Go daemon with no third-party Go modules.

## Capabilities

- Root-only JSON credential file
- Parallel race across official API domains
- Bounded provider responses and candidate fan-out
- Password login and bearer-token management
- Shadowsocks and Trojan candidate translation
- Initial TCP latency ranking
- sing-box URL-test host selection
- 60-second performance monitoring
- Three-round degradation hysteresis
- Automatic candidate refresh, rollback, and tunnel restart
- Persistent last-known-good startup during provider outages
- Exponential retry with jitter and unlimited procd recovery
- Process-group cleanup and parent-death protection for sing-box
- Bounded health, credential, status, and diagnostic reads
- Compatibility routing (China through Transocks, other destinations direct)
- Optional full-tunnel mode
- procd supervision, UCI configuration, and OpenWrt feed packaging

## Configure

The service ships disabled.

```sh
vi /etc/transocks/credentials.json
chmod 600 /etc/transocks/credentials.json
uci set transocks.main.enabled='1'
uci commit transocks
/etc/init.d/transocks enable
/etc/init.d/transocks validate
/etc/init.d/transocks start
```

Credential forms:

```json
{"auth_by":"username","username":"name","password":"secret"}
```

```json
{"auth_by":"email","email":"name@example.com","password":"secret"}
```

```json
{"auth_by":"mobile","cc":"1","phone":"5551234567","password":"secret"}
```

Status:

```sh
transocks-headless status
logread -e transocks
```

Runtime proxy ports:

- Transparent TUN/fw4 routing: enabled by default
- Mixed HTTP/SOCKS listener: `127.0.0.1:7890`
- Local health API: `127.0.0.1:9090`

## Feed integration

Add to an OpenWrt source tree:

```text
src-git transocks https://github.com/tardeaux/Transocks-Headless.git;master
```

Then:

```sh
./scripts/feeds update transocks
./scripts/feeds install -p transocks transocks-headless
make menuconfig
```

Select `Network -> VPN -> transocks-headless`, or set
`CONFIG_PACKAGE_transocks-headless=y`.

See `image/README.md` for firmware image builds and `docs/APK_ANALYSIS.md` for
the static-analysis result and limitations.

## Test

```sh
cd net/transocks-headless/src
go test ./...
go test -race ./...
go vet ./...
```

Live authentication and tunnel validation require an authorized Transocks
account and an OpenWrt 25.12 router/VM. No credentials are included.
