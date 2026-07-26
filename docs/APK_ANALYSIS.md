# APK analysis

Input:

- `official/transocks_official_4.4.4_1053_20265221745_release.apk`
- SHA-256: `BCEACC765FF7E4B1763B3ECAA23F50827ACB8C11679D7B87C03124A0616CA966`
- Android package: `com.fobwifi.transocks`
- Version: `4.4.4` (`1053`)
- Minimum/target SDK: Android 7.0 (`24`) / Android 15 (`35`)

## Portability result

The APK is not directly portable. It contains Android/Bionic JNI libraries for
`arm64-v8a` and `armeabi-v7a` only. The embedded `libclash.so` identifies an old
Dreamacro Clash 1.7.1/Go 1.20.3 lineage. OpenWrt 25.12 uses musl and supports
additional architectures. This implementation therefore uses a clean-room Go
control plane and the maintained OpenWrt `sing-box` package.

No APK code, native library, embedded credential, certificate, or asset is
redistributed.

## Recovered control-plane behavior

Production API domains:

- `https://abscf2.fobwifi.com`
- `https://b.kolavpn.xyz`
- `https://b.kolavpn.win`
- `https://b.transmoon.xyz`

The Android client races `GET /api/1/ip` and selects the fastest successful API
domain. Relevant operations are:

- `POST /api/1/login`
- `GET /api/2/line`
- `POST /api/2/line/connect/{lineID}`
- `POST /api/2/line/connectmultiple`
- `POST /api/2/line/disconnect/{lineID}`

Login supports `username`, `email`, and `mobile` password authentication. The
response supplies a JWT-style token used as `Authorization: Bearer …`.
`connectmultiple` returns proxy candidates. Supported clean-room translations:

- Shadowsocks: server, port, password, method
- Trojan: server, port, password, TLS/SNI, optional WebSocket

The proprietary GTS/SSW formats and Android VPN/JNI bridge are intentionally
unsupported.

## Selection behavior

The APK's automatic profile asks for two candidates and configures a Clash
`url-test` group:

- Probe URL: `https://connect.rom.miui.com/generate_204`
- Interval: 300 seconds
- Tolerance: 120 ms

The headless controller generalizes this:

- Configurable candidate count
- Initial three-sample TCP ranking
- sing-box URL-test selection every 60 seconds by default
- Persistent-delay/failure detection
- Candidate refresh after three bad rounds
- Scheduled reauthentication and fleet refresh
- Atomic checked configuration updates

## Security differences

The Android client disables parts of normal TLS verification. This implementation
does not copy that behavior. Public API and rule-set requests require HTTPS with
normal certificate and hostname verification. Credentials and generated proxy
configuration are mode `0600`; runtime state stays under `/var/run`.

The service API is private and undocumented. Provider schema changes, account
terms, and redistribution authorization remain external constraints.

