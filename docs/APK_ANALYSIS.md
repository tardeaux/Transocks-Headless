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

## REA re-evaluation (2026-10-30)

Rechecked the same APK digest with REA/JADX headless MCP 0.7.1. Static
inspection covered authentication/result handling, response models, proxy
translation, default routing/selection configuration, and a reconnect callback.
The APK was not executed. Complete local Evidence is retained in
`official/rea-2026-10-30-evidence.json` (ignored by Git because it includes
decompiled proprietary material). No embedded test credentials are reused.

| Observation | REA Evidence | Result in this project |
| --- | --- | --- |
| `Ssl` has `sni` and `verify`, no `enabled`; `LinesManager.getProxyForTrojan` creates a Trojan proxy and maps SNI, verification and optional WebSocket | `ev_dd1a536a70bb70c12916e058f2eb2bfa8c9a085a222bc43aa52602662711bcc7`, `ev_77681bed9153cfefeedc8241620e6f83470f019bb31bf4d1a92d9a5560fb4ae2` | Always enable Trojan TLS; absent `verify` defaults to certificate verification. Explicit `verify:false` still requests insecure proxy TLS, matching the vendor response. API HTTPS verification remains strict. |
| `UserRepository.saveAndUpdateAccount(LoginResponse)` stores bearer token and type for subsequent operations | `ev_316e8d69fe77be8318b1b69cb428d348b0601346e5835d0cee94bbebe481e99e` | Reuse in-memory tokens across refreshes; renew near declared expiry or once after authentication rejection. Network failures retain the session. |
| `ApiCodeError.Companion.toError` distinguishes 20001/20006/20010/40015 authentication failures; 20000 is an error, not success | `ev_3b58d756d95b3048b033ee609c04ce361cf1873497c256532b22e0260ee8e9d4`, `ev_012a573adb3433b4860cc0be250ae24e3591058b266aeef0c745799bea1bf882` | Typed code handling; bounded reauthentication. Removed erroneous acceptance of 20000. Error messages omit raw provider bodies, which may contain secrets. |
| `DomainProvider.checkSingleDomain` evaluates application success, with a ten-second timeout | `ev_ae3b0a9c2dab437c13d57f5a08a425f3d500077c43647fffa06c29a04565e527` | Validate probe result codes. Treat discovery as advisory so a broken IP-check endpoint does not block otherwise functioning login. |
| `ConnectConfigKt` auto profile uses URL-test, 300s, 120ms; routes China through proxy and the rest direct; its DNS config uses fake-IP and disables IPv6 | `ev_fb9e5e48d8cdab09c44d6e9d19741f7fc6fe26dabcf0070da23afe6ff80b17ce` | Retain configurable faster 60s tunnel tests and 120ms tolerance. Keep compatibility/full routing choice. Do not transplant Android DNS/fake-IP ranges into an existing AP network. |
| `ConnectResponse`, `Config`, `BootsInfo` confirm config/configs with SSConf/trojanConf and optional transport metadata | `ev_997c649136ab2f5cc1c9851a44bd969b61ff30983713b93a10d1dfba2b9937f5`, `ev_3eb41020e0e1bd33cd054c377b387f30cc656ec3a85035a08334f7703630797d`, `ev_bb5ad840f15c1d90384fc651745cdee2bf4301e86aa858c37d93911e733e094f` | Existing supported protocol boundary remains valid; no GTS/SSW emulation added. |

Related source-level fixes: all refresh triggers now share the retry deadline;
the OpenWrt init script watches the configured credential path; startup permits
30 seconds for initialization. sing-box 1.12.22 source confirms URL-test stops
periodic probing after idle timeout, so the controller now performs a live
`/proxies/auto/delay` test before consuming history. The same source confirms
remote rule sets can load from `experimental.cache_file`; this is now enabled
for compatibility routing and tested by starting online, stopping the rule-set
origin, then successfully restarting the core from cache. When persistent
fallback is enabled, the database lives beside `last-known-good.json`; otherwise
it lives in `run_dir`.

Retained deliberate differences: deterministic tag ordering avoids restarts
caused solely by TCP-rank noise; sing-box tunnel URL tests make the final choice.
TCP timing alone is not claimed to measure throughput. The inspected reconnect
callback (`ev_c9842982bdce9fb00a6e7c5d983e5d63fe2688cd9740ee80943f2228aa5863ca`)
handles a user-confirmed mode change, not an unattended recovery algorithm.
The headless retry policy therefore remains a project design choice.

OpenWrt boundary: automatic TUN capture is currently global. The future
`maggie-cn`/VLAN10 deployment requires source-scoped capture plus explicit DNS,
IPv6 and failure policy; adding an SSID alone does not establish isolation.
Device configuration is deferred to the separate AP design task. No AP was
modified during this pass. Live account authentication, vendor-side session
limits, and throughput under real network faults remain unobserved.

