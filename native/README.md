# Native VPN components

Mosaic now has native client implementations for macOS, Windows, Linux, iOS and Android. They use the existing Rust QUIC, TLS, authorization and packet code. Installed-device acceptance is still required; compiling a target does not certify traffic protection on that operating system.

| Platform target | Integration | Package | Verification available here |
| --- | --- | --- | --- |
| macOS 14+, Apple silicon and Intel | Network Extension packet tunnel system extension, shared Keychain, on-demand connection | Developer ID signed and notarized PKG | Both application and extension compile; signing assets and installation tests unavailable |
| Windows 10 2004+, x64 | Wintun, restricted named-pipe service, IP Helper, persistent and boot-time WFP filters | Signed MSI containing the official signed Wintun DLL | GNU cross-build passes; MSVC installer and Windows runtime tests unavailable |
| Linux, x64, systemd and systemd-resolved | Exclusive TUN, nftables protection, marked outer sockets, owned policy table, restricted Unix socket | Compiled installation bundle | musl cross-build passes; dedicated Linux runtime tests unavailable |
| iOS 17+, arm64 | Network Extension packet tunnel app extension, shared Keychain, on-demand connection | Provisioned IPA | Application and extension compile; signing assets and device tests unavailable |
| Android 10+, arm64 and x64 | VpnService, protected network-bound sockets, Android Keystore, system lockdown | APK | Both Rust libraries, Java/JNI, APK and lint pass; device tests unavailable |

These are implementation targets, not a list of certified releases. Windows ARM, 32-bit Android and other operating systems are not currently packaged.

## Configuration and connection

Export an existing valid diagnostic configuration into a new private file:

```sh
./mosaic-client export-config -c client.json --output client.mosaic
```

The export embeds the client token and relay trust certificate. It never contains the relay private key. Keep the file private and remove transfer copies after import. Export refuses an existing destination and refuses a shared-node isolated configuration. The example address is `10.77.0.2/30`, with relay peer `10.77.0.1`; the deployed relay must use the matching tunnel subnet and existing authenticated tunnel service with working Internet forwarding.

Desktop normal operation uses these commands after installation:

```sh
./mosaic-client import -c client.mosaic
./mosaic-client connect
./mosaic-client status
./mosaic-client disconnect
```

Do not run host-mode setup on the shared VPN test servers. Their existing isolated namespace and preservation-monitor commands remain required. The compiled client does not provision a remote relay or replace the existing relay administration tools.

On macOS, install the signed PKG and activate the system extension:

```sh
/Applications/Mosaic.app/Contents/MacOS/mosaic-client setup
/Applications/Mosaic.app/Contents/MacOS/mosaic-client import -c "$HOME/client.mosaic"
/Applications/Mosaic.app/Contents/MacOS/mosaic-client connect
/Applications/Mosaic.app/Contents/MacOS/mosaic-client status
```

Approve Mosaic in macOS system settings when requested. An ad-hoc development signature cannot install this Network Extension. This Mac currently has no valid signing identity or matching provisioning profiles, so the unsigned build cannot provide a live macOS VPN test.

On a dedicated Linux installation, extract the bundle, then run `sudo ./mosaic-client setup --user YOUR_NUMERIC_UID`. The compiled installer installs and starts its system service. Subsequent import, connect, status and disconnect run as that ordinary user. Repeat setup while disconnected to repair or upgrade the owned installation; it verifies the saved binary hashes before replacement. Run `sudo /usr/local/lib/mosaic/mosaic-client uninstall` while disconnected to remove it. Linux requires `ip`, `nft`, `resolvectl`, and `systemctl` in their standard system paths.

On Windows, install `Mosaic.msi`, then run the commands above from `C:\Program Files\Mosaic`. Setup approval occurs in the installer. The named pipe permits only the installed user, administrators and SYSTEM. MSI removal and upgrade require explicit disconnect first. Service ownership is checked before repair or removal. Wintun is loaded only from the protected installation directory.

On iOS and Android, import the private file in the app and use Connect, Disconnect and status. Android requires approval through `VpnService.prepare`, followed by enabling both **Always-on VPN** and **Block connections without VPN** for Mosaic in Android VPN settings. On Android, explicit disconnect opens those settings; disable those two options to release the system's traffic restriction. Android deliberately retains its lockdown policy when an app crashes or stops. Do not enable another VPN concurrently for these acceptance tests.

## Protection and recovery

The inner tunnel is IPv4-only, MTU 1100, with DNS at `1.1.1.1`. IPv6 is blocked rather than advertised as supported. The shared engine verifies relay TLS before sending the token, authorizes every new connection, uses bounded queues, discards stale packets and retries transient failures with jitter over 1, 2, 4 and 8 seconds, capped at 8 seconds. Invalid identity, credentials or configuration stop retries. Connected status requires native routing and DNS readiness.

Apple uses `includeAllNetworks` and on-demand connection. The system owns tunnel routing and DNS, and provider transport sockets stay outside the tunnel. The system's documented platform exceptions still apply, including required DHCP and captive-network traffic. See [Apple's VPN routing rules](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic). Public IPv6 blocking, provider termination, reboot, sleep and wake must be verified on installed devices.

Windows installs persistent WFP protection before creating the adapter and separate boot-time transport filters. It permits loopback, the owned IPv4 tunnel, the service's relay UDP flow and DHCP broadcast. Ordinary public IPv6 is blocked. Other firewalls can still block the permitted traffic. Filter snapshots retain ownership and compare conditions, actions and priorities before recovery or removal.

Linux permits loopback, the marked relay UDP flow, the owned tunnel and DHCP broadcast. Its `not fwmark` rule selects table 19791 at priority 10990. The outer socket follows the existing underlying routing policy, binds to that interface and never replaces the host's original default route. DNS belongs only to the temporary tunnel link. Disconnect deletes only verified owned state; dropping the exclusive link releases its resolver state. External changes cause a cleanup error with protection retained. If a crash happens between firewall installation and saving its ownership snapshot, inspect the named Mosaic table rather than deleting unrelated firewall rules.

Linux host mode can carry narrowly defined traffic exceptions, for a host that also serves other users. Add them to the private configuration before export:

```json
"exceptions": {"inbound_replies": true, "services": ["xray.service"]}
```

- **`inbound_replies`** sends replies on connections that a remote peer opened, such as SSH or a hosted service, through the original interface.
- **`services`** sends all traffic from up to eight named systemd services in `system.slice` through the original interface.

These rules live in the owned `inet mosaic_exempt` route table, which marks matching packets with the relay mark. The protection table then admits marked packets.

- **Foreign marks.** The table first clears the Mosaic mark from any packet that is not relay transport, and it only marks packets that carry no other mark. Another program cannot borrow the exception by setting the mark itself, and marks set by other tools such as WireGuard are left alone.
- **Tamper check.** The service compares the table with a saved copy every two seconds.

- **Service restarts.** The table is rebuilt within two seconds of a named service restarting, so a new cgroup is matched again.
- **Resolver traffic.** The exceptions do not change the resolver. A named service that uses the system resolver still sends its lookups through the tunnel.
- **Other operating systems.** Exceptions are rejected outside Linux.
- **What leaves directly.** Exempted traffic, including IPv6 replies and service traffic, leaves through the original interface. Everything else stays in the tunnel, and other IPv6 stays blocked.
- **Service scope.** A service exception covers every process the service starts, and any proxy it offers to local users. Exempt only services whose direct traffic is intended.
- **Supported services.** Template units (`name@instance.service`) are not supported. Service exceptions need the unified cgroup v2 hierarchy, and nftables `socket cgroupv2` matching on output, which needs Linux 5.13 or newer.

Setup refuses strict reverse-path filtering (`rp_filter=1`) on the relay path, because strict filtering would drop relay replies. Use loose mode (`2`).

Android omits the IPv6 address family, uses `protect` and binds each relay socket to the chosen non-VPN network. VPN preparation and system lockdown are required before connection. The manifest's narrowly scoped `ForegroundServicePermission` lint suppression follows the documented VPN eligibility for [the system-exempted foreground service type](https://developer.android.com/develop/background-work/services/fgs/service-types#system-exempted); Mosaic does not request unrelated alarm permissions. Backups and device transfers exclude configuration data.

Desktop service connection intent and credential-directory ownership survive service restarts. Abrupt shutdown retains traffic protection. Cleanup conflicts are reported instead of restoring a whole-machine snapshot. No native runtime invokes Python or offers arbitrary privileged command execution.

## Build packages

These commands are for developers. End users install the resulting package without a compiler, source checkout or Python.

```sh
python3 scripts/package-native.py macos --unsigned --output dist/native/mac-development
python3 scripts/package-native.py macos --unsigned --target x86_64-apple-darwin --output dist/native/mac-intel-development
python3 scripts/package-native.py ios --unsigned --output dist/native/ios-development
python3 scripts/package-native.py linux --output dist/native/linux-package
python3 scripts/package-native.py windows --identity CERTIFICATE_THUMBPRINT --output dist/native/windows-package
python3 scripts/package-native.py android --unsigned --sdk ANDROID_SDK_PATH --output dist/native/android-development
```

Use a new output directory for each invocation. Install Rust targets before cross-building. Linux packaging expects a native Linux build environment or an explicitly configured cross toolchain. With cargo-zigbuild installed, use `--zig --target x86_64-unknown-linux-musl` for the Linux build from macOS. Windows packaging runs on Windows with the MSVC build tools, Windows SDK `signtool` and WiX CLI. The builder downloads Wintun 0.14.1 from its official distribution, verifies its fixed SHA-256, includes its license and verifies the driver's signature.

Apple release builds require `--team`, `--identity`, `--app-profile` and `--extension-profile`, with bundle identifiers matching `--bundle` and its `.tunnel` extension. macOS also requires `--installer-identity` and `--notary-profile`. For iOS, use `python3 scripts/package-native.py ios` with those Apple signing arguments and a new `--output` directory. Full Xcode and the iPhoneOS SDK are required; if `xcode-select -p` shows Command Line Tools, prefix the command with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`. App Store, development and ad-hoc provisioning have different device and distribution restrictions; use profiles appropriate to the intended devices.

Android builds require JDK 17 or newer, Gradle 9.7.1, Android Gradle Plugin 9.4.0, platform SDK 37, build tools 36.0.0, NDK 28.2.13676358, CMake 3.22.1 and Rust `aarch64-linux-android` / `x86_64-linux-android` targets. Native libraries use 16 KiB load alignment. `--unsigned` selects a debug-signed APK for local installation. Release signing takes `--keystore`, `--key-alias`, and the `MOSAIC_STORE_PASSWORD` / `MOSAIC_KEY_PASSWORD` environment variables. Passwords are never placed in command arguments.

Each build writes `build.json` with source revision/content hash, dependency lock hash, build OS/architecture and package hashes. Acceptance remains BLOCKED until installed-device evidence exists. Development packages are not signed release deliveries.

## Tests

With your other VPN off, these local tests are safe to run on macOS; they use loopback QUIC and disposable credentials, without changing host routes or DNS:

```sh
cargo test -p mosaic-core --test native_connection
cargo test -p mosaic-native --lib
python3 scripts/check.py 5 --local-only
```

The connection tests include three actual 20-second loopback relay outages, each followed by fresh authentication within 45 seconds. These tests exercise the shared engine, not OS firewall behavior.

After installing a properly signed macOS package on a dedicated test Mac and importing a reachable relay configuration, connect and check ordinary networking:

```sh
/Applications/Mosaic.app/Contents/MacOS/mosaic-client connect
/Applications/Mosaic.app/Contents/MacOS/mosaic-client status
curl --max-time 15 https://api.ipify.org
curl --max-time 15 https://ifconfig.me/ip
dscacheutil -q host -a name example.com
scutil --dns
curl -6 --max-time 10 https://api64.ipify.org
/Applications/Mosaic.app/Contents/MacOS/mosaic-client disconnect
```

Both IPv4 results must match an independently measured relay address; public IPv6 must fail while connected. Also load ordinary HTTPS sites in a browser. Resolver output alone does not prove DNS protection: use packet captures on the underlying interface and tunnel during DNS queries, startup, three relay outages, abrupt provider/service termination, sleep/wake and network changes. Check explicit disconnect restores ordinary networking and removes only Mosaic's state. Follow every installed-device assertion in `tests/manifest.json`; passing these few commands alone is insufficient.

For the Android development APK built here:

```sh
adb install -r dist/native/testing/android/Mosaic.apk
adb shell am start -n net.mosaic.client/.MainActivity
```

Use an attached dedicated device, import the private configuration and approve its VPN settings. Device tests, Windows installer execution, Apple signed installation and the existing relay delivery gaps remain unverified. No public deployment or existing VPN configuration was changed by these builds.

Replace credentials by disconnecting, provisioning a fresh certificate/token on the relay through its existing secure administration path, exporting a fresh private file, and importing it. The client continues to validate certificate name and lifetime during TLS; short-lived fixture certificates are not production provisioning.
