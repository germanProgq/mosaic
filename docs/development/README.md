# Development

[Mosaic](../../README.md) › Docs › Development

How to build Mosaic, run the local checks and package the diagnostic bundle. Rust is pinned to 1.96.0, with resolved dependencies in `Cargo.lock`.

> [!NOTE]
> Developer scripts use the Python 3 and OpenSSL already present on the machine. They never install packages on a shared Linux node.

**Contents:** [Build and check](#build-and-check) · [Check levels](#check-levels) · [What the checks cover](#what-the-checks-cover) · [Diagnostic bundle](#diagnostic-bundle) · [Repository layout](#repository-layout) · [Secrets](#secrets)

## Build and check

Build the workspace, run the local checks, then the deployment checks:

```sh
cargo build --workspace --locked
python3 scripts/check.py 5 --local-only
python3 scripts/check.py 5
```

| Command | Result |
| --- | --- |
| `check.py N --local-only` | Returns 0 only for successful local checks, with `scope: local-only` and `deployment_status: BLOCKED`. |
| `check.py N` | Returns 2 while live gates are incomplete. |

The runner deliberately cannot certify live deployment from hand-authored evidence files. The required live assertions are listed in [`tests/manifest.json`](../../tests/manifest.json).

## Check levels

The number passed to `check.py` selects how much to check.

| Level | Checks |
| --- | --- |
| `0` | Setup |
| `1` | QUIC connectivity |
| `2` | Authentication and framing |
| `3` | Isolated TUN |
| `4` | Internet forwarding and native fetch |
| `5` | Namespace DNS and routing |
| `6`–`9` | Planned features |

Higher levels also run the shared reconnect and native bridge tests. Unfinished platform acceptance stays BLOCKED, and missing tests are never treated as passes.

> [!NOTE]
> The original plan's `scripts/check.sh` is now `python3 scripts/check.py`, and `scripts/node-baseline.sh` is now `python3 tools/network/baseline.py`.

## What the checks cover

- **Static checks:** formatting, Clippy and native builds.
- **Rust tests:** config and credentials, session rejection, captured handshake and real loopback QUIC.
- **QUIC tests:** the full echo matrix, real TLS trust, name and ALPN rejections, silent UDP timeout, rejected streams and fresh relay restart.
- **Native command-line tests:** launch and stop exact child relay processes, verify reports and check UDP port release.
- **Python tests:** command-line and monitor tests.
- **Repetition:** tests run twice with fresh processes. Each subprocess has a deadline.
- **Output:** logs and JSON reports go to owner-only `results/checks-*/` directories.
- **Credentials:** local tests generate disposable certificates in temporary directories and remove them afterwards.

## Diagnostic bundle

Build the diagnostic development bundle for the current macOS or Linux target:

```sh
./scripts/package.sh
```

The bundle contains compiled diagnostic binaries, credential-free examples, both requirement documents, the acceptance manifest and the Linux developer helpers with their preservation dependencies.

> [!IMPORTANT]
> This is not a desktop installer or a completed relay installation package. Windows packaging is blocked. Native VPN packages are built with `scripts/package-native.py`; see [native clients](../../native/README.md#build-packages).

- **Linux relay:** must be built on Linux, or with a separately verified cross-compilation setup.
- **macOS relay:** can validate configs and serve authenticated local fixtures. It is not a Linux deployment artifact.

## Repository layout

| Path | Contents |
| --- | --- |
| [`crates/`](../../crates) | Rust client, relay, shared protocol, native engine and Rust integration tests |
| [`native/`](../../native) | macOS and iOS Network Extension, Android VpnService and native packaging |
| [`configs/`](../../configs) | Tracked examples and ignored private deployment configuration |
| [`scripts/`](../../scripts) | Local checks, packaging and credential generation |
| [`tools/network/`](../../tools/network) | Linux baseline, listener ownership and Fail2Ban verification |
| [`tools/xray/`](../../tools/xray) | Representative Xray probes, staging, preservation and cleanup. `client/` holds the Go probe; `remote/` holds worker payloads |
| [`tests/`](../../tests) | Python command-line and monitor tests, plus the acceptance manifest |
| [`docs/`](..) | Guides, the session protocol and live test records |
| `dist/`, `target/`, `results/` | Ignored packages, build output and private run evidence |

## Secrets

Secrets, private configs, raw baselines, generated binaries and run evidence are ignored by Git. Example configs are safe to track.

> [!CAUTION]
> Never commit a relay private key or a private ready-to-use config.

## See also

- [Native clients](../../native/README.md)
- [Live test records](../testing/README.md)
- [Acceptance manifest](../../tests/manifest.json)
