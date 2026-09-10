#!/bin/sh
set -eu
umask 077
cd "$(dirname "$0")/.."
native_target=$(rustc -vV | sed -n 's/^host: //p')
case "$native_target" in ''|*[!a-zA-Z0-9_-]*) echo 'FAIL invalid native target' >&2; exit 1 ;; esac
case "$native_target" in
  *-apple-darwin|*-unknown-linux-gnu|*-unknown-linux-musl) ;;
  *) echo 'BLOCKED: development packaging supports native macOS and Linux builds only; no Windows installer is implemented' >&2; exit 2 ;;
esac
cargo build --release --workspace --locked --target "$native_target"
mkdir -p "dist/$native_target"
cp "target/$native_target/release/mosaic-client" "target/$native_target/release/mosaic-relay" "dist/$native_target/"
cp README.md configs/client.example.json configs/client-node.example.json configs/relay.example.json "dist/$native_target/"
cp Mosaic_Prototype_Plan_v2.docx fixes.md "dist/$native_target/"
mkdir -p "dist/$native_target/docs/session" "dist/$native_target/docs/isolation" "dist/$native_target/docs/testing" "dist/$native_target/docs/egress" "dist/$native_target/docs/dns" "dist/$native_target/tools/network"
cp docs/session/README.md "dist/$native_target/docs/session/"
cp docs/isolation/README.md "dist/$native_target/docs/isolation/"
cp docs/testing/README.md "dist/$native_target/docs/testing/"
cp docs/egress/README.md "dist/$native_target/docs/egress/"
cp docs/dns/README.md "dist/$native_target/docs/dns/"
cp tools/network/baseline.py tools/network/isolation.py tools/network/forwarding.py tools/network/egress.py tools/network/dns.py tools/network/no_escape.py "dist/$native_target/tools/network/"
cp tools/network/ownership.py tools/network/fail2ban.py tools/network/preservation_guard.py "dist/$native_target/tools/network/"
mkdir -p "dist/$native_target/tests"
cp tests/manifest.json "dist/$native_target/tests/"
cp configs/node-baseline.example.json "dist/$native_target/"
chmod 755 "dist/$native_target/mosaic-client" "dist/$native_target/mosaic-relay"
"dist/$native_target/mosaic-client" --version
"dist/$native_target/mosaic-client" check-config -c "dist/$native_target/client.example.json" --schema-only
echo 'PASS: native development bundle built; desktop VPN installers and compiled relay setup remain BLOCKED'
