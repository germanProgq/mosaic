#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo build --release --workspace --locked
native_target=$(rustc -vV | sed -n 's/^host: //p')
case "$native_target" in ''|*[!a-zA-Z0-9_-]*) echo 'FAIL invalid native target' >&2; exit 1 ;; esac
mkdir -p "dist/$native_target"
cp target/release/mosaic-client target/release/mosaic-relay "dist/$native_target/"
cp README.md configs/client.example.json configs/client-node.example.json configs/relay.example.json "dist/$native_target/"
mkdir -p "dist/$native_target/docs/session" "dist/$native_target/docs/isolation" "dist/$native_target/docs/testing" "dist/$native_target/tools/network"
cp docs/session/README.md "dist/$native_target/docs/session/"
cp docs/isolation/README.md "dist/$native_target/docs/isolation/"
cp docs/testing/README.md "dist/$native_target/docs/testing/"
cp tools/network/baseline.py tools/network/isolation.py "dist/$native_target/tools/network/"
cp configs/node-baseline.example.json "dist/$native_target/"
chmod 755 "dist/$native_target/mosaic-client" "dist/$native_target/mosaic-relay"
"dist/$native_target/mosaic-client" --version
"dist/$native_target/mosaic-client" check-config -c "dist/$native_target/client.example.json" --schema-only
