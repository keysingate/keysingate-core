#!/usr/bin/env bash
# Builds the browser page: crates/ksg-web-v2/web/pkg/ with the module and its
# JS glue. Needs the wasm32 target and wasm-bindgen-cli of the version in
# core-v2/Cargo.lock:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version <wasm-bindgen in Cargo.lock>
# Then the reader serves the page itself:
#   ksg-remote-panel --home DIR --mobile-web 127.0.0.1:8787 --web-root crates/ksg-web-v2/web COMMAND
# and prints the address to open, with its one-time token.
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release --target wasm32-unknown-unknown -p ksg-web-v2
WASM=../../target/wasm32-unknown-unknown/release/ksg_web_v2.wasm
wasm-bindgen --target web --out-dir web/pkg "$WASM"
