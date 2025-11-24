#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Building bot-father WASM module..."

# Build for WASI Preview 2 (needed for HTTP)
cargo build --target wasm32-wasip2 --release

# Copy to output location
mkdir -p target/wasm
cp target/wasm32-wasip2/release/bot-father.wasm target/wasm/

echo "Build complete: target/wasm/bot-father.wasm"
ls -lh target/wasm/bot-father.wasm
