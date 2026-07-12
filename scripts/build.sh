#!/usr/bin/env bash

set -e  

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build"
BINARY="$BUILD_DIR/cappp"

cd "$PROJECT_ROOT"

if [ ! -f "$BUILD_DIR/build.ninja" ]; then
    echo "==> No existing build found, configuring..."
    mkdir -p "$BUILD_DIR"
    cmake -S . -B "$BUILD_DIR" -G Ninja -DCMAKE_BUILD_TYPE=Release
else
    echo "==> Existing build found, skipping configure."
fi

echo "==> Building..."
cmake --build "$BUILD_DIR"

echo "==> Running tests..."
ctest --test-dir "$BUILD_DIR" --output-on-failure

echo "==> Setting capabilities on $BINARY..."
sudo setcap cap_net_raw,cap_net_admin=eip "$BINARY"

echo ""
echo "==> Build complete."
echo "    Run it with:  ./build/cappp -i <interface>"
echo "    Or replay:    ./build/cappp -r tests/fixtures/sample.pcap"
