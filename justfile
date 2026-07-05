set dotenv-load

target := "aarch64-unknown-linux-musl"

# Cross-compile for the UDM (aarch64-musl). Uses cargo-zigbuild if installed otherwise falls back to cross.
build-udm:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v cargo-zigbuild >/dev/null; then
        echo "Using cargo-zigbuild"
        cargo zigbuild --release --target {{target}}
    elif command -v cross >/dev/null; then
        echo "Using cross"
        cross build --release --target {{target}}
    else
        echo "Neither cargo-zigbuild nor cross found." >&2
        echo "Install one: cargo install cargo-zigbuild (+ zig), or cargo install cross" >&2
        exit 1
    fi
    echo "Binary: target/{{target}}/release/unifi-rampart"

# Push the built binary + config to the UDM. Reads UDM_HOST, UDM_USER (default root),
# UDM_PASS, UDM_PATH (default /data/custom/unifi-rampart) from .env
sync: build-udm
    SSHPASS="${UDM_PASS}" sshpass -e scp -o StrictHostKeyChecking=accept-new \
        target/{{target}}/release/unifi-rampart config.toml \
        "${UDM_USER:-root}@${UDM_HOST}:${UDM_PATH:-/data/custom/unifi-rampart}/"
