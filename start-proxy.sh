#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Auto-enable git pre-commit security protections if running in a git repo
if [ -d ".git" ] && [ -d ".githooks" ]; then
    git config core.hooksPath .githooks 2>/dev/null || true
fi

BIN_PATH="$SCRIPT_DIR/target/release/olp-proxy"

ensure_build_deps() {
    if ! command -v cc >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
        echo "[olp-proxy] Installing system build prerequisites silently..."
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case "${ID:-}" in
                ubuntu|debian|linuxmint|pop)
                    DEBIAN_FRONTEND=noninteractive sudo apt-get update -qq >/dev/null 2>&1 || true
                    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq build-essential curl ca-certificates >/dev/null 2>&1
                    ;;
                fedora|rhel|centos|almalinux|rocky|amzn)
                    if command -v dnf >/dev/null 2>&1; then
                        sudo dnf install -y -q gcc curl ca-certificates >/dev/null 2>&1
                    else
                        sudo yum install -y -q gcc curl ca-certificates >/dev/null 2>&1
                    fi
                    ;;
                alpine)
                    sudo apk add --no-cache -q build-base curl ca-certificates >/dev/null 2>&1
                    ;;
                arch|manjaro)
                    sudo pacman -Sy --noconfirm --quiet base-devel curl ca-certificates >/dev/null 2>&1
                    ;;
            esac
        fi
    fi

    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        echo "[olp-proxy] Installing minimal Rust toolchain silently (first-time only)..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --quiet >/dev/null 2>&1
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi
}

if [ ! -x "$BIN_PATH" ]; then
    ensure_build_deps
    echo "[olp-proxy] Compiling release binary (first-time only)..."
    cargo build --release --quiet --bin olp-proxy
fi

exec "$BIN_PATH" "$@"

