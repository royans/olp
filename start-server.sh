#!/usr/bin/env bash
# ==============================================================================
# Bootstrap & Lifecycle Script for `olp-server`
# Handles graceful restarts, pre-compiled binary detection, and build auto-provisioning.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OLP_DATA_DIR="${OLP_HOME:-$HOME/.olp}"
PID_FILE="$OLP_DATA_DIR/olp-server.pid"

# Auto-enable git pre-commit security protections if in a git repo
if [ -d ".git" ] && [ -d ".githooks" ]; then
    git config core.hooksPath .githooks 2>/dev/null || true
fi

# Load Cargo environment if present
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

# ------------------------------------------------------------------------------
# 1. Detect if compiled binary already exists
# ------------------------------------------------------------------------------
find_compiled_binary() {
    if [ -x "$SCRIPT_DIR/target/release/olp-server" ]; then
        echo "$SCRIPT_DIR/target/release/olp-server"
        return 0
    fi
    if [ -x "$SCRIPT_DIR/target/debug/olp-server" ]; then
        echo "$SCRIPT_DIR/target/debug/olp-server"
        return 0
    fi
    if [ -x "$HOME/.cargo/bin/olp-server" ]; then
        echo "$HOME/.cargo/bin/olp-server"
        return 0
    fi
    if command -v olp-server >/dev/null 2>&1; then
        command -v olp-server
        return 0
    fi
    return 1
}

# ------------------------------------------------------------------------------
# 2. Process Lifecycle Management (Status / Stop / Restart)
# ------------------------------------------------------------------------------
is_running() {
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null || true)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return 0
        fi
    fi
    # Fallback: check pgrep for running olp-server binary
    local pgrep_pid
    pgrep_pid=$(pgrep -x "olp-server" 2>/dev/null | head -n 1 || true)
    if [ -n "$pgrep_pid" ]; then
        echo "$pgrep_pid"
        return 0
    fi
    return 1
}

stop_process() {
    local pid
    if pid=$(is_running); then
        echo "[olp-server] Stopping running process (PID: $pid)..."
        kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..20}; do
            if ! kill -0 "$pid" 2>/dev/null; then
                rm -f "$PID_FILE"
                echo "[olp-server] Process stopped cleanly."
                return 0
            fi
            sleep 0.25
        done
        echo "[olp-server] Process did not terminate; forcing shutdown (SIGKILL)..."
        kill -9 "$pid" 2>/dev/null || true
        rm -f "$PID_FILE"
        echo "[olp-server] Process stopped."
    else
        echo "[olp-server] No running process found."
        rm -f "$PID_FILE"
    fi
}

# Handle CLI lifecycle subcommands (stop, restart, status)
ACTION="${1:-}"
if [ "$ACTION" = "stop" ]; then
    stop_process
    exit 0
elif [ "$ACTION" = "status" ]; then
    if pid=$(is_running); then
        echo "[olp-server] Running (PID: $pid)"
        exit 0
    else
        echo "[olp-server] Stopped"
        exit 1
    fi
elif [ "$ACTION" = "restart" ]; then
    stop_process
    shift || true
elif pid=$(is_running); then
    # Running without 'restart' flag: check if user passed arguments like --show-pubkey
    case "${1:-}" in
        --show-pubkey|--set-proxy-key|-h|--help|-V|--version)
            # Allow query commands to proceed without conflicting with the running daemon
            ;;
        *)
            echo "[olp-server] Already running (PID: $pid)."
            echo "  To restart:  ./start-server.sh restart"
            echo "  To stop:     ./start-server.sh stop"
            echo "  To check:    ./start-server.sh status"
            exit 0
            ;;
    esac
fi

# ------------------------------------------------------------------------------
# 3. Ensure Build Dependencies & Compile if not yet built
# ------------------------------------------------------------------------------
BIN_PATH=""
if BIN_PATH=$(find_compiled_binary); then
    echo "[olp-server] Detected compiled binary at $BIN_PATH"
else
    echo "[olp-server] Compiled binary not found. Checking build prerequisites..."

    # Check for C linker (cc / gcc / clang)
    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
        echo "[olp-server] C compiler/linker (cc/gcc) is required for building."
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            case "${ID:-}" in
                ubuntu|debian|linuxmint|pop)
                    echo "[olp-server] Installing build-essential..."
                    if sudo -n true 2>/dev/null; then
                        DEBIAN_FRONTEND=noninteractive sudo apt-get update -qq >/dev/null 2>&1 || true
                        DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq build-essential curl ca-certificates >/dev/null 2>&1
                    else
                        echo "[olp-server] Sudo password required to install build-essential:"
                        sudo apt-get update
                        sudo apt-get install -y build-essential curl ca-certificates
                    fi
                    ;;
                fedora|rhel|centos|almalinux|rocky|amzn)
                    echo "[olp-server] Installing gcc..."
                    if command -v dnf >/dev/null 2>&1; then
                        sudo dnf install -y gcc curl ca-certificates
                    else
                        sudo yum install -y gcc curl ca-certificates
                    fi
                    ;;
                alpine)
                    echo "[olp-server] Installing build-base..."
                    sudo apk add --no-cache build-base curl ca-certificates
                    ;;
                arch|manjaro)
                    echo "[olp-server] Installing base-devel..."
                    sudo pacman -Sy --noconfirm base-devel curl ca-certificates
                    ;;
                *)
                    echo "[olp-server] Warning: Unknown OS. Please install gcc/clang and curl manually."
                    ;;
            esac
        fi
    fi

    # Check for Rust (cargo)
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        echo "[olp-server] Installing minimal Rust toolchain silently (first-time only)..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --quiet
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    fi

    echo "[olp-server] Compiling release binary..."
    cargo build --release --bin olp-server
    BIN_PATH="$SCRIPT_DIR/target/release/olp-server"
fi

# ------------------------------------------------------------------------------
# 4. Launch with PID Tracking & Graceful Cleanup
# ------------------------------------------------------------------------------
mkdir -p "$OLP_DATA_DIR"
chmod 0700 "$OLP_DATA_DIR" 2>/dev/null || true

cleanup() {
    rm -f "$PID_FILE"
}
trap cleanup EXIT INT TERM

# Run binary in foreground, recording PID
"$BIN_PATH" "$@" &
CHILD_PID=$!
echo "$CHILD_PID" > "$PID_FILE"

# Wait for process to exit
wait "$CHILD_PID"
