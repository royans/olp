#!/usr/bin/env bash
# ==============================================================================
# Bootstrap & Lifecycle Script for `olp-server`
# Handles auto-updates on restart, graceful lifecycles, and binary detection.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OLP_DATA_DIR="${OLP_HOME:-$HOME/.olp}"
PID_FILE="$OLP_DATA_DIR/olp-server.pid"
NEED_RECOMPILE=0

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
    if [ -x "$SCRIPT_DIR/olp-server" ]; then
        echo "$SCRIPT_DIR/olp-server"
        return 0
    fi
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
# 2. Git Auto-Update Logic
# ------------------------------------------------------------------------------
auto_update_from_git() {
    if [ -d ".git" ] && command -v git >/dev/null 2>&1; then
        if git remote get-url origin >/dev/null 2>&1; then
            echo "[olp-server] Checking for repository updates from git..."
            local HEAD_BEFORE
            HEAD_BEFORE=$(git rev-parse HEAD 2>/dev/null || true)
            # Try fast-forward pull
            if git pull --ff-only -q 2>/dev/null || git pull --ff-only -q origin main 2>/dev/null; then
                local HEAD_AFTER
                HEAD_AFTER=$(git rev-parse HEAD 2>/dev/null || true)
                if [ -n "$HEAD_BEFORE" ] && [ -n "$HEAD_AFTER" ] && [ "$HEAD_BEFORE" != "$HEAD_AFTER" ]; then
                    echo "[olp-server] Successfully pulled new updates (${HEAD_BEFORE:0:7} -> ${HEAD_AFTER:0:7}). Recompiling binary..."
                    NEED_RECOMPILE=1
                else
                    echo "[olp-server] Code is already up to date (${HEAD_BEFORE:0:7})."
                fi
            else
                echo "[olp-server] Note: Could not pull latest git commits (offline or local modifications). Continuing."
            fi
        fi
    fi
}

# ------------------------------------------------------------------------------
# 3. Process Lifecycle Management (Status / Stop / Restart / Update)
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
elif [ "$ACTION" = "update" ]; then
    auto_update_from_git
    if [ "$NEED_RECOMPILE" -eq 1 ] || [ ! -x "$SCRIPT_DIR/target/release/olp-server" ]; then
        echo "[olp-server] Compiling release binary..."
        cargo build --release --bin olp-server
    fi
    echo "[olp-server] Update complete."
    exit 0
elif [ "$ACTION" = "restart" ]; then
    stop_process
    auto_update_from_git
    shift || true
elif pid=$(is_running); then
    # Running without 'restart' flag: check if user passed query arguments
    case "${1:-}" in
        --show-pubkey|--set-proxy-key|-h|--help|-V|--version)
            # Allow query commands to proceed without conflicting with the running daemon
            ;;
        *)
            echo "[olp-server] Already running (PID: $pid)."
            echo "  To restart & auto-update:  ./start-server.sh restart"
            echo "  To update code now:        ./start-server.sh update"
            echo "  To stop:                   ./start-server.sh stop"
            echo "  To check:                  ./start-server.sh status"
            exit 0
            ;;
    esac
fi

# ------------------------------------------------------------------------------
# 4. Ensure Build Dependencies & Compile if not yet built or updated
# ------------------------------------------------------------------------------
BIN_PATH=""
if [ "$NEED_RECOMPILE" -eq 0 ] && BIN_PATH=$(find_compiled_binary); then
    echo "[olp-server] Using compiled binary at $BIN_PATH"
else
    if [ "$NEED_RECOMPILE" -eq 1 ]; then
        echo "[olp-server] Recompiling updated binary..."
    else
        echo "[olp-server] Compiled binary not found. Checking build prerequisites..."
    fi

    # Check for C linker (cc / gcc / clang)
    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
        echo "[olp-server] C compiler/linker (cc/gcc) not found."

        # Attempt to download pre-built release binary from GitHub Releases (no sudo needed!)
        mkdir -p "$SCRIPT_DIR/target/release"
        local ARCH OS_NAME DOWNLOAD_URL
        ARCH="$(uname -m)"
        case "$(uname -s)" in
            Linux*)  OS_NAME="linux" ;;
            Darwin*) OS_NAME="darwin" ;;
            *)       OS_NAME="unknown" ;;
        esac
        DOWNLOAD_URL="https://github.com/royans/olp/releases/latest/download/olp-server-${OS_NAME}-${ARCH}"
        echo "[olp-server] Attempting to download pre-built binary from GitHub Releases ($DOWNLOAD_URL)..."
        if command -v curl >/dev/null 2>&1 && curl -sSfL "$DOWNLOAD_URL" -o "$SCRIPT_DIR/target/release/olp-server" 2>/dev/null; then
            chmod +x "$SCRIPT_DIR/target/release/olp-server"
            echo "[olp-server] Successfully downloaded pre-compiled binary! Skipping compilation."
            BIN_PATH="$SCRIPT_DIR/target/release/olp-server"
            return 0
        fi

        # If download is not available, check if sudo is available
        local HAS_SUDO=0
        if command -v sudo >/dev/null 2>&1; then
            if sudo -n true 2>/dev/null || sudo -v 2>/dev/null; then
                HAS_SUDO=1
            fi
        fi

        if [ "$HAS_SUDO" -eq 1 ] && [ -f /etc/os-release ]; then
            . /etc/os-release
            case "${ID:-}" in
                ubuntu|debian|linuxmint|pop)
                    echo "[olp-server] Installing build-essential via sudo..."
                    DEBIAN_FRONTEND=noninteractive sudo apt-get update -qq >/dev/null 2>&1 || true
                    DEBIAN_FRONTEND=noninteractive sudo apt-get install -y -qq build-essential curl ca-certificates >/dev/null 2>&1 || true
                    ;;
                fedora|rhel|centos|almalinux|rocky|amzn)
                    echo "[olp-server] Installing gcc via sudo..."
                    if command -v dnf >/dev/null 2>&1; then
                        sudo dnf install -y gcc curl ca-certificates || true
                    else
                        sudo yum install -y gcc curl ca-certificates || true
                    fi
                    ;;
                alpine)
                    echo "[olp-server] Installing build-base via sudo..."
                    sudo apk add --no-cache build-base curl ca-certificates || true
                    ;;
                arch|manjaro)
                    echo "[olp-server] Installing base-devel via sudo..."
                    sudo pacman -Sy --noconfirm base-devel curl ca-certificates || true
                    ;;
            esac
        fi

        # If cc is still missing after attempts:
        if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
            echo ""
            echo "================================================================================"
            echo "  [olp-server] Cannot compile from source without a C compiler/linker (cc/gcc)"
            echo "  and user '$USER' does not have sudo privileges to install packages."
            echo ""
            echo "  SOLUTION: You don't need to compile on this machine! Simply copy the precompiled"
            echo "  binary from your local machine to this host:"
            echo ""
            echo "    scp target/release/olp-server $USER@$(hostname):~/olp/"
            echo ""
            echo "  Once copied, run ./start-server.sh and it will start immediately with ZERO sudo."
            echo "================================================================================"
            echo ""
            exit 1
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
# 5. Launch with PID Tracking & Graceful Cleanup
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
