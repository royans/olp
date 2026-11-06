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
# 1. Detect if compiled binary already exists and is up to date
# ------------------------------------------------------------------------------
is_binary_outdated() {
    local bin="$1"
    if [ ! -f "$bin" ]; then
        return 0
    fi
    if [ -d "$SCRIPT_DIR/src" ]; then
        local newer
        newer=$(find "$SCRIPT_DIR/src" "$SCRIPT_DIR/Cargo.toml" -type f -newer "$bin" 2>/dev/null | head -n 1)
        if [ -n "$newer" ]; then
            return 0
        fi
    fi
    return 1
}

find_compiled_binary() {
    for candidate in \
        "$SCRIPT_DIR/olp-server" \
        "$SCRIPT_DIR/target/release/olp-server" \
        "$SCRIPT_DIR/target/debug/olp-server" \
        "$HOME/.cargo/bin/olp-server"; do
        if [ -x "$candidate" ]; then
            if is_binary_outdated "$candidate"; then
                echo "[olp-server] Existing binary at $candidate is older than source files. Recompilation needed." >&2
                NEED_RECOMPILE=1
                return 1
            fi
            echo "$candidate"
            return 0
        fi
    done
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
        -h|--help|-V|--version|--init-only|--non-interactive)
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

# Auto-check git updates on launch
auto_update_from_git

# ------------------------------------------------------------------------------
# 4. Resolve Binary: Try User-Space First, Explain Root Needs & Fail Fast
# ------------------------------------------------------------------------------
BIN_PATH=""
if [ "$NEED_RECOMPILE" -eq 0 ] && BIN_PATH=$(find_compiled_binary); then
    echo "[olp-server] Using compiled binary at $BIN_PATH"
else
    # 4a. Try downloading pre-built static binary from GitHub (requires ZERO root)
    if [ "$NEED_RECOMPILE" -eq 0 ]; then
        mkdir -p "$SCRIPT_DIR/target/release"
        ARCH="$(uname -m)"
        case "$(uname -s)" in
            Linux*)  OS_NAME="linux" ;;
            Darwin*) OS_NAME="darwin" ;;
            *)       OS_NAME="unknown" ;;
        esac
        DOWNLOAD_URL="https://github.com/royans/olp/releases/latest/download/olp-server-${OS_NAME}-${ARCH}"
        if command -v curl >/dev/null 2>&1; then
            echo "[olp-server] Compiled binary not found locally. Attempting user-space download from GitHub ($DOWNLOAD_URL)..."
            if curl -sSfL "$DOWNLOAD_URL" -o "$SCRIPT_DIR/target/release/olp-server" 2>/dev/null; then
                chmod +x "$SCRIPT_DIR/target/release/olp-server"
                echo "[olp-server] Download successful! Starting pre-compiled binary without root."
                BIN_PATH="$SCRIPT_DIR/target/release/olp-server"
            fi
        fi
    fi

    # 4b. If still no binary, we must compile from source
    if [ -z "$BIN_PATH" ]; then
        # Check for system C compiler/linker (cc/gcc/clang)
        if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
            # FAIL FAST & EXPLAIN EXACTLY WHAT IS NEEDED AS ROOT
            PKG_CMD="sudo apt install build-essential"
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                case "${ID:-}" in
                    fedora|rhel|centos|almalinux|rocky|amzn) PKG_CMD="sudo dnf install gcc" ;;
                    alpine) PKG_CMD="sudo apk add build-base" ;;
                    arch|manjaro) PKG_CMD="sudo pacman -S base-devel" ;;
                    *) PKG_CMD="sudo apt install build-essential (or equivalent C compiler)" ;;
                esac
            fi

            echo ""
            echo "================================================================================"
            echo "  [olp-server] ROOT PRIVILEGES REQUIRED TO COMPILE ON THIS MACHINE"
            echo "================================================================================"
            echo "  To compile olp from source code, the system linker (gcc/cc) is missing."
            echo ""
            echo "  What requires root:"
            echo "    A system C compiler package must be installed once by an administrator."
            echo "    Run as root / with sudo:"
            echo ""
            echo "      $PKG_CMD"
            echo ""
            echo "  ----------------------------------------------------------------------------"
            echo "  HOW TO RUN WITHOUT ROOT (RECOMMENDED):"
            echo "  ----------------------------------------------------------------------------"
            echo "  You do NOT need to install anything as root on this server."
            echo "  Simply copy the binary from a machine that already has it built:"
            echo ""
            echo "    scp target/release/olp-server $USER@$(hostname):~/olp/"
            echo ""
            echo "  Then re-run ./start-server.sh. It will detect it and start with zero root."
            echo "================================================================================"
            echo ""
            exit 1
        fi

        # 4c. Compiler is present: Install Rust user-space toolchain if needed (ZERO root!)
        if [ -f "$HOME/.cargo/env" ]; then
            # shellcheck disable=SC1091
            . "$HOME/.cargo/env"
        fi

        if ! command -v cargo >/dev/null 2>&1; then
            echo "[olp-server] Installing minimal Rust toolchain in user-space (~/.cargo) without root..."
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --quiet
            # shellcheck disable=SC1091
            . "$HOME/.cargo/env"
        fi

        echo "[olp-server] Compiling release binary in user-space..."
        cargo build --release --bin olp-server
        BIN_PATH="$SCRIPT_DIR/target/release/olp-server"
    fi
fi

# ------------------------------------------------------------------------------
# 5. Launch with PID Tracking & Graceful Cleanup
# ------------------------------------------------------------------------------
mkdir -p "$OLP_DATA_DIR"
chmod 0700 "$OLP_DATA_DIR" 2>/dev/null || true

# If config does not exist yet and stdin is a TTY, run first-time setup in foreground
CONFIG_FILE="${OLP_CONFIG:-$OLP_DATA_DIR/server.toml}"
if [ ! -f "$CONFIG_FILE" ] && [ -t 0 ]; then
    "$BIN_PATH" --init-only
fi

# Run binary replacing this shell with full TTY control
echo $$ > "$PID_FILE"
exec "$BIN_PATH" "$@"
