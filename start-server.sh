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
LOG_FILE="$OLP_DATA_DIR/server.log"
LOCK_FILE="$OLP_DATA_DIR/olp-server.lock"
NEED_RECOMPILE="${OLP_FORCE_RECOMPILE:-0}"
DAEMON_MODE=0
ORIG_ARGS=("$@")
CONFIG_FILE="${OLP_CONFIG:-$OLP_DATA_DIR/server.toml}"

# Parse daemon flag from arguments. Lifecycle verbs (restart/ensure) are consumed
# by this script and never forwarded to the binary (its CLI rejects positionals).
CLEAN_ARGS=()
EXPECT_CONFIG_VALUE=0
NON_INTERACTIVE=0
INIT_ONLY=0
HELP_OR_VERSION=""
for arg in "$@"; do
    if [ "$EXPECT_CONFIG_VALUE" -eq 1 ]; then
        CONFIG_FILE="$arg"
        EXPECT_CONFIG_VALUE=0
        CLEAN_ARGS+=("$arg")
        continue
    fi
    case "$arg" in
        --daemon|-d)
            DAEMON_MODE=1
            ;;
        restart|ensure)
            ;;
        --non-interactive)
            NON_INTERACTIVE=1
            CLEAN_ARGS+=("$arg")
            ;;
        --init-only)
            INIT_ONLY=1
            CLEAN_ARGS+=("$arg")
            ;;
        --help|-h|--version|-V)
            HELP_OR_VERSION="$arg"
            CLEAN_ARGS+=("$arg")
            ;;
        -c|--config)
            EXPECT_CONFIG_VALUE=1
            CLEAN_ARGS+=("$arg")
            ;;
        --config=*)
            CONFIG_FILE="${arg#--config=}"
            CLEAN_ARGS+=("$arg")
            ;;
        *)
            CLEAN_ARGS+=("$arg")
            ;;
    esac
done

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
# Reads `auto_git_pull` from the [maintenance] section of the config file.
# Missing file/key => enabled (default). "false"/"no"/"off"/"0" => disabled.
git_pull_enabled() {
    if [ ! -f "$CONFIG_FILE" ]; then
        return 0
    fi
    local val
    val=$(sed -n -E 's/^[[:space:]]*auto_git_pull[[:space:]]*=[[:space:]]*["'\'']?([A-Za-z0-9]+).*/\1/p' "$CONFIG_FILE" 2>/dev/null | tail -n 1 | tr '[:upper:]' '[:lower:]')
    case "$val" in
        false|no|n|off|0) return 1 ;;
    esac
    return 0
}

# Usage: auto_update_from_git [force]
#   Without "force", honours OLP_SKIP_GIT_PULL=1 and auto_git_pull in the config.
auto_update_from_git() {
    if [ "${1:-}" != "force" ]; then
        if [ "${OLP_SKIP_GIT_PULL:-0}" = "1" ]; then
            return 0
        fi
        if [ -d ".git" ] && ! git_pull_enabled; then
            echo "[olp-server] auto_git_pull is disabled in $CONFIG_FILE; skipping git pull."
            return 0
        fi
    fi
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

# ------------------------------------------------------------------------------
# Serialise lifecycle operations (watchdog vs. daily restart vs. manual runs) so
# the watchdog never launches a second copy while a restart is pulling/compiling.
# The lock fd (9) is closed before the binary is launched, so it is held only
# while this script is doing work.
# ------------------------------------------------------------------------------
acquire_lock() {
    local mode="$1"   # "try" => give up immediately if busy, "wait" => wait up to 15 min
    command -v flock >/dev/null 2>&1 || return 0
    mkdir -p "$OLP_DATA_DIR"
    exec 9>"$LOCK_FILE"
    if [ "$mode" = "try" ]; then
        flock -n 9
    else
        flock -w 900 9
    fi
}

# ------------------------------------------------------------------------------
# Cron management. Managed entries carry a marker comment so they can be found,
# left alone (keeping their randomized times) or upgraded in place.
#   @reboot              start on boot
#   every 15 min         `ensure`: start only if not running (no git pull)
#   once a day           `restart`: full restart, git pull if auto_git_pull=true
# Minutes/hour are randomized per host at install time to spread load.
# ------------------------------------------------------------------------------
CRON_MARKER="# olp-server-managed:$SCRIPT_DIR"

build_cron_entries() {
    local base="cd \"$SCRIPT_DIR\" && ./start-server.sh"
    local log=">> \"$LOG_FILE\" 2>&1"
    local off=$((RANDOM % 15))
    local daily_min=$((RANDOM % 60))
    local daily_hour=$((1 + RANDOM % 5))   # 01:00-05:59 local time
    printf '%s\n' \
        "@reboot $base --daemon $log $CRON_MARKER" \
        "$off,$((off + 15)),$((off + 30)),$((off + 45)) * * * * $base ensure $log $CRON_MARKER" \
        "$daily_min $daily_hour * * * $base restart --daemon $log $CRON_MARKER"
}

write_crontab() {
    # $1 = existing crontab with olp-server managed/legacy lines already removed
    local kept="$1" entries
    entries="$(build_cron_entries)"
    if [ -n "$kept" ]; then
        printf '%s\n%s\n' "$kept" "$entries" | crontab -
    else
        printf '%s\n' "$entries" | crontab -
    fi
    echo "$entries" | sed 's/^/    /'
}

install_managed_cron() {
    command -v crontab >/dev/null 2>&1 || {
        echo "[olp-server] Error: crontab command not found on this system." >&2
        return 1
    }
    local existing legacy kept
    existing="$(crontab -l 2>/dev/null || true)"
    legacy="@reboot cd $SCRIPT_DIR && ./start-server.sh --daemon"
    kept="$(printf '%s\n' "$existing" | grep -v -F -x -- "$legacy" | grep -v -F -- "$CRON_MARKER" || true)"
    echo "[olp-server] Installing managed cronjobs (watchdog every 15 min + daily 24h git pull/restart):"
    write_crontab "$kept"
    echo "[olp-server] [✓] Managed cronjobs successfully installed into crontab!"
}

uninstall_managed_cron() {
    command -v crontab >/dev/null 2>&1 || return 0
    local existing legacy kept
    existing="$(crontab -l 2>/dev/null || true)"
    legacy="@reboot cd $SCRIPT_DIR && ./start-server.sh --daemon"
    kept="$(printf '%s\n' "$existing" | grep -v -F -x -- "$legacy" | grep -v -F -- "$CRON_MARKER" || true)"
    if [ -n "$kept" ]; then
        printf '%s\n' "$kept" | crontab -
    else
        crontab -r 2>/dev/null || true
    fi
    echo "[olp-server] [✓] Managed cronjobs removed from crontab."
}

manage_cronjob() {
    command -v crontab >/dev/null 2>&1 || return 0
    local existing legacy managed kept
    existing="$(crontab -l 2>/dev/null || true)"
    legacy="@reboot cd $SCRIPT_DIR && ./start-server.sh --daemon"
    managed="$(printf '%s\n' "$existing" | grep -F -- "$CRON_MARKER" || true)"

    # Already fully installed: keep the existing randomized schedule.
    if printf '%s\n' "$managed" | grep -q -- "start-server.sh ensure" &&
       printf '%s\n' "$managed" | grep -q -- "start-server.sh restart" &&
       printf '%s\n' "$managed" | grep -q -- "^@reboot"; then
        return 0
    fi

    kept="$(printf '%s\n' "$existing" | grep -v -F -x -- "$legacy" | grep -v -F -- "$CRON_MARKER" || true)"

    # Upgrade the previously auto-installed @reboot entry (or a partial managed set).
    if [ -n "$managed" ] || printf '%s\n' "$existing" | grep -q -F -x -- "$legacy"; then
        echo "[olp-server] Upgrading olp-server cronjobs (watchdog every 15 min + daily restart):"
        write_crontab "$kept"
        return 0
    fi

    # Some other hand-written entry references this script: don't touch it.
    if printf '%s\n' "$existing" | grep -q -- "start-server.sh"; then
        return 0
    fi

    # Nothing installed yet: offer to install (interactive runs only).
    if [ "$DAEMON_MODE" -eq 0 ] && [ "$NON_INTERACTIVE" -eq 0 ] && [ -t 0 ]; then
        echo ""
        echo "================================================================================"
        echo "  [olp-server] Automated Cronjob Setup"
        echo "================================================================================"
        echo "  No crontab jobs were found for olp-server. Recommended schedule:"
        echo "    - start on reboot"
        echo "    - every 15 minutes: start it if it is not running"
        echo "    - once a day (random time 01:00-05:59): full restart, incl. git pull"
        echo "      (disable the pull with 'auto_git_pull = false' under [maintenance] in"
        echo "       $CONFIG_FILE)"
        echo ""
        read -r -p "  Would you like to install these cronjobs now? [y/N]: " cron_choice
        case "${cron_choice:-n}" in
            y|Y|yes|YES)
                write_crontab "$kept"
                echo "  [✓] Cronjobs successfully installed into crontab!"
                ;;
            *)
                echo "  Skipped. You can add them later via: crontab -e"
                ;;
        esac
        echo "================================================================================"
        echo ""
    fi
}

ACTION="${1:-}"
case "$ACTION" in
    status|-h|--help|-V|--version|cron|install-cron|uninstall-cron)
        ;;
    ensure)
        # Watchdog: if anything else holds the lock, a start/restart is in progress.
        if ! acquire_lock try; then
            exit 0
        fi
        ;;
    *)
        if ! acquire_lock wait; then
            echo "[olp-server] Another start/restart is still in progress (lock: $LOCK_FILE). Giving up." >&2
            exit 1
        fi
        ;;
esac

if [ "$ACTION" = "cron" ] || [ "$ACTION" = "install-cron" ]; then
    install_managed_cron
    exit 0
elif [ "$ACTION" = "uninstall-cron" ]; then
    uninstall_managed_cron
    exit 0
fi

if [ "$ACTION" = "ensure" ]; then
    if is_running >/dev/null; then
        exit 0
    fi
    echo "[olp-server] $(date '+%Y-%m-%d %H:%M:%S') Watchdog: process not running; starting it..."
    DAEMON_MODE=1
    OLP_SKIP_GIT_PULL=1
fi

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
    auto_update_from_git force
    if [ "$NEED_RECOMPILE" -eq 1 ] || [ ! -x "$SCRIPT_DIR/target/release/olp-server" ]; then
        echo "[olp-server] Compiling release binary..."
        cargo build --release --bin olp-server
    fi
    echo "[olp-server] Update complete."
    exit 0
fi

# Informational query commands do not terminate a running daemon
case "${1:-}" in
    -h|--help|-V|--version)
        ;;
    *)
        # Always terminate previous process for clean restart (cron & repeated run friendly)
        if pid=$(is_running); then
            echo "[olp-server] Existing process detected (PID: $pid). Terminating previous instance for clean restart..."
            stop_process
        fi
        if [ "${1:-}" = "restart" ]; then
            shift || true
        fi
        ;;
esac

# Auto-check git updates on launch (honours auto_git_pull in the config)
auto_update_from_git
if [ "$NEED_RECOMPILE" -eq 1 ] && [ "${OLP_SKIP_GIT_PULL:-0}" != "1" ] && [ "${OLP_REEXECED:-0}" != "1" ]; then
    # The pull may have changed this script; restart it so the new version runs.
    echo "[olp-server] Re-executing updated start-server.sh..."
    exec 9>&-
    exec env OLP_REEXECED=1 OLP_SKIP_GIT_PULL=1 OLP_FORCE_RECOMPILE=1 \
        "$SCRIPT_DIR/start-server.sh" ${ORIG_ARGS[@]+"${ORIG_ARGS[@]}"}
fi

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

# Handle immediate help / version / init-only flags
if [ -n "$HELP_OR_VERSION" ]; then
    exec "$BIN_PATH" "$HELP_OR_VERSION"
fi

if [ "$INIT_ONLY" -eq 1 ]; then
    exec "$BIN_PATH" ${CLEAN_ARGS[@]+"${CLEAN_ARGS[@]}"}
fi

# ------------------------------------------------------------------------------
# 5. Launch with PID Tracking & Graceful Cleanup
# ------------------------------------------------------------------------------
mkdir -p "$OLP_DATA_DIR"
chmod 0700 "$OLP_DATA_DIR" 2>/dev/null || true

# If config does not exist yet, run first-time setup
if [ ! -f "$CONFIG_FILE" ]; then
    if [ "$DAEMON_MODE" -eq 1 ] || [ "$NON_INTERACTIVE" -eq 1 ] || [ ! -t 0 -a ! -t 1 ]; then
        "$BIN_PATH" --init-only --non-interactive ${CLEAN_ARGS[@]+"${CLEAN_ARGS[@]}"}
    elif [ -t 0 ]; then
        "$BIN_PATH" --init-only ${CLEAN_ARGS[@]+"${CLEAN_ARGS[@]}"}
    fi
fi

# ------------------------------------------------------------------------------
# 6. Install / upgrade cronjobs (watchdog + daily restart)
# ------------------------------------------------------------------------------
manage_cronjob

if [ "$DAEMON_MODE" -eq 1 ] || [ ! -t 0 -a ! -t 1 ]; then
    # Run in background as daemon (ideal for cron jobs)
    nohup "$BIN_PATH" ${CLEAN_ARGS[@]+"${CLEAN_ARGS[@]}"} >> "$LOG_FILE" 2>&1 9>&- &
    CHILD_PID=$!
    disown "$CHILD_PID" 2>/dev/null || true
    echo "$CHILD_PID" > "$PID_FILE"
    echo "[olp-server] Started in background (PID: $CHILD_PID, log: $LOG_FILE)"
    exit 0
else
    # Run in foreground with full TTY control, teeing to log file so ~/.olp/server.log always records activity
    echo $$ > "$PID_FILE"
    exec 9>&-
    "$BIN_PATH" ${CLEAN_ARGS[@]+"${CLEAN_ARGS[@]}"} 2>&1 | tee -a "$LOG_FILE"
fi
