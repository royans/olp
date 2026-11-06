#!/usr/bin/env bash
# ==============================================================================
# Automated Let's Encrypt TLS Certificate Provisioner & Renewer for `olp-proxy`
#
# Designed to be run manually or as a root cron job to:
#  1. Obtain or renew Let's Encrypt TLS certificates using Certbot.
#  2. Securely export dereferenced certs to user-space (~/.olp/tls/).
#  3. Enforce strict permissions (0600) owned by the proxy user.
#  4. Automatically enable TLS in ~/.olp/proxy.toml.
#  5. Gracefully restart olp-proxy to load the renewed certificates.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ANSI formatting helpers
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

# Allow --help without root
for arg in "$@"; do
    if [ "$arg" = "-h" ] || [ "$arg" = "--help" ]; then
        echo "Usage: sudo ./renew-tls.sh [DOMAIN] [OPTIONS]"
        echo ""
        echo "Arguments:"
        echo "  DOMAIN            Public domain pointing to this proxy (e.g. ssh3.blogofy.com)"
        echo ""
        echo "Options:"
        echo "  --cron, -q        Run quietly for automated cron execution"
        echo "  --force           Force certificate renewal even if not close to expiry"
        echo "  --user <username> Target user who runs olp-proxy (default: current/sudo user)"
        echo "  --email <email>   Email address for Let's Encrypt expiration notifications"
        echo "  --webroot <path>  Path to existing web server root (if port 80 is occupied)"
        echo ""
        exit 0
    fi
done

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[olp-tls] Error: This script must be run as root (or via sudo).${NC}" >&2
    echo -e "Reason: Let's Encrypt ACME verification requires binding port 80 or accessing /etc/letsencrypt/." >&2
    echo -e "Try: ${BOLD}sudo $0 \"$@\"${NC}" >&2
    exit 1
fi

# Detect target non-root user that runs olp-proxy
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    # Fallback to the owner of start-proxy.sh
    TARGET_USER="$(stat -c '%U' "$SCRIPT_DIR/start-proxy.sh" 2>/dev/null || stat -f '%Su' "$SCRIPT_DIR/start-proxy.sh" 2>/dev/null || echo "root")"
fi

if [ "$TARGET_USER" = "root" ]; then
    echo -e "${YELLOW}[olp-tls] Warning: Detected target user as 'root'. It is strongly recommended${NC}" >&2
    echo -e "${YELLOW}to run olp-proxy as a regular unprivileged user.${NC}" >&2
fi

# Resolve target user's home directory
if command -v getent >/dev/null 2>&1; then
    TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
else
    TARGET_HOME="$(eval echo "~$TARGET_USER")"
fi

OLP_DIR="$TARGET_HOME/.olp"
TLS_DIR="$OLP_DIR/tls"
DOMAIN_FILE="$OLP_DIR/domain"
CONFIG_FILE="$OLP_DIR/proxy.toml"

# Parse CLI flags
CRON_MODE=0
FORCE_RENEW=0
DOMAIN=""
EMAIL=""
WEBROOT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cron|-q)
            CRON_MODE=1
            shift
            ;;
        --force)
            FORCE_RENEW=1
            shift
            ;;
        --user)
            TARGET_USER="$2"
            TARGET_HOME="$(eval echo "~$TARGET_USER")"
            OLP_DIR="$TARGET_HOME/.olp"
            TLS_DIR="$OLP_DIR/tls"
            DOMAIN_FILE="$OLP_DIR/domain"
            CONFIG_FILE="$OLP_DIR/proxy.toml"
            shift 2
            ;;
        --email)
            EMAIL="$2"
            shift 2
            ;;
        --webroot)
            WEBROOT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: sudo ./renew-tls.sh [DOMAIN] [OPTIONS]"
            echo ""
            echo "Arguments:"
            echo "  DOMAIN            Public domain pointing to this proxy (e.g. ssh3.blogofy.com)"
            echo ""
            echo "Options:"
            echo "  --cron, -q        Run quietly for automated cron execution"
            echo "  --force           Force certificate renewal even if not close to expiry"
            echo "  --user <username> Target user who runs olp-proxy (default: $TARGET_USER)"
            echo "  --email <email>   Email address for Let's Encrypt expiration notifications"
            echo "  --webroot <path>  Path to existing web server root (if port 80 is occupied)"
            echo ""
            exit 0
            ;;
        *)
            if [ -z "$DOMAIN" ]; then
                DOMAIN="$1"
            else
                echo -e "${RED}[olp-tls] Unknown argument: $1${NC}" >&2
                exit 1
            fi
            shift
            ;;
    esac
done

# If domain was not supplied as argument, check saved domain file
if [ -z "$DOMAIN" ] && [ -f "$DOMAIN_FILE" ]; then
    DOMAIN="$(cat "$DOMAIN_FILE" | tr -d '[:space:]')"
fi

# If still missing and interactive, prompt user
if [ -z "$DOMAIN" ]; then
    if [ -t 0 ] && [ "$CRON_MODE" -eq 0 ]; then
        echo -e "${CYAN}================================================================================${NC}"
        echo -e "${BOLD}  olp-proxy Let's Encrypt TLS Setup${NC}"
        echo -e "${CYAN}================================================================================${NC}"
        echo ""
        read -r -p "Enter the public domain name for this server (e.g. ssh3.blogofy.com): " INPUT_DOMAIN
        DOMAIN="$(echo "$INPUT_DOMAIN" | tr -d '[:space:]')"
    fi
fi

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}[olp-tls] Error: Domain name is required.${NC}" >&2
    echo -e "Usage: sudo $0 <your-domain.com>" >&2
    exit 1
fi

# Ensure certbot is installed
if ! command -v certbot >/dev/null 2>&1; then
    if [ "$CRON_MODE" -eq 0 ]; then
        echo -e "${YELLOW}[olp-tls] 'certbot' is not installed. Attempting to install via package manager...${NC}"
    fi
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq certbot
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q certbot
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q certbot
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm certbot
    else
        echo -e "${RED}[olp-tls] Error: Could not automatically install certbot. Please install certbot manually.${NC}" >&2
        exit 1
    fi
fi

# Check whether port 80 is in use
PORT_80_USED=0
if command -v ss >/dev/null 2>&1; then
    if ss -tlpn | grep -q ':80 '; then
        PORT_80_USED=1
    fi
elif command -v netstat >/dev/null 2>&1; then
    if netstat -tlpn 2>/dev/null | grep -q ':80 '; then
        PORT_80_USED=1
    fi
fi

CERTBOT_ARGS=(certonly --keep-until-expiring --agree-tos -d "$DOMAIN" --cert-name "$DOMAIN")

if [ -n "$EMAIL" ]; then
    CERTBOT_ARGS+=(--email "$EMAIL")
else
    CERTBOT_ARGS+=(--register-unsafely-without-email)
fi

if [ "$FORCE_RENEW" -eq 1 ]; then
    CERTBOT_ARGS+=(--force-renewal)
fi

if [ "$CRON_MODE" -eq 1 ]; then
    CERTBOT_ARGS+=(--non-interactive --quiet)
else
    CERTBOT_ARGS+=(--non-interactive)
fi

if [ -n "$WEBROOT" ]; then
    CERTBOT_ARGS+=(--webroot -w "$WEBROOT")
elif [ "$PORT_80_USED" -eq 1 ]; then
    # Look for common webroots
    if [ -d "/var/www/html" ]; then
        CERTBOT_ARGS+=(--webroot -w "/var/www/html")
    else
        echo -e "${YELLOW}[olp-tls] Port 80 appears to be occupied by another service (e.g. Nginx/Apache).${NC}" >&2
        echo -e "${YELLOW}Please specify your web server document root using: --webroot /path/to/html${NC}" >&2
        exit 1
    fi
else
    CERTBOT_ARGS+=(--standalone)
fi

if [ "$CRON_MODE" -eq 0 ]; then
    echo -e "${GREEN}[olp-tls] Requesting/Renewing certificate for '$DOMAIN' with Certbot...${NC}"
fi

certbot "${CERTBOT_ARGS[@]}"

LIVE_DIR="/etc/letsencrypt/live/$DOMAIN"
if [ ! -f "$LIVE_DIR/fullchain.pem" ] || [ ! -f "$LIVE_DIR/privkey.pem" ]; then
    echo -e "${RED}[olp-tls] Error: Certbot completed but certificates were not found in $LIVE_DIR${NC}" >&2
    exit 1
fi

# Ensure user-space destination directory exists with strict permissions
mkdir -p "$TLS_DIR"
mkdir -p "$OLP_DIR"

# Copy certificates dereferencing symlinks (-L) so they are real files accessible to $TARGET_USER
cp -L "$LIVE_DIR/fullchain.pem" "$TLS_DIR/fullchain.pem"
cp -L "$LIVE_DIR/privkey.pem" "$TLS_DIR/privkey.pem"

# Save domain name for future automated cron renewals
echo "$DOMAIN" > "$DOMAIN_FILE"

# Set strict ownership and permissions (0700 for directory, 0600 for certificate files)
chown -R "$TARGET_USER:$TARGET_USER" "$TLS_DIR"
chown "$TARGET_USER:$TARGET_USER" "$DOMAIN_FILE"
chmod 0700 "$TLS_DIR"
chmod 0600 "$TLS_DIR/fullchain.pem"
chmod 0600 "$TLS_DIR/privkey.pem"
chmod 0600 "$DOMAIN_FILE"

# Automatically update proxy.toml if TLS is off
if [ -f "$CONFIG_FILE" ]; then
    if grep -q 'mode = "off"' "$CONFIG_FILE"; then
        if [ "$CRON_MODE" -eq 0 ]; then
            echo -e "${GREEN}[olp-tls] Enabling TLS mode in $CONFIG_FILE...${NC}"
        fi
        sed -i 's/mode = "off"/mode = "manual"/' "$CONFIG_FILE"
        if ! grep -q 'cert_path =' "$CONFIG_FILE"; then
            sed -i '/mode = "manual"/a cert_path = "~/.olp/tls/fullchain.pem"\nkey_path = "~/.olp/tls/privkey.pem"' "$CONFIG_FILE"
        fi
        chown "$TARGET_USER:$TARGET_USER" "$CONFIG_FILE"
        chmod 0600 "$CONFIG_FILE"
    fi
fi

# Gracefully restart olp-proxy if it is currently running
RESTARTED=0
PROXY_PID_FILE="$OLP_DIR/olp-proxy.pid"
if [ -f "$PROXY_PID_FILE" ]; then
    PID="$(cat "$PROXY_PID_FILE" 2>/dev/null || echo "")"
    if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
        if [ "$CRON_MODE" -eq 0 ]; then
            echo -e "${GREEN}[olp-tls] Restarting olp-proxy for user $TARGET_USER to apply new certificates...${NC}"
        fi
        su - "$TARGET_USER" -c "cd '$SCRIPT_DIR' && ./start-proxy.sh restart" >/dev/null 2>&1 || true
        RESTARTED=1
    fi
fi

if [ "$CRON_MODE" -eq 0 ]; then
    echo ""
    echo -e "${CYAN}================================================================================${NC}"
    echo -e "${GREEN}${BOLD}  TLS Certificates Successfully Configured!${NC}"
    echo -e "${CYAN}================================================================================${NC}"
    echo -e "  Domain       : ${BOLD}$DOMAIN${NC}"
    echo -e "  Cert Path    : $TLS_DIR/fullchain.pem (0600, owned by $TARGET_USER)"
    echo -e "  Key Path     : $TLS_DIR/privkey.pem   (0600, owned by $TARGET_USER)"
    if [ "$RESTARTED" -eq 1 ]; then
        echo -e "  Proxy Status : ${GREEN}Restarted cleanly with active TLS${NC}"
    else
        echo -e "  Proxy Status : Run ${BOLD}./start-proxy.sh${NC} as $TARGET_USER to start with HTTPS"
    fi
    echo ""
    echo -e "${BOLD}To automate certificate renewals via root cronjob:${NC}"
    echo -e "Run ${BOLD}sudo crontab -e${NC} and add the following entry:"
    echo ""
    echo -e "  ${YELLOW}0 3 * * 1 $SCRIPT_DIR/renew-tls.sh --cron >> /var/log/olp-tls.log 2>&1${NC}"
    echo ""
    echo -e "${CYAN}================================================================================${NC}"
fi
