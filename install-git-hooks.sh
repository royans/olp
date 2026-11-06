#!/usr/bin/env bash
# ==============================================================================
# Installs olp's git security hooks to protect against committing secrets.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d ".git" ]; then
    echo "[olp-security] Initializing git repository..."
    git init -q
fi

chmod +x "$SCRIPT_DIR/.githooks/pre-commit"
git config core.hooksPath .githooks

echo "[olp-security] Git pre-commit security hooks installed successfully!"
echo "[olp-security] All commits will now automatically be scanned for private keys, passkeys, and sensitive files."

