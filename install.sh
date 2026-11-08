#!/bin/bash
# Installs secreds into its own virtual environment. No sudo, no system changes.
set -euo pipefail
[ "$(uname)" = "Darwin" ] || { echo "secreds stores secrets in the macOS Keychain and needs a Mac."; exit 1; }
HOME_DIR="${SECREDS_HOME:-$HOME/.secreds}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"
mkdir -p "$HOME_DIR" "$HOME/.local/bin"; chmod 700 "$HOME_DIR"
"$PY" -m venv "$HOME_DIR/venv"
"$HOME_DIR/venv/bin/pip" install --quiet --upgrade pip
"$HOME_DIR/venv/bin/pip" install --quiet "$HERE[export]"
ln -sf "$HOME_DIR/venv/bin/secreds" "$HOME/.local/bin/secreds"
echo "Installed: $HOME/.local/bin/secreds"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "Add \$HOME/.local/bin to your PATH to run 'secreds' directly." ;; esac
echo
echo "Next:"
echo "  secreds init --owner \"Your Name\" --agents claude,codex     # optional: your name and agents"
echo "  secreds install-app                                         # optional: a double-clickable seCreds.app"
echo "  secreds gui                                                 # add your first credential"
