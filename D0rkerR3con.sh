#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# D0rkerR3con Framework v2.0 — launcher
# Thin wrapper that runs the Python recon engine from any folder.
# ──────────────────────────────────────────────────────────────
cd "$(dirname "$0")" || exit 1

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 not found. Install it, then run ./install_mac_requirements.sh or ./install_kali_requirements.sh"
  exit 1
fi

exec python3 d0rkerr3con.py "$@"
