#!/bin/bash
# D0rkerR3con v2 — macOS setup
set -e
echo "[*] D0rkerR3con v2 — installing requirements…"
command -v python3 >/dev/null || brew install python
pip3 install -r requirements.txt

echo "[*] Installing httpx (ProjectDiscovery) for live probing…"
if ! command -v httpx >/dev/null 2>&1; then
  brew install httpx 2>/dev/null || { command -v go >/dev/null && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest; }
fi

echo "[*] Installing extra URL harvesters (gau · waybackurls)…"
command -v gau        >/dev/null 2>&1 || brew install gau 2>/dev/null        || { command -v go >/dev/null && go install -v github.com/lc/gau/v2/cmd/gau@latest; }
command -v waybackurls>/dev/null 2>&1 || brew install waybackurls 2>/dev/null || { command -v go >/dev/null && go install -v github.com/tomnomnom/waybackurls@latest; }
echo "[*] (optional) headless rendering:    pip3 install playwright && playwright install chromium"
echo "[*] (optional) OSINT bridge:          pipx install recon-ng"
echo "[+] Done. Run:  python3 d0rkerr3con.py"
