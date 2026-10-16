#!/bin/bash
# D0rkerR3con v2 — Kali/Debian setup
set -e
echo "[*] D0rkerR3con v2 — installing requirements…"
sudo apt-get update -y
sudo apt-get install -y python3 python3-pip golang-go
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt

echo "[*] Installing httpx (ProjectDiscovery) for live probing…"
if ! command -v httpx >/dev/null 2>&1; then
  GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  echo "    add Go bin to PATH:  export PATH=\$PATH:\$(go env GOPATH)/bin"
fi

echo "[*] Installing extra URL harvesters (gau · waybackurls)…"
command -v gau        >/dev/null 2>&1 || GO111MODULE=on go install -v github.com/lc/gau/v2/cmd/gau@latest
command -v waybackurls>/dev/null 2>&1 || GO111MODULE=on go install -v github.com/tomnomnom/waybackurls@latest
echo "[*] (optional) headless rendering:"
echo "    pip3 install playwright && playwright install chromium"
echo "[*] (optional) OSINT bridge:  pipx install recon-ng"
echo "[+] Done. Run:  python3 d0rkerr3con.py"
