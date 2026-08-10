#!/usr/bin/env bash

# ──────────────── ASCII & Quote ────────────────
clear
curl --silent "https://raw.githubusercontent.com/blackhatethicalhacking/Subdomain_Bruteforce_bheh/main/ascii.sh" | lolcat
echo ""

quotes=(
"The supreme art of war is to subdue the enemy without fighting."
"All warfare is based on deception."
"He who knows when he can fight and when he cannot, will be victorious."
"The whole secret lies in confusing the enemy, so that he cannot fathom our real intent."
"To win one hundred victories in one hundred battles is not the acme of skill."
)
random_quote=${quotes[$RANDOM % ${#quotes[@]}]}
echo "Offensive Security Tip: $random_quote – Sun Tzu" | lolcat
sleep 1

figlet -w 80 -f small "D0rkerR3con Framework" | lolcat
echo ""
echo "[YOU ARE USING D0rkerR3con.sh] - (v10.0 FINAL)" | lolcat
echo "CODED BY Chris 'SaintDruG' Abou‑Chabké WITH ❤ FOR blackhatethicalhacking.com" | lolcat
echo "FOR EDUCATIONAL PURPOSES ONLY!" | lolcat
echo ""

# ──────────────── Internet Check ────────────────
echo "CHECKING INTERNET CONNECTIVITY..." | lolcat
wget -q --spider https://google.com || { echo "NO INTERNET — EXITING!" | lolcat; exit 1; }
echo "INTERNET OK — LET'S GO ⚡" | lolcat
sleep 1

# ──────────────── Tool Info ────────────────
echo ""
echo "🔍 What is this tool?" | lolcat
echo "D0rkerR3con Framework is an Offensive Recon toolkit to:" | lolcat
echo "• Discover exposed files, secrets, panels, backups & misconfigs"
echo "• Launch weaponized Google Dorks per domain"
echo "• Save structured Recon output per target"
echo "• Export professional HTML / Markdown reports"
echo ""

# ──────────────── Paths & Setup ────────────────
DORK_DB="./dorkdb.json"
RESULTS_DIR="results"
mkdir -p "$RESULTS_DIR"

# ──────────────── Report Exporter ────────────────
function export_report {
  local DOMAIN="$1"
  local TXT_OUT="results/$DOMAIN/dorks_used.txt"
  local HTML_OUT="results/$DOMAIN/report.html"
  local MD_OUT="results/$DOMAIN/report.md"
  local DATE_NOW=$(date +"%Y-%m-%d %H:%M:%S %Z")

  cat > "$MD_OUT" <<EOF
# D0rkerR3con Framework

**Coded by:** Chris 'SaintDruG' Abou‑Chabké
**Website:** https://blackhatethicalhacking.com

**Target:** $DOMAIN
**Date:** $DATE_NOW

## Dorks Executed
$(cat "$TXT_OUT")
EOF

  cat > "$HTML_OUT" <<EOF
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>D0rkerR3con Report - $DOMAIN</title>
<style>
body { background:#0b0b0b; color:#00ffcc; font-family: monospace; padding:20px; }
h1,h2 { color:#00ffaa; }
a { color:#66ffcc; }
pre { background:#111; padding:15px; }
</style>
</head>
<body>
<h1>D0rkerR3con Framework</h1>
<p><b>Coded by:</b> Chris 'SaintDruG' Abou‑Chabké<br>
<b>Website:</b> blackhatethicalhacking.com</p>

<p><b>Target:</b> $DOMAIN<br>
<b>Date:</b> $DATE_NOW</p>

<h2>Dorks Executed</h2>
<pre>$(sed 's#→ \(.*\)#→ <a href="\1">\1</a>#' "$TXT_OUT")</pre>
</body>
</html>
EOF

  echo "[+] Exported HTML & MD reports for $DOMAIN" | lolcat
}

# ──────────────── View Previous Results ────────────────
function view_previous_results {
  local DOMAINS=$(ls "$RESULTS_DIR" 2>/dev/null)
  [ -z "$DOMAINS" ] && echo "No previous scans found." | lolcat && return

  echo "[*] Select a previous domain:" | lolcat
  SELECTED=$(echo "$DOMAINS" | gum choose)

  TXT_FILE="$RESULTS_DIR/$SELECTED/dorks_used.txt"
  if [[ -f "$TXT_FILE" ]]; then
    echo ""
    echo "📂 Results for: $SELECTED" | lolcat
    echo ""
    cat "$TXT_FILE" | lolcat
    echo ""
    gum confirm "Export this again to HTML / Markdown?" && export_report "$SELECTED"
  else
    echo "No dork results found for $SELECTED" | lolcat
  fi
}

# ──────────────── New Scan ────────────────
function start_new_scan {
  read -rp "[+] Enter target domain (example.com): " DOMAIN
  DOMAIN_CLEAN="${DOMAIN//[^a-zA-Z0-9.-]/_}"
  OUT_DIR="$RESULTS_DIR/$DOMAIN_CLEAN"
  mkdir -p "$OUT_DIR"
  DATE_NOW=$(date +"%Y-%m-%d %H:%M:%S %Z")
  TXT_OUT="$OUT_DIR/dorks_used.txt"
  touch "$TXT_OUT"

  CATEGORIES=$(jq -r '.[] | .category' "$DORK_DB" | sort -u)
  CATEGORIES="ALL"$'\n'"$CATEGORIES"

  echo "[?] Select category/modules to browse:" | lolcat
  SELECTED_CATEGORY=$(echo "$CATEGORIES" | gum choose)

  if [[ "$SELECTED_CATEGORY" == "ALL" ]]; then
    FILTER_JQ='to_entries[]'
  else
    FILTER_JQ="to_entries[] | select(.value.category == \"$SELECTED_CATEGORY\")"
  fi

  while true; do
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗" | lolcat
    echo "║  📌 HOW TO SELECT DORKS:                                   ║" | lolcat
    echo "║  • Use ↑/↓ arrow keys to navigate                          ║" | lolcat
    echo "║  • Press SPACE to select/deselect (✓ = selected)           ║" | lolcat
    echo "║  • Press ENTER when done selecting                         ║" | lolcat
    echo "║  • Press ENTER without selecting to exit                   ║" | lolcat
    echo "╚════════════════════════════════════════════════════════════╝" | lolcat
    echo ""
    
    OPTIONS=$(jq -r "$FILTER_JQ | \"[\" + .key + \"] \" + .value.name + \" — \" + .value.category" "$DORK_DB")
    SELECTED=$(echo "$OPTIONS" | gum choose --no-limit --height=15)
    
    # Trim whitespace and check if anything was selected
    SELECTED=$(echo "$SELECTED" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if [[ -z "$SELECTED" ]] || [[ "${#SELECTED}" -eq 0 ]]; then
      echo ""
      echo "[!] No dorks selected. Exiting dork selection." | lolcat
      break
    fi

    echo ""
    echo "[+] Launching selected dorks..." | lolcat
    echo ""
    
    while read -r LINE; do
      ID=$(echo "$LINE" | grep -oE '^\[[0-9]+\]' | tr -d '[]')

      NAME=$(jq -r --arg id "$ID" '.[$id].name' "$DORK_DB")
      DORK=$(jq -r --arg id "$ID" '.[$id].dork' "$DORK_DB")
      SPECIAL=$(jq -r --arg id "$ID" '.[$id].special // false' "$DORK_DB")
      BASE=$(jq -r --arg id "$ID" '.[$id].url // ""' "$DORK_DB")
      SUFFIX=$(jq -r --arg id "$ID" '.[$id].suffix // ""' "$DORK_DB")

      if [[ "$SPECIAL" == "true" ]]; then
        URL="${BASE}${DOMAIN}${SUFFIX}"
      else
        URL="https://www.google.com/search?q=$(printf "site:%s %s" "$DOMAIN" "$DORK" | jq -sRr @uri)"
      fi

      echo "[*] [$ID] $NAME" | lolcat
      echo "→ $URL" | lolcat

      {
        echo "[$ID] $NAME"
        echo "→ $URL"
        echo ""
      } >> "$TXT_OUT"

      xdg-open "$URL" &>/dev/null || open "$URL" &>/dev/null
      sleep 0.3
    done <<< "$SELECTED"

    echo ""
    gum confirm "Run more dorks for this domain?" || break
  done

  echo ""
  gum confirm "Generate HTML / Markdown report?" && export_report "$DOMAIN_CLEAN"
  echo "[+] Scan complete for $DOMAIN" | lolcat
}

# ──────────────── MAIN MENU ────────────────
while true; do
  echo ""
  CHOICE=$(gum choose "Start New Scan" "View Previous Results" "Exit")
  case "$CHOICE" in
    "Start New Scan") start_new_scan ;;
    "View Previous Results") view_previous_results ;;
    "Exit") echo "Later, ninja 🥷" | lolcat; exit 0 ;;
  esac
done
