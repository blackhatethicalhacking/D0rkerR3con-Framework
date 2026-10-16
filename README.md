<!-- Centered Title Block -->
<p align="center">
  <img src="https://blackhatethicalhacking.com/assets/images/Logo_Complete.png" width="280px">
</p>

<p align="center">
  <strong><span style="font-size: 26px;">D0rkerR3con Framework</span></strong><br>
  <em>"What They Forgot to Hide, We're Meant to Find"</em><br>
  <strong>v2.0 · Recon Intelligence Engine</strong>
</p>


---

**D0rkerR3con** is a Google Dorking **recon intelligence engine** with an interactive terminal interface (built with **Rich + Questionary**) for structured discovery, and **verification**, of exposed targets.

It is still a dorker at heart: every run writes the real **Google / Bing dork query URLs** for your target and can **open them for you**. Then it goes further than a bookmark list. Because search engines block automated dorking, it harvests a real URL corpus of the target, runs those same dorks as **filters** over it, and **probes the hits live**, so a finding is proven, not a guess.

Created by **Chris "SaintDruG" Abou-Chabké** from **Black Hat Ethical Hacking**.

---

## Who Is It For?

- Red Teams  
- Pentesters  
- Advanced Offensive Operators  
- Bug Bounty Hunters  
- Security Engineers  

Use this framework to **execute categorized Google dorks**, **verify live exposures**, aggregate **OSINT**, review saved results, and organize recon findings per target, without relying on external web GUIs.

---

## Outlaw Inspiration from RDR 2

This project is inspired by **Arthur Morgan**, the legendary outlaw from *Red Dead Redemption 2*. A man of few words but sharp instincts, Arthur wasn't just a gun-for-hire, he was a **watchful tactician**, someone who **read his enemies, moved in silence**, and acted only when it mattered.

**D0rkerR3con** reflects that same spirit:

- **Google Dorks** = your long-range rifle, precise, silent, deadly  
- **Corpus + Live Probing** = scouting from the hills, then confirming the kill  
- **Targets** = corporate fortresses hiding secrets in plain sight  
- **You** = the one who rides in with nothing but grit, wit, and a mission

> *"We can't change what's done, we can only move on."*  
> -- Arthur Morgan

This tool wasn't made for noise, but stealth in its core. It was made for **operators**, **watchers**, **digital outlaws** who understand the value of good Recon and **quiet power**. Built not for fame, but to get the job done.

<p align="center">
 <img src="https://github.com/user-attachments/assets/8fdb83aa-42dd-40f1-9a06-7044a49d96e6" width="420px" alt="d0rker-ui-preview"/>
</p>

---

## Description

**D0rkerR3con Framework v2.0** automates structured Google Dork reconnaissance using a local, categorized database of **214 high-impact dorks**, and then **verifies** what's actually exposed.

Each dork is categorized (Admin Panels, Exposed Files, Credentials, Secrets, Debug Info, Vuln Surface, IoT, Cloud, and more) and presented in an interactive terminal UI powered by **Rich + Questionary**. For every run the tool:

1. **Generates the real Google/Bing dork URLs** for your target (`dork-queries.txt`) and builds a **one-tab clickable launcher** (`dork-launcher.html`), or opens the dork searches directly in your browser.
2. **Harvests a live URL corpus** from Wayback, Common Crawl, AlienVault OTX, urlscan.io, gau and waybackurls (saved to `corpus-urls.txt`, streamed as it fetches).
3. **Runs each dork as a filter** over that corpus and shows you **which dork caught which URL**.
4. **Probes the matches live** with **httpx (ProjectDiscovery)** and **entropy-confirms** leaked secrets.
5. **Scores every finding** (risk x confidence x reachability x confirmation) and writes **HTML / Markdown / JSON reports** plus a per-target **SQLite** database.

> Findings are **only real, reachable hits (HTTP 200) or confirmed secrets**. A 403/404 never shows as a critical finding.

<p align="center">
 <img src="https://github.com/user-attachments/assets/8cd26776-fba7-4219-8c96-08d4193263ec" width="420px" alt="d0rker-ui-preview"/>
</p>

---

## The Flow Behind It

> The tool is fully modular. Each scan creates structured folders under `results/`, organized by domain.

### 1. Domain-Based Scanning

- You input a **target domain** (e.g., `example.com`), set once and shown in the menu
- A clean directory is created at: `results/example.com/`
- All scan data is saved per session

---

### 2. The Menu (Rich + Questionary)

- The whole menu lives in one box, laid out horizontally. Just type the number:
  - **1 Dork Recon (Corpus)**, **2 OSINT Recon**, **3 Active Sweep**
  - **4 Database**, **5 Modules / Dork DB**, **6 Set target**
  - **7 About**, **8 Usage**, **9 Open report**, **0 Exit**
- `Ctrl+C` in any module jumps back to the menu

---

### 3. Dork Recon (dork queries + corpus verification)

- Run all **214** dorks or narrow by category
- The real **Google/Bing dork URLs** are generated and **opened** (50 or fewer selected open as tabs, more opens the one-tab clickable launcher)
- A URL corpus is harvested, each dork is run as a filter, and matches are **probed live** with httpx
- Fetchable hits are **entropy-confirmed** for leaked secrets (optional hand-off to **SecretOpt1c** via the `SECRETOPT1C` env var)

---

### 4. OSINT Recon (recon-ng style)

- Runs **all passive modules** automatically: crt.sh, HackerTarget, CertSpotter, RapidDNS, Anubis, DNS (A/AAAA/MX/NS/TXT + SPF/DMARC), Wayback, recon-ng bridge
- Aggregates subdomains / DNS / URLs into the per-target database, with `[i/N]` stage numbering

---

### 5. Active Sweep

- Directly requests **high-value paths** on the host (`.env`, `.git/config`, `/actuator/env`, backups, admin panels, and more), no archive needed
- Confirms live exposures and scans them for secrets

---

### Files created

```
results/example.com/
├── dork-queries.txt        # Real Google/Bing dork URLs for the target
├── dork-launcher.html      # One-tab clickable launcher (all dorks, all engines)
├── corpus-urls.txt         # Full harvested URL corpus
├── recon.db                # SQLite: findings + assets (dedup)
├── report.html             # Neon HTML report (findings + subdomains + clickable dorks)
├── report.md               # Markdown report
└── report.json             # Machine-readable export
```

---

### 6. Database & Revisiting Scans

- From the menu, **Database** lets you view / export findings & assets (CSV / JSON)
- **Open report** opens `results/<target>/report.html` in your browser
- Extend the dork database by editing `build_dorkdb.py`, then run `python3 build_dorkdb.py`

> No APIs. No rate limits. No search-engine blocking. Just clean, focused, high-signal recon, with proof.

---

## Screenshots

**About**

<img width="1912" height="1069" alt="D0rker About" src="https://github.com/user-attachments/assets/422ce442-0218-48cc-9292-331e55137920" />

**In Progress Recon**

<img width="1912" height="1069" alt="D0rker In Progress Recon" src="https://github.com/user-attachments/assets/42411692-d0ef-4bcd-a6b5-cce6a369ed20" />

**In Progress Recon 2**

<img width="1912" height="1069" alt="D0rker In progress 2" src="https://github.com/user-attachments/assets/a1b0d10c-73ab-4caa-a474-f096ac506466" />

**Menu**

<img width="1912" height="1069" alt="D0rker Menu" src="https://github.com/user-attachments/assets/fd204cd0-8250-4318-9549-99bc40a8919b" />

**Modules**

<img width="1912" height="1069" alt="D0rker Modules" src="https://github.com/user-attachments/assets/e5ca1f0f-890e-4603-80e4-f2ba87faf640" />

**OSINT in Action**

<img width="1912" height="1069" alt="D0rker OSINT" src="https://github.com/user-attachments/assets/816c6ca7-6326-4c6e-aca7-60535ec63548" />

**Usage**

<img width="1912" height="1069" alt="D0rker Usage" src="https://github.com/user-attachments/assets/3220e92c-6df4-4bd6-b89a-d4da8247a24f" />

**Report**

<img width="1912" height="1005" alt="D0rker Report" src="https://github.com/user-attachments/assets/c7c122f1-9ea4-46f0-9a52-78241cc01535" />

---

## Real Demo of the Tool

https://github.com/user-attachments/assets/c01dcdf9-7cdf-4851-ad3b-22d73b7f4520

<!-- Add your NEW v2.0 demo video below (drag the video into a GitHub comment to get the URL):
https://github.com/user-attachments/assets/PASTE_NEW_VIDEO_URL_HERE
-->

---

## Features

- Interactive **Rich + Questionary** TUI: horizontal boxed menu, rainbow banner, colorful aesthetics  
- **214 categorized Google Dorks** across 16 categories (Secrets, Admin, Files, Logs, Vuln Surface, IoT, Cloud, and more)  
- **Classic dorking preserved**: generates real Google/Bing dork URLs and **opens them** (clickable launcher page, capped so no tab-storms)  
- **Corpus engine**: harvests real URLs from Wayback, Common Crawl, OTX, urlscan, gau and waybackurls (no search-engine blocking)  
- **Dorks-as-filters**: shows which dork caught which URL, then **probes live with httpx (ProjectDiscovery)**  
- **Entropy-Confirm**: Shannon entropy + regex secret rules (AWS, Stripe, GitHub, JWT, SendGrid, and more) to confirm real leaks  
- **Exposure Scoring**: risk x confidence x reachability x confirmation, scaled 0 to 100  
- **OSINT Recon (recon-ng style)**: crt.sh, HackerTarget, CertSpotter, RapidDNS, Anubis, DNS (+SPF/DMARC), Wayback  
- **Active Sweep**: direct live probing of sensitive paths, archive-independent  
- **Per-target SQLite database** with dedup, plus CSV / JSON export  
- **Reports**: neon HTML (with clickable dorks) + Markdown + JSON, auto-generated every run  
- Optional headless **chromium** rendering for JS-heavy pages  
- Installer scripts for **Kali Linux** and **macOS**  
- Easily extend the database with your own dorks and categories  

---

## Installation

```bash
git clone https://github.com/blackhatethicalhacking/D0rkerR3con-Framework.git
cd D0rkerR3con-Framework
```

---

## Install Requirements

### Option 1: Use Included Scripts

#### On Kali Linux

```bash
chmod +x install_kali_requirements.sh
./install_kali_requirements.sh
```

#### On macOS

```bash
chmod +x install_mac_requirements.sh
./install_mac_requirements.sh
```

The scripts install the Python requirements plus **httpx (ProjectDiscovery)** and the extra URL harvesters (**gau**, **waybackurls**), and optionally **playwright + chromium** (headless) and **recon-ng**.

### Option 2: Manual Setup

- `python3` + `pip`
- Python packages: `rich`, `questionary`, `requests`, `dnspython` (`pip install -r requirements.txt`)
- [`httpx`](https://github.com/projectdiscovery/httpx) (ProjectDiscovery) for live probing
- Optional: `gau`, `waybackurls` (more corpus sources), `playwright` + chromium (headless), `recon-ng`
- `xdg-open` (Linux) or `open` (macOS) to launch dorks/reports in the browser

---

## Run the Tool

Use the launcher (recommended):

```bash
chmod +x D0rkerR3con.sh
./D0rkerR3con.sh
```

The `.sh` is just a thin wrapper that runs the Python engine. You can also run it directly:

```bash
python3 d0rkerr3con.py
```

Non-interactive / scriptable:

```bash
python3 d0rkerr3con.py -t example.com --dork --recon --sweep
python3 d0rkerr3con.py -t example.com --dork --source wayback,otx,gau
python3 d0rkerr3con.py -t example.com --dork --headless
```

Deep secret scan hand-off: `export SECRETOPT1C=/path/to/secretopt1c.py`

---

## The Terminal UI

v1 lived in [**gum**](https://github.com/charmbracelet/gum). v2.0 is a native **Python** TUI built with [**Rich**](https://github.com/Textualize/rich) and [**Questionary**](https://github.com/tmbo/questionary), keeping the same lively, colorful, neon spirit with no external UI binaries. A hat-tip to Charm's gum for the v1 era:

<a href="https://stuff.charm.sh/gum/nutritional-information.png" target="_blank"><img src="https://stuff.charm.sh/gum/gum.png" alt="Gum Image" width="450" /></a>
<img alt="Shell running the ./demo.sh script" width="600" src="https://vhs.charm.sh/vhs-1qY57RrQlXCuydsEgDp68G.gif">

---

## Disclaimer

This tool is for **Educational and Authorized Testing Only**.
You are responsible for how you use it. Only run this framework on targets you have **explicit permission to test**.

---

<h2 align="center">
  <a href="https://store.blackhatethicalhacking.com/" target="_blank">BHEH Official Merch</a>
</h2>

<p align="center">
Hack in style with our exclusive merch, designed for cyberpunk red teamers.
</p>

<p align="center">
  <img src="https://github.com/blackhatethicalhacking/blackhatethicalhacking/blob/main/Merch_Promo.gif" width="540px" height="540">
</p>
