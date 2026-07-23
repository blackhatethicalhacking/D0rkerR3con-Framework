<!-- Centered Title Block -->
<p align="center">
  <img src="https://blackhatethicalhacking.com/assets/images/Logo_Complete.png" width="280px">
</p>

<p align="center">
  <strong><span style="font-size: 26px;">D0rkerR3con Framework</span></strong><br>
  <em>"What They Forgot to Hide, We’re Meant to Find"</em>
</p>


---

**D0rkerR3con** is a fast, offline Google Dorking toolkit that provides an interactive terminal interface (built with `gum`) for structured discovery of exposed targets.

Created by **Chris "SaintDruG" Abou‑Chabké** from **Black Hat Ethical Hacking**.

---

## Who Is It For?

- Red Teams  
- Pentesters  
- Advanced Offensive Operators  
- Bug Bounty Hunters  
- Security Engineers  

Use this framework to **quickly execute categorized Google dorks**, review saved results, and organize recon findings without relying on external tools or web GUIs.

---

## Outlaw Inspiration from RDR 2

This project is inspired by **Arthur Morgan** — the legendary outlaw from *Red Dead Redemption 2*. A man of few words but sharp instincts, Arthur wasn't just a gun-for-hire — he was a **watchful tactician**, someone who **read his enemies, moved in silence**, and acted only when it mattered.

**D0rkerR3con** reflects that same spirit:

- **Google Dorks** = your long-range rifle — precise, silent, deadly  
- **Search Engine Recon** = scouting from the hills, seeing without being seen  
- **Targets** = corporate fortresses hiding secrets in plain sight  
- **You** = the one who rides in with nothing but grit, wit, and a mission

> *"We can't change what's done, we can only move on."*  
> — Arthur Morgan

This tool wasn’t made for noise, but stealth in its core. It was made for **operators**, **watchers**, **digital outlaws** who understand the value of good Recon and **quiet power**. Built not for fame — but to get the job done.

<p align="center">
 <img src="https://github.com/user-attachments/assets/8fdb83aa-42dd-40f1-9a06-7044a49d96e6" width="420px" alt="d0rker-ui-preview"/>
</p>

---

## Description

**D0rkerR3con Framework** automates structured Google Dork-based reconnaissance by leveraging a local, categorized database of over 68 high-impact dorks.

Each dork is categorized (e.g., Admin Panels, Exposed Files, Credentials, Debug Info, Secrets, etc.) and presented to the user via an interactive terminal UI powered by `gum`, allowing for quick multi-selection, clean execution, and full result organization per target domain.

The tool executes live Google searches in the default browser and cleanly stores each result for auditing, reporting, or re-use.

<p align="center">
 <img src="https://github.com/user-attachments/assets/8cd26776-fba7-4219-8c96-08d4193263ec" width="420px" alt="d0rker-ui-preview"/>
</p>

---

## The Flow Behind It

> The tool is fully modular. Each scan creates structured folders under `results/`, organized by domain.

### 1. **Domain-Based Scanning**

- You input a **target domain** (e.g., `example.com`)
- A clean directory is created at: `results/example.com/`
- All scan data is saved per session

---

### 2. **Dork Selection via Gum UI**

- Categories are presented in a scrollable, colorful Gum-based menu
- You select from:
  - Specific categories (e.g., Secrets, Cloud Buckets)
  - `Show All` to view all dorks (68+)
- Multi-selection is supported
- Each dork has:
  - Title (for clarity)
  - Category (for grouping)
  - The raw Google Dork query

---

### 3. **Live Execution in Browser**

- Selected dorks are executed in your default browser
- Google search opens with `site:example.com` + the selected dork
- All URLs are saved locally

Files created:

```
results/example.com/
├── dorks_used.txt           # Dorks run, with titles
├── raw_results.txt          # All discovered links
└── export_example.com.html  # (Optional) Pretty report
```

---

### 4. **Optional HTML Report Generation**

- After the scan, you're asked if you want to export to HTML
- If yes, a clean `export_example.com.html` is created with:
  - Domain name
  - Scan date
  - Dorks used with titles
  - All discovered URLs
  - Framework credits

---

### 5. **Revisiting Old Scans**

- From the main menu, you can select `View Previous Results`
- Pick any domain from the `results/` directory
- View the TXT output in terminal
- Re-export it into HTML if needed

---

You can also extend the database by editing `dorkdb.json`, adding your own titles, categories, and dork strings.

> No APIs. No rate limits. No noise. Just clean, focused, high-signal recon.


## Screenshots

<img width="1911" height="1080" alt="Screenshot 2026-01-30 at 3 25 15 PM" src="https://github.com/user-attachments/assets/7906d654-e0fe-4266-9925-1efc8ee5cbb9" />
<img width="1911" height="1080" alt="Screenshot 2026-01-30 at 3 25 28 PM" src="https://github.com/user-attachments/assets/c53fc085-7c02-4803-8a88-ec076b3d436b" />
<img width="1911" height="1080" alt="Screenshot 2026-01-30 at 3 25 32 PM" src="https://github.com/user-attachments/assets/74e6106e-2b34-45fa-9a02-5562c3daa577" />
<img width="1911" height="1080" alt="Screenshot 2026-01-30 at 3 25 53 PM" src="https://github.com/user-attachments/assets/aef781f8-42ba-4897-b825-774bf921f257" />
<img width="1911" height="1080" alt="Screenshot 2026-01-30 at 3 26 00 PM" src="https://github.com/user-attachments/assets/229091fe-732c-4c43-8fc2-08e2c7f6f954" />
<img width="1911" height="1080" alt="Screenshot 2026-01-30 at 3 29 41 PM" src="https://github.com/user-attachments/assets/2a5f0dca-b892-41ab-a606-80464c670168" />

---

## Real Demo of the Tool

https://github.com/user-attachments/assets/c01dcdf9-7cdf-4851-ad3b-22d73b7f4520

---

## Features

- Clean CLI interface with interactive `gum` powered menus  
- Neon banner art and colorful terminal aesthetics  
- 68+ categorized Google Dorks (Secrets, Admin, Files, Logs, etc.)  
- Structured local database (`dorkdb.json`)  
- Real-time search execution in browser (no APIs needed)  
- Automatic result saving by domain  
- Organized output: `dorks_used.txt`, `raw_results.txt`, and optional HTML reports  
- Export results to styled HTML with timestamps and categories  
- Revisit old scans and re-export previous results  
- Lightweight and fast — no dependencies beyond core UNIX tools + gum + jq  
- Installer scripts included for Kali Linux and macOS  
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

### Option 2: Manual Setup

Install the following manually if you prefer:

- `bash`
- `gum`
- `jq`
- `xdg-open` (Linux) or `open` (macOS)
- `lolcat`

---

## Run the Tool

```bash
chmod +x D0rkerR3con.sh
./D0rkerR3con.sh
```

---

## I love GUM why?

Well a picture is worth a thousand words ain't it?

The tool uses [**GUM**](https://github.com/charmbracelet/gum) for its interactive and vibrant terminal UI, bringing a lively, colorful experience to recon workflows.

<a href="https://stuff.charm.sh/gum/nutritional-information.png" target="_blank"><img src="https://stuff.charm.sh/gum/gum.png" alt="Gum Image" width="450" /></a>
<img alt="Shell running the ./demo.sh script" width="600" src="https://vhs.charm.sh/vhs-1qY57RrQlXCuydsEgDp68G.gif">

---


## Future Plans: GUI Edition

I am planning to build a cross-platform GUI version of **D0rkerR3con** using:

- **Vite + Svelte** for the frontend
- **TailwindCSS** for the visual style (matching the neon/pink terminal look)
- Local bridge/API to access dorkdb.json and results
- Offline-first with an interactive dork launcher, viewer, and HTML exporter

The GUI will mirror the terminal workflow, adding clarity and accessibility for visual Recon OPS and future users.

---

## Disclaimer

This tool is for **Educational and Authorized Testing Only**.
You are responsible for how you use it. Only run this framework on targets you have **explicit permission to test**.

---

<h2 align="center">
  <a href="https://store.blackhatethicalhacking.com/" target="_blank">BHEH Official Merch</a>
</h2>

<p align="center">
Hack in style with our exclusive merch — designed for cyberpunk red teamers.
</p>

<p align="center">
  <img src="https://github.com/blackhatethicalhacking/blackhatethicalhacking/blob/main/Merch_Promo.gif" width="540px" height="540">
</p>
