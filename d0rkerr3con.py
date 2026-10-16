#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
D0rkerR3con Framework v2.0  —  Recon Intelligence Engine
Coded by Chris "SaintDruG" Abou-Chabké  ·  Black Hat Ethical Hacking

From a dork *launcher* to a recon *engine*:
  • Corpus Dork Recon : harvest a real URL corpus (Wayback · CommonCrawl · OTX ·
    urlscan · gau · waybackurls), then run 200+ dorks as FILTERS over it — no search-engine
    blocking — then probe live with httpx (ProjectDiscovery) and entropy-confirm secrets.
  • OSINT Recon       : crt.sh · HackerTarget · CertSpotter · RapidDNS · Anubis · DNS · Wayback · recon-ng
  • Active Sweep      : probe high-value paths live + entropy-confirm
  • SQLite recon DB   : per target, dedup, export CSV/JSON
  • Reports           : interactive neon HTML + MD + JSON (auto, every run)

FOR AUTHORIZED TESTING & EDUCATIONAL USE ONLY.
"""
import os, re, sys, json, csv, math, time, sqlite3, argparse, random, webbrowser, urllib.parse, base64, shutil, subprocess, colorsys, tempfile
from datetime import datetime, timezone

try:
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    from rich import box
    RICH = True
    console = Console()
except Exception:
    RICH = False
    class _D:
        def print(self,*a,**k): print(*[str(x) for x in a])
        def clear(self): pass
    console = _D()

try:
    import questionary
    from questionary import Style
    QUESTIONARY = True
    QSTYLE = Style([("qmark","fg:#39d353 bold"),("question","bold"),("pointer","fg:#39d353 bold"),
                    ("highlighted","fg:#39d353 bold"),("selected","fg:#7fe8a8"),("answer","fg:#ff9f45 bold"),
                    ("instruction","fg:#5c6b61")])
except Exception:
    QUESTIONARY = False; QSTYLE = None

try:
    import requests
    SESSION = requests.Session()
except Exception:
    requests = None; SESSION = None

VERSION = "2.0"
AUTHOR  = "Chris 'SaintDruG' Abou-Chabké"
ROOT    = os.path.dirname(os.path.abspath(__file__))
DORK_DB = os.path.join(ROOT, "dorkdb.json")
RESULTS = os.path.join(ROOT, "results")
UA      = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
SECRETOPT1C = os.environ.get("SECRETOPT1C", "")
HAS_HTTPX = bool(shutil.which("httpx"))
try:
    from playwright.sync_api import sync_playwright  # optional headless
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False

RISK_WEIGHT = {"critical":1.0,"high":0.8,"medium":0.55,"low":0.3,"info":0.15}
RISK_COLOR  = {"critical":"bold red","high":"red","medium":"yellow","low":"cyan","info":"dim"}
FETCHABLE   = re.compile(r"\.(env|sql|bak|backup|old|log|json|ya?ml|xml|conf|cfg|ini|txt|pem|key|git|config|properties|tfstate|npmrc|dockercfg)(\?|$)", re.I)

QUOTES = ["All warfare is based on deception.",
    "The supreme art of war is to subdue the enemy without fighting.",
    "He who knows when he can fight and when he cannot, will be victorious.",
    "In the midst of chaos, there is also opportunity.",
    "Opportunities multiply as they are seized.",
    "The whole secret lies in confusing the enemy, so he cannot fathom our real intent."]

SEARCH_ENGINES = {"google":"https://www.google.com/search?q=","bing":"https://www.bing.com/search?q=",
    "duckduckgo":"https://duckduckgo.com/html/?q=","yandex":"https://yandex.com/search/?text=",
    "brave":"https://search.brave.com/search?q="}

# ─────────────────── entropy / secret engine ───────────────────
SECRET_RULES = [
    ("AWS Access Key", re.compile(r"\b(AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b")),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key[\"'\s:=]+([0-9a-zA-Z/+]{40})")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("Stripe Live Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Generic Secret Assign", re.compile(r"(?i)(?:api[_-]?key|secret|token|passwd|password|client_secret)[\"'\s:=]{1,4}([0-9a-zA-Z._\-/+]{12,})")),
    ("DB Connection URI", re.compile(r"\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^\s\"']{6,}")),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("Azure Storage Key", re.compile(r"AccountKey=[0-9a-zA-Z+/=]{80,}")),
]
def shannon(s):
    if not s: return 0.0
    cc={}
    for ch in s: cc[ch]=cc.get(ch,0)+1
    n=len(s); return -sum((v/n)*math.log2(v/n) for v in cc.values())
def scan_secrets(text):
    out,seen=[],set()
    if not text: return out
    for label,rx in SECRET_RULES:
        for m in rx.finditer(text):
            val=(m.group(1) if m.groups() else m.group(0)).strip()
            if not val or val.lower() in ("password","secret","changeme","example","your_key"): continue
            ent=shannon(val)
            strong = ent>=3.2 or label in ("Private Key Block","AWS Access Key","Slack Token","Stripe Live Key","GitHub Token","JWT","Google API Key")
            if not strong: continue
            k=(label,val[:12])
            if k in seen: continue
            seen.add(k)
            out.append({"type":label,"sample":(val[:6]+"…"+val[-4:]) if len(val)>14 else val,"entropy":round(ent,2)})
            if len(out)>=25: return out
    return out
def exposure_score(risk,confidence,reachable,confirmed,fresh=1.0):
    s=RISK_WEIGHT.get(risk,0.3)*confidence*(0.4+0.6*reachable)*fresh
    if confirmed: s=min(1.0,s*1.6+0.2)
    return round(s*100,1)
def deep_scan_secretopt1c(url):
    if not SECRETOPT1C or not os.path.exists(SECRETOPT1C): return None
    try: return subprocess.run([sys.executable,SECRETOPT1C,"-u",url],capture_output=True,text=True,timeout=120).stdout
    except Exception: return None

# ─────────────────── recon DB ───────────────────
class ReconDB:
    def __init__(self, target):
        d=os.path.join(RESULTS,target); os.makedirs(d,exist_ok=True)
        self.target,self.dir=target,d
        self.db=sqlite3.connect(os.path.join(d,"recon.db"))
        self.db.execute("""CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY AUTOINCREMENT,
            module TEXT,name TEXT,category TEXT,risk TEXT,url TEXT,status INTEGER,score REAL,
            confirmed INTEGER,secrets TEXT,note TEXT,first_seen TEXT,UNIQUE(module,name,url))""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT,value TEXT,note TEXT,first_seen TEXT,UNIQUE(kind,value))""")
        self.db.commit()
    def add_finding(self,module,name,category,risk,url,status=None,score=0.0,confirmed=False,secrets=None,note=""):
        now=datetime.now(timezone.utc).isoformat()
        isnew=self.db.execute("SELECT 1 FROM findings WHERE module=? AND name=? AND url=?",(module,name,url or "")).fetchone() is None
        self.db.execute("""INSERT OR IGNORE INTO findings(module,name,category,risk,url,status,score,confirmed,secrets,note,first_seen)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)""",(module,name,category,risk,url or "",status,score,int(confirmed),json.dumps(secrets or []),note,now))
        self.db.commit(); return isnew
    def add_asset(self,kind,value,note=""):
        now=datetime.now(timezone.utc).isoformat()
        isnew=self.db.execute("SELECT 1 FROM assets WHERE kind=? AND value=?",(kind,value)).fetchone() is None
        self.db.execute("INSERT OR IGNORE INTO assets(kind,value,note,first_seen) VALUES(?,?,?,?)",(kind,value,note,now))
        self.db.commit(); return isnew
    def findings(self,only_real=True):
        cur=self.db.execute("SELECT module,name,category,risk,url,status,score,confirmed,secrets,note,first_seen FROM findings ORDER BY score DESC")
        cols=[c[0] for c in cur.description]; rows=[dict(zip(cols,r)) for r in cur.fetchall()]
        if only_real: rows=[r for r in rows if r["confirmed"] or (r["status"]==200)]
        return rows
    def assets(self,kind=None):
        q="SELECT kind,value,note,first_seen FROM assets"+(" WHERE kind=?" if kind else "")+" ORDER BY kind,value"
        cur=self.db.execute(q,(kind,) if kind else ()); cols=[c[0] for c in cur.description]
        return [dict(zip(cols,r)) for r in cur.fetchall()]

# ─────────────────── helpers ───────────────────
def load_db():
    with open(DORK_DB) as f: return json.load(f)
def http_get(url,timeout=12,allow_redirects=True):
    if SESSION is None: return None
    try: return SESSION.get(url,headers={"User-Agent":UA},timeout=timeout,allow_redirects=allow_redirects,verify=True)
    except Exception: return None
def http_get_retry(url,timeout=25,tries=3,backoff=2.0):
    """For flaky sources (crt.sh, Wayback) that 5xx / time out under load."""
    for n in range(tries):
        r=http_get(url,timeout=timeout)
        if r is not None and r.status_code==200 and r.text.strip(): return r
        time.sleep(backoff*(n+1))
    return r if 'r' in dir() else None
def c(txt,style=""):
    console.print(Text(txt,style=style) if (RICH and style) else txt)
def status_line(msg,kind="info"):
    st={"ok":"bold green","info":"green","warn":"yellow","crit":"bold red","dim":"dim","stage":"bold cyan"}
    sym={"ok":"[+]","info":"[*]","warn":"[!]","crit":"[!!]","dim":"[.]","stage":"[»]"}
    c(f"{sym.get(kind,'[*]')} {msg}", st.get(kind,"green"))
def stage(i,total,name):
    c(f"[{i}/{total}] {name}", "bold cyan")

# ─────────────────── rainbow banner ───────────────────
BANNER_ART = r"""
 ██████╗  ██████╗ ██████╗ ██╗  ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔═████╗██╔══██╗██║ ██╔╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║  ██║██║██╔██║██████╔╝█████╔╝ █████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║  ██║████╔╝██║██╔══██╗██╔═██╗ ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██████╔╝╚██████╔╝██║  ██║██║  ██╗███████╗██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"""
def rainbow(text,freq=0.08,spread=2.2):
    if not RICH: return text
    t=Text()
    for y,line in enumerate(text.split("\n")):
        for x,ch in enumerate(line):
            if ch==" ": t.append(" "); continue
            r,g,b=colorsys.hsv_to_rgb(((x+y*spread)*freq)%1.0,0.85,1.0)
            t.append(ch,style=f"rgb({int(r*255)},{int(g*255)},{int(b*255)})")
        t.append("\n")
    return t
def rainbow_inline(text,freq=0.12):
    if not RICH: return Text(text)
    t=Text()
    for x,ch in enumerate(text):
        if ch==" ": t.append(" "); continue
        r,g,b=colorsys.hsv_to_rgb((x*freq)%1.0,0.85,1.0)
        t.append(ch,style=f"bold rgb({int(r*255)},{int(g*255)},{int(b*255)})")
    return t
def banner():
    # Kept short on purpose so the logo + menu fit one screen even at big font sizes.
    if RICH:
        console.clear(); console.print(rainbow(BANNER_ART))
        console.print(Text.assemble(
            ("  D0rkerR3con ","bold green"),(f"v{VERSION}","bold white"),
            ("  ·  Recon Intelligence Engine  ·  ","green"),
            (f"{AUTHOR} · Black Hat Ethical Hacking","dim")))
        console.print(Text(f'  "What They Forgot to Hide, We\'re Meant to Find"  ·  Sun Tzu: {random.choice(QUOTES)}',"italic dim"))
    else:
        print(f"=== D0rkerR3con v{VERSION} — pip install -r requirements.txt ===")

# ─────────────────── prompts ───────────────────
NONINTERACTIVE=False  # set by CLI flag path; auto-selects "all" instead of prompting
def ask_select(message,choices,multi=False,default=None):
    if NONINTERACTIVE or not sys.stdin.isatty():
        # auto-pick the first "ALL …" option (skipping any Back), else first real choice
        reals=[c for c in choices if isinstance(c,str) and "Back to main menu" not in c]
        allo=next((c for c in reals if isinstance(c,str) and "ALL" in c), None)
        pick=allo or (reals[0] if reals else None)
        print(f"\n{message}\n  → (non-interactive) {pick}")
        return [pick] if multi else pick
    if QUESTIONARY:
        if multi: return questionary.checkbox(message,choices=choices,qmark="▸",pointer="❯",style=QSTYLE).ask() or []
        return questionary.select(message,choices=choices,default=default,qmark="▸",pointer="❯",style=QSTYLE).ask()
    print("\n"+message)
    for i,ch in enumerate(choices,1): print(f"  {i}) {ch}")
    raw=input("Select (comma-sep): " if multi else "Select #: ").strip()
    idx=[int(x) for x in re.findall(r"\d+",raw)]
    if multi: return [choices[i-1] for i in idx if 1<=i<=len(choices)]
    try: return choices[idx[0]-1]
    except Exception: return choices[0] if choices else None
def ask_text(message,default=""):
    if QUESTIONARY: return (questionary.text(message,default=default,qmark="▸",style=QSTYLE).ask() or "").strip()
    return (input(f"▸ {message} ").strip() or default)
def ask_confirm(message,default=True):
    if QUESTIONARY: return questionary.confirm(message,default=default,qmark="▸",style=QSTYLE).ask()
    v=input(f"▸ {message} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not v else v.startswith("y")

def _table(rows,title=None,cols=("Risk","Finding","Status","URL")):
    if not rows or not RICH:
        for r in rows or []: print("  ", r)
        return
    t=Table(box=box.SIMPLE_HEAVY,title=title,title_style="bold green")
    for i,cname in enumerate(cols):
        t.add_column(cname,no_wrap=(i==0),overflow="fold")
    for risk,name,st,url in rows[:120]:
        t.add_row(Text(risk.upper(),style=RISK_COLOR.get(risk,"white")),name,st,url)
    console.print(t)

# ─────────────────── dork → matcher ───────────────────
def dork_matchers(entry):
    dork=entry.get("dork","") or ""
    url_tokens=set(); suffixes=set(); content_tokens=set()
    for ext in re.findall(r'ext:([a-z0-9~]+)',dork,re.I): suffixes.add("."+ext.lower())
    for t in re.findall(r'inurl:([^\s|)]+)',dork,re.I): url_tokens.add(t.strip('"').lower())
    for q in re.findall(r'"([^"]+)"',dork):
        (url_tokens if ("." in q or "/" in q) else content_tokens).add(q.lower())
    for t in re.findall(r'in(?:title|text):([^\s|)]+)',dork,re.I): content_tokens.add(t.strip('"').lower())
    if entry.get("type")=="probe" and entry.get("path"): url_tokens.add(entry["path"].lower())
    return url_tokens,suffixes,content_tokens
def url_matches(u,url_tokens,suffixes):
    ul=u.lower()
    path=urllib.parse.urlparse(ul).path
    if any(path.endswith(s) or (s+"?") in ul for s in suffixes): return True
    if any(tok in ul for tok in url_tokens): return True
    return False
def open_in_browser(path_or_url):
    """Open a local file or URL in the default browser (macOS/Linux/other)."""
    is_url=path_or_url.startswith("http")
    arg=path_or_url if is_url else ("file://"+os.path.abspath(path_or_url))
    try:
        if not is_url and sys.platform=="darwin": subprocess.run(["open",path_or_url]); return True
        if not is_url and os.name=="posix" and shutil.which("xdg-open"): subprocess.run(["xdg-open",path_or_url]); return True
        webbrowser.open(arg); return True
    except Exception:
        try: webbrowser.open(arg); return True
        except Exception: return False
def build_dork_launcher(target, sel, outdir):
    """One clickable HTML page with every selected dork → Google/Bing/DuckDuckGo. Opens in ONE tab."""
    from collections import defaultdict
    by=defaultdict(list)
    for e in sel: by[e["category"]].append(e)
    rc={"critical":"#ff4d6d","high":"#ff9f45","medium":"#ffe066","low":"#4dd2ff","info":"#9aa"}
    cards=""
    for cat in sorted(by):
        items=""
        for e in sorted(by[cat],key=lambda x:x["name"]):
            q=dork_query(e,target); col=rc.get(e["risk"],"#9aa")
            g=dork_url(e,target,"google"); b=dork_url(e,target,"bing"); d=dork_url(e,target,"duckduckgo")
            items+=(f"<div class='d' data-q=\"{_esc(q.lower())}\"><div class='dh'>"
                    f"<span class='rk' style='color:{col};border-color:{col}'>{e['risk'].upper()}</span>"
                    f"<b>{_esc(e['name'])}</b></div><code>{_esc(q)}</code>"
                    f"<div class='bt'><a class='go' href=\"{_esc(g)}\" target='_blank' rel='noopener'>Google</a>"
                    f"<a href=\"{_esc(b)}\" target='_blank' rel='noopener'>Bing</a>"
                    f"<a href=\"{_esc(d)}\" target='_blank' rel='noopener'>DuckDuckGo</a></div></div>")
        cards+=(f"<section data-cat=\"{_esc(cat.lower())}\"><h2>{_esc(cat)} "
                f"<span class='n'>{len(by[cat])}</span> "
                f"<button class='oa' onclick=\"openAll(this)\">▶ open all (Google)</button></h2>"
                f"<div class='grid'>{items}</div></section>")
    html=f"""<!DOCTYPE html><html><head><meta charset='utf-8'><title>Dork Launcher — {_esc(target)}</title><style>
:root{{--bg:#070b0f;--card:#0d141c;--line:#163a28;--fg:#d6ffe9;--pink:#ff5fd7;--grn:#39d353}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,Menlo,monospace;padding:22px}}
h1{{color:var(--pink);margin:0}}.sub{{color:#7fe8a8;margin:4px 0 14px}}
#f{{width:100%;max-width:520px;padding:10px 14px;background:var(--card);border:1px solid var(--line);border-radius:10px;color:var(--fg);font-size:14px;margin-bottom:18px}}
section{{margin:0 0 22px}}h2{{color:var(--grn);font-size:15px;border-bottom:1px solid var(--line);padding-bottom:6px;display:flex;align-items:center;gap:10px}}
.n{{background:#13351f;color:#9fe;border-radius:20px;padding:1px 9px;font-size:12px}}
.oa{{margin-left:auto;background:#1a1030;color:var(--pink);border:1px solid var(--pink);border-radius:8px;padding:4px 10px;cursor:pointer;font:inherit;font-size:12px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:12px;margin-top:12px}}
.d{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px}}
.dh{{display:flex;align-items:center;gap:8px;margin-bottom:6px}}.rk{{border:1px solid;border-radius:6px;font-size:10px;padding:1px 6px}}
code{{display:block;color:#bfe;font-size:12px;word-break:break-all;margin-bottom:9px;opacity:.85}}
.bt{{display:flex;gap:7px}}.bt a{{text-decoration:none;font-size:12px;padding:5px 11px;border-radius:7px;background:#11212e;color:#9df;border:1px solid var(--line)}}
.bt a.go{{background:var(--pink);color:#140018;border-color:var(--pink);font-weight:bold}}
.foot{{color:#556;font-size:12px;margin-top:26px}}</style></head><body>
<h1>🔎 Dork Launcher — {_esc(target)}</h1>
<p class='sub'>{len(sel)} dorks · click any engine, or “open all” per category. Classic dorking, your call which to fire.</p>
<input id='f' placeholder='filter dorks… (e.g. env, admin, sql)' oninput='flt(this.value)'>
{cards}
<p class='foot'>D0rkerR3con v{VERSION} · {_esc(AUTHOR)} · Black Hat Ethical Hacking · Authorized testing only.</p>
<script>
function flt(v){{v=v.toLowerCase();document.querySelectorAll('.d').forEach(d=>{{d.style.display=d.dataset.q.includes(v)?'':'none'}});
document.querySelectorAll('section').forEach(s=>{{s.style.display=[...s.querySelectorAll('.d')].some(d=>d.style.display!=='none')?'':'none'}})}}
function openAll(btn){{let ds=[...btn.closest('section').querySelectorAll('.d')].filter(d=>d.style.display!=='none');
if(ds.length>50&&!confirm(ds.length+' tabs will open. Continue?'))return;
ds.slice(0,50).forEach((d,i)=>setTimeout(()=>window.open(d.querySelector('a.go').href,'_blank'),i*180))}}
</script></body></html>"""
    p=os.path.join(outdir,"dork-launcher.html"); open(p,"w").write(html); return p
def dork_query(entry,target):
    """The literal Google dork string, scoped to the target (classic dorker output)."""
    d=(entry.get("dork","") or "").strip()
    if not d and entry.get("path"):            # probe entries carry a path, not a dork
        d=f'inurl:"{entry["path"]}"'
    if "site:" in d: return d.replace("{target}",target)
    return f"site:{target} {d}".strip()
def dork_url(entry,target,engine="google"):
    base=SEARCH_ENGINES.get(engine,SEARCH_ENGINES["google"])
    return base+urllib.parse.quote_plus(dork_query(entry,target))

# ─────────────────── CORPUS SOURCES ───────────────────
def src_wayback(domain):
    r=http_get_retry(f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=text&fl=original&collapse=urlkey&limit=10000",timeout=40,tries=3)
    if not r or r.status_code!=200: return set(),"unreachable"
    return set(u.strip() for u in r.text.splitlines() if u.strip()),"ok"
def src_commoncrawl(domain):
    try:
        idx=http_get("https://index.commoncrawl.org/collinfo.json",timeout=20)
        coll=idx.json()[0]["cdx-api"] if (idx and idx.status_code==200) else None
        if not coll: return set(),"no index"
        r=http_get_retry(f"{coll}?url=*.{domain}/*&output=json&fl=url&limit=8000",timeout=45,tries=2)
        if not r or r.status_code!=200: return set(),"unreachable"
        urls=set()
        for line in r.text.splitlines():
            try: urls.add(json.loads(line)["url"])
            except Exception: pass
        return urls,"ok"
    except Exception: return set(),"error"
def src_otx_urls(domain):
    urls=set()
    for page in (1,2):
        r=http_get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page={page}",timeout=25)
        if not r or r.status_code!=200: return (urls,"ok" if urls else "unreachable")
        try:
            for e in r.json().get("url_list",[]):
                if e.get("url"): urls.add(e["url"])
        except Exception: break
    return urls,"ok"
def src_urlscan(domain):
    r=http_get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000",timeout=30)
    if not r or r.status_code!=200: return set(),"unreachable/rate-limited"
    try: return set(x["page"]["url"] for x in r.json().get("results",[]) if x.get("page",{}).get("url")),"ok"
    except Exception: return set(),"error"

def _run_url_binary(binary, domain, timeout=90):
    if not shutil.which(binary): return set(),"not installed"
    try:
        p=subprocess.run([binary,domain] if binary=="gau" else [binary],
                         input=(domain if binary=="waybackurls" else None),
                         capture_output=True,text=True,timeout=timeout)
        urls={u.strip() for u in p.stdout.splitlines() if u.strip().startswith("http")}
        return urls,("ok" if urls else "no results")
    except Exception: return set(),"error"
def src_gau(domain): return _run_url_binary("gau",domain)
def src_waybackurls(domain): return _run_url_binary("waybackurls",domain)

CORPUS_SOURCES=[("Wayback Machine",src_wayback),("Common Crawl",src_commoncrawl),
                ("AlienVault OTX URLs",src_otx_urls),("urlscan.io",src_urlscan),
                ("gau",src_gau),("waybackurls",src_waybackurls)]
SOURCE_FILTER=None  # set by --source (comma list of names/keywords); None = all
def _active_sources():
    if not SOURCE_FILTER: return CORPUS_SOURCES
    keys=[k.strip().lower() for k in SOURCE_FILTER.split(",") if k.strip()]
    sel=[s for s in CORPUS_SOURCES if any(k in s[0].lower() for k in keys)]
    return sel or CORPUS_SOURCES

# ─────────────────── httpx / probe ───────────────────
def probe_live(urls, on_result, max_probe=2500):
    """Probe URLs live; call on_result(url,status,title) for each. httpx if it works, else threaded requests."""
    urls=list(dict.fromkeys(urls))[:max_probe]
    if not urls: return
    got=0
    if HAS_HTTPX:
        tf=tempfile.NamedTemporaryFile("w",suffix=".txt",delete=False); tf.write("\n".join(urls)); tf.close()
        try:
            p=subprocess.Popen(["httpx","-silent","-sc","-no-color","-timeout","8","-l",tf.name],
                               stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
            for line in p.stdout:
                m=re.match(r"(\S+)\s+\[(\d+)\]", line.strip())
                if m:
                    got+=1; on_result(m.group(1), int(m.group(2)), "")
            try: p.wait(timeout=10)
            except Exception:
                try: p.kill()
                except Exception: pass
        except Exception: pass
        finally:
            try: os.unlink(tf.name)
            except Exception: pass
    if got==0:   # httpx missing, flag-incompatible, or produced nothing → reliable threaded fallback
        if HAS_HTTPX: status_line("httpx returned nothing — using built-in threaded prober.","warn")
        from concurrent.futures import ThreadPoolExecutor, as_completed
        def one(u):
            r=http_get(u,timeout=8,allow_redirects=False)
            return (u, r.status_code if r else 0)
        with ThreadPoolExecutor(max_workers=40) as ex:
            futs=[ex.submit(one,u) for u in urls]
            for f in as_completed(futs):
                try: u,code=f.result(); on_result(u,code,"")
                except Exception: pass

def fetch_body(url, headless=False):
    if headless and HAS_PLAYWRIGHT:
        try:
            with sync_playwright() as pw:
                b=pw.chromium.launch(headless=True); pg=b.new_page(user_agent=UA)
                pg.goto(url,timeout=15000,wait_until="domcontentloaded"); txt=pg.content(); b.close()
                return txt
        except Exception: pass
    r=http_get(url,timeout=10)
    return r.text if (r and r.status_code==200) else ""

# ─────────────────── MODULE: Corpus Dork Recon ───────────────────
def module_dork(db, target, rdb, headless=False):
    entries=sorted(db.values(), key=lambda e:(e["category"].lower(), e["name"].lower()))
    cats=sorted(set(e["category"] for e in entries))
    # One simple choice: run everything (default) or narrow by category. Ctrl+C = back to menu.
    scope=ask_select("Dork scope  (Ctrl+C = back to menu):",
                     ["⚡ ALL 214 dorks  (recommended)","▸ Pick categories…"])
    if scope is None: return
    if "Pick categories" in scope:
        picked=ask_select("Categories:",cats,multi=True)
        sel=[e for e in entries if e["category"] in (picked or [])] or entries
    else:
        sel=entries
    # Sources: always ALL by default (override non-interactively with --source a,b,c)
    chosen_src=_active_sources()

    # 0) ALWAYS emit the classic Google/Bing dork query URLs for the selected dorks — the dorker identity.
    #    (You can open these in any browser; no scraping, no blocking.)
    qpath=os.path.join(rdb.dir,"dork-queries.txt")
    with open(qpath,"w") as f:
        for e in sel:
            f.write(f"# {e['name']}  [{e['risk'].upper()}·{e['category']}]\n")
            f.write(f"{dork_query(e,target)}\n")
            f.write(f"google : {dork_url(e,target,'google')}\n")
            f.write(f"bing   : {dork_url(e,target,'bing')}\n\n")
    status_line(f"Generated {len(sel)} live Google/Bing dork queries → {qpath}","ok")
    preview=[e for e in sel if (e.get('dork') or '').strip()][:5] or sel[:5]
    for e in preview:
        c(f"   🔎 {dork_query(e,target)}","#ff5fd7")
    # Build the clickable launcher page and OPEN the dorks (the classic dorker move) — capped so no tab-storms.
    launcher=build_dork_launcher(target, sel, rdb.dir)
    CAP=50
    if not NONINTERACTIVE and sys.stdin.isatty():
        if ask_confirm(f"Open these {len(sel)} dorks in your browser now?", default=True):
            if len(sel)<=CAP:
                status_line(f"Opening {len(sel)} dork searches in your browser…","stage")
                for e in sel:
                    open_in_browser(dork_url(e,target,"google")); time.sleep(0.15)
            else:
                status_line(f"{len(sel)} dorks is a lot of tabs — opening the clickable launcher instead "
                            f"(one tab, every dork, or “open all” per category).","info")
                open_in_browser(launcher)
        else:
            status_line(f"Skipped. Launcher saved → {launcher} (open anytime; also “9 Open report” area).","dim")
    else:
        status_line(f"Dork launcher page → {launcher}","ok")

    # 1) build corpus — stream a sample of the URLs as they come in, save ALL to disk
    corpus=set()
    status_line(f"Building URL corpus for {target} from {len(chosen_src)} sources…","info")
    for i,(name,fn) in enumerate(chosen_src,1):
        stage(i,len(chosen_src),f"{name} …")
        try: urls,st=fn(target)
        except Exception as ex: urls,st=set(),f"error:{ex}"
        for u in urls: rdb.add_asset("url",u,name.split()[0].lower())
        corpus|=urls
        status_line(f"{name}: {len(urls)} URLs ({st})","ok" if urls else "warn")
        for u in sorted(urls)[:8]: c(f"      {u[:110]}","dim")          # <-- see the URLs
        if len(urls)>8: c(f"      … +{len(urls)-8} more","dim")
    cpath=os.path.join(rdb.dir,"corpus-urls.txt")
    with open(cpath,"w") as f: f.write("\n".join(sorted(corpus)))
    status_line(f"Corpus built → {len(corpus)} unique URLs (full list → {cpath})","ok")
    if len(corpus)<10:
        status_line(f"Thin corpus ({len(corpus)} URLs). This target has little public URL history — "
                    "dorks have almost nothing to filter. The Google dork queries above still work.","warn")
        c("    → Try OSINT Recon first, install gau+waybackurls, or test a larger/older domain.","dim")
    if not corpus:
        report(target,rdb); return

    # 2) run each dork AS A FILTER over the corpus — show which dork caught what (dorker view)
    compiled=[]
    for e in sel:
        ut,sf,ct=dork_matchers(e)
        if ut or sf: compiled.append((e,ut,sf,ct))
    candidates={}  # url -> dork entry
    status_line(f"Running {len(compiled)} dorks over the corpus …","stage")
    matched_dorks=0
    for e,ut,sf,ct in compiled:
        hits=[u for u in corpus if url_matches(u,ut,sf)]
        if not hits: continue
        matched_dorks+=1
        c(f"  ▸ {e['name']}  [{e['risk'].upper()}]  → {len(hits)} hit(s)","#ff5fd7")
        c(f"      dork: {e['dork']}","dim")
        for u in hits[:5]: c(f"        {u[:104]}","green")
        if len(hits)>5: c(f"        … +{len(hits)-5} more","dim")
        for u in hits: candidates.setdefault(u,e)
    status_line(f"{matched_dorks} dorks matched → {len(candidates)} candidate URLs to verify.",
                "ok" if candidates else "warn")
    if not candidates:
        status_line("No corpus URLs matched your dorks — but the Google dork queries above are ready to run manually.","info")
        report(target,rdb); return

    # 3) probe candidates live (httpx), stream output
    cand_urls=list(candidates.keys())
    status_line(f"Probing {len(cand_urls)} candidates live with "
                f"{'httpx' if HAS_HTTPX else 'requests'} …","stage")
    live=[]
    counter={"n":0}; hist={}
    def on_res(url,status,title):
        counter["n"]+=1
        hist[status]=hist.get(status,0)+1
        if status and status!=0:
            col="bold green" if status==200 else ("yellow" if status in (401,403) else "dim")
            c(f"  [{status}] {url[:90]}" + (f"  ·  {title[:40]}" if title else ""), col)
        if status==200: live.append(url)
    probe_live(cand_urls,on_res)
    status_line(f"Probed {counter['n']} · {len(live)} live (HTTP 200).","ok")
    # explain non-200s so '0 live' is never a mystery
    others={k:v for k,v in hist.items() if k not in (200,0)}
    if len(live)==0 and others:
        brk=" · ".join(f"{v}×{k}" for k,v in sorted(others.items()))
        note={202:"202 = Cloudflare/WAF challenge (site is behind a bot-wall)",
              403:"403 = exists but access-forbidden",401:"401 = auth required",
              301:"redirects",302:"redirects"}
        hint=next((note[k] for k in others if k in note),"non-200 responses")
        status_line(f"Candidates answered {brk} — {hint}. "
                    f"These aren't counted as findings (only true 200s are).","warn")

    # 4) entropy-confirm on fetchable live URLs
    rows=[]; confirmed=0
    fetch_targets=[u for u in live if FETCHABLE.search(u)][:120]
    if fetch_targets:
        status_line(f"Entropy-confirming {len(fetch_targets)} fetchable files…","stage")
    for j,u in enumerate(fetch_targets,1):
        e=candidates[u]
        body=fetch_body(u,headless=headless)
        secs=scan_secrets(body[:200000]) if body else []
        conf=len(secs)>0
        if conf: confirmed+=1
        sc=exposure_score(e["risk"],0.95,1,conf)
        rdb.add_finding("dork/corpus",e["name"],e["category"],e["risk"],u,status=200,score=sc,confirmed=conf,secrets=secs)
        if conf:
            c(f"  [!!] CONFIRMED {u[:80]} → {', '.join(s['type'] for s in secs[:3])}","bold red")
            rows.append((e["risk"],e["name"],"CONFIRMED SECRET",u[:70]))
    # store the rest of live (non-fetchable or no secret) as real findings (200)
    for u in live:
        if u in fetch_targets: continue
        e=candidates[u]
        rdb.add_finding("dork/corpus",e["name"],e["category"],e["risk"],u,status=200,
                        score=exposure_score(e["risk"],0.75,1,False))
        rows.append((e["risk"],e["name"],"LIVE (200)",u[:70]))

    if rows: _table(rows,title="Live dork findings (real, reachable)")
    status_line(f"Dork Recon done → {len(live)} live findings · {confirmed} CONFIRMED secrets.",
                "crit" if confirmed else "ok")
    report(target,rdb)

# ─────────────────── MODULE: OSINT ───────────────────
def module_recon(target, rdb):
    modules=[("crt.sh (Certificate Transparency)",_recon_crtsh),
             ("HackerTarget (host search)",_recon_hackertarget),
             ("CertSpotter (CT log issuances)",_recon_certspotter),
             ("RapidDNS (passive DNS)",_recon_rapiddns),
             ("Anubis (jldc subdomain DB)",_recon_anubis),
             ("DNS records (A/AAAA/MX/NS/TXT + SPF/DMARC)",_recon_dns),
             ("Wayback URLs",_recon_wayback),
             ("recon-ng bridge (if installed)",_recon_ng)]
    # Runs ALL passive modules automatically (recon-ng only if its binary is installed).
    # To see the module list without running: main menu → "Modules / Dork DB".
    to_run=[(n,f) for n,f in modules if "recon-ng" not in n or shutil.which("recon-ng")]
    status_line(f"Running {len(to_run)} passive OSINT modules against {target} …","info")
    for i,(name,fn) in enumerate(to_run,1):
        stage(i,len(to_run),name)
        try: fn(target,rdb)
        except Exception as ex: status_line(f"{name} error: {ex}","warn")
    subs=rdb.assets("subdomain")
    status_line(f"OSINT complete → {len(subs)} subdomains · {len(rdb.assets('url'))} URLs · {len(rdb.assets('dns'))} DNS.","ok")
    if subs: _table([("info",s["value"],s.get("note",""),"") for s in subs[:50]],
                    title=f"Subdomains ({len(subs)})",cols=("","Subdomain","Source",""))
    report(target,rdb)

def _recon_crtsh(target,rdb):
    r=http_get_retry(f"https://crt.sh/?q=%25.{target}&output=json",timeout=30,tries=3)
    if not r or r.status_code!=200: status_line("crt.sh slow/unreachable (CertSpotter covers the same CT data).","warn"); return
    try: data=r.json()
    except Exception: return
    subs={n.strip().lstrip("*.").lower() for row in data for n in str(row.get("name_value","")).split("\n") if n.strip().endswith(target) and " " not in n}
    new=sum(rdb.add_asset("subdomain",s,"crt.sh") for s in subs)
    status_line(f"crt.sh → {len(subs)} subdomains ({new} new)","ok")
def _recon_hackertarget(target,rdb):
    r=http_get(f"https://api.hackertarget.com/hostsearch/?q={target}",timeout=20)
    if not r or r.status_code!=200 or "error" in r.text.lower(): status_line("HackerTarget: no data / rate-limited.","warn"); return
    subs={l.split(",")[0].strip().lower() for l in r.text.splitlines() if l.split(",")[0].strip().endswith(target)}
    new=sum(rdb.add_asset("subdomain",s,"hackertarget") for s in subs)
    status_line(f"HackerTarget → {len(subs)} hosts ({new} new)","ok")
def _recon_certspotter(target,rdb):
    r=http_get(f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names",timeout=25)
    if not r or r.status_code!=200: status_line("CertSpotter unreachable.","warn"); return
    try: data=r.json()
    except Exception: return
    subs=set()
    for iss in data:
        for n in iss.get("dns_names",[]):
            n=n.strip().lstrip("*.").lower()
            if n.endswith(target): subs.add(n)
    new=sum(rdb.add_asset("subdomain",s,"certspotter") for s in subs)
    status_line(f"CertSpotter → {len(subs)} subdomains ({new} new)","ok")
def _recon_rapiddns(target,rdb):
    r=http_get(f"https://rapiddns.io/subdomain/{target}?full=1",timeout=25)
    if not r or r.status_code!=200: status_line("RapidDNS unreachable.","warn"); return
    subs={m.lower() for m in re.findall(r">([a-z0-9_.-]+\."+re.escape(target)+r")<", r.text, re.I)}
    new=sum(rdb.add_asset("subdomain",s,"rapiddns") for s in subs)
    status_line(f"RapidDNS → {len(subs)} subdomains ({new} new)","ok")
def _recon_anubis(target,rdb):
    r=http_get(f"https://jldc.me/anubis/subdomains/{target}",timeout=20)
    if not r or r.status_code!=200: status_line("Anubis: no data.","warn"); return
    try: subs={s.strip().lower() for s in r.json() if s.endswith(target)}
    except Exception: return
    new=sum(rdb.add_asset("subdomain",s,"anubis") for s in subs)
    status_line(f"Anubis → {len(subs)} subdomains ({new} new)","ok")
def _recon_dns(target,rdb):
    try: import dns.resolver
    except Exception: status_line("dnspython not installed — skipping DNS.","warn"); return
    found=0
    for rtype in ("A","AAAA","MX","NS","TXT"):
        try:
            for a in dns.resolver.resolve(target,rtype,lifetime=8):
                val=a.to_text(); rdb.add_asset("dns",f"{rtype} {val}"); found+=1
                if rtype=="TXT" and ("spf" in val.lower() or "dmarc" in val.lower()):
                    rdb.add_finding("recon/dns",f"{rtype} policy","Domain Intelligence","info","",note=val[:120])
        except Exception: pass
    status_line(f"DNS → {found} records","ok")
def _recon_wayback(target,rdb):
    r=http_get(f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=text&fl=original&collapse=urlkey&limit=3000",timeout=30)
    if not r or r.status_code!=200: status_line("Wayback unreachable / rate-limited.","warn"); return
    urls=[u.strip() for u in r.text.splitlines() if u.strip()]
    for u in urls[:2000]: rdb.add_asset("url",u,"wayback")
    status_line(f"Wayback → {len(urls)} URLs","ok")
def _recon_ng(target,rdb):
    if not shutil.which("recon-ng"): status_line("recon-ng not in PATH — skip (pipx install recon-ng).","warn"); return
    rc="\n".join([f"workspaces create d0rk_{re.sub(r'[^a-z0-9]','_',target)}",f"db insert domains {target}",
        "modules load recon/domains-hosts/certificate_transparency","run",
        "modules load recon/domains-hosts/hackertarget","run","show hosts","exit"])
    try:
        out=subprocess.run(["recon-ng","-r","/dev/stdin"],input=rc,text=True,capture_output=True,timeout=180).stdout
        hosts=set(re.findall(rf"\b([a-z0-9_.-]+\.{re.escape(target)})\b",out,re.I))
        new=sum(rdb.add_asset("subdomain",h.lower(),"recon-ng") for h in hosts)
        status_line(f"recon-ng → {len(hosts)} hosts ({new} new)","ok")
    except Exception as ex: status_line(f"recon-ng error: {ex}","warn")

# ─────────────────── MODULE: Active Sweep ───────────────────
def module_sweep(db, target, rdb, headless=False):
    probes=sorted([e for e in db.values() if e.get("type")=="probe"], key=lambda e:e["path"])
    status_line(f"Active Sweep — directly requesting {len(probes)} high-value paths on {target} (live).","info")
    c("  Purpose: no archive needed — it knocks on known sensitive files (.env, .git/config,","dim")
    c("  /actuator/env, backups, admin panels…) straight on the host and confirms what's exposed.","dim")
    urls=[f"https://{target}{e['path']}" for e in probes]
    byurl={f"https://{target}{e['path']}":e for e in probes}
    live=[]; hist={}
    def on_res(url,status,title):
        e=byurl.get(url)
        if not e: return
        hist[status]=hist.get(status,0)+1
        if status==200:
            c(f"  [200] exposed  {e['path']}","bold green"); live.append(url)
        elif status in (401,403):
            c(f"  [{status}] present-but-blocked  {e['path']}","yellow")
        # 404/others: silent
    probe_live(urls,on_res)
    others={k:v for k,v in hist.items() if k not in (200,0)}
    if not live and others:
        brk=" · ".join(f"{v}×{k}" for k,v in sorted(others.items()))
        hint=("202/503 = Cloudflare/WAF challenge — the host is behind a bot-wall, so direct path probes "
              "can't be verified (try a target not behind Cloudflare)") if (202 in others or 503 in others) \
             else "none of the probed paths returned a live 200"
        status_line(f"Paths answered {brk} — {hint}.","warn")
    # confirm secrets on live fetchable
    rows=[]; confirmed=0
    for i,u in enumerate(live,1):
        e=byurl[u]
        secs=[]
        if e.get("confirm"):
            body=fetch_body(u,headless=headless); secs=scan_secrets(body[:200000]) if body else []
        conf=len(secs)>0
        if conf:
            confirmed+=1
            c(f"  [!!] CONFIRMED {e['path']} → {', '.join(s['type'] for s in secs[:3])}","bold red")
            rows.append((e["risk"],e["name"],"CONFIRMED SECRET",u[:70]))
            if SECRETOPT1C: deep_scan_secretopt1c(u)
        else:
            rows.append((e["risk"],e["name"],"LIVE (200)",u[:70]))
        rdb.add_finding("dork/probe",e["name"],e["category"],e["risk"],u,status=200,
                        score=exposure_score(e["risk"],0.95,1,conf),confirmed=conf,secrets=secs)
    if rows: _table(rows,title="Exposed paths (live)")
    status_line(f"Sweep done → {len(live)} exposed · {confirmed} CONFIRMED secrets.","crit" if confirmed else "ok")
    report(target,rdb)

# ─────────────────── DATABASE VIEWER / EXPORT ───────────────────
def module_database(target, rdb):
    while True:
        ch=ask_select(f"Database — {target}",[
            "View findings","View assets (subdomains/URLs/DNS)","Export findings → CSV",
            "Export everything → JSON","Back"])
        if ch is None or ch.startswith("Back"): return
        if ch.startswith("View findings"):
            fs=rdb.findings(only_real=True)
            _table([(x["risk"],x["name"],("CONFIRMED" if x["confirmed"] else f"HTTP {x['status']}"),x["url"][:70]) for x in fs[:120]],
                   title=f"Findings ({len(fs)})")
        elif ch.startswith("View assets"):
            a=rdb.assets()
            _table([("info",x["value"][:70],x["kind"],x["note"]) for x in a[:150]],
                   title=f"Assets ({len(a)})",cols=("","Value","Kind","Source"))
        elif ch.startswith("Export findings"):
            p=os.path.join(rdb.dir,"findings.csv")
            with open(p,"w",newline="") as f:
                w=csv.writer(f); w.writerow(["score","risk","confirmed","name","category","status","url","secrets"])
                for x in rdb.findings(only_real=True):
                    w.writerow([x["score"],x["risk"],x["confirmed"],x["name"],x["category"],x["status"],x["url"],x["secrets"]])
            status_line(f"Exported → {p}","ok")
        elif ch.startswith("Export everything"):
            p=os.path.join(rdb.dir,"export.json")
            json.dump({"target":target,"findings":rdb.findings(only_real=False),"assets":rdb.assets()},open(p,"w"),indent=2)
            status_line(f"Exported → {p}","ok")

# ─────────────────── ABOUT / USAGE / MODULES ───────────────────
def show_about():
    txt=Text.assemble(
        ("D0rkerR3con is a Google-dorking engine — with proof.\n","bold green"),
        ("It is still a dorker at heart: every run writes the real ","white"),
        ("Google/Bing dork query URLs","bold #ff5fd7"),
        (" for\nyour target (dork-queries.txt) that you can open in any browser — classic dorking, nothing lost.\n\n","white"),
        ("Then it goes further than a bookmark list. Because search engines block automated dorking,\n","white"),
        ("it harvests a real URL corpus of the target (Wayback · Common Crawl · OTX · urlscan · gau),\n","white"),
        ("runs those same 214 dorks AS FILTERS over it, shows you which dork caught which URL, probes\n","white"),
        ("the hits LIVE with httpx, and entropy-confirms leaked secrets — so a 'finding' is verified,\n","white"),
        ("not a guess. OSINT (subdomains/DNS/wayback) and an Active Sweep of sensitive paths round it out.\n\n","white"),
        ("Classic dork URLs + verified live hits · No API keys · Everything saved per target.\n","dim"),
        (f"\nCoded by {AUTHOR} · Black Hat Ethical Hacking","italic cyan"))
    console.print(Panel(txt,title="[bold green]ABOUT",border_style="green",box=box.ROUNDED)) if RICH else print(txt)

def show_usage():
    txt=Text.assemble(
        ("Menu = type the number. The whole menu sits in the box up top.\n\n","bold green"),
        ("1 Dork Recon  ","bold #ff5fd7"),("→ writes the real Google/Bing dork URLs (dork-queries.txt),\n","white"),
        ("              harvests a URL corpus (corpus-urls.txt), runs each dork over it (shows which\n","white"),
        ("              dork caught what), then probes the hits live. Run all 214 or pick categories.\n","white"),
        ("2 OSINT Recon ","bold #ff5fd7"),("→ runs ALL passive modules (subdomains/DNS/wayback) automatically.\n","white"),
        ("3 Active Sweep","bold #ff5fd7"),("→ knocks on sensitive paths (.env, .git/config, backups) on the host.\n","white"),
        ("4 Database · 5 Modules · 6 Set target · 7 About · 8 Usage · 9 Open report · 0 Exit\n\n","white"),
        ("Ctrl+C","bold cyan"),(" in any module = back to menu. Sources default to ALL (no picking).\n\n","white"),
        ("Every run saves to results/<target>/:  dork-queries.txt · corpus-urls.txt · recon.db ·\n","dim"),
        ("report.html/.md/.json.\n\n","dim"),
        ("CLI (headless / scriptable):\n","bold green"),
        ("  python3 d0rkerr3con.py -t example.com --dork --recon --sweep\n","dim"),
        ("  --source wayback,otx,gau   choose corpus sources (default: all)\n","dim"),
        ("  --headless                 render JS pages with chromium (needs playwright)","dim"))
    console.print(Panel(txt,title="[bold green]USAGE",border_style="green",box=box.ROUNDED)) if RICH else print(txt)

def show_modules(db):
    from collections import Counter
    cats=Counter(e["category"] for e in db.values())
    types=Counter(e.get("type","search") for e in db.values())
    if RICH:
        t=Table(box=box.SIMPLE_HEAVY,title="Dork Database — what it scans")
        t.add_column("Category",style="green"); t.add_column("Dorks",justify="right")
        for cat,n in cats.most_common(): t.add_row(cat,str(n))
        console.print(t)
        console.print(Text(f"Types: {dict(types)}  |  OSINT sources: crt.sh, HackerTarget, OTX, Anubis, DNS, Wayback, recon-ng","dim"))
        console.print(Text(f"Corpus sources: {', '.join(s[0] for s in CORPUS_SOURCES)}","dim"))
    else:
        for cat,n in cats.most_common(): print(f"  {n:>3}  {cat}")

# ─────────────────── REPORTS ───────────────────
def _esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")
def report(target, rdb):
    real=rdb.findings(only_real=True); subs=rdb.assets("subdomain")
    now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    json.dump({"target":target,"generated":now,"version":VERSION,"findings":real,
               "subdomains":[s["value"] for s in subs]},open(os.path.join(rdb.dir,"report.json"),"w"),indent=2)
    md=[f"# D0rkerR3con v{VERSION} — Recon Report","",f"**Target:** {target}  ",f"**Generated:** {now}  ",
        f"**Live findings:** {len(real)} | **Subdomains:** {len(subs)}","","## Findings (live / confirmed only)",""]
    for x in real[:80]:
        flag=" **[CONFIRMED SECRET]**" if x["confirmed"] else ""
        md.append(f"- `{x['score']:.0f}` **{x['risk'].upper()}** — {x['name']}{flag}  \n  {x['url']}")
    if subs: md+=["","## Subdomains",""]+[f"- {s['value']}" for s in subs[:400]]
    open(os.path.join(rdb.dir,"report.md"),"w").write("\n".join(md))
    rowshtml=""
    for x in real[:400]:
        col={"critical":"#ff4d6d","high":"#ff9f45","medium":"#ffe066","low":"#4dd2ff","info":"#9aa"}.get(x["risk"],"#9aa")
        secs=json.loads(x["secrets"] or "[]")
        sb=(f"<span class='sec'>🔑 {len(secs)}: "+", ".join(s['type'] for s in secs[:4])+"</span>") if secs else ""
        cf="<b class='conf'>CONFIRMED</b> " if x["confirmed"] else ""
        rowshtml+=(f"<tr><td class='score'>{x['score']:.0f}</td><td style='color:{col}'>{x['risk'].upper()}</td>"
                   f"<td>{cf}{_esc(x['name'])} {sb}</td><td class='cat'>{_esc(x['category'])}</td>"
                   f"<td><a href='{_esc(x['url'])}' target='_blank'>{_esc(x['url'][:85])}</a></td></tr>")
    # clickable Google/Bing dorks, grouped by category
    dorkhtml=""; ndork=0
    try:
        from collections import defaultdict
        dd=load_db(); by=defaultdict(list)
        for e in dd.values(): by[e["category"]].append(e)
        rc={"critical":"#ff4d6d","high":"#ff9f45","medium":"#ffe066","low":"#4dd2ff","info":"#9aa"}
        for cat in sorted(by):
            dorkhtml+=f"<div class='dorkcat'>{_esc(cat)} ({len(by[cat])})</div>"
            for e in sorted(by[cat],key=lambda x:x["name"]):
                ndork+=1; q=dork_query(e,target); col=rc.get(e["risk"],"#9aa")
                dorkhtml+=(f"<div class='dork'><span class='rk' style='color:{col};border-color:{col}'>{e['risk'].upper()}</span>"
                           f"<code>{_esc(q)}</code>"
                           f"<a class='go' href=\"{_esc(dork_url(e,target,'google'))}\" target='_blank' rel='noopener'>Google</a>"
                           f"<a href=\"{_esc(dork_url(e,target,'bing'))}\" target='_blank' rel='noopener'>Bing</a></div>")
    except Exception: dorkhtml="<p class='sub'>(dork list unavailable)</p>"
    html=HTML_TEMPLATE.format(target=_esc(target),now=now,nfind=len(real),nsub=len(subs),
        nconf=sum(1 for x in real if x["confirmed"]),rows=rowshtml,version=VERSION,author=_esc(AUTHOR),
        subs="".join(f"<li>{_esc(s['value'])}</li>" for s in subs[:400]),dorks=dorkhtml,ndork=ndork)
    open(os.path.join(rdb.dir,"report.html"),"w").write(html)
    status_line(f"Report updated → results/{target}/report.html (live findings only)","ok")

def open_report(target):
    p=os.path.join(RESULTS,re.sub(r"[^a-z0-9.-]","_",target),"report.html")
    if not os.path.exists(p): status_line("No report yet — run a module first.","warn"); return
    try:
        if sys.platform=="darwin": subprocess.run(["open",p])
        elif os.name=="posix": subprocess.run(["xdg-open",p])
        else: webbrowser.open("file://"+p)
        status_line(f"Opened {p}","ok")
    except Exception:
        webbrowser.open("file://"+os.path.abspath(p)); status_line(f"Opened {p}","ok")

HTML_TEMPLATE="""<!DOCTYPE html><html><head><meta charset='utf-8'><title>D0rkerR3con Report — {target}</title><style>
:root{{--bg:#070b0f;--card:#0d141c;--green:#39d353;--line:#163a28;--fg:#d6ffe9;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,Menlo,monospace;padding:28px}}
h1{{color:var(--green);margin:0 0 4px}}.sub{{color:#7fe8a8;margin:0 0 18px}}
.cards{{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}}.kpi{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 22px;min-width:150px}}
.kpi b{{font-size:30px;color:var(--green);display:block}}.kpi span{{color:#7f91a0;font-size:12px;text-transform:uppercase;letter-spacing:2px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{padding:9px 12px;text-align:left;border-bottom:1px solid #11212e;font-size:13px;vertical-align:top}}
th{{color:var(--green);text-transform:uppercase;letter-spacing:1px;font-size:11px}}
a{{color:#66d9ff;text-decoration:none}}.score{{color:var(--green);font-weight:bold}}.cat{{color:#7f91a0}}
.conf{{background:#ff4d6d;color:#fff;padding:1px 6px;border-radius:5px;font-size:11px}}.sec{{color:#ffe066;font-size:11px;display:block;margin-top:3px}}
details{{margin-top:22px}}summary{{cursor:pointer;color:var(--green)}}ul{{columns:3;color:#9fb}}.foot{{margin-top:28px;color:#556;font-size:12px}}
.dorkcat{{color:#ff5fd7;font-size:13px;margin:14px 0 6px;font-weight:bold}}
.dork{{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:8px 11px;margin:6px 0;display:flex;flex-wrap:wrap;gap:8px;align-items:center}}
.dork code{{color:#bfe;font-size:12px;word-break:break-all;flex:1;min-width:200px}}
.dork .rk{{border:1px solid;border-radius:5px;font-size:10px;padding:1px 6px}}
.dork a{{font-size:12px;padding:3px 10px;border-radius:6px;background:#11212e;border:1px solid var(--line)}}
.dork a.go{{background:#ff5fd7;color:#140018;border-color:#ff5fd7;font-weight:bold}}
</style></head><body><h1>D0rkerR3con Framework v{version}</h1>
<p class='sub'>Recon Intelligence Report · Target: <b>{target}</b> · {now}</p>
<div class='cards'><div class='kpi'><b>{nfind}</b><span>Live Findings</span></div>
<div class='kpi'><b style='color:#ff4d6d'>{nconf}</b><span>Confirmed Secrets</span></div>
<div class='kpi'><b>{nsub}</b><span>Subdomains</span></div></div>
<table><thead><tr><th>Score</th><th>Risk</th><th>Finding</th><th>Category</th><th>URL</th></tr></thead><tbody>{rows}</tbody></table>
<details><summary>Subdomains ({nsub})</summary><ul>{subs}</ul></details>
<details open><summary>🔎 Google Dorks — {ndork} queries (click to run)</summary>{dorks}</details>
<p class='foot'>Generated by D0rkerR3con Framework · {author} · Black Hat Ethical Hacking · Authorized testing only.</p>
</body></html>"""

# ─────────────────── MENU ───────────────────
MENU_ITEMS=[("1","dork"),("2","osint"),("3","sweep"),("4","db"),("5","modules"),
            ("6","set"),("7","about"),("8","usage"),("9","open"),("0","exit")]
def menu_header(target, clear=True):
    # Whole menu lives INSIDE one rectangle, laid out horizontally so it fits on any screen.
    if not RICH:
        print(f"\n=== D0RKERR3CON v{VERSION} · target: {target or 'not set'} ===")
        print("  1 Dork Recon  2 OSINT  3 Active Sweep  4 Database  5 Modules")
        print("  6 Set target  7 About  8 Usage  9 Open report  0 Exit")
        return
    if clear: console.clear()
    caps=("httpx ✓" if HAS_HTTPX else "requests") + (" · headless ✓" if HAS_PLAYWRIGHT else "")
    bar=Text.assemble(rainbow_inline(" D0RKERR3CON "),
                      (f" v{VERSION} ","dim"),("· target ▸ ","dim"),
                      (target or "not set","bold orange1" if target else "bold red"),
                      (f"   [{caps}]","dim"))
    PINK="#ff5fd7"; CYAN="#45d6ff"; DIM="#8b949e"; RED="#ff6b6b"
    def cell(n,label,color):
        return Text.assemble((f" {n} ","bold white on grey23"),(" "+label,f"bold {color}"))
    g=Table.grid(padding=(0,2)); [g.add_column() for _ in range(4)]
    g.add_row(Text("THE WORK ⚡","bold #ff5fd7"), cell("1","Dork Recon",PINK), cell("2","OSINT Recon",PINK), cell("3","Active Sweep",PINK))
    g.add_row(Text("DATA","bold #45d6ff"), cell("4","Database",CYAN), cell("5","Modules",CYAN), cell("6","Set target",CYAN))
    g.add_row(Text("HELP","dim"), cell("7","About",DIM), cell("8","Usage",DIM),
              Text.assemble(cell("9","Open report",DIM),("    ",""),cell("0","Exit",RED)))
    console.print(Panel(Group(bar, Text(""), g), border_style="magenta", box=box.HEAVY, padding=(0,1)))

def main_menu_select():
    # The menu grid is already drawn inside the box by menu_header(); just read a key.
    keymap=dict(MENU_ITEMS)
    if NONINTERACTIVE or not sys.stdin.isatty(): return "exit"
    while True:
        try: raw=input("\n ▸ pick a number ▸ ").strip().lower()
        except (EOFError,KeyboardInterrupt): return "exit"
        if raw in ("q","x","exit","quit"): return "exit"
        v=keymap.get(raw[:1])
        if v: return v
        status_line("Pick a number from the menu (0–9).","warn")

def main():
    ap=argparse.ArgumentParser(description="D0rkerR3con Framework v2 — Recon Intelligence Engine")
    ap.add_argument("-t","--target"); ap.add_argument("--sweep",action="store_true")
    ap.add_argument("--dork",action="store_true"); ap.add_argument("--recon",action="store_true")
    ap.add_argument("--headless",action="store_true",help="use chromium headless for page rendering")
    ap.add_argument("--source",help="corpus sources to use (comma list: wayback,commoncrawl,otx,urlscan,gau,waybackurls). default: all")
    args=ap.parse_args()
    if args.source:
        global SOURCE_FILTER; SOURCE_FILTER=args.source
    if not os.path.exists(DORK_DB): print("[!] dorkdb.json missing — run: python3 build_dorkdb.py"); sys.exit(1)
    db=load_db(); os.makedirs(RESULTS,exist_ok=True)
    banner()
    status_line(f"Loaded {len(db)} dorks "
                f"({sum(1 for e in db.values() if e.get('type')=='search')} search · "
                f"{sum(1 for e in db.values() if e.get('type')=='special')} pivots · "
                f"{sum(1 for e in db.values() if e.get('type')=='probe')} probes)","ok")

    if args.target and (args.sweep or args.recon or args.dork):
        global NONINTERACTIVE; NONINTERACTIVE=True
        t=args.target.strip().lower(); rdb=ReconDB(re.sub(r"[^a-z0-9.-]","_",t))
        if args.dork: module_dork(db,t,rdb,headless=args.headless)
        if args.recon: module_recon(t,rdb)
        if args.sweep: module_sweep(db,t,rdb,headless=args.headless)
        return

    target=(args.target or "").strip().lower()
    first=True
    while True:
        if not first:
            try: input("\n  ↵ press Enter for the menu … ")
            except (EOFError,KeyboardInterrupt): pass
        menu_header(target, clear=not first)   # keep the big startup logo on the very first paint
        first=False
        choice=main_menu_select()
        if choice in (None,"exit"): c("\nLater, ninja.","bold green"); break
        if choice=="set":
            target=ask_text("Target domain (e.g. example.com):").lower()
            if target: status_line(f"Target set → {target}","ok")
            continue
        if choice=="about": show_about(); continue
        if choice=="usage": show_usage(); continue
        if choice=="modules": show_modules(db); continue
        if not target: status_line("Set a target first.","warn"); continue
        safe=re.sub(r"[^a-z0-9.-]","_",target); rdb=ReconDB(safe)
        try:
            if   choice=="dork":  module_dork(db,target,rdb,headless=args.headless)
            elif choice=="osint": module_recon(target,rdb)
            elif choice=="sweep": module_sweep(db,target,rdb,headless=args.headless)
            elif choice=="db":    module_database(target,rdb)
            elif choice=="open":  open_report(target)
        except KeyboardInterrupt:
            status_line("↩ Back to menu.","warn")

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: print("\n[!] Interrupted. Later, ninja.")
