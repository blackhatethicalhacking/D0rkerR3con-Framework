#!/usr/bin/env python3
"""
build_dorkdb.py  —  D0rkerR3con v2 dork database generator.

Emits dorkdb.json : a large, curated + family-generated dork database.

Entry schema (v2, backward compatible with v1 fields):
{
  "id": "0001",
  "name": "Human readable name",
  "dork": "google-style dork (without the site: prefix)",
  "category": "Category",
  "risk": "critical|high|medium|low|info",
  "description": "What it finds / why it matters",
  "tags": ["..."],
  "type": "search" | "special" | "probe",
  # type==special : open a direct source URL for the target
  "url": "https://...", "suffix": "...", "source": "shodan",
  # type==probe   : fetch <scheme>://<host><path> directly and (optionally) entropy-confirm
  "path": "/.env", "confirm": true
}
"""
import json

ROWS = []
_id = 0

def add(name, dork, category, risk, description, tags=None, type="search",
        url=None, suffix=None, source=None, path=None, confirm=False, engines=None):
    global _id
    _id += 1
    row = {
        "id": f"{_id:04d}",
        "name": name,
        "dork": dork,
        "category": category,
        "risk": risk,
        "description": description,
        "tags": tags or [],
        "type": type,
    }
    if engines:
        row["engines"] = engines
    if type == "special":
        row["url"] = url
        if suffix:
            row["suffix"] = suffix
        row["source"] = source or ""
    if type == "probe":
        row["path"] = path
        row["confirm"] = bool(confirm)
    ROWS.append(row)


# ─────────────────────────── SEARCH DORKS ───────────────────────────
# ── File exposure (directory listings / index.of families) ──
INDEX_TARGETS = [
    ("conf.php", "critical", "Exposed conf.php via open index"),
    ("config.php", "critical", "Exposed config.php via open index"),
    ("wp-config.php", "critical", "Exposed wp-config.php"),
    ("configuration.php", "critical", "Exposed Joomla configuration.php"),
    (".env", "critical", "Exposed .env environment file"),
    ("docker-compose.yml", "high", "Exposed docker-compose.yml"),
    ("main.yml", "high", "Exposed Ansible/CI main.yml"),
    ("users.yml", "high", "Exposed users.yml"),
    ("secrets.yml", "critical", "Exposed Rails/K8s secrets.yml"),
    ("credentials", "critical", "Exposed credentials directory/file"),
    ("id_rsa", "critical", "Exposed SSH private keys"),
    ("id_dsa", "critical", "Exposed SSH DSA keys"),
    (".htpasswd", "high", "Exposed .htpasswd files"),
    (".htaccess", "medium", "Exposed .htaccess files"),
    ("pom.xml", "medium", "Exposed Maven pom.xml"),
    ("web.config", "high", "Exposed IIS web.config"),
    ("settings.py", "critical", "Exposed Django settings.py"),
    ("database.yml", "critical", "Exposed Rails database.yml"),
    ("backup.sql", "critical", "Exposed SQL backup"),
    ("dump.sql", "critical", "Exposed SQL dump"),
    ("admin.zip", "critical", "Exposed admin backup archive"),
    ("backup.zip", "high", "Exposed backup archive"),
    ("www.zip", "high", "Exposed site archive"),
    ("site.tar.gz", "high", "Exposed site tarball"),
    ("/etc", "critical", "Exposed /etc directory"),
    ("/proc", "high", "Exposed /proc directory"),
    ("phpinfo.php", "high", "Exposed phpinfo page"),
    ("robots.txt", "info", "robots.txt (recon)"),
    ("sitemap.xml", "info", "sitemap.xml (recon)"),
    ("error_log", "medium", "Exposed PHP error log"),
    ("access.log", "medium", "Exposed access log"),
    ("debug.log", "medium", "Exposed debug log"),
    (".git", "high", "Exposed .git directory listing"),
    (".svn", "high", "Exposed .svn directory"),
    (".DS_Store", "medium", "Exposed .DS_Store (dir structure leak)"),
    ("npm-debug.log", "medium", "Exposed npm debug log"),
    ("yarn-error.log", "medium", "Exposed yarn error log"),
    ("composer.json", "low", "Exposed composer.json"),
    ("composer.lock", "low", "Exposed composer.lock"),
    ("package.json", "low", "Exposed package.json"),
    ("Gemfile", "low", "Exposed Gemfile"),
    ("Dockerfile", "low", "Exposed Dockerfile"),
    ("terraform.tfstate", "critical", "Exposed Terraform state (contains secrets)"),
    ("kubeconfig", "critical", "Exposed kubeconfig"),
    ("credentials.json", "critical", "Exposed credentials.json (GCP/service accounts)"),
    ("service-account.json", "critical", "Exposed GCP service account key"),
    ("aws", "high", "Exposed aws credential files"),
]
for fname, risk, desc in INDEX_TARGETS:
    add(f"Index of → {fname}", f'intitle:"index of" "{fname}"', "File Exposure", risk,
        desc, tags=["index-of", "file-exposure"])

# ── Extension-based exposure families ──
EXT_FAMILIES = {
    "Config files": (["xml", "conf", "cnf", "reg", "inf", "rdp", "cfg", "ini", "ora", "env", "yaml", "yml", "toml", "properties"], "high", "Exposed configuration files"),
    "Database files": (["sql", "dbf", "mdb", "sqlite", "sqlitedb", "db", "db3", "accdb"], "critical", "Exposed database files"),
    "Backup files": (["bak", "backup", "bkp", "bkf", "old", "orig", "save", "swp", "tmp", "~"], "high", "Exposed backup / temp files"),
    "Log files": (["log", "logs"], "medium", "Exposed log files"),
    "Secret / key files": (["pem", "key", "ppk", "pfx", "p12", "keystore", "jks", "asc", "gpg"], "critical", "Exposed private keys / certs"),
    "Documents / PII": (["pdf", "doc", "docx", "xls", "xlsx", "csv", "ppt", "pptx", "rtf", "odt"], "medium", "Exposed documents (potential PII)"),
    "Archives": (["zip", "tar", "gz", "rar", "7z", "tgz"], "high", "Exposed archives"),
    "Source / scripts": (["php~", "phps", "inc", "bak.php", "java", "cs", "rb", "py", "go"], "high", "Exposed source files"),
}
for name, (exts, risk, desc) in EXT_FAMILIES.items():
    dork = " | ".join(f"ext:{e}" for e in exts)
    add(name, dork, "File Exposure", risk, desc, tags=["ext", "file-exposure"])

# ── Secrets & keys in indexed content ──
SECRET_PATTERNS = [
    ("AWS Access Key in files", 'intext:"AKIA" ext:log | ext:txt | ext:json | ext:env', "critical", "AWS access keys in indexed files"),
    ("AWS Secret references", 'intext:"aws_secret_access_key"', "critical", "AWS secret key references"),
    ("Private RSA keys", 'intext:"-----BEGIN RSA PRIVATE KEY-----"', "critical", "Leaked RSA private keys"),
    ("OpenSSH private keys", 'intext:"-----BEGIN OPENSSH PRIVATE KEY-----"', "critical", "Leaked OpenSSH private keys"),
    ("PGP private keys", 'intext:"-----BEGIN PGP PRIVATE KEY BLOCK-----"', "critical", "Leaked PGP private keys"),
    ("Generic API key assignments", 'intext:"api_key" | intext:"apikey" | intext:"client_secret" ext:env | ext:json | ext:txt', "high", "API key / secret assignments"),
    ("Slack tokens", 'intext:"xoxb-" | intext:"xoxp-"', "critical", "Slack bot/user tokens"),
    ("Google API keys", 'intext:"AIza"', "high", "Google API keys"),
    ("Stripe secret keys", 'intext:"sk_live_"', "critical", "Stripe live secret keys"),
    ("Firebase configs", 'intext:"firebaseio.com" ext:json', "medium", "Firebase config exposure"),
    ("JDBC connection strings", 'intext:"jdbc:mysql://" | intext:"jdbc:postgresql://"', "high", "Database connection strings with creds"),
    ("MongoDB connection URIs", 'intext:"mongodb://" | intext:"mongodb+srv://"', "high", "MongoDB URIs with creds"),
    ("SMTP credentials", 'intext:"smtp" intext:"password" ext:env | ext:cfg | ext:ini', "high", "SMTP credentials"),
    ("DB passwords in configs", 'intext:"DB_PASSWORD" | intext:"database_password"', "high", "Database passwords in config"),
    ("JWT secrets", 'intext:"jwt_secret" | intext:"JWT_SECRET"', "high", "JWT signing secrets"),
    ("Twilio credentials", 'intext:"TWILIO_AUTH_TOKEN"', "high", "Twilio auth tokens"),
    ("SendGrid keys", 'intext:"SG." ext:env | ext:txt', "high", "SendGrid API keys"),
    ("GitHub tokens", 'intext:"ghp_" | intext:"github_token"', "critical", "GitHub personal access tokens"),
    ("Mailgun keys", 'intext:"key-" intext:"mailgun"', "high", "Mailgun API keys"),
    ("Azure storage keys", 'intext:"DefaultEndpointsProtocol" intext:"AccountKey="', "critical", "Azure storage account keys"),
]
for name, dork, risk, desc in SECRET_PATTERNS:
    add(name, dork, "Secrets & Keys", risk, desc, tags=["secrets", "keys", "confirmable"])

# ── Auth / panels / login ──
AUTH = [
    ("Login portals", 'inurl:login | inurl:signin | intitle:login | intitle:"sign in"', "low", "Login/sign-in pages"),
    ("Admin panels", 'inurl:admin | inurl:administrator | inurl:adminpanel | intitle:"admin login"', "medium", "Admin panels"),
    ("phpMyAdmin", 'inurl:phpmyadmin | intitle:phpMyAdmin', "high", "phpMyAdmin interfaces"),
    ("Adminer", 'intitle:"Adminer" inurl:adminer.php', "high", "Adminer DB panels"),
    ("cPanel", 'inurl:cpanel | intitle:cPanel', "medium", "cPanel logins"),
    ("Webmin", 'inurl:10000 intitle:webmin', "high", "Webmin panels"),
    ("Jenkins", 'intitle:"Dashboard [Jenkins]"', "high", "Exposed Jenkins dashboards"),
    ("Grafana", 'inurl:/login intitle:"Grafana"', "medium", "Grafana login"),
    ("Kibana", 'inurl:app/kibana', "high", "Exposed Kibana"),
    ("Jupyter notebooks", 'intitle:"Jupyter" inurl:/tree', "high", "Open Jupyter notebooks"),
    ("Spring Boot Actuator", 'inurl:/actuator/health | inurl:/actuator/env', "high", "Spring Boot actuator endpoints"),
    ("GitLab", 'intitle:"GitLab" inurl:/users/sign_in', "medium", "GitLab logins"),
    ("Keycloak", 'inurl:/auth/realms', "medium", "Keycloak realms"),
    ("Citrix", 'inurl:/vpn/index.html | intitle:"Citrix Gateway"', "high", "Citrix gateways"),
    ("RDP web", 'inurl:/RDWeb/Pages', "high", "RD Web Access"),
    ("VMware vSphere", 'intitle:"VMware" inurl:/ui', "high", "VMware vSphere UIs"),
    ("Default credentials pages", 'intext:"default password" intitle:login', "medium", "Pages mentioning default passwords"),
]
for name, dork, risk, desc in AUTH:
    add(name, dork, "Auth & Panels", risk, desc, tags=["auth", "panels"])

# ── API exposure ──
API = [
    ("API endpoints", 'inurl:/api/ | inurl:/rest/ | inurl:/v1/ | inurl:/v2/ | inurl:/v3/', "medium", "API endpoints"),
    ("Swagger / OpenAPI", 'inurl:swagger | inurl:api-docs | inurl:openapi.json | intitle:"Swagger UI"', "medium", "API documentation"),
    ("GraphQL endpoints", 'inurl:/graphql | inurl:/graphiql', "medium", "GraphQL endpoints"),
    ("Postman collections", 'inurl:postman ext:json', "medium", "Exposed Postman collections"),
    ("WADL / WSDL", 'inurl:?wsdl | ext:wadl', "low", "SOAP WSDL/WADL"),
    ("API keys in JS", 'inurl:/js/ intext:"api_key" ext:js', "high", "API keys in JavaScript"),
    ("JSON-RPC", 'inurl:json-rpc | inurl:/rpc', "medium", "JSON-RPC endpoints"),
    ("Firebase REST", 'inurl:firebaseio.com', "medium", "Firebase REST databases"),
]
for name, dork, risk, desc in API:
    add(name, dork, "API Exposure", risk, desc, tags=["api"])

# ── Cloud storage buckets ──
CLOUD = [
    ("S3 buckets (text)", 'inurl:s3.amazonaws.com | intitle:"Index" inurl:s3.amazonaws.com', "high", "Open S3 buckets"),
    ("S3 listed files", 'site:s3.amazonaws.com', "high", "Files on S3", "special", "https://www.google.com/search?q=site:s3.amazonaws.com+", None, "google"),
    ("Google Cloud Storage", 'inurl:storage.googleapis.com', "high", "Open GCS buckets"),
    ("Azure Blob", 'inurl:blob.core.windows.net', "high", "Open Azure blob storage"),
    ("DigitalOcean Spaces", 'inurl:digitaloceanspaces.com', "high", "Open DO Spaces"),
    ("Firebase storage", 'inurl:firebasestorage.googleapis.com', "medium", "Firebase storage objects"),
    ("Backblaze B2", 'inurl:backblazeb2.com', "medium", "Backblaze B2 buckets"),
]
for item in CLOUD:
    if len(item) == 4:
        name, dork, risk, desc = item
        add(name, dork, "Cloud Storage", risk, desc, tags=["cloud", "buckets"])
    else:
        name, dork, risk, desc, type, url, suffix, source = item
        add(name, dork, "Cloud Storage", risk, desc, tags=["cloud", "buckets"],
            type=type, url=url, suffix=suffix, source=source)

# ── CMS specific ──
CMS = [
    ("WordPress core", 'inurl:wp-content | inurl:wp-includes | inurl:wp-admin', "low", "WordPress installs"),
    ("WP config backups", 'intitle:"index of" "wp-config.php.bak" | "wp-config.php.old"', "critical", "WordPress config backups"),
    ("WP debug.log", 'inurl:wp-content/debug.log', "medium", "WordPress debug logs"),
    ("WP uploads dir listing", 'intitle:"index of" inurl:wp-content/uploads', "low", "Open WP uploads"),
    ("WP plugin disclosure", 'inurl:wp-content/plugins/ intitle:"index of"', "medium", "WP plugin enumeration"),
    ("Joomla config", 'inurl:configuration.php.bak | inurl:configuration.php-dist', "high", "Joomla config"),
    ("Joomla admin", 'inurl:administrator/index.php intitle:Joomla', "medium", "Joomla admin"),
    ("Drupal login", 'inurl:user intitle:"Drupal" intext:"Log in"', "medium", "Drupal login"),
    ("Drupal CHANGELOG", 'inurl:CHANGELOG.txt intext:drupal', "low", "Drupal version via changelog"),
    ("Magento admin", 'inurl:/admin intitle:Magento', "medium", "Magento admin"),
    ("Magento config", 'inurl:app/etc/local.xml', "critical", "Magento local.xml (DB creds)"),
    ("Laravel .env", 'inurl:.env intext:"APP_KEY"', "critical", "Laravel .env exposure"),
    ("Laravel telescope", 'inurl:/telescope/requests', "high", "Laravel Telescope exposed"),
    ("Symfony profiler", 'inurl:/_profiler', "high", "Symfony profiler exposed"),
]
for name, dork, risk, desc in CMS:
    add(name, dork, "CMS", risk, desc, tags=["cms"])

# ── Error messages / debug ──
ERRORS = [
    ("SQL errors", 'intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"mysql_fetch" | intext:"ORA-01756"', "high", "SQL error disclosure"),
    ("PHP warnings", 'intext:"Warning: include(" | intext:"Fatal error:" ext:php', "medium", "PHP error disclosure"),
    ("Stack traces", 'intext:"Stack trace:" | intext:"Traceback (most recent call last)"', "medium", "Stack traces"),
    ("Django debug", 'intext:"DisallowedHost" | intitle:"Dj​ango" "DEBUG = True"', "high", "Django debug pages"),
    ("ASP.NET errors", 'intext:"Server Error in" intext:"Application"', "medium", "ASP.NET error pages"),
    ("Whoops Laravel", 'intitle:"Whoops! There was an error"', "high", "Laravel Whoops error page"),
    ("Node stack traces", 'intext:"at Object.<anonymous>" intext:"node_modules"', "medium", "Node.js stack traces"),
]
for name, dork, risk, desc in ERRORS:
    add(name, dork, "Error Disclosure", risk, desc, tags=["errors", "debug"])

# ── Network devices / IoT / cameras ──
DEVICES = [
    ("Webcams (generic)", 'inurl:/view.shtml | intitle:"Live View / - AXIS"', "medium", "Exposed webcams"),
    ("Hikvision", 'intext:"Hikvision" inurl:login', "medium", "Hikvision devices"),
    ("Dahua", 'intitle:"WEB SERVICE" inurl:login intext:Dahua', "medium", "Dahua devices"),
    ("Printers (HP)", 'intitle:"HP LaserJet" inurl:hp/device', "low", "Exposed HP printers"),
    ("Routers (generic)", 'intitle:"router" intitle:"login" inurl:/cgi-bin', "medium", "Exposed routers"),
    ("UPS devices", 'intitle:"UPS Web/SNMP"', "low", "UPS management"),
    ("SCADA/HMI", 'intitle:"Niagara Web Launcher" | inurl:/config/public/products', "high", "SCADA/HMI interfaces"),
    ("NAS (Synology)", 'intitle:"Synology" inurl:/webman', "medium", "Synology NAS"),
    ("NAS (QNAP)", 'intitle:"QNAP" inurl:/cgi-bin', "medium", "QNAP NAS"),
    ("VoIP (Asterisk)", 'intitle:"Asterisk" inurl:/panel', "medium", "Asterisk VoIP panels"),
]
for name, dork, risk, desc in DEVICES:
    add(name, dork, "Network Devices & IoT", risk, desc, tags=["iot", "devices"])

# ── Param-based vuln surface ──
PARAMS = [
    ("Open redirect params", 'inurl:redir | inurl:redirect= | inurl:url= | inurl:return= | inurl:next=', "medium", "Open-redirect-prone parameters"),
    ("LFI/RFI params", 'inurl:file= | inurl:path= | inurl:page= | inurl:include=', "high", "LFI/RFI-prone parameters"),
    ("SSRF params", 'inurl:dest= | inurl:uri= | inurl:continue= | inurl:feed= | inurl:host=', "high", "SSRF-prone parameters"),
    ("SQLi params", 'inurl:id= | inurl:cat= | inurl:pid= | inurl:product=', "high", "SQLi-prone numeric parameters"),
    ("XSS params", 'inurl:q= | inurl:search= | inurl:query= | inurl:keyword=', "medium", "Reflected-XSS-prone parameters"),
    ("Command injection params", 'inurl:cmd= | inurl:exec= | inurl:command= | inurl:run=', "high", "Command-injection-prone parameters"),
]
for name, dork, risk, desc in PARAMS:
    add(name, dork, "Vuln Surface Params", risk, desc, tags=["params", "vuln-surface"])

# ── Dev / staging / leaks ──
DEV = [
    ("Dev/staging subdomains", 'inurl:dev. | inurl:staging. | inurl:test. | inurl:uat. | inurl:qa.', "medium", "Dev/staging environments"),
    ("Git exposed configs", 'inurl:".git/config"', "high", "Exposed .git/config"),
    ("Env files in URL", 'inurl:.env -inurl:env.example', "critical", "Live .env files"),
    ("Jenkins script console", 'inurl:/script intitle:"Jenkins"', "critical", "Jenkins script console"),
    ("CI secrets (travis)", 'inurl:.travis.yml intext:secure', "medium", "Travis CI secrets"),
    ("GitHub Actions secrets", 'inurl:.github/workflows ext:yml intext:secrets.', "low", "GitHub Actions workflow refs"),
    ("Sentry DSN", 'intext:"sentry.io" intext:"dsn"', "medium", "Exposed Sentry DSNs"),
]
for name, dork, risk, desc in DEV:
    add(name, dork, "Dev & CI/CD", risk, desc, tags=["devops", "ci"])


# ─────────────────────────── SPECIAL SOURCE PIVOTS ───────────────────────────
SPECIALS = [
    ("Shodan (host)", "Shodan host search", "Domain Intelligence", "low", "shodan", "https://www.shodan.io/search?query=hostname:", None),
    ("Censys hosts", "Censys host search", "Domain Intelligence", "low", "censys", "https://search.censys.io/search?resource=hosts&q=", None),
    ("FOFA", "FOFA search", "Domain Intelligence", "low", "fofa", "https://fofa.info/result?qbase64=", None),
    ("ZoomEye", "ZoomEye search", "Domain Intelligence", "low", "zoomeye", "https://www.zoomeye.org/searchResult?q=", None),
    ("BinaryEdge", "BinaryEdge search", "Domain Intelligence", "low", "binaryedge", "https://app.binaryedge.io/services/query?query=", None),
    ("GreyNoise", "GreyNoise lookup", "Domain Intelligence", "low", "greynoise", "https://viz.greynoise.io/query/?gnql=", None),
    ("crt.sh (CT logs)", "Certificate Transparency subdomains", "Domain Intelligence", "low", "crtsh", "https://crt.sh/?q=%25.", None),
    ("CertSpotter", "CertSpotter CT logs", "Domain Intelligence", "low", "certspotter", "https://api.certspotter.com/v1/issuances?domain=", "&include_subdomains=true&expand=dns_names"),
    ("Wayback URLs", "Wayback Machine archived URLs", "Domain Intelligence", "low", "wayback", "https://web.archive.org/cdx/search/cdx?url=", "/*&output=text&fl=original&collapse=urlkey"),
    ("GitHub code search", "GitHub code search for domain", "Code Repositories", "medium", "github", "https://github.com/search?type=code&q=", None),
    ("GitLab search", "GitLab code search", "Code Repositories", "medium", "gitlab", "https://gitlab.com/search?search=", None),
    ("GrayHatWarfare buckets", "Open bucket file search", "Cloud Storage", "high", "grayhatwarfare", "https://buckets.grayhatwarfare.com/results/", None),
    ("PublicWWW source search", "Source-code search across the web", "Code Repositories", "medium", "publicwww", "https://publicwww.com/websites/", "/"),
    ("IntelX leaks", "Intelligence X leak search", "Leaks & Pastes", "medium", "intelx", "https://intelx.io/?s=", None),
    ("Pastebin mentions", "Pastebin mentions", "Leaks & Pastes", "medium", "pastebin", "https://www.google.com/search?q=site:pastebin.com+", None),
    ("DeHashed", "DeHashed breach search", "Leaks & Pastes", "medium", "dehashed", "https://www.dehashed.com/search?query=", None),
    ("LinkedIn employees", "Employee enumeration", "People OSINT", "low", "linkedin", 'https://www.google.com/search?q=site:linkedin.com/in+"', '"'),
    ("Hunter.io emails", "Email pattern discovery", "People OSINT", "low", "hunter", "https://hunter.io/search/", None),
    ("DNSDumpster", "Passive DNS map", "Domain Intelligence", "low", "dnsdumpster", "https://dnsdumpster.com/?q=", None),
    ("ViewDNS", "ViewDNS reverse tools", "Domain Intelligence", "low", "viewdns", "https://viewdns.info/reverseip/?host=", "&t=1"),
    ("SecurityTrails", "SecurityTrails history", "Domain Intelligence", "low", "securitytrails", "https://securitytrails.com/domain/", "/dns"),
    ("urlscan.io", "urlscan historical scans", "Domain Intelligence", "low", "urlscan", "https://urlscan.io/search/#", None),
    ("VirusTotal domain", "VirusTotal relations", "Domain Intelligence", "low", "virustotal", "https://www.virustotal.com/gui/domain/", "/relations"),
    ("AbuseIPDB", "AbuseIPDB reputation", "Domain Intelligence", "low", "abuseipdb", "https://www.abuseipdb.com/check/", None),
    ("OpenBugBounty", "Public vuln reports", "Bug Bounty", "low", "openbugbounty", "https://www.openbugbounty.org/search/?search=", "&type=host"),
]
for name, desc, cat, risk, source, url, suffix in SPECIALS:
    add(name, "", cat, risk, desc, tags=["pivot", source], type="special",
        url=url, suffix=suffix, source=source)


# ─────────────────────────── ACTIVE PROBES (entropy-confirm) ───────────────────────────
# Direct paths fetched against the live target; confirm=True runs the entropy/secret engine.
PROBES = [
    ("/.env", "critical", "Live Laravel/Node .env with secrets", True),
    ("/.env.local", "critical", "Local env overrides", True),
    ("/.env.production", "critical", "Production env", True),
    ("/.git/config", "high", "Git config (repo URL, maybe creds)", True),
    ("/.git/HEAD", "medium", "Git repo presence", False),
    ("/.svn/entries", "medium", "SVN repo presence", False),
    ("/.aws/credentials", "critical", "AWS credentials file", True),
    ("/config.json", "high", "App config.json", True),
    ("/config.php.bak", "critical", "PHP config backup", True),
    ("/wp-config.php.bak", "critical", "WordPress config backup", True),
    ("/wp-config.php~", "critical", "WordPress config tilde backup", True),
    ("/.DS_Store", "medium", "macOS directory listing leak", False),
    ("/phpinfo.php", "high", "phpinfo page", False),
    ("/server-status", "medium", "Apache server-status", False),
    ("/server-info", "medium", "Apache server-info", False),
    ("/actuator/env", "high", "Spring Boot env (secrets)", True),
    ("/actuator/health", "low", "Spring Boot health", False),
    ("/actuator/heapdump", "critical", "Spring Boot heapdump (memory secrets)", False),
    ("/debug/default/view", "high", "Yii debug toolbar", False),
    ("/_profiler/phpinfo", "medium", "Symfony profiler phpinfo", False),
    ("/telescope/requests", "high", "Laravel Telescope", False),
    ("/.well-known/security.txt", "info", "security.txt (contact)", False),
    ("/backup.zip", "high", "Backup archive", False),
    ("/backup.sql", "critical", "SQL backup", True),
    ("/dump.sql", "critical", "SQL dump", True),
    ("/credentials.json", "critical", "Service account credentials", True),
    ("/.npmrc", "high", "npm registry token", True),
    ("/.dockercfg", "high", "Docker registry creds", True),
    ("/docker-compose.yml", "high", "Compose with env secrets", True),
    ("/sftp-config.json", "high", "Sublime SFTP creds", True),
    ("/.vscode/sftp.json", "high", "VSCode SFTP creds", True),
    ("/storage/logs/laravel.log", "medium", "Laravel log", True),
    ("/api/swagger.json", "low", "Swagger spec", False),
    ("/graphql", "medium", "GraphQL endpoint", False),
    ("/.env.bak", "critical", "Env backup", True),
    ("/security.txt", "info", "security.txt", False),
    ("/crossdomain.xml", "low", "Flash crossdomain policy", False),
    ("/clientaccesspolicy.xml", "low", "Silverlight policy", False),
]
for path, risk, desc, confirm in PROBES:
    add(f"Probe {path}", "", "Active Exposure Probe", risk,
        desc, tags=["probe", "active"] + (["confirmable"] if confirm else []),
        type="probe", path=path, confirm=confirm)


# ─────────────────────────── EMIT ───────────────────────────
db = {r["id"]: r for r in ROWS}
with open("dorkdb.json", "w") as f:
    json.dump(db, f, indent=2)

from collections import Counter
cats = Counter(r["category"] for r in ROWS)
types = Counter(r["type"] for r in ROWS)
risks = Counter(r["risk"] for r in ROWS)
print(f"Total entries: {len(ROWS)}")
print("By type:   ", dict(types))
print("By risk:   ", dict(risks))
print("Categories:", len(cats))
for c, n in cats.most_common():
    print(f"   {n:>3}  {c}")
