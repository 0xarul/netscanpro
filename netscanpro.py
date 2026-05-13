#!/usr/bin/env python3
"""
NetScan Pro - Single File Edition
Professional Network & Web Security Assessment Framework
For authorized penetration testing use only.

Usage:
    python3 netscanpro.py --target 192.168.1.1 --full
    python3 netscanpro.py --target https://example.com --web
    python3 netscanpro.py --target 10.0.0.1 --ports --port-range 1-65535
"""

# ── Auto-install dependencies ─────────────────────────────────────────────────
import subprocess, sys

def install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

for pkg in ["requests", "colorama"]:
    try:
        __import__(pkg)
    except ImportError:
        print(f"[*] Installing {pkg}...")
        install(pkg)

# ── Imports ───────────────────────────────────────────────────────────────────
import argparse, socket, threading, urllib.parse
import concurrent.futures
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)
import requests
requests.packages.urllib3.disable_warnings()

# ═════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║        NetScan Pro — Security Assessment Framework          ║
║        Single-File Edition | Authorized Use Only           ║
║                 AUTHOR - ARULKUMARAN V                     ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

COMMON_SERVICES = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 111:"RPCBind", 135:"MSRPC", 139:"NetBIOS",
    143:"IMAP", 443:"HTTPS", 445:"SMB", 993:"IMAPS", 995:"POP3S",
    1433:"MSSQL", 1521:"Oracle", 2181:"ZooKeeper", 3306:"MySQL",
    3389:"RDP", 4444:"Metasploit", 5432:"PostgreSQL", 5900:"VNC",
    5985:"WinRM-HTTP", 5986:"WinRM-HTTPS", 6379:"Redis",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt", 8888:"Jupyter",
    9200:"Elasticsearch", 27017:"MongoDB",
}

RISKY_PORTS = {23, 21, 135, 139, 445, 1433, 3306, 3389, 5900, 4444, 6379, 9200, 27017}

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HIGH",   "Missing HSTS — vulnerable to downgrade attacks"),
    ("X-Frame-Options",           "MEDIUM", "Missing X-Frame-Options — clickjacking possible"),
    ("X-Content-Type-Options",    "MEDIUM", "Missing X-Content-Type-Options — MIME sniffing risk"),
    ("Content-Security-Policy",   "HIGH",   "Missing CSP — XSS less mitigated"),
    ("Referrer-Policy",           "LOW",    "Missing Referrer-Policy — referrer data leaked"),
    ("Permissions-Policy",        "LOW",    "Missing Permissions-Policy header"),
    ("X-XSS-Protection",          "LOW",    "Missing X-XSS-Protection (legacy browsers)"),
]

SENSITIVE_PATHS = [
    "/.git/config","/.env","/robots.txt","/sitemap.xml",
    "/admin","/admin/login","/wp-admin","/wp-login.php",
    "/phpinfo.php","/info.php","/test.php",
    "/.htaccess","/web.config","/config.php",
    "/backup.zip","/backup.sql","/dump.sql",
    "/api/v1","/api/v2","/swagger","/swagger-ui.html",
    "/actuator","/actuator/env","/actuator/health",
    "/server-status","/server-info",
    "/crossdomain.xml","/.well-known/security.txt",
    "/graphql","/graphiql",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
]

SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "1' AND 1=1--"]

SQLI_ERRORS = [
    "sql syntax","mysql_fetch","ora-","unclosed quotation",
    "quoted string not properly terminated","syntax error",
    "you have an error in your sql","warning: mysql",
    "pg_query","sqlite_","mssql_","odbc_",
]

SEVERITY_ORDER  = {"HIGH":0,"MEDIUM":1,"LOW":2,"INFO":3}
SEVERITY_COLORS = {"HIGH":"#e74c3c","MEDIUM":"#f39c12","LOW":"#3498db","INFO":"#27ae60"}


# ═════════════════════════════════════════════════════════════════════════════
#  PORT SCANNER
# ═════════════════════════════════════════════════════════════════════════════

class PortScanner:
    def __init__(self, target, port_range="1-1024", threads=100, timeout=3, verbose=False):
        self.target     = target
        self.port_range = port_range
        self.threads    = threads
        self.timeout    = timeout
        self.verbose    = verbose
        self.open_ports = []
        self.lock       = threading.Lock()

    def _parse_ports(self):
        ports = []
        for part in self.port_range.split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-")
                ports.extend(range(int(a), int(b)+1))
            else:
                ports.append(int(part))
        return ports

    def _resolve(self):
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            return None

    def _grab_banner(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                if port in (80, 8080, 8888):
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                else:
                    s.send(b"\r\n")
                return s.recv(1024).decode("utf-8", errors="ignore").strip()[:200]
        except Exception:
            return ""

    def _scan_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((ip, port)) == 0:
                    svc    = COMMON_SERVICES.get(port, "Unknown")
                    banner = self._grab_banner(ip, port)
                    risk   = "HIGH" if port in RISKY_PORTS else "INFO"
                    entry  = {"port":port,"service":svc,"banner":banner,"risk":risk}
                    with self.lock:
                        self.open_ports.append(entry)
                    if self.verbose:
                        c = Fore.RED if risk=="HIGH" else Fore.GREEN
                        print(f"  {c}[OPEN]{Style.RESET_ALL} {port}/tcp  {svc}"
                              + (f"  [{banner[:60]}]" if banner else ""))
        except Exception:
            pass

    def run(self):
        ip = self._resolve()
        if not ip:
            print(f"{Fore.RED}[-] Cannot resolve: {self.target}{Style.RESET_ALL}")
            return {"error": f"Cannot resolve {self.target}"}

        ports = self._parse_ports()
        print(f"  {Fore.WHITE}IP        : {ip}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Ports     : {self.port_range} ({len(ports)} total){Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Threads   : {self.threads}{Style.RESET_ALL}\n")

        start = datetime.now()
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(self._scan_port, ip, p) for p in ports]
            done, total = 0, len(futures)
            for f in concurrent.futures.as_completed(futures):
                done += 1
                if not self.verbose and done % 50 == 0:
                    pct = int(done/total*100)
                    print(f"\r  {Fore.CYAN}Scanning... {pct}% ({done}/{total}){Style.RESET_ALL}", end="", flush=True)

        duration = (datetime.now()-start).total_seconds()
        self.open_ports.sort(key=lambda x: x["port"])

        print(f"\r  {Fore.GREEN}Done in {duration:.1f}s — {len(self.open_ports)} open port(s){Style.RESET_ALL}        ")
        hr = [p for p in self.open_ports if p["risk"]=="HIGH"]
        if hr:
            print(f"  {Fore.RED}[!] High-risk: {', '.join(str(p['port']) for p in hr)}{Style.RESET_ALL}")

        return {"target":self.target,"ip":ip,"ports_scanned":len(ports),
                "duration_seconds":duration,"open_ports":self.open_ports}


# ═════════════════════════════════════════════════════════════════════════════
#  WEB SCANNER
# ═════════════════════════════════════════════════════════════════════════════

class WebScanner:
    def __init__(self, target, timeout=5, verbose=False):
        self.target   = target.rstrip("/")
        self.timeout  = timeout
        self.verbose  = verbose
        self.findings = []
        self.session  = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent":"Mozilla/5.0 (Security Assessment Tool)"})

    def _get(self, path="", params=None):
        try:
            return self.session.get(self.target+path, params=params,
                                    timeout=self.timeout, allow_redirects=True)
        except Exception:
            return None

    def _add(self, category, severity, title, detail, url=""):
        self.findings.append({"category":category,"severity":severity,
                               "title":title,"detail":detail,"url":url or self.target})
        c = {"HIGH":Fore.RED,"MEDIUM":Fore.YELLOW,"LOW":Fore.CYAN}.get(severity, Fore.WHITE)
        if self.verbose or severity in ("HIGH","MEDIUM"):
            print(f"  {c}[{severity:<6}]{Style.RESET_ALL} {title}")

    def check_headers(self):
        print(f"  {Fore.CYAN}→ Security headers{Style.RESET_ALL}")
        r = self._get()
        if not r: return
        hl = {k.lower():v for k,v in r.headers.items()}
        for hdr, sev, msg in SECURITY_HEADERS:
            if hdr.lower() not in hl:
                self._add("Security Headers", sev, f"Missing {hdr}", msg)
        for h in ["Server","X-Powered-By","X-AspNet-Version"]:
            v = r.headers.get(h)
            if v:
                self._add("Info Disclosure","LOW",f"{h} exposes server info",f"Value: {v}")

    def check_https(self):
        print(f"  {Fore.CYAN}→ HTTPS enforcement{Style.RESET_ALL}")
        if not self.target.startswith("https://"):
            try:
                r = self.session.get(self.target, timeout=self.timeout, allow_redirects=False)
                loc = r.headers.get("Location","")
                if r.status_code not in (301,302,307,308) or "https" not in loc:
                    self._add("Transport","HIGH","HTTP not redirected to HTTPS",
                               "Plain HTTP accepted without redirect")
            except Exception: pass

    def check_cookies(self):
        print(f"  {Fore.CYAN}→ Cookie flags{Style.RESET_ALL}")
        r = self._get()
        if not r: return
        for c in r.cookies:
            issues = []
            if not c.secure:   issues.append("no Secure flag")
            if not c.has_nonstandard_attr("HttpOnly"):  issues.append("no HttpOnly flag")
            if not c.has_nonstandard_attr("SameSite"):  issues.append("no SameSite")
            if issues:
                self._add("Cookie Security","MEDIUM",f"Insecure cookie: {c.name}",", ".join(issues))

    def check_cors(self):
        print(f"  {Fore.CYAN}→ CORS policy{Style.RESET_ALL}")
        try:
            r = self.session.get(self.target, timeout=self.timeout,
                                 headers={"Origin":"https://evil.example.com"})
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")
            if acao == "*":
                self._add("CORS","MEDIUM","Wildcard CORS","ACAO: * allows any origin")
            elif acao == "https://evil.example.com":
                self._add("CORS","HIGH","CORS reflects arbitrary origin","Server mirrors Origin header")
                if acac.lower()=="true":
                    self._add("CORS","HIGH","CORS + credentials enabled","Credential theft possible")
        except Exception: pass

    def check_clickjacking(self):
        print(f"  {Fore.CYAN}→ Clickjacking{Style.RESET_ALL}")
        r = self._get()
        if not r: return
        xfo = r.headers.get("X-Frame-Options","")
        csp = r.headers.get("Content-Security-Policy","")
        if not xfo and "frame-ancestors" not in csp.lower():
            self._add("Clickjacking","MEDIUM","No clickjacking protection",
                       "Neither X-Frame-Options nor CSP frame-ancestors set")

    def check_methods(self):
        print(f"  {Fore.CYAN}→ HTTP methods{Style.RESET_ALL}")
        try:
            r = self.session.options(self.target, timeout=self.timeout)
            allow = r.headers.get("Allow","")
            bad = [m for m in ["TRACE","PUT","DELETE","CONNECT"] if m in allow]
            if bad:
                self._add("Config","MEDIUM",f"Dangerous HTTP methods: {', '.join(bad)}",
                           f"Allow: {allow}")
            r2 = self.session.request("TRACE", self.target, timeout=self.timeout)
            if r2.status_code==200 and "TRACE" in r2.text:
                self._add("Config","LOW","TRACE method enabled","May facilitate XST attacks")
        except Exception: pass

    def check_dir_listing(self):
        print(f"  {Fore.CYAN}→ Directory listing{Style.RESET_ALL}")
        for path in ["/uploads/","/images/","/files/","/static/","/assets/"]:
            r = self._get(path)
            if r and r.status_code==200:
                body = r.text.lower()
                if "index of" in body or "parent directory" in body:
                    self._add("Info Disclosure","MEDIUM",f"Directory listing: {path}",
                               "Server lists directory contents", url=r.url)

    def check_sensitive_paths(self):
        print(f"  {Fore.CYAN}→ Sensitive paths ({len(SENSITIVE_PATHS)}){Style.RESET_ALL}")
        for path in SENSITIVE_PATHS:
            r = self._get(path)
            if not r: continue
            if r.status_code==200:
                sev = "HIGH" if any(x in path for x in [".env",".git",".sql","phpinfo","actuator/env"]) else "MEDIUM"
                self._add("Sensitive Exposure", sev, f"Accessible: {path}",
                           f"HTTP 200 — {len(r.content)} bytes", url=r.url)
            elif r.status_code==403:
                self._add("Access Control","LOW",f"Forbidden path exists (403): {path}",
                           "Path exists but access-controlled", url=r.url)

    def check_sqli(self):
        print(f"  {Fore.CYAN}→ SQL injection indicators{Style.RESET_ALL}")
        params = {"id":"1","q":"test","search":"test"}
        for param in list(params.keys())[:3]:
            for payload in SQLI_PAYLOADS:
                resp = self._get(params={param:payload})
                if resp:
                    body = resp.text.lower()
                    for err in SQLI_ERRORS:
                        if err in body:
                            self._add("Injection","HIGH",f"SQLi indicator in param: {param}",
                                       f"Error pattern '{err}' with payload: {payload}")
                            return

    def check_xss(self):
        print(f"  {Fore.CYAN}→ Reflected XSS indicators{Style.RESET_ALL}")
        for param in ["q","search","query","s"]:
            for payload in XSS_PAYLOADS[:2]:
                resp = self._get(params={param:payload})
                if resp and payload in resp.text:
                    self._add("Injection","HIGH",f"Reflected XSS in param: {param}",
                               f"Payload unescaped in response: {payload[:60]}")
                    return

    def check_open_redirect(self):
        print(f"  {Fore.CYAN}→ Open redirect{Style.RESET_ALL}")
        for param in ["redirect","url","next","return","goto","redir"]:
            resp = self._get(params={param:"https://evil.example.com"})
            if resp and resp.history:
                for hr in resp.history:
                    if "evil.example.com" in hr.headers.get("Location",""):
                        self._add("Open Redirect","MEDIUM",f"Open redirect via: {param}",
                                   f"Redirects to: {hr.headers['Location']}")
                        return

    def run(self):
        checks = [
            self.check_headers, self.check_https, self.check_cookies,
            self.check_clickjacking, self.check_cors, self.check_methods,
            self.check_dir_listing, self.check_sensitive_paths,
            self.check_sqli, self.check_xss, self.check_open_redirect,
        ]
        for check in checks:
            try: check()
            except Exception as e:
                if self.verbose:
                    print(f"  {Fore.YELLOW}[!] {check.__name__}: {e}{Style.RESET_ALL}")

        s = {k: sum(1 for f in self.findings if f["severity"]==k)
             for k in ("HIGH","MEDIUM","LOW","INFO")}
        print(f"\n  {Fore.GREEN}Web done.{Style.RESET_ALL}  "
              f"{Fore.RED}HIGH:{s['HIGH']}{Style.RESET_ALL}  "
              f"{Fore.YELLOW}MEDIUM:{s['MEDIUM']}{Style.RESET_ALL}  "
              f"{Fore.CYAN}LOW:{s['LOW']}{Style.RESET_ALL}")
        return {"target":self.target,"findings":self.findings,"summary":s}


# ═════════════════════════════════════════════════════════════════════════════
#  REPORTER
# ═════════════════════════════════════════════════════════════════════════════

class Reporter:
    def __init__(self, results):
        self.r = results

    def print_summary(self):
        r = self.r
        print(f"\n{Fore.CYAN}{'═'*62}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═'*62}{Style.RESET_ALL}")
        print(f"  Target   : {r['target']}")
        print(f"  Started  : {r['scan_start'][:19]}")
        print(f"  Duration : {r.get('duration','N/A')}")

        pr = r.get("port_results") or {}
        if pr.get("open_ports") is not None:
            print(f"\n  {Fore.WHITE}PORT SCAN{Style.RESET_ALL}")
            print(f"  Scanned : {pr.get('ports_scanned',0)}  |  Open : {len(pr['open_ports'])}")
            for p in pr["open_ports"]:
                c = Fore.RED if p["risk"]=="HIGH" else Fore.GREEN
                banner = f"  [{p['banner'][:50]}]" if p.get("banner") else ""
                print(f"    {c}{p['port']:>5}/tcp{Style.RESET_ALL}  {p['service']:<15}{banner}")

        wr = r.get("web_results") or {}
        if wr.get("findings") is not None:
            s = wr.get("summary",{})
            print(f"\n  {Fore.WHITE}WEB ASSESSMENT{Style.RESET_ALL}")
            print(f"  HIGH:{s.get('HIGH',0)}  MEDIUM:{s.get('MEDIUM',0)}  "
                  f"LOW:{s.get('LOW',0)}  INFO:{s.get('INFO',0)}")
            for f in sorted(wr["findings"], key=lambda x: SEVERITY_ORDER.get(x["severity"],9)):
                c = {"HIGH":Fore.RED,"MEDIUM":Fore.YELLOW,"LOW":Fore.CYAN}.get(f["severity"],Fore.WHITE)
                print(f"    {c}[{f['severity']:<6}]{Style.RESET_ALL} {f['title']}")

        print(f"\n{Fore.CYAN}{'═'*62}{Style.RESET_ALL}\n")

    def save_html(self, filename):
        with open(filename,"w",encoding="utf-8") as f:
            f.write(self._html())
        print(f"{Fore.GREEN}[+] Report: {filename}{Style.RESET_ALL}")

    def _html(self):
        r    = self.r
        pr   = r.get("port_results") or {}
        wr   = r.get("web_results")  or {}
        op   = pr.get("open_ports",[])
        wf   = wr.get("findings",[])
        ws   = wr.get("summary",{"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0})
        rp   = len([p for p in op if p["risk"]=="HIGH"])

        port_rows = "".join(f"""
          <tr>
            <td><code>{p['port']}/tcp</code></td>
            <td>{p['service']}</td>
            <td><span class="badge {'high' if p['risk']=='HIGH' else 'info'}">{p['risk']}</span></td>
            <td class="mono">{(p.get('banner') or '')[:80]}</td>
          </tr>""" for p in op) or "<tr><td colspan='4' class='empty'>No port scan data</td></tr>"

        finding_rows = "".join(f"""
          <tr>
            <td><span class="badge {f['severity'].lower()}">{f['severity']}</span></td>
            <td>{f['category']}</td>
            <td>{f['title']}</td>
            <td class="mono">{f.get('detail','')}</td>
          </tr>""" for f in sorted(wf,key=lambda x:SEVERITY_ORDER.get(x["severity"],9))
        ) or "<tr><td colspan='4' class='empty'>No web assessment data</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScan Pro — {r['target']}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
     background:#f4f6f9;color:#2c3e50;font-size:14px;line-height:1.6}}
.hdr{{background:linear-gradient(135deg,#1a1a2e,#0f3460);color:#fff;
      padding:40px;text-align:center}}
.hdr h1{{font-size:1.8rem;margin-bottom:6px}}
.hdr .sub{{color:#a0aec0;font-size:.9rem}}
.hdr .tgt{{display:inline-block;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);
           border-radius:20px;padding:5px 20px;margin-top:10px;font-family:monospace}}
.meta{{display:flex;gap:20px;justify-content:center;margin-top:14px;flex-wrap:wrap}}
.meta span{{color:#a0aec0;font-size:.82rem}}
.meta strong{{color:#fff}}
.body{{max-width:1100px;margin:0 auto;padding:28px 16px}}
.notice{{background:#fffbf0;border:1px solid #f6e05e;border-radius:8px;
         padding:12px 16px;margin-bottom:20px;color:#744210;font-size:.82rem}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}}
.card{{background:#fff;border-radius:10px;padding:18px;text-align:center;
       box-shadow:0 2px 6px rgba(0,0,0,.06);border-top:4px solid #ddd}}
.card .n{{font-size:2.2rem;font-weight:700;line-height:1}}
.card .l{{color:#718096;font-size:.75rem;margin-top:3px;text-transform:uppercase;letter-spacing:.4px}}
.red{{border-top-color:#e74c3c}}.red .n{{color:#e74c3c}}
.org{{border-top-color:#f39c12}}.org .n{{color:#f39c12}}
.blu{{border-top-color:#3498db}}.blu .n{{color:#3498db}}
.grn{{border-top-color:#27ae60}}.grn .n{{color:#27ae60}}
.sec{{background:#fff;border-radius:10px;box-shadow:0 2px 6px rgba(0,0,0,.06);margin-bottom:20px;overflow:hidden}}
.sec-hdr{{background:#f8fafc;padding:14px 20px;border-bottom:1px solid #e2e8f0;
          display:flex;align-items:center;gap:8px}}
.sec-hdr h2{{font-size:.95rem;font-weight:600;color:#2d3748}}
.sec-hdr .ct{{margin-left:auto;color:#718096;font-size:.78rem}}
table{{width:100%;border-collapse:collapse}}
th{{background:#f8fafc;padding:9px 14px;text-align:left;font-size:.7rem;font-weight:600;
    text-transform:uppercase;letter-spacing:.4px;color:#718096;border-bottom:2px solid #e2e8f0}}
td{{padding:9px 14px;border-bottom:1px solid #f0f4f8;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#fafbfc}}
code{{font-family:monospace;font-size:12px;color:#e53e3e;background:#fff5f5;padding:1px 5px;border-radius:3px}}
.mono{{font-family:monospace;font-size:12px;color:#718096;word-break:break-all;max-width:280px}}
.badge{{display:inline-block;padding:2px 9px;border-radius:10px;font-size:.68rem;font-weight:600;text-transform:uppercase}}
.high  {{background:#fdf0ef;color:#e74c3c;border:1px solid #f5c6c6}}
.medium{{background:#fef9ec;color:#f39c12;border:1px solid #fde8a0}}
.low   {{background:#eef5fb;color:#3498db;border:1px solid #bcd9f1}}
.info  {{background:#eafaf1;color:#27ae60;border:1px solid #a9dfbf}}
.empty {{text-align:center;color:#a0aec0;padding:20px;font-style:italic}}
.foot  {{text-align:center;color:#a0aec0;font-size:.75rem;padding:16px 0 36px}}
</style></head><body>
<div class="hdr">
  <h1>NetScan Pro</h1>
  <div class="sub">Security Assessment Report</div>
  <div class="tgt">{r['target']}</div>
  <div class="meta">
    <span>Started: <strong>{r['scan_start'][:19]}</strong></span>
    <span>Duration: <strong>{r.get('duration','N/A')}</strong></span>
    <span>Generated: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M')}</strong></span>
  </div>
</div>
<div class="body">
  <div class="notice">
    AUTHORIZED USE ONLY — This report contains sensitive security data.
    Handle according to your organization's data classification policy.
  </div>
  <div class="cards">
    <div class="card red"><div class="n">{ws.get('HIGH',0)}</div><div class="l">High</div></div>
    <div class="card org"><div class="n">{ws.get('MEDIUM',0)}</div><div class="l">Medium</div></div>
    <div class="card blu"><div class="n">{ws.get('LOW',0)}</div><div class="l">Low</div></div>
    <div class="card grn"><div class="n">{len(op)}</div><div class="l">Open ports</div></div>
    <div class="card {'red' if rp else 'grn'}"><div class="n">{rp}</div><div class="l">High-risk ports</div></div>
  </div>
  <div class="sec">
    <div class="sec-hdr">
      <h2>Port scan results</h2>
      <span class="ct">{pr.get('ports_scanned',0)} scanned &middot; {len(op)} open</span>
    </div>
    <table>
      <thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Banner</th></tr></thead>
      <tbody>{port_rows}</tbody>
    </table>
  </div>
  <div class="sec">
    <div class="sec-hdr">
      <h2>Web vulnerability assessment</h2>
      <span class="ct">{len(wf)} finding(s)</span>
    </div>
    <table>
      <thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th></tr></thead>
      <tbody>{finding_rows}</tbody>
    </table>
  </div>
</div>
<div class="foot">NetScan Pro &middot; Authorized penetration testing use only</div>
</body></html>"""


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

def main():
    print(BANNER)
    print(f"{Fore.YELLOW}[!] LEGAL: Only scan systems you own or have written authorization to test.{Style.RESET_ALL}\n")

    ap = argparse.ArgumentParser(
        description="NetScan Pro — Single-file security assessment framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 netscanpro.py --target 192.168.1.1 --ports
  python3 netscanpro.py --target https://example.com --web
  python3 netscanpro.py --target 10.0.0.1 --full --verbose
  python3 netscanpro.py --target 10.0.0.1 --ports --port-range 1-65535 --threads 200
  python3 netscanpro.py --target 192.168.1.1 --full --output myreport.html"""
    )
    ap.add_argument("--target",          required=True,             help="IP, hostname, or URL")
    ap.add_argument("--ports",           action="store_true",       help="Run port scan")
    ap.add_argument("--web",             action="store_true",       help="Run web assessment")
    ap.add_argument("--full",            action="store_true",       help="Run all modules")
    ap.add_argument("--port-range",      default="1-1024",          help="Port range (default: 1-1024)")
    ap.add_argument("--threads",         type=int, default=100,     help="Threads (default: 100)")
    ap.add_argument("--timeout",         type=int, default=3,       help="Timeout in seconds (default: 3)")
    ap.add_argument("--output",          default=None,              help="HTML report filename")
    ap.add_argument("--skip-auth-check", action="store_true",       help="Skip authorization prompt")
    ap.add_argument("--verbose",         action="store_true",       help="Verbose output")
    args = ap.parse_args()

    if not args.skip_auth_check:
        print(f"{Fore.YELLOW}[?] Target: {Fore.WHITE}{args.target}{Style.RESET_ALL}")
        ans = input(f"{Fore.YELLOW}    Do you have written authorization to scan this target? (yes/no): {Style.RESET_ALL}").strip().lower()
        if ans != "yes":
            print(f"\n{Fore.RED}[-] Aborted. Always obtain authorization first.{Style.RESET_ALL}")
            sys.exit(0)

    if args.full:
        args.ports = args.web = True

    if not args.ports and not args.web:
        print(f"{Fore.YELLOW}[!] Select a module: --ports, --web, or --full{Style.RESET_ALL}")
        ap.print_help()
        sys.exit(1)

    scan_start = datetime.now()
    results = {"target":args.target, "scan_start":scan_start.isoformat(),
                "port_results":None, "web_results":None}

    if args.ports:
        print(f"\n{Fore.CYAN}[*] PORT SCAN — {args.target}{Style.RESET_ALL}")
        results["port_results"] = PortScanner(
            target=args.target, port_range=args.port_range,
            threads=args.threads, timeout=args.timeout, verbose=args.verbose
        ).run()

    if args.web:
        url = args.target if args.target.startswith("http") else f"http://{args.target}"
        print(f"\n{Fore.CYAN}[*] WEB ASSESSMENT — {url}{Style.RESET_ALL}")
        results["web_results"] = WebScanner(
            target=url, timeout=args.timeout, verbose=args.verbose
        ).run()

    scan_end = datetime.now()
    results["scan_end"] = scan_end.isoformat()
    results["duration"]  = str(scan_end - scan_start).split(".")[0]

    rpt = Reporter(results)
    rpt.print_summary()

    out = args.output or f"netscan_{args.target.replace('/','_').replace('.','_').replace(':','_')}_{scan_start.strftime('%Y%m%d_%H%M%S')}.html"
    if not out.endswith(".html"):
        out += ".html"
    rpt.save_html(out)


if __name__ == "__main__":
    main()
