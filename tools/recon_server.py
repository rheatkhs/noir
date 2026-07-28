import subprocess
import time
import hashlib
import json
import os
import re
from urllib.request import urlopen, Request
from urllib.error import HTTPError
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("noir-recon")

# --- Cache ---
_cache = {}
_cache_ttl = {
    "nmap": 300, "dns": 60, "whois": 600, "http": 30, "ffuf": 300,
    "tech": 600, "subdomain": 300, "ssl": 600, "cve": 3600,
}

def _cache_key(name, *args):
    raw = f"{name}:{json.dumps(args, sort_keys=True)}"
    return hashlib.sha256(raw.encode()).hexdigest()

def _cached(name, ttl_key, *args):
    key = _cache_key(name, *args)
    entry = _cache.get(key)
    if entry and time.time() - entry["ts"] < _cache_ttl.get(ttl_key, 60):
        return entry["data"]
    return None

def _store(name, ttl_key, data, *args):
    key = _cache_key(name, *args)
    _cache[key] = {"data": data, "ts": time.time()}

# --- Execution ---
_TIMEOUTS = {
    "nmap": 120, "dns": 15, "whois": 15, "http": 20, "ffuf": 60,
    "subdomain": 30, "ssl": 15, "cve": 15,
}

def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or r.stderr)[:8000]
    except FileNotFoundError:
        return f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return f"command timed out after {timeout}s"
    except Exception as e:
        return f"error: {e}"

# --- Existing tools ---

@mcp.tool()
def nmap_scan(target: str, ports: str = "80,443,8000,8080,8443", force: bool = False) -> str:
    """Fast port scan on common web ports. Results cached 5 min."""
    if not force:
        cached = _cached("nmap", "nmap", target, ports)
        if cached:
            return f"[CACHED]\n{cached}"
    result = _run(["nmap", "-sS", "-sV", "-p", ports, "-T4", target], timeout=_TIMEOUTS["nmap"])
    _store("nmap", "nmap", result, target, ports)
    return result

@mcp.tool()
def port_scan_full(target: str, force: bool = False) -> str:
    """Full port scan on all 65535 ports. Slow but thorough. Results cached 5 min."""
    if not force:
        cached = _cached("nmap", "nmap", target, "full")
        if cached:
            return f"[CACHED]\n{cached}"
    result = _run(["nmap", "-sS", "-p-", "-T4", "--min-rate", "1000", target], timeout=600)
    _store("nmap", "nmap", result, target, "full")
    return result

@mcp.tool()
def http_probe(url: str, method: str = "HEAD", follow_redirects: bool = False, force: bool = False) -> str:
    """Probe HTTP headers and fetch page content from a URL. Results cached 30s."""
    if not force:
        cached = _cached("http", "http", url, method, follow_redirects)
        if cached:
            return f"[CACHED]\n{cached}"
    cmd = ["curl", "-sI" if method == "HEAD" else "-s", url]
    if follow_redirects:
        cmd.insert(1, "-L")
    result = _run(cmd, timeout=_TIMEOUTS["http"])
    _store("http", "http", result, url, method, follow_redirects)
    return result

@mcp.tool()
def dns_lookup(domain: str, record_type: str = "ANY", force: bool = False) -> str:
    """DNS record lookup for a domain. Results cached 1 min."""
    if not force:
        cached = _cached("dns", "dns", domain, record_type)
        if cached:
            return f"[CACHED]\n{cached}"
    out = _run(["dig", "+short", record_type, domain], timeout=_TIMEOUTS["dns"])
    if not out.strip() or "timed out" in out:
        out = _run(["nslookup", "-type=" + record_type, domain], timeout=_TIMEOUTS["dns"])
    _store("dns", "dns", out, domain, record_type)
    return out

@mcp.tool()
def whois_lookup(target: str, force: bool = False) -> str:
    """WHOIS lookup for a domain or IP address. Results cached 10 min."""
    if not force:
        cached = _cached("whois", "whois", target)
        if cached:
            return f"[CACHED]\n{cached}"
    result = _run(["whois", target], timeout=_TIMEOUTS["whois"])
    _store("whois", "whois", result, target)
    return result

@mcp.tool()
def ffuf_fuzz(url: str, wordlist: str = "api,admin,login,backup,config,.git,wp-admin", mc: str = "200,301,302", force: bool = False) -> str:
    """Run ffuf directory fuzzing. Use FUZZ keyword in URL. Results cached 5 min."""
    if not force:
        cached = _cached("ffuf", "ffuf", url, wordlist, mc)
        if cached:
            return f"[CACHED]\n{cached}"
    wl_path = "/tmp/noir_words.txt"
    with open(wl_path, "w") as f:
        f.write(wordlist.replace(",", "\n"))
    result = _run(["ffuf", "-w", wl_path, "-u", url, "-mc", mc, "-s", "-t", "20"], timeout=_TIMEOUTS["ffuf"])
    _store("ffuf", "ffuf", result, url, wordlist, mc)
    return result

# --- New tools ---

@mcp.tool()
def tech_detect(url: str, force: bool = False) -> str:
    """Detect technology stack from HTTP headers and page content. Results cached 10 min."""
    if not force:
        cached = _cached("tech", "tech", url)
        if cached:
            return f"[CACHED]\n{cached}"

    headers = _run(["curl", "-sI", "-L", url], timeout=15)
    body = _run(["curl", "-s", "-L", url], timeout=15)

    findings = []
    lower_headers = headers.lower()
    lower_body = body.lower()

    # Server header
    m = re.search(r'(?i)^server:\s*(.+)', headers, re.MULTILINE)
    if m: findings.append(f"Server: {m.group(1).strip()}")

    # X-Powered-By
    m = re.search(r'(?i)^x-powered-by:\s*(.+)', headers, re.MULTILINE)
    if m: findings.append(f"X-Powered-By: {m.group(1).strip()}")

    # Frameworks via body patterns
    patterns = [
        ("React", r'react\.js|react\.min\.js|__NEXT_DATA__|next\.js'),
        ("Angular", r'angular\.js|ng-app|ng-version'),
        ("Vue", r'vue\.js|vue\.min\.js|__VUE__'),
        ("jQuery", r'jquery\.js|jquery\.min\.js'),
        ("Bootstrap", r'bootstrap\.(min\.)?css|bootstrap\.(min\.)?js'),
        ("Django", r'csrfmiddlewaretoken|__admin|django\.'),
        ("Laravel", r'laravel_session|livewire|__livewire'),
        ("WordPress", r'wp-content|wp-includes|wp-json'),
        ("Spring Boot", r'actuator|spring|_csrf'),
        ("Express", r'express|connect\.sid|X-Powered-By: Express'),
        ("ASP.NET", r'__VIEWSTATE|__EVENTVALIDATION|asp\.net'),
        ("Ruby on Rails", r'rails|csrf-token.*content="|_session_id'),
    ]
    for name, pat in patterns:
        if re.search(pat, lower_body) or re.search(pat, lower_headers):
            findings.append(name)

    if not findings:
        findings.append("No specific tech detected")

    result = "\n".join(findings)
    _store("tech", "tech", result, url)
    return result

@mcp.tool()
def subdomain_enum(domain: str, force: bool = False) -> str:
    """Enumerate subdomains via crt.sh and certspotter. Results cached 5 min."""
    if not force:
        cached = _cached("subdomain", "subdomain", domain)
        if cached:
            return f"[CACHED]\n{cached}"

    result_parts = []

    try:
        import urllib.request
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urlopen(url, timeout=20)
        data = json.loads(req.read().decode())
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip().lower()
                if n.endswith("." + domain) or n == domain:
                    subdomains.add(n)
        if subdomains:
            result_parts.append(f"crt.sh found {len(subdomains)} subdomains:")
            for s in sorted(subdomains)[:50]:
                result_parts.append(f"  {s}")
        else:
            result_parts.append("crt.sh: no subdomains found")
    except Exception as e:
        result_parts.append(f"crt.sh: {e}")

    result = "\n".join(result_parts)
    _store("subdomain", "subdomain", result, domain)
    return result

@mcp.tool()
def ssl_check(host: str, port: int = 443, force: bool = False) -> str:
    """Check SSL/TLS certificate details, expiry, weak ciphers. Results cached 10 min."""
    if not force:
        cached = _cached("ssl", "ssl", host, port)
        if cached:
            return f"[CACHED]\n{cached}"

    lines = []

    # Certificate details
    cert = _run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "</dev/null" if os.name != "nt" else "", "2>/dev/null"], timeout=15)
    if cert and "BEGIN CERTIFICATE" not in cert:
        lines.append("No certificate returned (connection failed)")

    # Expiry
    expiry = _run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "</dev/null" if os.name != "nt" else "", "2>/dev/null", "|", "openssl", "x509", "-noout", "-enddate"], timeout=15)
    if "notAfter=" in expiry:
        lines.append(f"Certificate expires: {expiry.split('notAfter=')[1].strip()[:30]}")

    # Weak ciphers
    weak = _run(["nmap", "--script", "ssl-enum-ciphers", "-p", str(port), host], timeout=60)
    lines.append("Cipher scan:")
    for l in weak.split("\n"):
        if "weak" in l.lower() or "TLS" in l or "SSL" in l or l.strip().startswith("|"):
            lines.append(f"  {l.strip()}")

    result = "\n".join(lines) if lines else "SSL check: no issues detected"
    _store("ssl", "ssl", result, host, port)
    return result

@mcp.tool()
def cve_search(product: str, version: str = "", force: bool = False) -> str:
    """Search for CVEs by product name and optional version. Results cached 1 hour."""
    if not force:
        cached = _cached("cve", "cve", product, version)
        if cached:
            return f"[CACHED]\n{cached}"

    try:
        import urllib.request
        query = f"{product} {version}".strip()
        url = f"https://cve.circl.lu/api/search/{urllib.parse.quote(query)}"
        req = urlopen(url, timeout=15)
        data = json.loads(req.read().decode())

        results = []
        for cve in data.get("results", data, [])[:15]:
            cve_id = cve.get("id", "")
            summary = cve.get("summary", "")[:150]
            score = cve.get("cvss", "")
            results.append(f"{cve_id} (CVSS: {score}) {summary}")
            results.append("")

        if results:
            result = "\n".join(results)
        else:
            result = f"No CVEs found for {query}"
    except Exception as e:
        result = f"CVE search error: {e}"

    _store("cve", "cve", result, product, version)
    return result

@mcp.tool()
def screenshot(url: str, output_path: str = "") -> str:
    """Take a Playwright screenshot of a URL. Returns file path. No caching."""
    try:
        import subprocess
        code = f"""
import asyncio
from playwright.async_api import async_playwright
async def run():
    async with async_playwright() as p:
        b = await p.chromium.launch(headless=True)
        page = await b.new_page()
        await page.goto("{url}", timeout=30000, wait_until='networkidle')
        out = "{output_path}" or "noir_reports/screenshots/{hashlib.md5(url.encode()).hexdigest()[:8]}.png"
        import os; os.makedirs(os.path.dirname(out), exist_ok=True)
        await page.screenshot(path=out, full_page=True)
        await b.close()
        print(out)
asyncio.run(run())
"""
        r = subprocess.run(["python3", "-c", code], capture_output=True, text=True, timeout=45)
        path = r.stdout.strip() if r.returncode == 0 else r.stderr.strip()
        return f"Screenshot: {path}"
    except Exception as e:
        return f"Screenshot failed: {e}"

@mcp.tool()
def wayback_urls(domain: str, limit: int = 50, force: bool = False) -> str:
    """Fetch historical URLs from Wayback Machine CDX API. Finds hidden endpoints and old paths. Results cached 1 hour."""
    cache_key = f"wayback:{domain}:{limit}"
    if not force:
        cached = _cached("wayback", "cve", domain, limit)
        if cached:
            return f"[CACHED]\n{cached}"
    try:
        import urllib.request
        url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit={limit}&fl=original,timestamp,statuscode"
        req = urlopen(url, timeout=30)
        data = json.loads(req.read().decode())
        lines = []
        for entry in data[1:]:  # skip header
            lines.append(f"{entry[2]} {entry[1]} {entry[0]}" if len(entry) >= 3 else str(entry))
        result = f"Wayback: {len(lines)} unique URLs\n" + "\n".join(lines[:limit])
        _store("wayback", "cve", result, domain, limit)
        return result
    except Exception as e:
        return f"Wayback error: {e}"

@mcp.tool()
def waf_detect(url: str, force: bool = False) -> str:
    """Fingerprint Web Application Firewall from response headers and cookies. Results cached 10 min."""
    if not force:
        cached = _cached("waf", "ssl", url)
        if cached:
            return f"[CACHED]\n{cached}"
    headers = _run(["curl", "-sI", "-L", url], timeout=15)
    lower = headers.lower()
    findings = []

    waf_signatures = {
        "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status", "server: cloudflare"],
        "AWS WAF": ["x-amzn-requestid", "x-amzn-trace-id", "aws-waf"],
        "Akamai": ["x-akamai", "akamai", "x-akamai-request-id"],
        "ModSecurity": ["mod_security", "modsecurity", "nb_user"],
        "F5 BIG-IP": ["bigip", "big-ip", "x-cnection"],
        "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
        "Imperva": ["incapsula", "x-iinfo", "x-cdn"],
        "Wordfence": ["wordfence"],
        "Stackpath": ["stackpath"],
    }

    for waf_name, sigs in waf_signatures.items():
        for sig in sigs:
            if sig in lower:
                findings.append(waf_name)
                break

    result = "\n".join(findings) if findings else "No WAF detected"
    _store("waf", "ssl", result, url)
    return result

@mcp.tool()
def cors_check(url: str, force: bool = False) -> str:
    """Test CORS misconfiguration on a URL. Results cached 10 min."""
    if not force:
        cached = _cached("cors", "ssl", url)
        if cached:
            return f"[CACHED]\n{cached}"

    import urllib.request
    results = []

    origins = ["https://evil.com", "null", "https://example.com", "http://127.0.0.1"]
    for origin in origins:
        try:
            req = Request(url)
            req.add_header("Origin", origin)
            resp = urlopen(req, timeout=10)
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acc = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao:
                note = f"Origin: {origin} → ACAO: {acao}"
                if acc:
                    note += f" Credentials: {acc}"
                results.append(note)
        except Exception as e:
            results.append(f"Origin: {origin} → {type(e).__name__}")

    result = "\n".join(results) if results else "No CORS headers found"
    _store("cors", "ssl", result, url)
    return result

@mcp.tool()
def dns_bruteforce(domain: str, wordlist: str = "www,mail,admin,api,dev,staging,test,blog,cdn,app,ftp,web,demo,portal,beta,docs", force: bool = False) -> str:
    """Brute force subdomains using a wordlist. Complements crt.sh. Results cached 5 min."""
    if not force:
        cached = _cached("dns_bf", "subdomain", domain, wordlist)
        if cached:
            return f"[CACHED]\n{cached}"
    subs = []
    for sub in wordlist.split(","):
        sub = sub.strip()
        if not sub:
            continue
        full = f"{sub}.{domain}"
        out = _run(["dig", "+short", full], timeout=5)
        if out.strip() and "timed out" not in out:
            ips = " ".join(out.strip().split("\n")[:3])
            subs.append(f"{full} → {ips}")
    result = "\n".join(subs) if subs else "No subdomains found via bruteforce"
    _store("dns_bf", "subdomain", result, domain, wordlist)
    return result

@mcp.tool()
def param_fuzz(url: str, wordlist: str = "id,user,admin,debug,token,key,api_key,secret,file,url,redirect,page,limit,offset,sort,filter,search,q,callback,format,type,action,cmd,password,email,role,status", force: bool = False) -> str:
    """Fuzz hidden GET parameters on a URL. Results cached 10 min."""
    if not force:
        cached = _cached("param", "ssl", url, wordlist)
        if cached:
            return f"[CACHED]\n{cached}"

    import urllib.request
    base = url.rstrip("/?&")
    found = []
    for param in wordlist.split(","):
        param = param.strip()
        if not param:
            continue
        try:
            full_url = f"{base}?{param}=1"
            req = Request(full_url)
            req.add_header("User-Agent", "Mozilla/5.0")
            resp = urlopen(req, timeout=10)
            if resp.status in (200, 302, 403):
                found.append(f"{param} → {resp.status} ({len(resp.read())} bytes)")
        except Exception:
            pass  # 4xx/5xx = param likely doesn't exist

    result = "\n".join(found) if found else "No undocumented params found"
    _store("param", "ssl", result, url, wordlist)
    return result

@mcp.tool()
def method_discover(url: str, force: bool = False) -> str:
    """Test HTTP methods (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE) on a URL. Results cached 10 min."""
    if not force:
        cached = _cached("method", "ssl", url)
        if cached:
            return f"[CACHED]\n{cached}"

    import urllib.request
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]
    results = []
    for method in methods:
        try:
            req = Request(url, method=method)
            req.add_header("User-Agent", "Mozilla/5.0")
            resp = urlopen(req, timeout=10)
            results.append(f"{method} → {resp.status}")
        except HTTPError as e:
            results.append(f"{method} → {e.code}")
        except Exception as e:
            results.append(f"{method} → {type(e).__name__}")

    result = "\n".join(results)
    _store("method", "ssl", result, url)
    return result

@mcp.tool()
def git_leak(url: str, force: bool = False) -> str:
    """Check for exposed .git/config, HEAD, and other repository files. Results cached 10 min."""
    base = url.rstrip("/")
    files_to_check = ["/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG", "/.git/description", "/.gitignore"]
    found = []
    for path in files_to_check:
        import urllib.request
        try:
            full = base + path
            req = Request(full, method="HEAD")
            req.add_header("User-Agent", "Mozilla/5.0")
            resp = urlopen(req, timeout=10)
            if resp.status == 200:
                ct = resp.headers.get("Content-Type", "")
                cl = resp.headers.get("Content-Length", "?")
                import hashlib
                found.append(f"EXPOSED: {path} ({cl} bytes)")
        except Exception:
            pass
    result = "\n".join(found) if found else "No exposed .git files detected"
    return result

@mcp.tool()
def cache_stats() -> str:
    """Show MCP cache statistics — entries and hit ages."""
    now = time.time()
    lines = [f"Cache entries: {len(_cache)}"]
    for key, entry in sorted(_cache.items(), key=lambda x: x[1]["ts"], reverse=True)[:10]:
        age = now - entry["ts"]
        lines.append(f"  {key[:16]}...  {age:.0f}s old")
    return "\n".join(lines)

@mcp.tool()
def cache_clear() -> str:
    """Clear all cached MCP results."""
    _cache.clear()
    return "Cache cleared"

@mcp.tool()
def db_summary(detail: str = "overview") -> str:
    """Query the findings database and return a human-readable summary. Use detail='overview', 'open', 'per_target', or 'latest'."""
    import sqlite3, os
    db = os.path.expanduser("~/.noir/findings.db")
    if not os.path.exists(db):
        return "No findings database found at ~/.noir/findings.db. Run a scan first."
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row

    if detail == "open":
        rows = conn.execute("SELECT * FROM findings WHERE status='open' ORDER BY cvss DESC").fetchall()
        if not rows:
            return "No open findings. Security is clean."
        parts = [f"Open findings ({len(rows)}):"]
        for r in rows:
            sev = r["severity"] or "medium"
            cvss = f" (CVSS {r['cvss']})" if r["cvss"] else ""
            parts.append(f"  [{sev.upper()}{cvss}] {r['vuln_type']} on {r['endpoint']} — {r['target']}")
        return "\n".join(parts)

    if detail == "per_target":
        rows = conn.execute("""
            SELECT target, COUNT(*) as total,
                   SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open,
                   SUM(CASE WHEN status='fixed' THEN 1 ELSE 0 END) as fixed,
                   MAX(MAX(cvss,0)) as max_cvss
            FROM findings GROUP BY target ORDER BY total DESC
        """).fetchall()
        if not rows:
            return "No targets scanned yet."
        parts = [f"Targets scanned: {len(rows)}"]
        for r in rows:
            parts.append(f"  {r['target']}: {r['total']} findings ({r['open']} open, {r['fixed']} fixed, max CVSS {r['max_cvss'] or 'N/A'})")
        return "\n".join(parts)

    if detail == "latest":
        rows = conn.execute("SELECT * FROM findings ORDER BY created_at DESC LIMIT 5").fetchall()
        if not rows:
            return "No findings yet."
        parts = ["Latest 5 findings:"]
        for r in rows:
            parts.append(f"  [{r['created_at'][:19]}] {r['vuln_type']} on {r['endpoint']} ({r['status']})")
        return "\n".join(parts)

    # overview (default)
    total = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
    open_f = conn.execute("SELECT COUNT(*) as c FROM findings WHERE status='open'").fetchone()["c"]
    fixed = conn.execute("SELECT COUNT(*) as c FROM findings WHERE status='fixed'").fetchone()["c"]
    targets = conn.execute("SELECT COUNT(DISTINCT target) as c FROM findings").fetchone()["c"]
    top = conn.execute("SELECT vuln_type, COUNT(*) as c FROM findings GROUP BY vuln_type ORDER BY c DESC LIMIT 5").fetchall()
    sev = conn.execute("SELECT severity, COUNT(*) as c FROM findings GROUP BY severity ORDER BY c DESC").fetchall()

    parts = [f"Findings database: {total} total ({open_f} open, {fixed} fixed) across {targets} target(s)."]
    if top:
        parts.append("Most common vuln types:")
        for r in top:
            parts.append(f"  {r['vuln_type']}: {r['c']}")
    if sev:
        parts.append("Severity distribution:")
        for r in sev:
            parts.append(f"  {r['severity']}: {r['c']}")
    return "\n".join(parts)

if __name__ == "__main__":
    mcp.run(transport="stdio")
