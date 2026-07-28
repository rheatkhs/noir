import subprocess
import time
import hashlib
import json
import os
import re
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
        req = urllib.request.urlopen(url, timeout=20)
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
        req = urllib.request.urlopen(url, timeout=15)
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

if __name__ == "__main__":
    mcp.run(transport="stdio")
