import subprocess
import time
import hashlib
import json
import os
import atexit
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("noir-recon")

# --- Cache ---
_cache = {}
_cache_ttl = {
    "nmap": 300,      # 5 min
    "dns": 60,        # 1 min
    "whois": 600,     # 10 min
    "http": 30,       # 30 sec (headers change often)
    "ffuf": 300,      # 5 min
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
    "nmap": 120,
    "dns": 15,
    "whois": 15,
    "http": 20,
    "ffuf": 60,
}

def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or r.stderr)[:8000] if r.returncode == 0 else (r.stderr or r.stdout)[:8000]
    except FileNotFoundError:
        return f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return f"command timed out after {timeout}s"
    except Exception as e:
        return f"error: {e}"

@mcp.tool()
def nmap_scan(target: str, ports: str = "80,443,8000,8080,8443", force: bool = False) -> str:
    """Run nmap port scan on a target host. Results cached 5 min per target."""
    if not force:
        cached = _cached("nmap", "nmap", target, ports)
        if cached:
            return f"[CACHED]\n{cached}"
    result = _run(["nmap", "-sS", "-sV", "-p", ports, "-T4", target], timeout=_TIMEOUTS["nmap"])
    _store("nmap", "nmap", result, target, ports)
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
    """Run ffuf directory fuzzing against a target URL. Use FUZZ keyword in URL. Results cached 5 min."""
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
