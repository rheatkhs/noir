import re, sys, os

SERVER_PATH = os.path.join(os.path.dirname(__file__), "..", "tools", "recon_server.py")

with open(SERVER_PATH) as f:
    src = f.read()

# Find all @mcp.tool() decorated function definitions
tools = re.findall(r'^@mcp\.tool\(\)\s*\n^def (\w+)\(', src, re.MULTILINE)

EXPECTED = {
    "nmap_scan", "port_scan_full", "http_probe", "dns_lookup", "whois_lookup",
    "ffuf_fuzz", "tech_detect", "subdomain_enum", "ssl_check", "cve_search",
    "screenshot", "wayback_urls", "waf_detect", "cors_check", "dns_bruteforce",
    "param_fuzz", "method_discover", "git_leak",
    "cache_stats", "cache_clear", "db_summary",
}

registered = set(tools)
missing = EXPECTED - registered
extra = registered - EXPECTED

if missing:
    print(f"FAIL: {len(missing)} expected tools missing: {sorted(missing)}")
    sys.exit(1)

print(f"PASS: {len(registered)} MCP tools registered")
if extra:
    print(f"  (unexpected: {sorted(extra)})")
sys.exit(0)