import subprocess
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("noir-recon")

def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout[:5000] if r.returncode == 0 else r.stderr[:5000]
    except FileNotFoundError:
        return f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return f"command timed out after {timeout}s"
    except Exception as e:
        return f"error: {e}"

@mcp.tool()
def nmap_scan(target: str, ports: str = "80,443,8000,8080,8443") -> str:
    """Run nmap port scan on a target host."""
    return _run(["nmap", "-sS", "-sV", "-p", ports, "-T4", target], timeout=120)

@mcp.tool()
def http_probe(url: str, method: str = "HEAD", follow_redirects: bool = False) -> str:
    """Probe HTTP headers and fetch page content from a URL."""
    cmd = ["curl", "-sI" if method == "HEAD" else "-s", url]
    if follow_redirects:
        cmd.insert(1, "-L")
    return _run(cmd)

@mcp.tool()
def dns_lookup(domain: str, record_type: str = "ANY") -> str:
    """DNS record lookup for a domain."""
    out = _run(["dig", "+short", record_type, domain])
    if not out.strip():
        out = _run(["nslookup", "-type=" + record_type, domain])
    return out

@mcp.tool()
def whois_lookup(target: str) -> str:
    """WHOIS lookup for a domain or IP address."""
    return _run(["whois", target], timeout=15)

@mcp.tool()
def ffuf_fuzz(url: str, wordlist: str = "api,admin,login,backup,config,.git,wp-admin", mc: str = "200,301,302") -> str:
    """Run ffuf directory fuzzing against a target URL. Use FUZZ keyword in URL."""
    wl_path = "/tmp/noir_words.txt"
    with open(wl_path, "w") as f:
        f.write(wordlist.replace(",", "\n"))
    return _run(["ffuf", "-w", wl_path, "-u", url, "-mc", mc, "-s", "-t", "20"], timeout=60)

if __name__ == "__main__":
    mcp.run(transport="stdio")
