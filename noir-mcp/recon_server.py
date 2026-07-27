import asyncio
import subprocess
import json
from urllib.parse import urlparse
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.types import Tool, TextContent

server = Server("noir-recon")

def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else r.stderr
    except FileNotFoundError:
        return f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return f"command timed out after {timeout}s"
    except Exception as e:
        return f"error: {e}"

@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    return [
        Tool(
            name="nmap_scan",
            description="Run nmap port scan on a target host. Scans common web ports if no ports specified.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Hostname or IP address"},
                    "ports": {"type": "string", "description": "Port range (e.g. 80,443,8000-8080). Default: 80,443,8000,8080,8443"},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="http_probe",
            description="Probe HTTP headers and fetch page content from a URL.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full URL to probe"},
                    "method": {"type": "string", "description": "HTTP method (GET, HEAD). Default: HEAD"},
                    "follow_redirects": {"type": "boolean", "description": "Follow redirects. Default: false"},
                },
                "required": ["url"],
            },
        ),
        Tool(
            name="dns_lookup",
            description="DNS record lookup for a domain.",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain name"},
                    "record_type": {"type": "string", "description": "Record type: A, AAAA, MX, TXT, NS, CNAME, ANY. Default: ANY"},
                },
                "required": ["domain"],
            },
        ),
        Tool(
            name="whois_lookup",
            description="WHOIS lookup for a domain or IP address.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Domain or IP address"},
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="ffuf_fuzz",
            description="Run ffuf directory fuzzing against a target URL.",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL with FUZZ keyword (e.g. http://target.com/FUZZ)"},
                    "wordlist": {"type": "string", "description": "Comma-separated words. Default: api,admin,login,backup,config,.git,wp-admin"},
                    "mc": {"type": "string", "description": "Match HTTP status codes. Default: 200,301,302"},
                },
                "required": ["url"],
            },
        ),
    ]

@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None) -> list[TextContent]:
    if not arguments:
        arguments = {}

    if name == "nmap_scan":
        target = arguments["target"]
        ports = arguments.get("ports", "80,443,8000,8080,8443")
        out = _run(["nmap", "-sS", "-sV", "-p", ports, "-T4", target], timeout=120)
        return [TextContent(type="text", text=out[:10000])]

    elif name == "http_probe":
        url = arguments["url"]
        method = arguments.get("method", "HEAD")
        cmd = ["curl", "-sI" if method == "HEAD" else "-s", url]
        if arguments.get("follow_redirects"):
            cmd.insert(1, "-L")
        out = _run(cmd)
        return [TextContent(type="text", text=out[:5000])]

    elif name == "dns_lookup":
        domain = arguments["domain"]
        rtype = arguments.get("record_type", "ANY")
        out = _run(["dig", "+short", rtype, domain])
        if not out.strip():
            out = _run(["nslookup", "-type=" + rtype, domain])
        return [TextContent(type="text", text=out[:5000])]

    elif name == "whois_lookup":
        target = arguments["target"]
        out = _run(["whois", target], timeout=15)
        return [TextContent(type="text", text=out[:5000])]

    elif name == "ffuf_fuzz":
        url = arguments["url"]
        words = arguments.get("wordlist", "api,admin,login,backup,config,.git,wp-admin")
        mc = arguments.get("mc", "200,301,302")
        wordlist_path = "/tmp/noir_words.txt"
        with open(wordlist_path, "w") as f:
            f.write(words.replace(",", "\n"))
        out = _run(["ffuf", "-w", wordlist_path, "-u", url, "-mc", mc, "-s", "-t", "20"], timeout=60)
        return [TextContent(type="text", text=out[:5000])]

async def run():
    async with server.run(
        initialization_options=InitializationOptions(
            server_name="noir-recon",
            server_version="0.1.0",
        ),
    ) as running:
        await running.wait_for_shutdown()

def main():
    asyncio.run(run())

if __name__ == "__main__":
    main()
