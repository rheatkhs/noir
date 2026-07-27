# Noir

Autonomous security penetration testing agent for [opencode](https://opencode.ai).  
249 skill playbooks · 10 engagement modes · Recon MCP server

[![opencode](https://img.shields.io/badge/opencode-agent-8A2BE2)](https://opencode.ai)
[![skills](https://img.shields.io/badge/skills-249-00FF88)](.opencode/skills)
[![license](https://img.shields.io/badge/license-Apache--2.0%20%7C%20MIT-FFD700)](#license)

---

## Quick Start

```bash
git clone https://github.com/rheatkhs/noir.git
cd noir
opencode

scan http://localhost:3000
scan http://target.com in ctf mode
```

### Requirements

| Tool | Purpose |
|------|---------|
| [opencode](https://opencode.ai) | Agentic CLI runtime |
| `nmap`, `curl`, `ffuf`, `python3` | Scanning, requests, fuzzing, scripting |

---

## Engagement Modes

Auto-detected from target URL or set explicitly.

| Mode | Use Case | Priority | Output |
|------|----------|----------|--------|
| `auto` | Unknown target | Adaptive | Standard |
| `bug-bounty` | HackerOne, Bugcrowd, Intigriti | Recon > Enum > Exploit | HackerOne format |
| `red-team` | Stealth ops, AD, persistence | Recon > Exploit > Enum | Executive summary |
| `ctf` | HackTheBox, TryHackMe, picoCTF | Exploit > Enum > Recon | Flag submission |
| `blue-team` | Detection, IR, defense | Enum > Recon > Report | IR report |
| `offensive` | Aggressive exploitation | Exploit > Enum > Recon | Technical |
| `grey-hat` | Balanced assessment | Balanced | Technical |
| `forensic` | Evidence preservation | Forensics > Report | Chain-of-custody |
| `reverse-engineering` | Binaries, firmware, malware | RE > Exploit > Utility | Technical RE |
| `mobile-pentest` | Android / iOS assessment | Mobile > Enum > Exploit | OWASP Mobile Top 10 |

---

## Recon MCP Server

Noir ships with a lightweight MCP server (`noir-mcp/recon_server.py`) that wraps recon tools into callable tools. The agent calls these directly instead of generating ad-hoc bash commands.

| Tool | What it does |
|------|-------------|
| `nmap_scan` | Port scan target host |
| `http_probe` | Fetch HTTP headers / page content |
| `dns_lookup` | DNS record lookup (A, MX, TXT, etc.) |
| `whois_lookup` | WHOIS domain/IP lookup |
| `ffuf_fuzz` | Directory fuzzing with custom wordlist |

Registered in `opencode.jsonc` under `mcp` — auto-loaded on project open.

---

## Skill Library (249 Playbooks)

**Vulnerability Classes** — `noir-vuln-sqli`, `noir-vuln-xss`, `noir-vuln-ssrf`, `noir-vuln-ssti`, `noir-vuln-xxe`, `noir-vuln-rce`, `noir-vuln-idor`, `noir-vuln-csrf`, `noir-vuln-jwt`, `noir-vuln-oauth`, `noir-vuln-deserialization`, `noir-vuln-http-smuggling`, `noir-vuln-race-conditions`, `noir-vuln-prototype-pollution`, `noir-vuln-file-upload`, `noir-vuln-websocket`, `noir-vuln-nosql`, `noir-vuln-llm-attacks`, `noir-vuln-log4shell`, `noir-vuln-supply-chain`, and more.

**Reconnaissance** — `noir-recon-full`, `noir-recon-subdomain`, `noir-recon-asn-whois`, `noir-recon-dorking`, `noir-recon-shodan`, `noir-recon-js-analysis`, `noir-recon-secrets`, `noir-recon-favicon`, `noir-recon-cloud-assets`.

**Payloads** — `noir-payload-xss`, `noir-payload-sqli`, `noir-payload-ssrf`, `noir-payload-ssti`, `noir-payload-xxe`, `noir-payload-lfi`, `noir-payload-command-injection`.

**Frameworks** — `noir-framework-django`, `noir-framework-laravel`, `noir-framework-rails`, `noir-framework-spring`, `noir-framework-express`, `noir-framework-nextjs`, `noir-framework-fastapi`, `noir-framework-dotnet`, `noir-framework-flask`, `noir-framework-wordpress`.

**Technology** — `noir-tech-docker`, `noir-tech-kubernetes`, `noir-tech-redis`, `noir-tech-mongodb`, `noir-tech-elasticsearch`, `noir-tech-jenkins`, `noir-tech-firebase`, `noir-tech-spring`, `noir-tech-wordpress`, `noir-tech-stack-fingerprint`.

**Protocols** — `noir-proto-smb`, `noir-proto-kerberos`, `noir-proto-ldap`, `noir-proto-rdp`, `noir-proto-ssh`, `noir-proto-dns`, `noir-proto-smtp`, `noir-proto-graphql`, `noir-proto-mssql`.

**CTF** — Crypto (RSA, ECC, modern, classic, ZKP), Pwn (basics, ROP, heap, kernel, format string), Reverse (tools, dynamic, patterns), Forensics (disk, memory, network, stego), Web (server-side, client-side, auth, CVEs), Misc, OSINT, Malware, WASM.

**Post-Exploitation** — `noir-post-linux-privesc`, `noir-post-windows-privesc`, `noir-post-pivoting`, `noir-post-lateral-movement`, `noir-post-bloodhound`, `noir-post-credential-dumping`, `noir-post-container-escape`.

**Other** — `noir-mobile-android`, `noir-mobile-ios`, `noir-forensic-disk`, `noir-forensic-memory`, `noir-ad-attacks`, `noir-iot-firmware`, `noir-tool-nmap`, `noir-tool-sqlmap`, `noir-tool-nuclei`, `noir-tool-metasploit`, `noir-tool-impacket`.

---

## Project Structure

```
.opencode/
  agents/noir.md         # Agent definition
  commands/scan.md       # Scan command
  skills/                # 249 skill playbooks
noir-mcp/
  recon_server.py        # Recon MCP server (nmap, curl, dig, whois, ffuf)
opencode.jsonc           # Configuration
```

---

## Configuration

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "default_agent": "noir",
  "agent": {
    "noir": {
      "description": "Autonomous security penetration testing agent",
      "mode": "primary",
      "permission": {
        "bash": { "nmap *": "allow", "curl *": "allow", "*": "ask" },
        "edit": "deny",
        "read": "allow"
      }
    }
  },
  "mcp": {
    "noir-recon": {
      "type": "local",
      "command": ["python", "noir-mcp/recon_server.py"],
      "enabled": true
    }
  }
}
```

No model pinned, no API key required. Set `ROUTER_API_KEY` or `OPENAI_API_KEY` in your environment to use a custom LLM.

---

## License

Dual-licensed under Apache-2.0 or MIT.
