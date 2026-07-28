# Noir

Autonomous security penetration testing agent for [opencode](https://opencode.ai).  
251 skill playbooks · 10 engagement modes · Findings database · MCP server · CVSS scoring · Remediation patterns

[![opencode](https://img.shields.io/badge/opencode-agent-8A2BE2)](https://opencode.ai)
[![skills](https://img.shields.io/badge/skills-251-00FF88)](.opencode/skills)
[![version](https://img.shields.io/github/v/release/rheatkhs/noir)](https://github.com/rheatkhs/noir/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0%20%7C%20MIT-FFD700)](#license)

---

## Quick Start

```bash
git clone https://github.com/rheatkhs/noir.git
cd noir
opencode

attack http://localhost:3000
scan http://target.com in ctf mode
```

### Requirements

| Tool | Purpose |
|------|---------|
| [opencode](https://opencode.ai) | Agentic CLI runtime |
| `nmap`, `curl`, `ffuf`, `python3` | Scanning, requests, fuzzing, scripting |

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Attack pipeline** | Fully autonomous 9-step chain: recon → fuzz → JS analysis → vuln scan (8 types) → PoC validation → CVSS scoring → remediation → DB persist → report |
| **Findings database** | SQLite persistence at `~/.noir/findings.db`. Query, filter, summarize across sessions |
| **Differential re-scan** | Caches response hashes per endpoint. Skips unchanged endpoints on repeat scans. 10x faster |
| **CVSS 4.0 scoring** | Quantitative severity vectors and scores for every validated finding |
| **Remediation patterns** | BAD/GOOD code fixes for SQLi, XSS, LFI, SSRF, deserialization, prototype pollution, command injection |
| **Recon MCP server** | Standalone server wrapping nmap, curl, dig, whois, ffuf as callable tools |
| **10 engagement modes** | Auto-detected modes optimizing tool priority, workflow, and output format |
| **251 skill playbooks** | Vulnerability classes, CTF, frameworks, protocols, post-exploitation, payloads, forensics, mobile, IoT, AD/red team |

---

## Commands

| Command | Description |
|---------|-------------|
| `attack <url>` | Full autonomous pipeline (recon → exploit → validate → report) |
| `scan <url>` | Guided multi-phase scan with mode detection |

---

## Engagement Modes

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

## Findings Database

Every validated vulnerability is persisted to `~/.noir/findings.db` with target, type, CVSS score, PoC, evidence, and status.

```bash
# Summary per target
python tools/db.py summary

# Query all open findings
python tools/db.py query "SELECT * FROM findings WHERE status='open'"

# Close a finding
python tools/db.py update 1 fixed
```

---

## Recon MCP Server

Registered in `opencode.jsonc` — auto-loaded on project open.

| Tool | What it does |
|------|-------------|
| `nmap_scan` | Port scan target host |
| `http_probe` | Fetch HTTP headers / page content |
| `dns_lookup` | DNS record lookup |
| `whois_lookup` | WHOIS domain/IP lookup |
| `ffuf_fuzz` | Directory fuzzing with custom wordlist |

---

## Project Structure

```
.github/workflows/       # CI (skill validation + MCP smoke test)
.opencode/
  agents/noir.md         # Agent definition
  commands/attack.md     # Autonomous attack pipeline
  commands/scan.md       # Guided scan command
  skills/                # 251 skill playbooks
scripts/                 # Dev/test scripts
tools/
  db.py                 # SQLite findings database
  recon_server.py       # MCP server
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
      "command": ["python", "tools/recon_server.py"],
      "enabled": true
    }
  }
}
```

No model pinned, no API key required. Set `ROUTER_API_KEY` or `OPENAI_API_KEY` to use a custom LLM.

---

## License

Dual-licensed under Apache-2.0 or MIT.
