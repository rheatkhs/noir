# 🕵️ Noir

> **Autonomous security penetration testing agent for [opencode](https://opencode.ai).**  
> 249 skill playbooks · 10 engagement modes · Zero-config setup

[![opencode](https://img.shields.io/badge/opencode-agent-8A2BE2)](https://opencode.ai)
[![skills](https://img.shields.io/badge/skills-249-00FF88)](.opencode/skills)
[![model](https://img.shields.io/badge/model-agnostic-FF6B6B)](#configuration)
[![license](https://img.shields.io/badge/license-Apache--2.0_|_MIT-FFD700)](#license)

---

## ✨ Features

| | |
|---|---|
| 🧠 **249 Skill Playbooks** | Vulnerability classes, CTF categories, frameworks, protocols, post-exploitation, payload collections, recon, forensics, mobile, IoT, and more |
| 🎯 **10 Engagement Modes** | Auto-detected modes optimize tool priority, workflow order, and output format for every context |
| ⚡ **Multi-Phase Pipeline** | Recon → Fuzzing → Exploitation → Validation → Reporting — all guided by LLM reasoning |
| 🔌 **No Lock-In** | Model-agnostic. Works with any model opencode supports — local or cloud |

---

## 🚀 Quick Start

```bash
# Clone & launch
git clone https://github.com/rheatkhs/noir.git
cd noir
opencode

# Full scan with auto mode detection
scan http://localhost:3000

# Scan with explicit mode
scan http://target.com in ctf mode

# Targeted testing
recon http://localhost:8000
test sql injection on http://localhost:3000/api/login
check for ssrf on http://localhost:3000/fetch
validate http://localhost:3000
```

### Requirements

| Tool | Purpose |
|------|---------|
| [opencode](https://opencode.ai) | Agentic CLI runtime |
| `nmap` | Port scanning |
| `curl` | HTTP requests |
| `ffuf` | Directory/parameter fuzzing |
| `python3` | PoC scripts & payloads |

---

## 🎮 Engagement Modes

Auto-detected from target URL or set explicitly. Each mode optimizes tool priority, workflow order, and output format.

| Mode | Use Case | Priority | Output |
|------|----------|----------|--------|
| `auto` | Unknown target | Adaptive | Standard |
| `bug-bounty` | HackerOne / Bugcrowd / Intigriti | Recon → Enum → Exploit | HackerOne format |
| `red-team` | Stealth ops, AD, persistence | Recon → Exploit → Enum | Executive summary |
| `ctf` | HackTheBox / TryHackMe / picoCTF | Exploit → Enum → Recon | Flag submission |
| `blue-team` | Detection, IR, defense | Enum → Recon → Report | IR report |
| `offensive` | Aggressive exploitation, PoC chains | Exploit → Enum → Recon | Technical |
| `grey-hat` | Balanced assessment | Balanced | Technical |
| `forensic` | Evidence preservation | Forensics → Report | Chain-of-custody |
| `reverse-engineering` | Binaries, firmware, malware | RE → Exploit → Utility | Technical RE |
| `mobile-pentest` | Android / iOS app assessment | Mobile → Enum → Exploit | OWASP Mobile Top 10 |

```
scan http://target.com in red-team mode
recon http://target.com in bug-bounty mode
```

---

## 📚 Skill Library (249 Playbooks)

### 🛡️ Vulnerability Classes
`noir-vuln-sqli` · `noir-vuln-xss` · `noir-vuln-blind-xss` · `noir-vuln-dom-xss` · `noir-vuln-ssrf` · `noir-vuln-ssti` · `noir-vuln-xxe` · `noir-vuln-rce` · `noir-vuln-idor` · `noir-vuln-bfla` · `noir-vuln-privesc-web` · `noir-vuln-csrf` · `noir-vuln-cors` · `noir-vuln-jwt` · `noir-vuln-oauth` · `noir-vuln-2fa-bypass` · `noir-vuln-account-takeover` · `noir-vuln-file-upload` · `noir-vuln-deserialization` · `noir-vuln-http-smuggling` · `noir-vuln-race-conditions` · `noir-vuln-business-logic` · `noir-vuln-prototype-pollution` · `noir-vuln-websocket` · `noir-vuln-grpc` · `noir-vuln-nosql` · `noir-vuln-llm-attacks` · `noir-vuln-log4shell` · `noir-vuln-spring4shell` · `noir-vuln-supply-chain` · `noir-vuln-host-header` · `noir-vuln-open-redirect` · `noir-vuln-clickjacking` · `noir-vuln-xs-leaks` · `noir-vuln-crlf` · `noir-vuln-cache-deception` · `noir-vuln-mass-assignment` · `noir-vuln-password-reset-poisoning` · `noir-vuln-path-traversal` · `noir-vuln-info-disclosure` · `noir-vuln-sensitive-exposure` · `noir-vuln-api-schema-exposure` · `noir-vuln-api-testing` · `noir-vuln-auth-workflow` · `noir-vuln-subdomain-takeover` · `noir-vuln-waf-bypass` · `noir-vuln-interactsh-oob` · `noir-vuln-exploit-validation`

### 🔍 Reconnaissance
`noir-recon-full` · `noir-recon-subdomain` · `noir-recon-asn-whois` · `noir-recon-dorking` · `noir-recon-shodan` · `noir-recon-js-analysis` · `noir-recon-js-hostname` · `noir-recon-secrets` · `noir-recon-favicon` · `noir-recon-devtools` · `noir-recon-cloud-assets` · `noir-recon-internal`

### 📦 Payload Collections
`noir-payload-xss` · `noir-payload-sqli` · `noir-payload-ssrf` · `noir-payload-ssti` · `noir-payload-xxe` · `noir-payload-lfi` · `noir-payload-command-injection` · `noir-payload-csv-injection` · `noir-payload-ldap-injection` · `noir-payload-ssi-injection` · `noir-payload-http-param-pollution` · `noir-payload-xpath-injection` · `noir-payload-redos`

### 🏗️ Frameworks
`noir-framework-django` · `noir-framework-laravel` · `noir-framework-rails` · `noir-framework-spring` · `noir-framework-express` · `noir-framework-nextjs` · `noir-framework-fastapi` · `noir-framework-dotnet` · `noir-framework-flask` · `noir-framework-php` · `noir-framework-wordpress`

### ⚙️ Technology-Specific
`noir-tech-docker` · `noir-tech-kubernetes` · `noir-tech-redis` · `noir-tech-mongodb` · `noir-tech-elasticsearch` · `noir-tech-jenkins` · `noir-tech-firebase` · `noir-tech-tomcat` · `noir-tech-spring` · `noir-tech-wordpress` · `noir-tech-apache-misconfig` · `noir-tech-nginx-apache` · `noir-tech-git-platforms` · `noir-tech-stack-fingerprint` · `noir-tech-cloud-security` · `noir-tech-observability` · `noir-tech-enterprise-web` · `noir-tech-supabase` · `noir-tech-memcached` · `noir-tech-qemu-emulation` · `noir-tech-frida-hooking` · `noir-tech-config-hardening` · `noir-tech-cicd`

### 🌐 Protocols
`noir-proto-smb` · `noir-proto-kerberos` · `noir-proto-ldap` · `noir-proto-rdp` · `noir-proto-ssh` · `noir-proto-dns` · `noir-proto-smtp` · `noir-proto-graphql` · `noir-proto-mssql` · `noir-proto-ftp` · `noir-proto-snmp` · `noir-proto-vnc`

### 🎯 CTF Categories
`noir-ctf-crypto` · `noir-ctf-crypto-rsa` · `noir-ctf-crypto-ecc` · `noir-ctf-crypto-modern` · `noir-ctf-crypto-classic` · `noir-ctf-crypto-zkp` · `noir-ctf-crypto-prng` · `noir-ctf-pwn-basics` · `noir-ctf-pwn-rop` · `noir-ctf-pwn-heap` · `noir-ctf-pwn-kernel` · `noir-ctf-pwn-format-string` · `noir-ctf-pwn-sandbox` · `noir-ctf-reverse-tools` · `noir-ctf-reverse-dynamic` · `noir-ctf-reverse-patterns` · `noir-ctf-forensics-disk` · `noir-ctf-forensics-memory` · `noir-ctf-forensics-network` · `noir-ctf-forensics-stego` · `noir-ctf-web-server-side` · `noir-ctf-web-client-side` · `noir-ctf-web-auth` · `noir-ctf-malware-analysis` · `noir-ctf-misc-pyjails` · `noir-ctf-osint` · `noir-ctf-wasm` · and more

### 🔧 Post-Exploitation
`noir-post-linux-privesc` · `noir-post-windows-privesc` · `noir-post-pivoting` · `noir-post-lateral-movement` · `noir-post-bloodhound` · `noir-post-credential-dumping` · `noir-post-container-escape`

### 🛠️ Tools
`noir-tool-nmap` · `noir-tool-sqlmap` · `noir-tool-nuclei` · `noir-tool-metasploit` · `noir-tool-impacket` · `noir-tool-hashcat-john` · `noir-tool-dalfox` · `noir-tool-semgrep` · `noir-tool-source-audit` · `noir-tool-caido` · `noir-tool-advanced-fuzzing` · `noir-tool-browser-automation` · `noir-tool-scripting` · `noir-tool-wapiti`

### 📱 Mobile
`noir-mobile-android` · `noir-mobile-ios` · `noir-mobile-dynamic` · `noir-mobile-report`

### 🔬 Forensics
`noir-forensic-disk` · `noir-forensic-memory` · `noir-forensic-network` · `noir-forensic-report`

### 🧩 AD & Red Team
`noir-ad-attacks` · `noir-ad-netexec` · `noir-red-recon` · `noir-red-exploit` · `noir-red-lateral` · `noir-red-persistence` · `noir-blue-detect` · `noir-blue-forensics` · `noir-blue-ir` · `noir-blue-report`

### 🧪 IoT
`noir-iot-firmware`

### 📋 Pentest Workflows
`noir-pentest-recon` · `noir-pentest-enum` · `noir-pentest-exploit` · `noir-pentest-browser` · `noir-pentest-mode` · `noir-pentest-report` · `noir-pentest-workflow`

---

## 📁 Project Structure

```
📂 .opencode/
├── 📂 agents/
│   └── noir.md                 # Agent definition & system prompt
├── 📂 commands/
│   └── scan.md                 # Scan command template
├── 📂 skills/                  # 249 skill playbooks
│   ├── noir-vuln-sqli/
│   ├── noir-vuln-xss/
│   ├── noir-ctf-pwn-basics/
│   └── ...
└── 📂 tools/
    └── REFERENCE.md            # Tool installation guide
📄 opencode.jsonc               # opencode configuration
📄 prd.md                       # Product Requirements Document
📄 README.md
```

---

## ⚙️ Configuration

```jsonc
// opencode.jsonc — No model pinning, no API key required
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
  }
}
```

To use a custom LLM, set in your environment:
```bash
export ROUTER_API_KEY="sk-..."
# or
export OPENAI_API_KEY="sk-..."
```

---

## 📜 License

Dual-licensed under **Apache-2.0** or **MIT** — your choice.
