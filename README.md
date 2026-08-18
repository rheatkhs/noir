# Noir - Grace Field House Edition  
🚀 Autonomous multi-agent security penetration testing team for [opencode](https://opencode.ai).

[![Python](https://img.shields.io/badge/python-367049?style=for-the-flat&logo=python&logoColor=ffdd54)](https://www.python.org)
[![Markdown](https://img.shields.io/badge/markdown-000000?style=for-the-flat&logo=markdown&logoColor=white)](https://dariusbubac.github.io/markdown/)
[![Git](https://img.shields.io/badge/git-F05032?style=for-the-flat&logo=git&logoColor=white)](https://git-scm.com)
[![Shell](https://img.shields.io/badge/powershell-1E3CF4?style=for-the-flat&logo=powershell&logoColor=white)]((utility))
[![Docker](https://img.shields.io/badge/docker-2496C0?style=for-the-flat&logo=docker&logoColor=white)](https://www.docker.com)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%7C%20MIT-FFD700?style=for-the-flat)](#license)

---

> **WARNING: DISCLAIMER & ETHICAL GUIDELINES**
>
 Noir is a **fully-autonomous security testing tool** designed for **authorized assessments only**. By using this tool you agree:
>
 - **Authorization required** - Only scan targets you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions.
 - **Responsible disclosure** - Report discovered vulnerabilities through the vendor's responsible disclosure program.
 - **No malicious use** - Do not use Noir for unauthorized access, data theft, denial of service, or any activity that violates applicable laws.
 - **Zero false positives** - Only validated, reproducible PoCs are flagged.
 - **Scope enforcement** - Noir enforces target-scope rules. URLs outside the target domain are automatically discarded.
 - **Destructive command blocking`** - Commands like `rm -rf`, `dd`, `mkfs`, `chmod 777`, and aggressive DDoS payloads are blocked.

---

## 📢 Architecture (Grace Field House Team)

Noir orchestrates security assessments using a cooperative, multi-agent workflow where each child has a specialized pipeline function:
```mermaid
flowchart TB
    USER["User Prompt"] --> ISABELLA["Isabella (Orchestrator)"]
    
    ISABELLA --> GILDA["Gilda (Recon)"]
    GILDA -->|endpoints.txt| KRONE["Krone (Stealth)"]
    KRONE -->|evasion_params.json| NORMAN["Norman (Threat Model)"]
    
    NORMAN -->|task_distribution.txt| EMMA["Emma (Web Offensive)"]
    NORMAN -->|task_distribution.txt| DON["Don (System Offensive)"]
    
    EMMA -->|emma_findings.json| RAY["Ray (Validator & Chainer)"]
    DON -->|don_findings.json| RAY

    

    RAY -->|validated_findings.json| PHIL["Phil (Reporting)"]

    PHIL -->|final report| ISABELLA

    ISABELLA -->|results| USER
```

---

## 📢 Agent Roles

| Agent | Role | Description | Permission |
|--------|--------|--------|--------|
|  **Isabella** | Orchestrator | Coordinates scan pipeline, spawns sub-agents | Edit, Read |
| 📢 **Gilda** | Recon & Scout | Performs port scans, fuzzing, and JS analysis | Bash (nmap/ffuf/curl), Read |
| 📍 **Krone** | Stealth & Evasion | Writes evasion config to bypass WAFs and rate limits | Edit, Read |
| 💓 **Norman** | Threat Model | Analyzes recon data, designs test plan for Emma & Don | Read |
| 📌 **Emma** | Web Offensive | Tests IDOR, CSRF, SSRF, XSS | Bash (curl), Read |
| 🎁 **Don** | System Offensive | Tests SQLi, RCE, LFI, file upload | Bash (curl), Read |
| 💅 **Ray** | Validator & PoC | Writes and executes PoCs, attack chaining | Bash (python3), Edit, Read |
| 🕑 **Phil** | Reporter | Gathers findings, generates interactive HTML report | Edit, Read |

---

## 🖮 Quick Start
```bash
git clone https://github.com/rheatkhs/noir.git
cd noir
opencode

# Isabella will autonomously initiate the scan flow
attack http://localhost:3000
agent isabella "scan http://target.com"
```

---

## 🖗 Configuration

Refer to `opencode.jsonc` for permission settings for each agent.

---

## 📢 License

Dual-licensed under Apache-2.0 or MIT.
