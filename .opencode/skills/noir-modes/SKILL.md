---
name: noir-modes
description: "Engagement modes for Noir security assessments. Controls tool priority, output format, and workflow order. Trigger keywords: mode, engagement, auto, bug-bounty, red-team, ctf, blue-team, offensive, grey-hat, forensic, reverse-engineering, mobile-pentest."
---

# Engagement Modes

Noir has ten engagement modes. Each optimizes tool priority, output format, and workflow order for a different context. Modes are auto-detected from the target URL or set explicitly.

## Mode Selection

### Auto-Detection

Noir auto-detects mode from the target URL:

| Pattern | Mode |
|---------|------|
| `hackerone.com`, `bugcrowd.com`, `intigriti.com` | `bug-bounty` |
| `hackthebox.com`, `tryhackme.com`, `picoctf.com`, `.ctf` | `ctf` |
| `.apk`, `.ipa`, `android`, `ios` | `mobile-pentest` |
| `.elf`, `.bin`, `.dll`, `.exe`, `.hex` | `reverse-engineering` |
| `.mem`, `.dd`, `.e01`, `memory` | `forensic` |
| Unknown | `auto` |

Override detection by specifying mode explicitly in the prompt.

## Mode Reference

### auto
- **Use case:** Unknown target
- **Tool priority:** Adaptive — probes target, adjusts order based on response
- **Output:** Standard markdown report
- **Workflow:** Probe → Identify → Adapt → Execute

### bug-bounty
- **Use case:** HackerOne, Bugcrowd, Intigriti programs
- **Tool priority:** Recon → Enumeration → Exploit
- **Output:** HackerOne-compatible markdown format with severity, CVSS, impact, remediation
- **Rules:** Scope validation strictly enforced. No automated scanning without explicit program permission. Rate limiting respected.
- **Workflow:** Recon → Subdomain/Endpoint enum → Parameter discovery → Exploit → Report

### red-team
- **Use case:** Stealth operations, persistence, Active Directory
- **Tool priority:** Recon → Exploit → Enumeration
- **Output:** Executive summary with risk ratings, business impact, remediation timeline
- **Rules:** Noisy scans minimized. OPSEQ (operational security) considered. Payloads OPSEC-safe.
- **Workflow:** External recon → Initial access → Persistence → Lateral movement → Data exfil simulation → Report

### ctf
- **Use case:** HackTheBox, TryHackMe, picoCTF, wargames
- **Tool priority:** Exploit → Enumeration → Recon
- **Output:** Flag submission format — concise, flag extraction only
- **Rules:** No destructive actions. Focus on the shortest path to flag. Skip verbose reporting.
- **Workflow:** Service discovery → Vulnerability identification → Exploit → Flag extraction

### blue-team
- **Use case:** Detection engineering, incident response, defensive audit
- **Tool priority:** Enumeration → Recon → Report
- **Output:** Incident response report with IoCs, TTPs (MITRE ATT&CK), detection rules, timeline
- **Rules:** Read-only where possible. Log all actions for replay. No exploitation that causes service degradation.
- **Workflow:** Environment enumeration → Vulnerability identification → Detection gap analysis → Remediation recommendations

### offensive
- **Use case:** Aggressive exploitation, PoC chain development
- **Tool priority:** Exploit → Enumeration → Recon
- **Output:** Full technical report with PoC chain, exploitation steps, remediation
- **Rules:** Assume worst-case. Chain multiple vulnerabilities for maximum impact. Document every step for reproducibility.
- **Workflow:** Quick recon → Vulnerability chaining → PoC development → Full exploitation → Technical report

### grey-hat
- **Use case:** Balanced assessment
- **Tool priority:** Adaptive — balanced across all phases
- **Output:** Technical report with risk ratings and recommendations
- **Rules:** Balance between depth and speed. Notify if critical findings discovered mid-assessment.
- **Workflow:** Standard recon → Exploitation → Validation → Report

### forensic
- **Use case:** Evidence preservation, disk/memory analysis
- **Tool priority:** Forensics → Report
- **Output:** Chain-of-custody report with findings, timestamps, hash verification
- **Rules:** Write-block all evidence sources. Never modify original media. Document hash chain.
- **Workflow:** Evidence acquisition → Hashing/verification → Analysis → Timeline reconstruction → Report

### reverse-engineering
- **Use case:** Binaries, firmware, malware analysis
- **Tool priority:** RE → Exploit → Utility
- **Output:** Technical RE report with decompiled code, vulnerability analysis, exploit PoC
- **Rules:** Static analysis first. Dynamic analysis in sandbox only. No production environment execution.
- **Workflow:** Static analysis → Dynamic analysis → Vulnerability identification → PoC → Technical report

### mobile-pentest
- **Use case:** Android/iOS app assessment
- **Tool priority:** Mobile → Enumeration → Exploit
- **Output:** OWASP Mobile Top 10 format with findings per category
- **Rules:** Test on real/emulated devices. No production user data. Analyze both APK/IPA and API.
- **Workflow:** Static app analysis → Dynamic app analysis → API testing → Data storage review → Report

## Output Format Override

All modes accept format override via the prompt:
- `standard` — Default markdown
- `json` — Machine-readable JSON
- `short` — Summary only
