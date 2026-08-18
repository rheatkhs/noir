---
description: Grace Field Infiltration pipeline with parallel scanning. Executes full recon -> exploit -> validate.
agent: isabella
subtask: false
---

Infiltrating target $ARGUMENTS using Grace Field House team.

## Phase 0: Parse Target
Get domain and hostname. Create report directories.

## Phase 1: Recon (Gilda) [PARALLEL]
- Port scan (nmap_scan)
- HTTP headers probe (http_probe)
- Fuzzing paths (ffuf_fuzz)

## Phase 2: Stealth Evasion Configuration (Krone)
- Generates delay and rotated User-Agents to evade WAF blocks.

## Phase 3: Threat Modeling & Strategy (Norman)
- Reads recon inputs and schedules tasks for Emma (Web) and Don (System).

## Phase 4: Exploitation (Emma & Don) [PARALLEL]
- Emma tests Logic, IDOR, CSRF, SSRF, XSS.
- Don tests SQLi, RCE, LFI, and expose system ports.

## Phase 5: Verification (Ray)
- Ray runs Python 3 validation PoCs (Zero False Positives) and chains vulnerabilities.

## Phase 6: HTML Reports & Cleanup (Phil)
- Compiles everything into tools/report_gen.py and cleans target evidence workspace.
