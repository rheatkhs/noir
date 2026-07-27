---
name: noir-playbook
description: "Master playbook that orchestrates the full Noir security assessment workflow. Use when running a complete scan. Trigger keywords: scan, full scan, assessment, pentest, playbook, workflow."
---

# Playbook: Full Security Assessment

This playbook orchestrates the complete Noir workflow. Follow these phases in order.

## Phase 1: Reconnaissance

**Skill:** `noir-recon`

1. Extract target host from URL
2. `nmap` port scan on common web ports (80, 443, 8000, 8080, 8443)
3. `curl -sI` for HTTP header & tech stack identification
4. `ffuf` directory fuzzing with common wordlist
5. LLM-assisted endpoint path discovery

**Deliverable:** List of discovered endpoints with URLs and HTTP metadata.

## Phase 2: Parameter Discovery

**Skill:** `noir-fuzzing`

1. Fuzz hidden parameters on discovered endpoints
2. Fuzz HTTP methods (GET, POST, PUT, PATCH, DELETE, OPTIONS)
3. Test header injection (Host, X-Forwarded-For, Content-Type)
4. Recursive directory discovery

**Deliverable:** Expanded endpoint list with parameter signatures and accepted methods.

## Phase 3: Exploitation

Run these skills in parallel for each discovered endpoint:

### 3a. SQL Injection + Path Traversal

**Skill:** `noir-exploit`

- Payloads: `'`, `"' OR 1=1 --`, `../../../etc/passwd`
- Check for SQL errors, file content leaks

### 3b. SSRF

**Skill:** `noir-ssrf`

- Cloud metadata endpoints (AWS, GCP)
- Internal service probing (localhost, 127.0.0.1)
- Protocol smuggling (file://, gopher://, dict://)

### 3c. IDOR

**Skill:** `noir-idor`

- Numeric ID tampering (horizontal & vertical)
- UUID/hash enumeration
- Object reference manipulation in POST bodies

### 3d. Broken Authentication

**Skill:** `noir-broken-auth`

- Weak credential testing
- Rate limiting checks
- JWT inspection (alg none, weak secret)
- Session fixation
- Password reset abuse

### 3e. Race Conditions

**Skill:** `noir-race`

- Concurrent request testing on state-changing endpoints
- Coupon/transfer/registration races

**Deliverable:** List of potential vulnerabilities with type, endpoint, payload, evidence.

## Phase 4: Validation

**Skill:** `noir-validate`

1. For each potential finding, write standalone Python PoC
2. Execute PoC
3. Exit code 0 = validated vulnerability
4. Exit code 1 = false positive

**Deliverable:** Confirmed vulnerabilities with reproducible PoC scripts.

## Phase 5: Reporting

**Skill:** `noir-validate`

1. Generate markdown report
2. Include: summary table, validated findings with type/endpoint/payload/PoC/evidence
3. Save to `./noir_reports/report_<timestamp>.md`

## Output

Final report path and summary:
```
Scan complete: ./noir_reports/report_20260727_113000.md
Endpoints discovered: 12
Potential vulnerabilities: 4
Validated findings: 2
```
