---
name: noir-validate
description: "Validation phase of security testing. Use when confirming potential vulnerabilities with reproducible Proofs-of-Concept. Trigger keywords: validate, confirm, verify, poc, proof."
---

# Validation

## Goal
For each potential vulnerability, create a self-contained Python PoC script, run it, and only mark as validated if the script exits with code 0.

## Steps

### 1. Create PoC script

For each potential vulnerability, write a standalone Python PoC script:

```python
import urllib.request
import urllib.parse
import sys

url = "<endpoint>?q=" + urllib.parse.quote("<payload>")
try:
    req = urllib.request.urlopen(url)
    content = req.read().decode('utf-8')
    if "<type>" == "SQLi" and any(x in content.lower() for x in ["sql syntax", "sqlite3"]):
        sys.exit(0)
    if "<type>" == "PathTraversal" and "root:x:0:0" in content:
        sys.exit(0)
    sys.exit(1)
except Exception as e:
    err = str(e).lower()
    if "sql" in err or "syntax" in err:
        sys.exit(0)
    sys.exit(1)
```

### 2. Execute PoC

```bash
python3 /tmp/poc.py
```

### 3. Check exit code

- **Exit code 0**: Vulnerability is VALIDATED. Add to validated findings.
- **Exit code 1**: Vulnerability is FALSE POSITIVE. Discard.

## Output

Generate a final report in markdown format:

```markdown
# Noir Security Report
Generated on: <timestamp>
Target URL: <target>

## Summary
- Discovered Endpoints: <count>
- Potential Vulnerabilities: <count>
- Validated Vulnerabilities: <count>

## Validated Findings
### 1. <type> on `<endpoint>`
- Type: <type>
- Endpoint: `<endpoint>`
- Payload: `<payload>`
#### PoC
```python
<poc_code>
```
#### Evidence
<evidence>
```
```
</markdown>
```

Save to `./noir_reports/report_<timestamp>.md`.
