---
name: noir-tool-browser-scanning
description: "Browser-based security testing using Playwright. Use for DOM XSS, authenticated scans, SPA route discovery, cookie analysis, CSP analysis, clickjacking, form testing. Trigger keywords: browser scan, dom xss, authenticated scan, spa, cookie, csp, clickjacking, csrf."
---

# Browser-Based Security Testing

Use Playwright-based browser automation for client-side vulnerability detection that curl/ffuf cannot find.

## When to Use

- Target is a Single Page Application (SPA) with client-side routing
- Need to test DOM-based XSS (sinks: innerHTML, eval, document.write)
- Need authenticated scanning (login, session cookies)
- Need to test cookie security flags (HttpOnly, Secure, SameSite)
- Need to test CSP headers and CSP bypasses
- Need to test clickjacking (X-Frame-Options, CSP frame-ancestors)
- Need to test CSRF token presence on forms
- Need to test client-side input validation bypasses
- Need to discover SPA routes not visible in HTML source
- Need to test cookie security flags (HttpOnly, Secure, SameSite)

## Prerequisites

```bash
pip install playwright
playwright install chromium
```

## Usage

```bash
python tools/browser_scanner.py <target_url> [--auth user:pass] [--max-pages 50] [--output ./reports]
```

Or programmatically:
```python
from tools.browser_scanner import BrowserScanner

async with BrowserScanner("https://target.com", auth=("user", "pass")) as scanner:
    findings = await scanner.scan(max_pages=50)
    scanner.save_report()
```

## Detection Capabilities

### DOM XSS
- Scans for dangerous sinks: `innerHTML`, `outerHTML`, `document.write`, `eval()`, `setTimeout()`, `Function()`, `innerText`
- Injects XSS payloads into form fields and checks for reflection in DOM
- Checks for dangerous event handlers: `onload`, `onerror`, `onclick`, etc.

### Authenticated Scanning
```python
async with BrowserScanner("https://target.com", auth=("user", "pass")) as scanner:
    findings = await scanner.scan(max_pages=50)
```

### SPA Route Discovery
- Renders pages fully
- Extracts client-side routes from router state
- Follows client-side navigation

### Cookie Security Analysis
Checks each cookie for:
- `HttpOnly` flag (mitigates XSS cookie theft)
- `Secure` flag (HTTPS only)
- `SameSite` attribute (Strict/Lax/None)

### CSP Analysis
- Checks for `Content-Security-Policy` header
- Flags `unsafe-inline`, `unsafe-eval`, `unsafe-hashes`
- Reports missing CSP

### Clickjacking
- Checks `X-Frame-Options` header
- Checks `frame-ancestors` in CSP

### CSRF Token Detection
- Scans forms for CSRF token fields (`_token`, `csrf_token`, `_token`, etc.)
- Flags forms without CSRF protection

### Form Testing
Injects XSS/SQLi/SSTI payloads into form fields and submits:
- XSS payloads: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
- SQLi payloads: `' OR 1=1--`, `' OR '1'='1`
- SSTI payloads: `{{7*7}}`, `${7*7}`

### Output
- JSON report with all findings
- Console output with findings summary
- Optionally saves to JSON file

## Integration with Attack Pipeline

In the attack command, after endpoint discovery:

```markdown
## Step X: Browser-Based Scanning [PARALLEL]

Launch browser-based scan for each unique endpoint:
```bash
python tools/browser_scanner.py <endpoint> --max-pages 20 --output noir_reports/<domain>/browser/
```

Merge findings into `potential_findings.md`.
```

## Output Format

Findings are returned as a list of dictionaries:
```json
{
  "type": "xss|sqli|ssti|lfi|csrf|cookie|dom_xss|csp|clickjacking",
  "endpoint": "https://target.com/page",
  "severity": "critical|high|medium|low",
  "evidence": "Description of finding",
  "payload": "payload used",
  "timestamp": 1234567890
}
```

## Output File
Saves JSON report to `noir_reports/<domain>/browser_<timestamp>.json`

## Tips

- Run browser scans AFTER basic recon so you have endpoints to test
- Use `--auth` for authenticated areas
- Limit `--max-pages` for large SPAs (default 50)
- Browser scans are slower than curl/ffuf — use selectively
- Combine with `noir-vuln-xss` for reflected XSS, `noir-tool-browser-scanning` for DOM XSS