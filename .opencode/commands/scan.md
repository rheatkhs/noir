---
description: Run a full Noir security assessment against a target. Supports engagement modes, vulnerability scanning, and report generation.
agent: noir
subtask: false
---

Run a full Noir security assessment against $ARGUMENTS.

## Mode Detection
Auto-detect engagement mode from the target URL:
- `hackerone.com`, `bugcrowd.com`, `intigriti.com` → `bug-bounty` mode
- `hackthebox.com`, `tryhackme.com`, `picoctf.com`, `.ctf` → `ctf` mode
- otherwise → `auto` mode (adaptive)

Override mode by specifying: `scan <url> in <mode>`.

## Workflow

### Phase 1: Reconnaissance
Use `noir-recon-full`, `noir-recon-subdomain`, `noir-recon-asn-whois`, `noir-recon-dorking`, `noir-recon-shodan`, `noir-recon-js-analysis`, `noir-recon-secrets`, and technology fingerprinting skills (`noir-tech-stack-fingerprint`, `noir-recon-favicon`).

### Phase 2: Discovery & Fuzzing
Use `noir-pentest-enum`, `noir-recon-devtools`, `noir-recon-cloud-assets`, `noir-recon-js-hostname` to expand the attack surface.

### Phase 3: Vulnerability Scanning
Test each discovered endpoint using the relevant vulnerability skills:

- `noir-vuln-sqli`, `noir-vuln-xss`, `noir-vuln-blind-xss`, `noir-vuln-dom-xss`
- `noir-vuln-ssrf`, `noir-vuln-ssti`, `noir-vuln-xxe`, `noir-vuln-rce`
- `noir-vuln-idor`, `noir-vuln-bfla`, `noir-vuln-privesc-web`
- `noir-vuln-csrf`, `noir-vuln-cors`, `noir-vuln-open-redirect`
- `noir-vuln-jwt`, `noir-vuln-oauth`, `noir-vuln-2fa-bypass`, `noir-vuln-account-takeover`
- `noir-vuln-file-upload`, `noir-vuln-deserialization`, `noir-vuln-http-smuggling`
- `noir-vuln-race-conditions`, `noir-vuln-business-logic`, `noir-vuln-prototype-pollution`
- `noir-vuln-websocket`, `noir-vuln-grpc`, `noir-vuln-grpc`, `noir-vuln-host-header`
- `noir-vuln-nosql`, `noir-vuln-llm-attacks`, `noir-vuln-log4shell`, `noir-vuln-cache-deception`
- `noir-vuln-password-reset-poisoning`, `noir-vuln-mass-assignment`, `noir-vuln-supply-chain`

### Phase 4: Technology-Specific Testing
Use framework and tech skills based on identified stack:
- Frameworks: `noir-framework-django`, `noir-framework-laravel`, `noir-framework-rails`, `noir-framework-spring`, `noir-framework-express`, `noir-framework-nextjs`, `noir-framework-fastapi`, `noir-framework-dotnet`, `noir-framework-flask`, `noir-framework-php`, `noir-framework-wordpress`
- Tech: `noir-tech-docker`, `noir-tech-kubernetes`, `noir-tech-redis`, `noir-tech-mongodb`, `noir-tech-jenkins`, `noir-tech-firebase`, `noir-tech-elasticsearch`, `noir-tech-tomcat`, `noir-tech-apache-misconfig`, `noir-tech-nginx-apache`

### Phase 5: Exploitation & Post-Exploitation
If applicable: `noir-post-linux-privesc`, `noir-post-windows-privesc`, `noir-post-pivoting`, `noir-post-lateral-movement`, `noir-post-bloodhound`, `noir-post-credential-dumping`, `noir-post-container-escape`.

### Phase 6: Validation
For each potential vulnerability, write a standalone Python PoC script and execute it. Use `noir-vuln-exploit-validation` and `noir-pentest-exploit`. Only mark as validated if PoC exits with code 0.

### Phase 7: Reporting
Generate markdown report and todos list, organized per target domain:
- Extract domain from target URL (e.g., `http://localhost:3000` → `localhost:3000`, `https://api.target.com` → `api.target.com`)
- Create folder `./noir_reports/<domain>/`
- Save report as `./noir_reports/<domain>/report_<timestamp>.md`
- Save todos as `./noir_reports/<domain>/todos.md` with: unchecked endpoints, pending tests, ideas for deeper investigation

## Tool Usage
Available tools: `noir-tool-nmap`, `noir-tool-sqlmap`, `noir-tool-nuclei`, `noir-tool-metasploit`, `noir-tool-impacket`, `noir-tool-hashcat-john`, `noir-tool-dalfox`, `noir-tool-semgrep`, `noir-tool-source-audit`, `noir-tool-caido`, `noir-tool-advanced-fuzzing`, `noir-tool-browser-automation`, `noir-tool-scripting`.

## Output
Return: brief summary of findings and path to the generated report.
