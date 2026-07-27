---
description: Run a full Noir security scan against a target URL.
---

Run a full security scan against $ARGUMENTS.

1. Extract domain from the target URL.
2. Run `nmap -p 80,443,8000,8080,8443 <host>`.
3. Run `curl -sI <target>` for HTTP header probing.
4. Run `ffuf` directory fuzzing against target.
5. For each discovered endpoint, test OWASP payloads (SQLi, Path Traversal).
6. For each potential finding, write & execute a standalone Python PoC.
7. Write markdown report to `./noir_reports/report_<timestamp>.md`.

Output a brief summary table of findings and the report path.
