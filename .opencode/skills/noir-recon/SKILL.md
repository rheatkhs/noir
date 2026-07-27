---
name: noir-recon
description: "Reconnaissance phase of security testing. Use when discovering target endpoints, tech stack, open ports, and hidden paths. Trigger keywords: recon, discover, map, enumerate, endpoints."
---

# Reconnaissance

## Goal
Map the target surface: identify tech stack, open ports, and discoverable endpoints.

## Steps

### 1. Extract target host

```python
from urllib.parse import urlparse
parsed = urlparse(target)
host = parsed.hostname
```

### 2. Port scan with nmap

```bash
nmap -p 80,443,8000,8080,8443 <host>
```

### 3. HTTP header probing

```bash
curl -sI <target>
```

### 4. Directory fuzzing with ffuf

```bash
printf "api\nadmin\nlogin\nwp-admin\nconfig\nbackup\n.git\ndb\nuploads" > /tmp/wordlist.txt
ffuf -w /tmp/wordlist.txt -u <target>/FUZZ -mc 200,301,302 -s
```

### 5. LLM-based path discovery

Ask the LLM for common endpoint paths based on identified headers/tech stack.

## Output

Collect all discovered endpoints into a list. Each entry is a full URL. Validate all URLs stay within the target domain scope.
