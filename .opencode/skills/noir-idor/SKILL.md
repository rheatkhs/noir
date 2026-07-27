---
name: noir-idor
description: "Insecure Direct Object Reference testing. Use when endpoints reference objects by ID, key, or index. Trigger keywords: idor, authorization, access control, object reference, privilege escalation, horizontal, vertical."
---

# IDOR Testing

## Goal
Find authorization flaws where a user can access, modify, or delete objects belonging to other users by tampering with object identifiers.

## Steps

### 1. Identify Object References

Look for numeric or UUID identifiers in URLs, request bodies, or headers:
```
GET /api/users/1234
GET /order?id=ORD-5678
POST /api/documents/delete {"doc_id": "doc-9012"}
```

### 2. Horizontal Privilege Escalation

Test accessing another user's resources:

```bash
# Original: access own profile
curl -s "https://target.com/api/users/1001"

# Tamper to access another user
curl -s "https://target.com/api/users/1002"
```

Check if the response returns data that doesn't belong to the current context.

### 3. Vertical Privilege Escalation

Test accessing admin-level resources as a low-privilege user:

```bash
curl -s "https://target.com/admin/users"
curl -s "https://target.com/api/admin/settings"
```

### 4. UUID / Hash Enumeration

If IDs are UUIDs or hashes, check if they are predictable or sequential:

```
00000000-0000-0000-0000-000000000001
00000000-0000-0000-0000-000000000002
```

## Detection

- 200 OK with data that shouldn't be accessible
- Missing `Authorization` header validation
- Response contains another user's PII, orders, documents, or settings

## Output

Log: endpoint, object ID, tampered value, type (horizontal/vertical), evidence.
