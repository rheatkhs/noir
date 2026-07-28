---
name: noir-vuln-remediation
description: "Code-level remediation patterns for common vulnerability types. Use to generate fix code after validating a vulnerability. Trigger keywords: remediate, fix, patch, mitigation, repair, how to fix."
---

# Remediation Patterns

For each validated vulnerability, append a `fix:` section to the report with language-specific remediation code.

## SQL Injection

### Node.js / Express
```javascript
// BAD: string concatenation
const q = `SELECT * FROM users WHERE id = ${req.params.id}`;

// GOOD: parameterized query
const q = "SELECT * FROM users WHERE id = ?";
db.query(q, [req.params.id]);
```

### Python / Flask
```python
# BAD: f-string
query = f"SELECT * FROM users WHERE id = {id}"

# GOOD: parameterized
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (id,))
```

### PHP / Laravel
```php
// BAD: raw SQL
$users = DB::select("SELECT * FROM users WHERE id = $id");

// GOOD: Eloquent
$user = User::find($id);
```

### Java / Spring
```java
// BAD: concatenation
String q = "SELECT * FROM users WHERE id = " + id;

// GOOD: PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, id);
```

## XSS (Reflected/Stored)

### React
```javascript
// BAD: dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{__html: userInput}} />

// GOOD: JSX auto-escapes
<div>{userInput}</div>
```

### Python / Django
```python
# BAD: mark_safe
return render(request, 'page.html', {'content': mark_safe(user_input)})

# GOOD: auto-escaped template
return render(request, 'page.html', {'content': user_input})
```

### Generic
```javascript
// HTML-encode user input before rendering
function escape(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}
```

## Path Traversal / LFI

### Node.js
```javascript
const path = require('path');
const safe = path.resolve('/app/files/', userInput);
if (!safe.startsWith('/app/files/')) throw new Error('invalid path');
```

### Python
```python
import os
base = '/app/files/'
safe = os.path.abspath(os.path.join(base, filename))
if not safe.startswith(base):
    raise ValueError('invalid path')
```

### PHP
```php
$base = '/var/www/files/';
$path = realpath($base . $filename);
if (strpos($path, $base) !== 0) { die('invalid path'); }
```

## SSRF

### Python
```python
import ipaddress
from urllib.parse import urlparse

parsed = urlparse(user_url)
host = parsed.hostname
if ipaddress.ip_address(host).is_private:
    raise ValueError('private IP blocked')

# Or use allowlist:
ALLOWED = ['api.trusted.com', 'cdn.trusted.com']
if host not in ALLOWED:
    raise ValueError('untrusted host')
```

### Node.js
```javascript
const { URL } = require('url');
const allowed = ['api.trusted.com'];

const parsed = new URL(userUrl);
if (!allowed.includes(parsed.hostname)) {
  throw new Error('host not allowed');
}
```

## Insecure Deserialization

### Python
```python
# BAD: pickle.loads(user_data)

# GOOD: validate before deserializing, or use safe format (JSON)
import json
data = json.loads(user_data)
```

### Java
```java
// BAD: ObjectInputStream
ObjectInputStream ois = new ObjectInputStream(input);

// GOOD: validate class allowlist, or use JSON
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(); // vulnerable
// Instead: use explicit types
MyClass obj = mapper.readValue(input, MyClass.class);
```

## Prototype Pollution

### JavaScript
```javascript
// BAD: unsafe merge
Object.assign(target, userInput);

// GOOD: sanitize keys
function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor') continue;
    target[key] = source[key];
  }
  return target;
}
```

## Command Injection

### Python
```python
import subprocess
# BAD: shell=True with user input
subprocess.run(f"grep {user_input} /data", shell=True)

# GOOD: no shell, pass args as list
subprocess.run(["grep", user_input, "/data"])
```

### Node.js
```javascript
const { execFile } = require('child_process');
// BAD: exec with user input
exec(`grep ${userInput} /data`);

// GOOD: execFile with args array
execFile('grep', [userInput, '/data']);
```

## How to Apply

After validating a finding:
1. Identify the vulnerability type
2. Select the matching remediation pattern from this skill
3. Adapt the code to the target's language and framework
4. Append a `### Remediation` section to the finding in the report
5. Include both the BAD and GOOD code examples
