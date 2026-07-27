---
name: noir-fuzzing
description: "Advanced fuzzing and parameter discovery. Use when you need to discover hidden parameters, endpoints, or bypass input filters. Trigger keywords: fuzz, fuzzing, brute force, parameter discovery, wordlist, hidden."
---

# Fuzzing & Parameter Discovery

## Goal
Discover hidden endpoints, parameters, and bypass input filters through systematic fuzzing.

## Steps

### 1. Parameter Fuzzing

Fuzz common parameter names on known endpoints:

```bash
# Common parameter wordlist
printf "id\nuser\nadmin\ndebug\ntoken\nkey\napi_key\nsecret\nfile\nurl\nredirect\npage\nlimit\noffset\nsort\nfilter\nsearch\nq\ncallback\nformat\ntype" > /tmp/params.txt

# Fuzz GET parameters
ffuf -w /tmp/params.txt -u "<target>/api?FUZZ=test" -mc 200,302 -s
```

### 2. Header Injection Fuzzing

```bash
# Test for host header injection
curl -s -H "Host: evil.com" "<target>"

# Test for X-Forwarded-For bypass
curl -s -H "X-Forwarded-For: 127.0.0.1" "<target>/admin"

# Test for content-type confusion
curl -s -X POST -H "Content-Type: application/xml" -d "<test>" "<target>/api"
```

### 3. HTTP Method Fuzzing

```bash
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  curl -s -X $method -o /dev/null -w "%{http_code}" "<target>/api/endpoint"
  echo " -> $method"
done
```

### 4. Recursive Directory Fuzzing

```bash
ffuf -w /tmp/wordlist.txt -u "<target>/FUZZ" -recursion -recursion-depth 2 -mc 200,301,302 -s
```

### 5. Extension Fuzzing

```bash
printf ".php\n.asp\n.aspx\n.jsp\n.do\n.action\n.json\n.xml\n.txt\n.html\n.js\n.zip\n.tar.gz\n.bak\n.old\n.swp" > /tmp/exts.txt
ffuf -w /tmp/exts.txt -u "<target>/api/userFUZZ" -mc 200 -s
```

## Output

Log: discovered endpoints, parameters, methods, and response codes.
