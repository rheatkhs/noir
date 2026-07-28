import json, os, sys, time, urllib.request, urllib.error, http.cookiejar
from urllib.parse import urlparse, urljoin

SESSIONS_DIR = os.path.expanduser("~/.noir/sessions")
os.makedirs(SESSIONS_DIR, exist_ok=True)

def _session_path(target):
    host = urlparse(target if "://" in target else f"http://{target}").hostname or target
    return os.path.join(SESSIONS_DIR, f"{host}.json")

def _load(target):
    p = _session_path(target)
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return None

def _save(target, data):
    p = _session_path(target)
    with open(p, "w") as f:
        json.dump(data, f, indent=2)

def _build_opener(cookies=None):
    cj = http.cookiejar.CookieJar()
    if cookies:
        for name, val in cookies.items():
            cj.set_cookie(http.cookiejar.Cookie(0, name, val, None, False, "", False, True, "/", True, False, None, False, None, None, None))
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def cmd_add(args):
    target = args[0]
    method = args[1] if len(args) > 1 else "basic"
    data = {"target": target, "method": method, "cookies": {}, "headers": {}, "created": time.time()}

    if method == "basic":
        data["username"] = args[2]
        data["password"] = args[3]
        import base64
        token = base64.b64encode(f"{data['username']}:{data['password']}".encode()).decode()
        data["headers"]["Authorization"] = f"Basic {token}"

    elif method == "form":
        data["username"] = args[2]
        data["password"] = args[3]
        data["login_url"] = args[4] if len(args) > 4 else urljoin(target, "/login")
        data["username_field"] = args[5] if len(args) > 5 else "username"
        data["password_field"] = args[6] if len(args) > 6 else "password"

    elif method == "bearer":
        data["headers"]["Authorization"] = f"Bearer {args[2]}"

    else:
        print(f"unknown method: {method}")
        sys.exit(1)

    _save(target, data)
    print(f"OK: session saved for {target} (method={method})")

def cmd_list(args):
    files = os.listdir(SESSIONS_DIR)
    if not files:
        print("no saved sessions")
        return
    for f in sorted(files):
        p = os.path.join(SESSIONS_DIR, f)
        with open(p) as fh:
            s = json.load(fh)
        age = int(time.time() - s.get("created", 0))
        print(f"  {s['target']:40s} {s['method']:12s} {age//3600}h old")

def cmd_check(args):
    target = args[0]
    s = _load(target)
    if not s:
        print(f"FAIL: no session for {target}")
        sys.exit(1)
    opener = _build_opener(s.get("cookies"))
    for k, v in s.get("headers", {}).items():
        opener.addheaders = [(k, v)]
    try:
        r = opener.open(urllib.request.Request(target))
        code = r.getcode()
        if code in (200, 204, 301, 302):
            print(f"OK: session valid for {target} (HTTP {code})")
        else:
            print(f"WARN: unexpected HTTP {code}")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print(f"FAIL: session expired for {target} (HTTP 401)")
        else:
            print(f"WARN: HTTP {e.code}")
    except Exception as e:
        print(f"FAIL: {e}")

def cmd_curl(args):
    target = args[0]
    url = args[1]
    s = _load(target)
    if not s:
        print(f"FAIL: no session for {target}", file=sys.stderr)
        sys.exit(1)

    opener = _build_opener(s.get("cookies"))
    for k, v in s.get("headers", {}).items():
        opener.addheaders = [(k, v)]

    if s.get("method") == "form":
        login_url = s.get("login_url", urljoin(target, "/login"))
        uf = s.get("username_field", "username")
        pf = s.get("password_field", "password")
        login_data = urllib.parse.urlencode({uf: s["username"], pf: s["password"]}).encode()
        try:
            opener.open(urllib.request.Request(login_url, data=login_data))
            if hasattr(opener, "opener") and hasattr(opener.opener, "cookiejar"):
                cj = opener.opener.cookiejar
                s["cookies"] = {c.name: c.value for c in cj}
                _save(target, s)
        except Exception as e:
            print(f"WARN: login failed: {e}", file=sys.stderr)

    try:
        r = opener.open(urllib.request.Request(url))
        body = r.read().decode("utf-8", errors="replace")
        print(body[:16000])
        print(f"\n--- HTTP {r.getcode()} ({len(body)} bytes) ---", file=sys.stderr)
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode('utf-8', errors='replace')[:2000]}")
    except Exception as e:
        print(f"error: {e}")

def cmd_remove(args):
    target = args[0]
    p = _session_path(target)
    if os.path.exists(p):
        os.remove(p)
        print(f"OK: removed session for {target}")
    else:
        print(f"no session for {target}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/auth.py <add|list|check|curl|remove> [args]")
        print("  add <target> basic <username> <password>")
        print("  add <target> form <username> <password> [login_url] [user_field] [pass_field]")
        print("  add <target> bearer <token>")
        print("  list")
        print("  check <target>")
        print("  curl <target> <url>")
        print("  remove <target>")
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]
    {
        "add": cmd_add, "list": cmd_list, "check": cmd_check,
        "curl": cmd_curl, "remove": cmd_remove,
    }.get(cmd, lambda _: print(f"Unknown: {cmd}"))(args)