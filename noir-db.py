# Noir Findings Database
# Usage: python noir-db.py <cmd> [args]
# Data stored in ~/.noir/findings.db

import json, os, sqlite3, sys, hashlib
from urllib.parse import urlparse

DB = os.path.expanduser("~/.noir/findings.db")
os.makedirs(os.path.dirname(DB), exist_ok=True)

def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            vuln_type TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            payload TEXT,
            severity TEXT DEFAULT 'medium',
            cvss REAL,
            poc TEXT,
            evidence TEXT,
            status TEXT DEFAULT 'open',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL UNIQUE,
            endpoints_found INTEGER DEFAULT 0,
            potential_findings INTEGER DEFAULT 0,
            validated_findings INTEGER DEFAULT 0,
            last_scanned TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS response_cache (
            endpoint TEXT PRIMARY KEY,
            body_hash TEXT NOT NULL,
            status_code INTEGER,
            content_type TEXT,
            last_checked TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    return conn

def cmd_add(args):
    data = json.loads(args[0])
    conn = get_conn()
    conn.execute("""
        INSERT INTO findings (target, vuln_type, endpoint, payload, severity, cvss, poc, evidence)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data.get("target", ""),
        data.get("vuln_type", ""),
        data.get("endpoint", ""),
        data.get("payload", ""),
        data.get("severity", "medium"),
        data.get("cvss"),
        data.get("poc", ""),
        data.get("evidence", ""),
    ))
    conn.commit()
    print(f"OK: finding saved (id={conn.lastrowid})")

def cmd_update(args):
    fid, status = args[0], args[1]
    conn = get_conn()
    conn.execute("UPDATE findings SET status=?, updated_at=datetime('now') WHERE id=?", (status, fid))
    conn.commit()
    print(f"OK: finding {fid} updated to {status}")

def cmd_query(args):
    sql = " ".join(args) if args else "SELECT * FROM findings ORDER BY created_at DESC LIMIT 20"
    conn = get_conn()
    rows = conn.execute(sql).fetchall()
    for r in rows:
        print(dict(r))

def cmd_scan(args):
    data = json.loads(args[0])
    conn = get_conn()
    conn.execute("""
        INSERT INTO scans (target, endpoints_found, potential_findings, validated_findings)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(target) DO UPDATE SET
            endpoints_found=excluded.endpoints_found,
            potential_findings=excluded.potential_findings,
            validated_findings=excluded.validated_findings,
            last_scanned=datetime('now')
    """, (
        data.get("target", ""),
        data.get("endpoints", 0),
        data.get("potential", 0),
        data.get("validated", 0),
    ))
    conn.commit()
    print(f"OK: scan record saved")

def cmd_summary(args):
    conn = get_conn()
    rows = conn.execute("""
        SELECT target, COUNT(*) as total,
               SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) as open,
               SUM(CASE WHEN status='fixed' THEN 1 ELSE 0 END) as fixed
        FROM findings GROUP BY target ORDER BY total DESC
    """).fetchall()
    for r in rows:
        print(f"{r['target']:40s} {r['total']:3d} total  {r['open']:3d} open  {r['fixed']:3d} fixed")

def cmd_cache(args):
    """Store response hash for an endpoint. Usage: cache <endpoint> <body_hash> [status_code] [content_type]"""
    endpoint = args[0]
    body_hash = args[1]
    status_code = int(args[2]) if len(args) > 2 else None
    content_type = args[3] if len(args) > 3 else None
    conn = get_conn()
    conn.execute("""
        INSERT INTO response_cache (endpoint, body_hash, status_code, content_type)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(endpoint) DO UPDATE SET
            body_hash=excluded.body_hash,
            status_code=excluded.status_code,
            content_type=excluded.content_type,
            last_checked=datetime('now')
    """, (endpoint, body_hash, status_code, content_type))
    conn.commit()
    print(f"OK: cached {endpoint}")

def cmd_check(args):
    """Check if endpoint response changed. Usage: check <endpoint> <current_body_hash>"""
    endpoint = args[0]
    current_hash = args[1] if len(args) > 1 else ""
    conn = get_conn()
    row = conn.execute("SELECT body_hash FROM response_cache WHERE endpoint=?", (endpoint,)).fetchone()
    if not row:
        print("CHANGED: no previous cache")
    elif row["body_hash"] == current_hash:
        print("UNCHANGED: skipping")
    else:
        print(f"CHANGED: hash differs (was {row['body_hash'][:12]}..., now {current_hash[:12]}...)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python noir-db.py <add|update|query|scan|summary|cache|check> [args]")
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]
    {"add": cmd_add, "update": cmd_update, "query": cmd_query,
     "scan": cmd_scan, "summary": cmd_summary,
     "cache": cmd_cache, "check": cmd_check}.get(cmd, lambda _: print(f"Unknown: {cmd}"))(args)
