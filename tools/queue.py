import json, os, sqlite3, sys, time, subprocess
from datetime import datetime, timedelta

DB = os.path.expanduser("~/.noir/findings.db")

def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            mode TEXT DEFAULT 'auto',
            schedule TEXT DEFAULT 'once',
            status TEXT DEFAULT 'pending',
            priority INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            last_run TEXT,
            next_run TEXT
        )
    """)
    conn.commit()
    return conn

def cmd_add(args):
    target = args[0]
    mode = "auto"
    schedule = "once"
    for i, a in enumerate(args[1:], 1):
        if a == "--mode" and i < len(args[1:]):
            mode = args[1 + i]
        if a == "--schedule" and i < len(args[1:]):
            schedule = args[1 + i]
    conn = get_conn()
    existing = conn.execute("SELECT id FROM queue WHERE target=? AND status='pending'", (target,)).fetchone()
    if existing:
        print(f"OK: already queued (id={existing['id']})")
        return
    next_run = datetime.now().isoformat() if schedule == "once" else None
    conn.execute("INSERT INTO queue (target, mode, schedule, next_run) VALUES (?, ?, ?, ?)",
                 (target, mode, schedule, next_run))
    conn.commit()
    print(f"OK: queued {target} (mode={mode}, schedule={schedule}, id={conn.lastrowid})")

def cmd_list(args):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM queue ORDER BY priority DESC, created_at DESC").fetchall()
    if not rows:
        print("queue empty")
        return
    for r in rows:
        sched = r["schedule"]
        next_s = f" next: {r['next_run'][:19]}" if r["next_run"] and sched != "once" else ""
        print(f"  #{r['id']:3d} {r['target']:40s} {r['mode']:12s} {r['status']:10s} [{sched}]{next_s}")

def cmd_remove(args):
    qid = int(args[0])
    conn = get_conn()
    conn.execute("DELETE FROM queue WHERE id=?", (qid,))
    conn.commit()
    print(f"OK: removed queue item #{qid}")

def cmd_run(args):
    conn = get_conn()
    concurrent = False
    for i, a in enumerate(args):
        if a == "--concurrent":
            concurrent = True
    pending = conn.execute("SELECT * FROM queue WHERE status='pending' ORDER BY priority DESC, created_at ASC").fetchall()
    if not pending:
        pending = conn.execute("SELECT * FROM queue WHERE status='running' OR (schedule!='once' AND (next_run IS NULL OR next_run <= datetime('now')))").fetchall()
    if not pending:
        print("nothing to run")
        return
    for item in pending:
        target = item["target"]
        mode = item["mode"]
        qid = item["id"]
        print(f"--- scanning {target} (id={qid}, mode={mode}) ---")
        conn.execute("UPDATE queue SET status='running' WHERE id=?", (qid,))
        conn.commit()
        cmd = ["python", "-m", "opencode", "attack" if not concurrent else "scan", target]
        env = os.environ.copy()
        env["NOIR_MODE"] = mode
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        status = "done" if r.returncode == 0 else "failed"
        last_run = datetime.now().isoformat(timespec="seconds")
        schedule = item["schedule"]
        if schedule == "hourly":
            next_run = (datetime.now() + timedelta(hours=1)).isoformat(timespec="seconds")
        elif schedule == "daily":
            next_run = (datetime.now() + timedelta(days=1)).isoformat(timespec="seconds")
        else:
            next_run = None
        conn.execute("UPDATE queue SET status=?, last_run=?, next_run=? WHERE id=?",
                     (status, last_run, next_run, qid))
        conn.commit()
        print(f"  result: {status} (exit={r.returncode})")
        print(r.stdout[:2000])

def cmd_results(args):
    conn = get_conn()
    since_days = 7
    for i, a in enumerate(args):
        if a == "--since" and i < len(args) - 1:
            since_days = int(args[i + 1])
    cutoff = (datetime.now() - timedelta(days=since_days)).isoformat()
    rows = conn.execute("""
        SELECT q.id, q.target, q.mode, q.status, q.last_run, q.schedule,
               COUNT(f.id) as findings, SUM(CASE WHEN f.severity='critical' THEN 1 ELSE 0 END) as criticals
        FROM queue q
        LEFT JOIN findings f ON f.target = q.target
        WHERE q.last_run IS NOT NULL AND q.last_run >= ?
        GROUP BY q.id
        ORDER BY q.last_run DESC
    """, (cutoff,)).fetchall()
    if not rows:
        print("no scan results in last {since_days}d")
        return
    print(f"Scan results (last {since_days}d):")
    for r in rows:
        crit = f" ({r['criticals']} critical)" if r.get('criticals') else ""
        print(f"  #{r['id']:3d} {r['target']:40s} {r['status']:8s} {r['findings']:3d} findings{crit}  [{r.get('last_run','')[:19]}]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python tools/queue.py <add|list|remove|run|results> [args]")
        print("  add <target> [--mode auto] [--schedule once|hourly|daily]")
        print("  list")
        print("  remove <id>")
        print("  run [--concurrent]")
        print("  results [--since N-days]")
        sys.exit(1)
    cmd = sys.argv[1]
    args = sys.argv[2:]
    {"add": cmd_add, "list": cmd_list, "remove": cmd_remove,
     "run": cmd_run, "results": cmd_results}.get(cmd, lambda _: print(f"Unknown: {cmd}"))(args)