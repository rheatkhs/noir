import json
import os
import sys
import sqlite3
from urllib.parse import urlparse

DB = os.path.expanduser("~/.noir/findings.db")

def get_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def generate_html(target_hostname, output_path):
    conn = get_conn()
    findings = conn.execute("SELECT * FROM findings WHERE target LIKE ? ORDER BY cvss DESC", (f"%{target_hostname}%",)).fetchall()
    scans = conn.execute("SELECT * FROM scans WHERE target LIKE ?", (f"%{target_hostname}%",)).fetchone()
    
    total = len(findings)
    open_f = sum(1 for f in findings if f["status"] == "open")
    fixed = sum(1 for f in findings if f["status"] == "fixed")
    
    findings_list = []
    for f in findings:
        findings_list.append(dict(f))
        
    scan_meta = dict(scans) if scans else {"target": target_hostname, "endpoints_found": 0, "potential_findings": 0, "validated_findings": 0, "last_scanned": "N/A"}

    html_template = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Noir Security Assessment Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    colors: {{
                        cyber: {{
                            black: '#0d0e15',
                            dark: '#161824',
                            border: '#262930',
                            primary: '#e94560',
                            accent: '#00ff87',
                            muted: '#94a3b8'
                        }}
                    }}
                }}
            }}
        }}
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;700&family=Inter:wght@400;600;800&display=swap');
        body {{
            font-family: 'Inter', sans-serif;
            background-color: #0d0e15;
        }}
        pre, code {{
            font-family: 'Fira Code', monospace;
        }}
    </style>
</head>
<body class="text-slate-100 min-h-screen pb-12">
    <!-- Header -->
    <header class="border-b border-cyber-border bg-cyber-dark/80 backdrop-blur sticky top-0 z-50 py-4 px-8 flex justify-between items-center">
        <div class="flex items-center gap-3">
            <span class="text-2xl">👑</span>
            <div>
                <h1 class="text-xl font-bold tracking-tight text-white">NOIR <span class="text-cyber-primary text-sm font-semibold">GRACE FIELD EDITION</span></h1>
                <p class="text-xs text-cyber-muted">Autonomous Multi-Agent Penetration Testing</p>
            </div>
        </div>
        <div class="text-right">
            <span class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                <span class="h-2 w-2 rounded-full bg-red-400 animate-pulse"></span>
                Completed Scan
            </span>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-8">
        <!-- Target Info -->
        <div class="bg-cyber-dark border border-cyber-border rounded-xl p-6 mb-8 flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div>
                <span class="text-xs font-semibold uppercase tracking-wider text-cyber-primary">Target Domain</span>
                <h2 class="text-3xl font-extrabold text-white tracking-tight mt-1">{scan_meta['target']}</h2>
                <p class="text-sm text-cyber-muted mt-2">Last Scanned: {scan_meta['last_scanned']}</p>
            </div>
            <div class="flex flex-wrap gap-4">
                <div class="bg-cyber-black border border-cyber-border rounded-lg px-4 py-3 min-w-[120px]">
                    <span class="text-xs text-cyber-muted block">Endpoints Found</span>
                    <span class="text-2xl font-bold text-white">{scan_meta['endpoints_found']}</span>
                </div>
                <div class="bg-cyber-black border border-cyber-border rounded-lg px-4 py-3 min-w-[120px]">
                    <span class="text-xs text-cyber-muted block">Potential Vulns</span>
                    <span class="text-2xl font-bold text-yellow-500">{scan_meta['potential_findings']}</span>
                </div>
                <div class="bg-cyber-black border border-cyber-border rounded-lg px-4 py-3 min-w-[120px]">
                    <span class="text-xs text-cyber-muted block">Validated (PoC)</span>
                    <span class="text-2xl font-bold text-cyber-accent">{scan_meta['validated_findings']}</span>
                </div>
            </div>
        </div>

        <!-- Vulnerability Stats -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-cyber-dark border border-cyber-border rounded-xl p-6">
                <h3 class="text-sm font-semibold text-cyber-muted uppercase tracking-wider mb-4">Severity Breakdown</h3>
                <div class="space-y-3">
                    <div class="flex justify-between items-center text-sm">
                        <span class="text-red-500 font-semibold">Critical / High</span>
                        <span class="bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded font-bold">{sum(1 for f in findings_list if f['severity'] in ['critical', 'high'])}</span>
                    </div>
                    <div class="flex justify-between items-center text-sm">
                        <span class="text-yellow-500 font-semibold">Medium</span>
                        <span class="bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 px-2 py-0.5 rounded font-bold">{sum(1 for f in findings_list if f['severity'] == 'medium')}</span>
                    </div>
                    <div class="flex justify-between items-center text-sm">
                        <span class="text-blue-500 font-semibold">Low / Info</span>
                        <span class="bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded font-bold">{sum(1 for f in findings_list if f['severity'] in ['low', 'info'])}</span>
                    </div>
                </div>
            </div>
            <div class="bg-cyber-dark border border-cyber-border rounded-xl p-6 col-span-2">
                <h3 class="text-sm font-semibold text-cyber-muted uppercase tracking-wider mb-4">Vulnerability List Summary</h3>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-cyber-border text-sm">
                        <thead>
                            <tr class="text-cyber-muted text-left">
                                <th class="pb-2 font-semibold">Type</th>
                                <th class="pb-2 font-semibold">Endpoint</th>
                                <th class="pb-2 font-semibold text-right">CVSS 4.0</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-cyber-border">
                            {"".join([f'''<tr class="hover:bg-cyber-black/40">
                                <td class="py-2.5 font-medium text-white">{f['vuln_type']}</td>
                                <td class="py-2.5 font-mono text-cyber-muted truncate max-w-xs">{f['endpoint']}</td>
                                <td class="py-2.5 text-right font-bold text-cyber-accent">{f['cvss'] or 'N/A'}</td>
                            </tr>''' for f in findings_list])}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Detailed Findings -->
        <h3 class="text-lg font-bold text-white mb-4">Detailed Findings & Proof of Concepts</h3>
        <div class="space-y-6">
            {"".join([f'''<div class="bg-cyber-dark border border-cyber-border rounded-xl overflow-hidden">
                <div class="bg-cyber-black px-6 py-4 border-b border-cyber-border flex justify-between items-center">
                    <div>
                        <span class="text-xs font-semibold uppercase tracking-wider text-cyber-primary">{f['vuln_type']}</span>
                        <h4 class="text-base font-bold text-white mt-0.5">{f['endpoint']}</h4>
                    </div>
                    <div class="flex items-center gap-2">
                        <span class="px-2.5 py-1 rounded text-xs font-bold uppercase border bg-red-500/10 text-red-400 border-red-500/20">{f['severity']}</span>
                        <span class="px-2.5 py-1 rounded text-xs font-bold bg-cyber-dark text-cyber-accent border border-cyber-border">CVSS {f['cvss'] or 'N/A'}</span>
                    </div>
                </div>
                <div class="p-6 space-y-4">
                    <div>
                        <h5 class="text-xs font-semibold uppercase tracking-wider text-cyber-muted mb-1">Payload</h5>
                        <code class="bg-cyber-black text-yellow-500 border border-cyber-border px-3 py-1.5 rounded block text-sm overflow-x-auto">{f['payload']}</code>
                    </div>
                    <div>
                        <h5 class="text-xs font-semibold uppercase tracking-wider text-cyber-muted mb-1">Evidence</h5>
                        <pre class="bg-cyber-black text-slate-300 border border-cyber-border p-4 rounded text-xs overflow-x-auto max-h-60"><code>{f['evidence']}</code></pre>
                    </div>
                    <div>
                        <h5 class="text-xs font-semibold uppercase tracking-wider text-cyber-muted mb-1">Reproducible Python PoC</h5>
                        <pre class="bg-cyber-black text-cyber-accent border border-cyber-border p-4 rounded text-xs overflow-x-auto"><code>{f['poc']}</code></pre>
                    </div>
                </div>
            </div>''' for f in findings_list])}
        </div>
    </main>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_template)
    print(f"[+] Interactive HTML report generated at {output_path}")

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python tools/report_gen.py <hostname> <output_path>")
        sys.exit(1)
    generate_html(sys.argv[1], sys.argv[2])
