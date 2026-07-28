import subprocess
import json
import sys
import time

SERVER_SCRIPT = "tools/recon_server.py"

def test_server_starts_and_lists_tools():
    proc = subprocess.Popen(
        [sys.executable, SERVER_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Send initialize request
    init = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "noir-test", "version": "0.1.0"},
        },
    })
    proc.stdin.write(init + "\n")
    proc.stdin.flush()

    # Send tools/list request
    tools_req = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    })
    proc.stdin.write(tools_req + "\n")
    proc.stdin.flush()

    # Read responses
    time.sleep(1)
    proc.stdin.close()
    proc.wait(timeout=5)
    stdout = proc.stdout.read()
    stderr = proc.stderr.read()

    if proc.returncode != 0 and proc.returncode != -1:
        print(f"server stderr: {stderr[:500]}")
        print(f"FAIL: server exited with code {proc.returncode}")
        sys.exit(1)

    if "nmap_scan" in stdout and "http_probe" in stdout and "ffuf_fuzz" in stdout:
        print("PASS: all MCP tools listed correctly")
        sys.exit(0)
    else:
        print(f"FAIL: expected tools not found in output")
        print(f"stdout[:1000]: {stdout[:1000]}")
        sys.exit(1)

if __name__ == "__main__":
    test_server_starts_and_lists_tools()
