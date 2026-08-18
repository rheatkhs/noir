import asyncio
import json
import os
import sys
from urllib.parse import urlparse

class GraceFieldOrchestrator:
    def __init__(self, target_url):
        self.target = target_url
        self.hostname = urlparse(target_url).hostname or "target"
        self.report_dir = os.path.join("noir_reports", self.hostname)
        os.makedirs(self.report_dir, exist_ok=True)
        self.endpoints_file = os.path.join(self.report_dir, "endpoints.txt")
        self.targ_file = os.path.join(self.report_dir, "task_distribution.txt")

    async def _run_agent(self, agent_name, prompt):
        print(f"[*] Spawning agent {agent_name}...")
        cmd = ["opencode", "--agent", agent_name, "--prompt", prompt]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            print(f"[1] Agent {agent_name} failed: {stderr.decode()}", file=sys.stderr)
            return None
        return stdout.decode()

    async def execute(self):
        print(f"[+] Starting scan on {self.target} using Grace Field House team.")

        # 1. Gilda (Recon)
        print("[1] Gilda starting reconnaissance...")
        recon_prompt = f"Perform reconnaissance and domain mapping for the target URL ={ self.target }. Save all discovered endpoints to {self.endpoints_file}."
        await self._run_agent("gilda", recon_prompt)

        if not os.path.exists(self.endpoints_file):
            print("[X] No endpoints.txt found. Creating mock endpoints.")
            with open(self.endpoints_file, "w") as f:
                f.write(self.target + "\n")

        # 2. Norman (Threat Model)
        print("[2] Norman starting threat modeling...")
        threat_prompt = f"read {self.endpoints_file}. Map attack vectors and create a test distribution plan for Emma and Don at {self.targ_file}."
        await self._run_agent("norman", threat_prompt)

        # 3. Emma & Don (Offensive Parallel)
        print("[3] Emma and Don launching offensive scans in parallel...")
        emma_prompt = f"Perform web logic and client-side vulnerability testing (IDOR, CSRF, SSRF, XSS) on {self.target} based on {self.endpoints_file}. Log potential findings to emma_findings.json."
        don_prompt = f"Perform system and server-side injection testing (SQLi, RCE, LFI, system ports) on {self.target} based on {self.endpoints_file}. Log potential findings to don_findings.json."

        await asyncio.gather(
            self._run_agent("emma", emma_prompt),
            self._run_agent("don", don_prompt)
        )

        # 4. Ray (Validator)
        print("[4] Ray starting poc validation and chaining...")
        valid_prompt = f"Review findings in emma_findings.json and don_findings.json for {self.target}. Write and run Python 3 PoCs to confirm. Save validated findings to validated_findings.json."
        await self._run_agent("ray", valid_prompt)

        # 5. Phil (Reporting)
        print("[5] Phil starting report compilation...")
        report_prompt = f"Collect all data from validated_findings.json and write final report under {self.report_dir}/report_scan.md. Clean up all json findings files."
        await self._run_agent("phil", report_prompt)

        print("[+] Scan completed!")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python grace_field.py <target_url>")
        sys.exit(1)
    target = sys.argv[1]
    orch = GraceFieldOrchestrator(target)
    asyncio.run(orch.execute())