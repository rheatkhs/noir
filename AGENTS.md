# Noir: Project Instructions

This file provides persistent context for any AI agent working in the Noir project.

## Project Purpose

Noir is a security penetration testing skill library for opencode. It contains 249 skill playbooks organized into categories: vulnerability classes, reconnaissance, payloads, frameworks, technology-specific testing, protocols, CTF categories, post-exploitation, forensics, mobile, AD/red team, IoT, and tools.

## Architecture

- **Agent**: `.opencode/agents/noir.md` — defines the Noir agent persona, operating principles, and default workflow.
- **Commands**: `.opencode/commands/scan.md` — the `scan` command template that orchestrates a full assessment.
- **Skills**: `.opencode/skills/` — 249 skill folders, each containing a `SKILL.md` with frontmatter (`name`, `description`) and markdown body.
- **Config**: `opencode.jsonc` — registers the agent and skill paths.

## Key Behaviors

1. **Engagement modes** — Auto-detect mode from target URL (e.g., hackerone.com → bug-bounty, hackthebox.com → ctf). Users can override with `scan <url> in <mode>`.
2. **Zero false positives** — Only flag vulnerabilities validated with a working PoC (exit code 0).
3. **Scope enforcement** — Never scan outside the user-provided target domain. Verify all URLs stay within scope.
4. **Destructive command blocking** — Block `rm -rf`, `dd`, `mkfs`, `chmod 777`. Never execute aggressive DDoS or data-destroying payloads.

## Skill Organization

Skills are prefixed by category:
- `noir-vuln-*` — Vulnerability classes
- `noir-recon-*` — Reconnaissance
- `noir-payload-*` — Payload collections
- `noir-framework-*` — Framework-specific testing
- `noir-tech-*` — Technology-specific testing
- `noir-proto-*` — Protocol testing
- `noir-ctf-*` — CTF categories
- `noir-post-*` — Post-exploitation
- `noir-forensic-*` — Forensics
- `noir-mobile-*` — Mobile app testing
- `noir-ad-*`, `noir-red-*`, `noir-blue-*` — AD/Red/Blue team
- `noir-tool-*` — Tool usage guides
- `noir-pentest-*` — Pentest workflows
- `noir-payload-*` — Payload lists
- `noir-iot-*` — IoT testing

## When to Use What

- User asks to "scan" → use `scan` command → full assessment pipeline
- User asks about a specific vulnerability → load the relevant `noir-vuln-*` skill
- User asks about a specific technology → load the relevant `noir-tech-*` or `noir-framework-*` skill
- User asks for paylods → load the relevant `noir-payload-*` skill
- User is doing a CTF → auto-detect ctf mode or load `noir-ctf-*` skills
