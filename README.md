# Noir

> Autonomous security penetration testing agent for opencode.

Noir transforms natural language prompts into structured security assessments — reconnaissance, exploitation, validation, and reporting — guided by LLM-driven reasoning. Designed for developers, security engineers, and red teams.

---

## Features

- **10 engagement modes** — Auto-detected or explicit modes (bug-bounty, ctf, red-team, blue-team, offensive, grey-hat, forensic, reverse-engineering, mobile-pentest, auto) that optimize tool priority, workflow order, and output format.
- **Multi-phase pipeline** — Reconnaissance, fuzzing, exploitation (SQLi, Path Traversal, SSRF, IDOR, Broken Auth, Race Conditions), validation with standalone PoC scripts, and markdown reporting.
- **Skill-based architecture** — Each phase is a self-contained opencode skill. Skills auto-load from `.opencode/skills/`.
- **No lock-in** — Model-agnostic. Uses whatever model opencode is configured with.

---

## Requirements

- [opencode](https://opencode.ai) or any MCP-compatible agentic CLI
- `nmap`, `curl`, `ffuf`, `python3` on `PATH`

---

## Getting Started

```bash
git clone https://github.com/rheatkhs/noir.git
cd noir
opencode
```

Once inside opencode:

```
scan http://localhost:3000
```

Or target specific phases:

```
recon http://localhost:8000
test sql injection on http://localhost:3000/api/login
check for ssrf on http://localhost:3000/fetch
validate http://localhost:3000
```

---

## Engagement Modes

Noir auto-detects the engagement mode from the target URL, or you can specify one explicitly.

| Mode                  | Use Case                            | Workflow Priority       | Output Format       |
| --------------------- | ----------------------------------- | ----------------------- | ------------------- |
| `auto`                | Unknown target                      | Adaptive                | Standard            |
| `bug-bounty`          | HackerOne, Bugcrowd, Intigriti      | Recon → Enum → Exploit  | HackerOne format    |
| `red-team`            | Stealth ops, persistence, AD        | Recon → Exploit → Enum  | Executive summary   |
| `ctf`                 | HackTheBox, TryHackMe, picoCTF      | Exploit → Enum → Recon  | Flag submission     |
| `blue-team`           | Detection, IR, defensive audit      | Enum → Recon → Report   | IR report           |
| `offensive`           | Aggressive exploitation, PoC chains | Exploit → Enum → Recon  | Technical           |
| `grey-hat`            | Balanced assessment                 | Balanced                | Technical           |
| `forensic`            | Evidence preservation, disk/memory  | Forensics → Report      | Chain-of-custody    |
| `reverse-engineering` | Binaries, firmware, malware         | RE → Exploit → Utility  | Technical RE        |
| `mobile-pentest`      | Android/iOS app assessment          | Mobile → Enum → Exploit | OWASP Mobile Top 10 |

Override auto-detection by including the mode in your prompt:

```
scan http://target.com in ctf mode
recon http://target.com in red-team mode
```

---

## Skills

| Skill              | Purpose                                                                  |
| ------------------ | ------------------------------------------------------------------------ |
| `noir-modes`       | Engagement mode definitions and auto-detection rules                     |
| `noir-playbook`    | Master workflow orchestrating all phases                                 |
| `noir-recon`       | Port scanning, directory fuzzing, header probing, LLM endpoint discovery |
| `noir-fuzzing`     | Parameter discovery, HTTP method fuzzing, header injection               |
| `noir-exploit`     | SQLi and Path Traversal payload testing                                  |
| `noir-ssrf`        | Server-Side Request Forgery — cloud metadata, internal services          |
| `noir-idor`        | Insecure Direct Object Reference — horizontal & vertical escalation      |
| `noir-broken-auth` | Weak credentials, JWT attacks, session fixation, rate limiting           |
| `noir-race`        | Race condition and TOCTOU testing                                        |
| `noir-validate`    | Python PoC generation, execution, and markdown reporting                 |

---

## Project Structure

```
.opencode/
├── agents/noir.md              # Agent definition and system prompt
├── commands/scan.md            # Scan command
├── skills/
│   ├── noir-modes/SKILL.md
│   ├── noir-playbook/SKILL.md
│   ├── noir-recon/SKILL.md
│   ├── noir-fuzzing/SKILL.md
│   ├── noir-exploit/SKILL.md
│   ├── noir-ssrf/SKILL.md
│   ├── noir-idor/SKILL.md
│   ├── noir-broken-auth/SKILL.md
│   ├── noir-race/SKILL.md
│   └── noir-validate/SKILL.md
└── tools/REFERENCE.md
opencode.jsonc
prd.md
README.md
```

---

## Commands

| Command      | Description                                                    |
| ------------ | -------------------------------------------------------------- |
| `scan <url>` | Full security assessment using auto-detected or specified mode |

---

## Configuration

Agent is configured in `opencode.jsonc`. Model selection is delegated to opencode's default — no model is pinned. No API key required when using opencode's built-in free model. To use a custom LLM, set `OPENAI_API_KEY` or `ROUTER_API_KEY` in your environment.

---

## License

Apache-2.0 / MIT
