# Noir

> An autonomous security penetration testing agent for opencode.

Noir transforms natural language commands into structured vulnerability assessments — reconnaissance, exploitation, validation, and reporting — all guided by LLM-driven reasoning.

## Requirements

- [opencode](https://opencode.ai) or any MCP-compatible CLI
- `nmap`, `curl`, `ffuf`, `python3` on `PATH`
- LLM API key (`ROUTER_API_KEY` or `OPENAI_API_KEY`) — or use the built-in free model

## Getting Started

```bash
cd noir
opencode

# Full scan
scan http://localhost:3000

# Specific phases
"recon http://localhost:8000"
"test sql injection on http://localhost:3000/api/login"
"check for ssrf on http://localhost:3000/fetch"
"validate findings on http://localhost:3000"
```

## Skills

| Skill | Purpose |
|-------|---------|
| `noir-recon` | Port scan (`nmap`), directory fuzzing (`ffuf`), header probing, LLM endpoint discovery |
| `noir-fuzzing` | Parameter fuzzing, HTTP method discovery, header injection, recursive directory brute force |
| `noir-exploit` | SQLi, Path Traversal payload testing |
| `noir-ssrf` | Server-Side Request Forgery — cloud metadata, internal services, protocol smuggling |
| `noir-idor` | Insecure Direct Object Reference — horizontal & vertical privilege escalation |
| `noir-broken-auth` | Weak credentials, JWT attacks, session fixation, rate limiting, password reset abuse |
| `noir-race` | Race condition & TOCTOU testing with concurrent request techniques |
| `noir-validate` | Python PoC script generation & execution to confirm findings |
| `noir-playbook` | Master playbook orchestrating the full 5-phase assessment workflow |

## Playbook: Full Assessment

The `noir-playbook` skill orchestrates the complete workflow:

```
Phase 1: Reconnaissance   → noir-recon
Phase 2: Discovery        → noir-fuzzing
Phase 3: Exploitation     → noir-exploit, noir-ssrf, noir-idor, noir-broken-auth, noir-race
Phase 4: Validation       → noir-validate
Phase 5: Reporting        → noir-validate (built-in)
```

## Project Structure

```
.opencode/
├── agents/noir.md              # Agent definition
├── commands/scan.md            # Scan command
├── skills/
│   ├── noir-recon/SKILL.md
│   ├── noir-fuzzing/SKILL.md
│   ├── noir-exploit/SKILL.md
│   ├── noir-ssrf/SKILL.md
│   ├── noir-idor/SKILL.md
│   ├── noir-broken-auth/SKILL.md
│   ├── noir-race/SKILL.md
│   ├── noir-validate/SKILL.md
│   └── noir-playbook/SKILL.md
└── tools/REFERENCE.md          # Tool installation reference
opencode.jsonc
prd.md
README.md
```

## Configuration

Agent settings in `opencode.jsonc`:

- **Model:** `oc/deepseek-v4-flash-free` (free, no API key needed)
- **Permissions:** `nmap`/`curl` allowed; edits denied; reads allowed
- **Skills:** auto-loaded from `.opencode/skills/`

To use your own LLM, set `OPENAI_API_KEY` or `ROUTER_API_KEY` in env.

## Commands

| Command | Description |
|---------|-------------|
| `scan <url>` | Full security assessment |

## License

Apache-2.0 / MIT
