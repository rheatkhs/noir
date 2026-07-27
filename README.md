# Noir

> An autonomous security penetration testing agent for opencode.

Noir is an open-source, agentic security scanning framework designed for opencode. It transforms natural language commands into structured vulnerability assessments — reconnaissance, exploitation, validation, and reporting — all guided by LLM-driven reasoning.

## Requirements

- [opencode](https://opencode.ai) or any MCP-compatible agentic CLI
- `nmap`, `curl`, `ffuf`, `python3` — available on `PATH`
- LLM API key (`ROUTER_API_KEY` or `OPENAI_API_KEY`) — or use the built-in free model

## Getting Started

```bash
# Open the project
cd noir
opencode

# Scan a target
scan http://localhost:3000

# Or use natural language:
# "scan localhost:3000 for vulnerabilities"
# "recon http://localhost:8000"
# "test the API at http://localhost:3000/api"
```

## Architecture

Noir operates as a four-phase pipeline, each phase implemented as an opencode skill:

| Phase | Skill | Description |
|-------|-------|-------------|
| Reconnaissance | `noir-recon` | Port scanning with `nmap`, directory fuzzing with `ffuf`, header probing with `curl`, LLM-assisted endpoint discovery |
| Exploitation | `noir-exploit` | OWASP Top 10 payload testing — SQLi, Path Traversal, IDOR, SSRF, Broken Auth |
| Validation | `noir-validate` | Standalone Python PoC script generation and execution to confirm findings |
| Reporting | (built into validate) | Markdown report with summary, findings, PoC code, and evidence — saved to `./noir_reports/` |

## Project Structure

```
noir/
├── .opencode/
│   ├── agents/
│   │   └── noir.md                # Agent definition & system prompt
│   ├── commands/
│   │   └── scan.md                # Scan command template
│   └── skills/
│       ├── noir-recon/SKILL.md    # Reconnaissance instructions
│       ├── noir-exploit/SKILL.md  # Exploitation instructions
│       └── noir-validate/SKILL.md # Validation & reporting instructions
├── opencode.jsonc                  # opencode configuration
├── prd.md                          # Product Requirements Document
└── README.md
```

## Configuration

The agent is configured in `opencode.jsonc`:

- **Default model:** `oc/deepseek-v4-flash-free` (free tier, no API key required)
- **Permissions:** `nmap` and `curl` allowed; file edits denied; reads allowed
- **Skills:** auto-loaded from `.opencode/skills/`

To use a different model, set `OPENAI_API_KEY` or `ROUTER_API_KEY` in your environment and update the `model` field in `opencode.jsonc`.

## Commands

| Command | Description |
|---------|-------------|
| `scan <url>` | Execute full security assessment against the target |

## License

Apache-2.0 / MIT
