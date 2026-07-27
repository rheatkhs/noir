# Contributing

Thanks for contributing to Noir. This document covers the skill format, naming conventions, and submission process.

## Skill Naming

All skills follow the pattern: `noir-<category>-<name>`

| Category | Prefix | Example |
|----------|--------|---------|
| Vulnerability | `noir-vuln-` | `noir-vuln-sqli` |
| Reconnaissance | `noir-recon-` | `noir-recon-subdomain` |
| Payload | `noir-payload-` | `noir-payload-xss` |
| Framework | `noir-framework-` | `noir-framework-django` |
| Technology | `noir-tech-` | `noir-tech-docker` |
| Protocol | `noir-proto-` | `noir-proto-smb` |
| CTF | `noir-ctf-` | `noir-ctf-pwn-basics` |
| Post-Exploitation | `noir-post-` | `noir-post-linux-privesc` |
| Forensics | `noir-forensic-` | `noir-forensic-disk` |
| Mobile | `noir-mobile-` | `noir-mobile-android` |
| AD / Red Team | `noir-ad-` / `noir-red-` | `noir-ad-attacks` |
| Blue Team | `noir-blue-` | `noir-blue-detect` |
| IoT | `noir-iot-` | `noir-iot-firmware` |
| Tool | `noir-tool-` | `noir-tool-nmap` |
| Pentest Workflow | `noir-pentest-` | `noir-pentest-recon` |

## Skill Format

Each skill is a folder containing a `SKILL.md` file:

```
.noir-vuln-xss/
  SKILL.md
```

### SKILL.md Frontmatter

Every SKILL.md requires valid YAML frontmatter:

```markdown
---
name: noir-vuln-xss
description: "Cross-Site Scripting testing. Use when testing input fields, URL parameters, or reflection points. Trigger keywords: xss, cross-site, script injection."
---

# Skill Content

Markdown body with instructions, commands, payloads, and examples.
```

`name` must match the folder name exactly. `description` must be a single line describing what the skill does and when to use it. Include trigger keywords so the AI can find the right skill.

## Validation

Before submitting, run:

```bash
python scripts/validate-skills.py
```

This checks every SKILL.md for valid YAML frontmatter, matching name field, and non-empty description.

## Submission

1. Create your skill folder under `.opencode/skills/`
2. Write `SKILL.md` with frontmatter and body
3. Run validation script
4. Submit a pull request

## Style Guidelines

- Use `bash` code blocks for commands
- Use `python` code blocks for PoC scripts
- Use `json`, `xml`, `sql`, `text` for data formats
- Keep descriptions under 200 characters
- Prefix trigger keywords in description
- Group related payloads in tables or lists
- Include detection indicators for each vulnerability type
