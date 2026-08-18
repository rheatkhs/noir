---
description: Decode Minerva clues from Morse code or hidden strings in targets (OSINT and Secrets discovery).
agent: norman
subtask: false
---

Decoding Minerva clues from target $ARGUMENTS.

## Execution Sequence
Calls Norman (Threat Model/Strategic agent) to:
1. Scan Git platform commits for hardcoded secrets.
2. Search files for API tokens, certificates, and backup keys.
3. Extract hidden paths in JavaScript or custom headers.
