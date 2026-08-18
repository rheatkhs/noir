---
description: Make a Promise (Pre-flight scope enforcement and policy check).
agent: isabella
subtask: false
---

Validating scan promise boundaries for target $ARGUMENTS.

## Execution Sequence
Calls Isabella to enforce scoping rules:
1. Verify target domain name. Reject immediately if external or outside scope.
2. Confirm permission configuration and verify blocked destructive command rules.
3. Establish safe scanning boundaries (exclude sensitive ports/URLs).
