---
description: Goldy Pond Multi-target scan scheduler and batch processing queue.
agent: norman
subtask: false
---

Entering Goldy Pond batch execution for targets $ARGUMENTS.

## Execution Sequence
Calls Norman to parse queue configuration:
1. Schedule daily or hourly scans using `tools/queue.py`.
2. Process target queue in order of priority or risk level.
3. Manage batch reports and alert orchestrator of new findings.
