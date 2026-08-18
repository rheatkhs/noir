---
description: Disable the tracking transmitter (Cleanup, footprint removal, and logs cleaning).
agent: ray
subtask: false
---

Disabling tracking transmitter on target $ARGUMENTS.

## Execution Sequence
Calls Ray (Validator/Exploitation/Chainer) to perform post-exploitation cleanup:
1. Delete any temporary exploit scripts, backdoors, or testing files from target filesystem.
2. If authenticated or RCE was achieved, clear execution logs/commands history.
3. Reset agent state database key/values related to target configuration.
