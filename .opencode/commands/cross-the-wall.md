---
description: Cross the wall to access internal network segments (Network Pivoting and Tunneling).
agent: ray
subtask: false
---

Crossing the wall for target $ARGUMENTS.

## Execution Sequence
Calls Ray to configure pivots and tunnels:
1. Setup SSH tunneling or SOCKS proxy configurations.
2. Probe internal services via pivot paths.
3. Test double pivoting strategies to bridge separate host systems.
