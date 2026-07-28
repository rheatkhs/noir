---
name: noir-vuln-cvss
description: "CVSS 4.0 severity scoring for validated vulnerabilities. Use to assign quantitative severity ratings to findings. Trigger keywords: cvss, severity, score, vector, impact, exploitability."
---

# CVSS 4.0 Scoring

Assign CVSS 4.0 base scores to validated vulnerabilities using the vector string format.

## CVSS 4.0 Vector

Format: `CVSS:4.0/AV:<X>/AC:<X>/AT:<X>/PR:<X>/UI:<X>/VC:<X>/VI:<X>/VA:<X>/SC:<X>/SI:<X>/SA:<X>`

### Attack Vector (AV)
| Value | Meaning |
|-------|---------|
| N | Network |
| A | Adjacent |
| L | Local |
| P | Physical |

### Attack Complexity (AC)
| Value | Meaning |
|-------|---------|
| L | Low |
| H | High |

### Attack Requirements (AT)
| Value | Meaning |
|-------|---------|
| N | None |
| P | Present |

### Privileges Required (PR)
| Value | Meaning |
|-------|---------|
| N | None |
| L | Low |
| H | High |

### User Interaction (UI)
| Value | Meaning |
|-------|---------|
| N | None |
| P | Passive |
| A | Active |

### Impact Metrics (VC, VI, VA — Confidentiality, Integrity, Availability)
| Value | Meaning |
|-------|---------|
| H | High |
| L | Low |
| N | None |

### Scope Impact (SC, SI, SA)
| Value | Meaning |
|-------|---------|
| H | High |
| L | Low |
| N | None |

## Severity Bands

| Score Range | Severity |
|-------------|----------|
| 9.0-10.0 | Critical |
| 7.0-8.9 | High |
| 4.0-6.9 | Medium |
| 0.1-3.9 | Low |
| 0.0 | None |

## Common Vulnerability Vectors

| Vulnerabilit |
|-------------|----------|
| XSS (reflected) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` → 5.1 (Medium) |
| SQLi (authenticated) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` → 8.2 (High) |
| SQLi (unauthenticated) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` → 9.3 (Critical) |
| RCE (remote) | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` → 9.3 (Critical) |
| LFI | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` → 6.9 (Medium) |
| SSRF | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N` → 5.1 (Medium) |
| IDOR | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` → 6.9 (Medium) |
| Auth bypass | `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` → 8.2 (High) |

## Scoring Formula

For quick estimates without the full calculator:

```python
import math

def cvss_score(vector: str) -> float:
    """Basic CVSS 4.0 score estimation from vector string."""
    parts = dict(p.split(":") for p in vector.split("/") if ":" in p)

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV", "N"), 0.85)
    ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC", "L"), 0.77)
    pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(parts.get("PR", "N"), 0.85)
    ui = {"N": 0.85, "P": 0.68, "A": 0.5}.get(parts.get("UI", "N"), 0.85)

    imp = {"H": 0.6, "L": 0.3, "N": 0}

    vc = imp.get(parts.get("VC", "N"), 0)
    vi = imp.get(parts.get("VI", "N"), 0)
    va = imp.get(parts.get("VA", "N"), 0)

    iss = 1 - (1 - vc) * (1 - vi) * (1 - va)
    exploitability = av * ac * pr * ui
    score = min(10, round((iss + exploitability) * 5, 1))
    return score
```

## How to Apply

After validating a finding:
1. Determine the vector values based on the actual exploitation context
2. Construct the vector string
3. Calculate or estimate the score
4. Include the vector and score in the report
5. Save to DB: include `"cvss": <score>` in the `tools/db.py add` JSON
