# WALKER_HEAP_OVERFLOW_RECIPE.md - F4 Analysis

## 1. Location
- Module: `ADSMSecurity.dll`
- Function: `sub_0x7410` - recursive delete-tree walker
- Offset: `sub_0x7410+0x74a4`
- Vulnerable call: `wsprintfW( malloc(0x208), "%s\\*.*", path )`

## 2. Root Cause
- Fixed heap buffer 0x208 bytes = 520 bytes = 260 WCHARs
- `wsprintfW` with `%s\*.*` appends 4 chars + null
- No length check on `path`
- Any path >=256 chars overflows

## 3. Overflow Size
- Input 100 chars: 105 wchars -> 210 bytes <520 safe
- Input 256 chars: 261 wchars -> 522 bytes >520 overflow 2 bytes
- Input 300 chars: 305 wchars -> 610 bytes overflow 90 bytes
- Input 1000 chars: 1005 wchars -> 2010 bytes overflow 1490 bytes (up to ~1530)

## 4. Heap Corruption Detection
- Adjacent heap metadata overwritten
- Windows heap manager detects on `HeapFree` / `HeapValidate` / `RtlFreeHeap`
- Exit codes:
  - `0xC0000374 STATUS_HEAP_CORRUPTION`
  - `0xC0000005 STATUS_ACCESS_VIOLATION`
  - `0xC0000409 STATUS_STACK_BUFFER_OVERRUN` (fail-fast)
  - `0xC0000417 synthetic HeapValidate FALSE`

## 5. Reachability Gating
- NOT claimed as remotely reachable without auth
- Requires ability to trigger walker with controlled path
- Audit context: local Administrator on ADManager Plus host
- Demonstrates DoS of the process, not RCE
- Real-world exploitability depends on callers of sub_0x7410 - out of scope for this PoC

## 6. Reproduction Steps (Authorized)
1. On ADManager Plus host, as Admin, open PowerShell
2. `python f4_crash_poc.py --control` -> should be 0 crashes
3. `python f4_crash_poc.py --len 100` -> 0 crashes
4. `python f4_crash_poc.py --len 1000` -> crash 0xC0000374
5. `python f4_crash_poc.py --len 300 --attempts 5` -> most/all crash
6. `python f4_crash_poc.py --sustain --len 1000 --duration 30` -> sustained DoS demo

## 7. Mitigation
- Replace `wsprintfW` with `StringCchPrintfW` / `swprintf_s` with buffer size
- Or check `wcslen(path) < 256` before formatting
- Use `MAX_PATH` aware APIs, dynamic allocation `len(path)+10`
- Enable `/GS`, heap guard pages in build

## 8. Simulation Mode (This Repo)
- On non-Windows, PoC simulates overflow logic without real heap damage
- Same thresholds, same exit code semantics (truncated)
- Allows CI testing

