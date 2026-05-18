#!/usr/bin/env python3
"""
Daemonizer for das_scanner_phones.py — runs the scanner as a persistent
background process with all stdio detached.

Usage:
    python3 daemonize.py
    python3 daemonize.py --checkpoint 123456
"""

import os
import sys
import time
import signal
import argparse

SCANNER = "src/das_scanner_phones.py"
PID_FILE = "assets/phone_scanner.pid"
DEFAULT_CHECKPOINT = None  # auto from existing

def daemonize():
    """Double-fork daemonization."""
    # First fork
    pid = os.fork()
    if pid > 0:
        # Parent exits
        return pid
    # Child (first)
    os.setsid()
    os.umask(0)
    
    # Second fork
    pid = os.fork()
    if pid > 0:
        # First child exits
        os._exit(0)
    # Second child = daemon
    
    # Redirect stdio to /dev/null
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    os.close(devnull)
    
    return 0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=int, default=None)
    parser.add_argument("--stop", action="store_true")
    args = parser.parse_args()
    
    os.chdir(os.path.dirname(os.path.abspath(__file__)) or ".")
    
    if args.stop:
        if os.path.exists(PID_FILE):
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                print(f"Sent SIGTERM to PID {pid}")
                # Wait for it to die
                for _ in range(10):
                    try:
                        os.kill(pid, 0)
                        time.sleep(1)
                    except OSError:
                        break
                os.remove(PID_FILE)
                print("Stopped")
            except ProcessLookupError:
                print(f"PID {pid} not found, removing stale PID file")
                os.remove(PID_FILE)
        else:
            print("No PID file found")
        return
    
    # Check if already running
    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            old_pid = int(f.read().strip())
        try:
            os.kill(old_pid, 0)
            print(f"Scanner already running (PID {old_pid})")
            return
        except OSError:
            print(f"Stale PID file ({old_pid}), overwriting")
    
    # Set checkpoint if specified
    if args.checkpoint is not None:
        os.makedirs("assets", exist_ok=True)
        with open("assets/phone_scan_checkpoint.txt", "w") as f:
            f.write(str(args.checkpoint))
        print(f"Checkpoint set to {args.checkpoint}")
    
    # Daemonize
    pid = daemonize()
    if pid > 0:
        # Parent: save PID and report
        with open(PID_FILE, "w") as f:
            f.write(str(pid))
        # Wait a moment and check if process is alive
        time.sleep(3)
        try:
            os.kill(pid, 0)
            print(f"Scanner started (PID {pid})")
        except OSError:
            print(f"Scanner failed to start (PID {pid} died)")
        return
    
    # Child (daemon): run the scanner
    sys.stdout = open(os.devnull, "w")
    sys.stderr = open(os.devnull, "w")
    sys.stdin = open(os.devnull)
    
    # Remove signal handler interference - use asyncio internal signals instead
    import asyncio
    
    # Run the scanner
    exec(open(SCANNER).read())

if __name__ == "__main__":
    main()
