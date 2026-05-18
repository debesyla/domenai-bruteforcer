#!/usr/bin/env python3
"""
Launch das_scanner_threaded.py in true background mode.
Removes signal handlers that might interfere with background execution.
"""
import os
import sys
import subprocess
from pathlib import Path

# Change to the domenai-bruteforcer directory
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__))))

# Set checkpoint
ckpt = 340000
Path("assets/phone_scan_checkpoint.txt").write_text(str(ckpt))
print(f"Checkpoint: {ckpt}")

# Create a modified version of the scanner without signal handlers
scanner_source = Path("src/das_scanner_threaded.py").read_text()
# Remove signal handler lines
scanner_source = scanner_source.replace(
    "signal.signal(signal.SIGINT, handle_sig)", ""
).replace(
    "signal.signal(signal.SIGTERM, handle_sig)", ""
)
# Also remove import signal since we removed its usage...
# Actually keep it, unused imports are harmless

# Write modified version
Path("src/das_scanner_threaded_nosig.py").write_text(scanner_source)

# Launch with subprocess, fully detached
proc = subprocess.Popen(
    [sys.executable, "-u", "src/das_scanner_threaded_nosig.py"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
    close_fds=True,
)
print(f"PID: {proc.pid}")
Path("assets/phone_scanner.pid").write_text(str(proc.pid))
