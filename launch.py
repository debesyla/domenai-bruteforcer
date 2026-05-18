#!/usr/bin/env python3
"""Launch scanner in background using exec cmd with guaranteed detach."""
import subprocess
import sys
import os
from pathlib import Path

os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Set checkpoint
ckpt = 340000
Path("assets/phone_scan_checkpoint.txt").write_text(str(ckpt))
print(f"Checkpoint: {ckpt}")

# Launch via subprocess fully detached
proc = subprocess.Popen(
    [sys.executable, "-u", "src/das_scanner_phones.py"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
    close_fds=True,
)
print(f"PID: {proc.pid}")

# Save PID
Path("assets/phone_scanner.pid").write_text(str(proc.pid))
