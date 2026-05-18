#!/usr/bin/env python3
"""
Launch das_scanner_phones.py as a true background daemon.
Does NOT use signal.signal() — removes all signal handlers first.
"""

import os
import sys
import time

# Change to script directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Set checkpoint
checkpoint = "340000"
os.makedirs("assets", exist_ok=True)
with open("assets/phone_scan_checkpoint.txt", "w") as f:
    f.write(checkpoint)
print(f"Checkpoint set to {checkpoint}")

# Fork into background
pid = os.fork()
if pid > 0:
    # Parent
    print(f"Scanner started (PID {pid})")
    sys.exit(0)
else:
    # Child - become session leader, second fork
    os.setsid()
    pid = os.fork()
    if pid > 0:
        os._exit(0)
    
    # Daemon process - redirect stdio
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    
    # Remove signal handling from the scanner module
    import signal as sig_module
    # Set SIGTERM to default (kill) instead of Python handler
    sig_module.signal(sig_module.SIGTERM, sig_module.SIG_DFL)
    sig_module.signal(sig_module.SIGINT, sig_module.SIG_DFL)
    
    # Remove signal handlers from the scanner BEFORE importing
    import importlib.util
    import shutil
    
    # Read scanner source, remove signal handler calls
    with open("src/das_scanner_phones.py") as f:
        source = f.read()
    
    # Remove signal-related code
    source = source.replace("install_signal_handlers()", "pass  # signals disabled for daemon")
    
    # Execute the modified source
    exec(source)
