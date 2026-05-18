#!/usr/bin/env python3
"""Test: does threaded DAS scan work in background with large range?"""
import socket, threading, time, os, signal
from pathlib import Path

os.chdir("/home/kaukas/.openclaw/workspace/domenai-bruteforcer")
log_file = "/tmp/phone_debug.txt"
checkpoint_file = "assets/phone_scan_checkpoint.txt"

Path(checkpoint_file).write_text("340000")
Path(log_file).write_text("")

def log(msg):
    with open(log_file, "a") as f:
        f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")

def query(n):
    domain = f"3706{n:07d}.lt"
    query = f"get 1.0 {domain}\n".encode()
    try:
        sock = socket.create_connection(("das.domreg.lt", 4343), timeout=10)
        sock.settimeout(5)
        sock.sendall(query)
        for _ in range(5):
            try:
                d = sock.recv(4096)
                if not d or b"Status:" in d:
                    break
            except:
                break
        sock.close()
        return True
    except Exception as e:
        log(f"ERROR: {e}")
        return False

counter = 340000
counter_lock = threading.Lock()
completed = 0
stats_lock = threading.Lock()
end = 9999999
shutdown = threading.Event()

def handle_sig(sig, frame):
    log(f"Signal {sig}, shutting down")
    shutdown.set()

signal.signal(signal.SIGINT, handle_sig)
signal.signal(signal.SIGTERM, handle_sig)

def worker(wid):
    global counter, completed
    log(f"Worker {wid} started")
    local_count = 0
    while not shutdown.is_set():
        with counter_lock:
            n = counter
            counter += 1
        if n > end:
            break
        ok = query(n)
        with stats_lock:
            completed += 1
            c = completed
        local_count += 1
        if local_count % 10 == 0:
            log(f"W{wid}: {local_count} done, n={n}")
    log(f"Worker {wid} done, did {local_count}")

log("Starting workers")
workers = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(4)]
start_time = time.time()
for w in workers: w.start()

# Run for 2 minutes
time.sleep(120)
shutdown.set()
for w in workers: w.join(timeout=2)

elapsed = time.time() - start_time
log(f"Done: {completed} completed in {elapsed:.0f}s ({completed/elapsed:.1f} req/s)")
