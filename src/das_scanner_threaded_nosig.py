#!/usr/bin/env python3
"""
Domain DAS Scanner — Phone number pattern scan (threaded version)

Same logic as asyncio version but uses threading + blocking sockets.
Works reliably in background processes.

Rate: ~25 req/s (DAS server max), 4 threads.

Usage:
    python3 src/das_scanner_threaded.py
"""

import argparse
import socket
import threading
import time
import os
import signal
from pathlib import Path

# Settings
THREADS = 4
DAS_HOST = "das.domreg.lt"
DAS_PORT = 4343
TIMEOUT = 10

PREFIX = "3706"
DIGITS = 7
DEFAULT_START = 0
DEFAULT_END = 9_999_999

CHECKPOINT_FILE = "assets/phone_scan_checkpoint.txt"
HITS_FILE = "assets/phone_hits.txt"
LOG_FILE = "assets/phone_scan_log.txt"
PROGRESS_INTERVAL = 5000
CHECKPOINT_INTERVAL = 2000
SKIP_STATUSES = frozenset({"available"})


def domain_for(n):
    return f"{PREFIX}{n:0{DIGITS}d}.lt"


def query_das_sync(domain):
    """Blocking DAS query over TCP. Returns status string or None."""
    query = f"get 1.0 {domain}\n".encode()
    try:
        sock = socket.create_connection((DAS_HOST, DAS_PORT), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT / 2)
        sock.sendall(query)
        # Read response lines
        lines = []
        for _ in range(5):
            try:
                data = sock.recv(4096)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                lines.extend(text.splitlines())
                if "Status:" in text:
                    break
            except socket.timeout:
                break
        sock.close()
        response = "\n".join(lines).lower()
        for line in response.splitlines():
            if line.strip().startswith("status:"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    return parts[1].strip()
        return "unknown"
    except (socket.timeout, OSError):
        return None


def read_checkpoint(path):
    p = Path(path)
    if p.exists():
        raw = p.read_text().strip()
        if raw:
            try:
                return int(raw)
            except ValueError:
                pass
    return None


def write_checkpoint(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(str(value))


def log_msg(msg):
    """Write to log file only (not stdout — avoids pipe issues in background)."""
    line = msg.rstrip()
    try:
        p = Path(LOG_FILE)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def append_hit(path, domain, status):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(f"{domain} -> {status}\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", type=int, default=DEFAULT_START)
    parser.add_argument("--end", type=int, default=DEFAULT_END)
    parser.add_argument("--checkpoint", default=CHECKPOINT_FILE)
    parser.add_argument("--hits", default=HITS_FILE)
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()

    start_num = args.start
    end_num = args.end
    total = end_num - start_num + 1
    ckpt_path = args.checkpoint
    hits_path = args.hits

    # Resume logic
    current = read_checkpoint(ckpt_path)
    if current is not None and current >= start_num and not args.no_resume:
        log_msg(f"[MAIN] Resuming from checkpoint: {current} ({domain_for(current)})")
        current += 1
    else:
        current = start_num
        write_checkpoint(ckpt_path, current)
        log_msg(f"[MAIN] Starting fresh from {current} ({domain_for(current)})")

    log_msg(f"[MAIN] Range: {start_num} to {end_num} ({total:,} domains)")
    log_msg(f"[MAIN] Threads: {THREADS}")
    log_msg(f"[MAIN] Start: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    counter = current
    counter_lock = threading.Lock()
    completed = 0
    hits = 0
    errors = 0
    stats_lock = threading.Lock()
    shutdown_flag = threading.Event()
    start_time = time.monotonic()

    # Handle signals gracefully
    def handle_sig(signum, frame):
        log_msg(f"\n[SIGNAL] Caught signal {signum}. Shutting down...")
        shutdown_flag.set()

    
    

    def worker(wid):
        nonlocal counter, completed, hits, errors
        while not shutdown_flag.is_set():
            with counter_lock:
                n = counter
                counter += 1

            if n > end_num:
                break

            domain = domain_for(n)
            status = query_das_sync(domain)

            with stats_lock:
                completed += 1
                if status is None:
                    errors += 1
                elif status not in SKIP_STATUSES:
                    append_hit(hits_path, domain, status)
                    hits += 1
                c = completed
                e = errors
                h = hits

            # Periodic checkpoint & progress
            if c % CHECKPOINT_INTERVAL == 0 and not shutdown_flag.is_set():
                write_checkpoint(ckpt_path, n)

            if c % PROGRESS_INTERVAL == 0 or c == 1:
                elapsed = time.monotonic() - start_time
                pct = (c / total * 100) if total > 0 else 0
                rate = c / elapsed if elapsed > 0 else 0
                eta_h = (total - c) / rate / 3600 if rate > 0 else 0
                log_msg(
                    f"[PROGRESS] {c:,}/{total:,} ({pct:.2f}%) "
                    f"| hits: {h} | errors: {e} "
                    f"| {rate:.1f} req/s | ETA: {eta_h:.1f}h"
                )

    # Start worker threads
    threads = []
    for i in range(THREADS):
        t = threading.Thread(target=worker, args=(i,), daemon=True)
        t.start()
        threads.append(t)

    # Wait for threads to complete
    for t in threads:
        t.join()

    elapsed = time.monotonic() - start_time
    log_msg(f"\n{'='*55}")
    log_msg(f"  [SUMMARY] Scan {'stopped' if shutdown_flag.is_set() else 'complete'}")
    log_msg(f"  [SUMMARY] Domains scanned: {completed:,}")
    log_msg(f"  [SUMMARY] Hits: {hits}")
    log_msg(f"  [SUMMARY] Errors: {errors}")
    log_msg(f"  [SUMMARY] Elapsed: {elapsed:.0f}s ({elapsed/3600:.1f}h)")
    rate = completed / elapsed if elapsed > 0 else 0
    log_msg(f"  [SUMMARY] Avg rate: {rate:.1f} req/s")
    log_msg(f"{'='*55}")

    write_checkpoint(ckpt_path, counter)


if __name__ == "__main__":
    main()
