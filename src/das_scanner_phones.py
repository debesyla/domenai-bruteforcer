#!/usr/bin/env python3
"""
Domain DAS Scanner — Phone number pattern scan (threaded, background-safe)

Generates all 3706XXXXXXX.lt domains (10M total) and checks each against
the .lt Domain Availability Service. Logs non-available results.

Uses threads + blocking sockets (not asyncio) for reliable background operation.

Usage:
    python3 src/das_scanner_phones.py
"""

import argparse
import socket
import threading
import time
import signal
from pathlib import Path

# ======== Settings ========
THREADS = 4
DAS_HOST = "das.domreg.lt"
DAS_PORT = 4343
TIMEOUT = 10

PREFIX = "3706"
DIGITS = 7
DEFAULT_START = 0
DEFAULT_END = 9_999_999
PROGRESS_INTERVAL = 5000
CHECKPOINT_INTERVAL = 2000
SKIP_STATUSES = frozenset({"available"})

# ======== File paths ========
CHECKPOINT_FILE = "assets/phone_scan_checkpoint.txt"
HITS_FILE = "assets/phone_hits.txt"
LOG_FILE = "assets/phone_scan_log.txt"

# ======== Global state (thread-safe) ========
_lock_counter = threading.Lock()
_lock_stats = threading.Lock()
_counter = 0
_completed = 0
_hits = 0
_errors = 0
_shutdown = threading.Event()


def domain_for(n: int) -> str:
    return f"{PREFIX}{n:0{DIGITS}d}.lt"


def query_das(domain: str) -> str | None:
    """One DAS query over a fresh TCP connection. Returns status or None."""
    query = f"get 1.0 {domain}\n".encode()
    try:
        sock = socket.create_connection((DAS_HOST, DAS_PORT), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT // 2)
        sock.sendall(query)
        data = b""
        for _ in range(5):
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"Status:" in data:
                    break
            except socket.timeout:
                break
        sock.close()
        text = data.decode("utf-8", errors="replace").lower()
        for line in text.splitlines():
            if line.strip().startswith("status:"):
                parts = line.split(":", 1)
                if len(parts) > 1:
                    return parts[1].strip()
        return "unknown"
    except (socket.timeout, OSError) as e:
        return None


# ======== Persistence ========

def read_checkpoint(path: str) -> int | None:
    p = Path(path)
    if p.exists():
        raw = p.read_text().strip()
        if raw:
            try:
                return int(raw)
            except ValueError:
                pass
    return None


def write_checkpoint(path: str, value: int):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(str(value))


def log_msg(msg: str):
    """Write to log file only — no stdout (BrokenPipeError safe)."""
    line = msg.rstrip()
    try:
        p = Path(LOG_FILE)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def append_hit(path: str, domain: str, status: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as f:
        f.write(f"{domain} -> {status}\n")


# ======== Main ========

def main():
    global _counter, _completed, _hits, _errors

    p = argparse.ArgumentParser()
    p.add_argument("--start", type=int, default=DEFAULT_START)
    p.add_argument("--end", type=int, default=DEFAULT_END)
    p.add_argument("--checkpoint", default=CHECKPOINT_FILE)
    p.add_argument("--hits", default=HITS_FILE)
    p.add_argument("--no-resume", action="store_true")
    args = p.parse_args()

    total = args.end - args.start + 1
    ckpt_path = args.checkpoint
    hits_path = args.hits

    # Resume logic
    current = read_checkpoint(ckpt_path)
    if current is not None and current >= args.start and not args.no_resume:
        log_msg(f"[MAIN] Resuming from checkpoint: {current} ({domain_for(current)})")
        current += 1
    else:
        current = args.start
        write_checkpoint(ckpt_path, current)
        log_msg(f"[MAIN] Starting fresh from {current} ({domain_for(current)})")

    log_msg(f"[MAIN] Range: {args.start} to {args.end} ({total:,} domains)")
    log_msg(f"[MAIN] Threads: {THREADS}")
    log_msg(f"[MAIN] Start: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    _counter = current
    _completed = 0
    _hits = 0
    _errors = 0
    _shutdown.clear()
    start_time = time.monotonic()

    # Signal handlers
    def handle_sig(signum, frame):
        log_msg(f"\n[SIGNAL] Caught signal {signum}. Shutting down...")
        _shutdown.set()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    def worker(wid: int):
        global _counter, _completed, _hits, _errors
        while not _shutdown.is_set():
            with _lock_counter:
                n = _counter
                _counter += 1

            if n > args.end:
                break

            domain = domain_for(n)
            status = query_das(domain)

            with _lock_stats:
                _completed += 1
                if status is None:
                    _errors += 1
                elif status not in SKIP_STATUSES:
                    append_hit(hits_path, domain, status)
                    _hits += 1
                c = _completed
                e = _errors
                h = _hits

            # Checkpoint & progress
            if c % CHECKPOINT_INTERVAL == 0 and not _shutdown.is_set():
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

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(THREADS)]
    for t in threads:
        t.start()

    for t in threads:
        t.join()

    elapsed = time.monotonic() - start_time
    log_msg(f"\n{'=' * 55}")
    log_msg(f"  [SUMMARY] Scan {'stopped' if _shutdown.is_set() else 'complete'}")
    log_msg(f"  [SUMMARY] Domains scanned: {_completed:,}")
    log_msg(f"  [SUMMARY] Non-available hits: {_hits}")
    log_msg(f"  [SUMMARY] Errors: {_errors}")
    log_msg(f"  [SUMMARY] Elapsed: {elapsed:.0f}s ({elapsed / 3600:.1f}h)")
    rate = _completed / elapsed if elapsed > 0 else 0
    log_msg(f"  [SUMMARY] Avg rate: {rate:.1f} req/s")
    log_msg(f"{'=' * 55}")

    write_checkpoint(ckpt_path, _counter)


if __name__ == "__main__":
    main()
