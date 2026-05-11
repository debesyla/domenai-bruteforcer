#!/usr/bin/env python3
"""
Domain DAS Scanner — Phone number pattern scan (special-phones branch)

Generates all 3706XXXXXXX.lt domains (10M total) and checks each against
the .lt Domain Availability Service. Almost all return 'available'; only
non-available results (registered, blocked, reserved, etc.) are logged.

Key differences from das_scanner.py:
  - No SQLite database (no input.txt, no progress DB)
  - No batched writes — hits written to file immediately
  - No picker thread — domains generated incrementally from a counter
  - Checkpoint file for resume capability
  - Rate limited to 20 req/sec

Usage:
    python3 src/das_scanner_phones.py
    # Or with custom range:
    python3 src/das_scanner_phones.py --start 500000 --end 9999999
"""

import argparse
import asyncio
import os
import signal
import time
from pathlib import Path

# ------------------------
# Settings (tunable)
# ------------------------
RATE = 20                     # requests/sec
CONCURRENCY = 40              # async workers
DAS_HOST = "das.domreg.lt"
DAS_PORT = 4343
DAS_QUERY_TEMPLATE = "get 1.0 {domain}\n"
CHECK_TIMEOUT = 6             # seconds per TCP query
MAX_RETRIES = 1
RETRY_BACKOFF = 2             # seconds

PREFIX = "3706"               # phone number prefix
DIGITS = 7                    # digits after prefix → 37060000000 .. 37069999999

# Default scan range (7 digits = 0 to 9,999,999)
DEFAULT_START = 0
DEFAULT_END = 10_000_000 - 1  # inclusive

CHECKPOINT_FILE = "assets/phone_scan_checkpoint.txt"
HITS_FILE = "assets/phone_hits.txt"

PROGRESS_INTERVAL = 5000     # log every N queries
CHECKPOINT_INTERVAL = 2000   # save position every N queries

STATUSES_OF_INTEREST = frozenset({
    "available",        # skip these
    "unknown",          # skip unparseable responses too
})


# ------------------------
# Helpers
# ------------------------

def domain_for(n: int) -> str:
    """Generate 3706XXXXXXX.lt from integer."""
    return f"{PREFIX}{n:0{DIGITS}d}.lt"


# ------------------------
# Async worker
# ------------------------

class TokenBucket:
    """Simple asyncio token bucket for rate limiting."""

    def __init__(self, rate: float):
        self.rate = rate
        self.capacity = int(max(1, rate))
        self._tokens = float(self.capacity)
        self._lock = asyncio.Lock()
        self._last = time.monotonic()
        self._refill_task = None

    async def start(self):
        self._refill_task = asyncio.create_task(self._refill_loop())

    async def stop(self):
        if self._refill_task:
            self._refill_task.cancel()
            try:
                await self._refill_task
            except asyncio.CancelledError:
                pass

    async def _refill_loop(self):
        while True:
            await asyncio.sleep(1.0 / self.rate)
            async with self._lock:
                self._tokens = min(self.capacity, self._tokens + 1)

    async def acquire(self):
        while True:
            async with self._lock:
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
            await asyncio.sleep(0.01)


async def query_das(domain: str, bucket: TokenBucket) -> str | None:
    """
    Send a single DAS query for `domain`.
    Returns the status string (e.g., 'available', 'registered') or None on error.
    """
    await bucket.acquire()
    query = DAS_QUERY_TEMPLATE.format(domain=domain).encode()

    for attempt in range(MAX_RETRIES + 1):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(DAS_HOST, DAS_PORT),
                timeout=CHECK_TIMEOUT,
            )
            writer.write(query)
            await writer.drain()
            # DAS returns multiple lines; read all until newline+newline or timeout
            lines = []
            for _ in range(5):
                try:
                    line = await asyncio.wait_for(
                        reader.readline(), timeout=CHECK_TIMEOUT / 2
                    )
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
                    lines.append(decoded)
                except asyncio.TimeoutError:
                    break
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass

            # Parse response: looks for "Status: <value>" line
            status = _parse_das_status("\n".join(lines))
            return status

        except (OSError, asyncio.TimeoutError) as exc:
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF)
                continue
            return None

    return None


# ------------------------
# DAS response parser
# ------------------------

CANONICAL_STATUSES = {
    "available",
    "registered",
    "blocked",
    "reserved",
    "restricteddisposal",
    "restrictedrights",
    "stopped",
    "pendingcreate",
    "pendingdelete",
    "pendingrelease",
    "outofservice",
}


def _parse_das_status(response_text: str) -> str:
    """
    Parse the DAS response for a 'Status:' line.
    Returns canonical lowercase status or 'unknown'.
    """
    if not response_text:
        return "unknown"
    for line in response_text.splitlines():
        line_stripped = line.strip()
        if line_stripped.lower().startswith("status:"):
            parts = line_stripped.split(":", 1)
            if len(parts) > 1:
                s = parts[1].strip().lower()
                s_norm = s.replace(" ", "").replace("-", "")
                if s_norm in CANONICAL_STATUSES:
                    return s_norm
                if s in CANONICAL_STATUSES:
                    return s
                return s if s else "unknown"
    return "unknown"


# ------------------------
# Checkpoint persistence
# ------------------------

def read_checkpoint(path: str) -> int:
    """Read last scanned number from checkpoint file. Returns None if missing."""
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
    """Save current position to checkpoint file."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(str(value))


def append_hit(path: str, domain: str, status: str):
    """Immediately write a hit (non-available domain) to the hits file."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{domain} -> {status}\n")


# ------------------------
# Shutdown
# ------------------------

_shutdown_flag = False


def _handle_signal(signum, frame):
    global _shutdown_flag
    print(f"\n[SIGNAL] Caught signal {signum}. Shutting down gracefully...")
    _shutdown_flag = True


def install_signal_handlers():
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)


# ------------------------
# Main
# ------------------------

async def main_async(args: argparse.Namespace):
    global _shutdown_flag

    start_num = args.start
    end_num = args.end  # inclusive
    total = end_num - start_num + 1
    checkpoint_path = args.checkpoint
    hits_path = args.hits

    # Resume from checkpoint if available
    current = read_checkpoint(checkpoint_path)
    if current is not None and current >= start_num and not args.no_resume:
        print(f"[MAIN] Resuming from checkpoint: {current} (domain {domain_for(current)})")
        # Advance past the last checkpoint
        current += 1
    else:
        current = start_num
        write_checkpoint(checkpoint_path, current)
        print(f"[MAIN] Starting fresh from {current} ({domain_for(current)})")

    print(f"[MAIN] Range: {start_num} to {end_num} ({total:,} domains)")
    print(f"[MAIN] Rate: {RATE}/sec | Workers: {CONCURRENCY}")
    print(f"[MAIN] Hits file: {hits_path}")
    print(f"[MAIN] Checkpoint file: {checkpoint_path}")

    install_signal_handlers()

    bucket = TokenBucket(RATE)
    await bucket.start()

    # Shared state
    counter_lock = asyncio.Lock()
    counter = current
    completed = 0
    hits = 0
    errors = 0
    start_time = time.monotonic()

    async def worker(worker_id: int):
        nonlocal counter, completed, hits, errors
        while not _shutdown_flag:
            async with counter_lock:
                n = counter
                counter += 1

            if n > end_num:
                break

            domain = domain_for(n)
            status = await query_das(domain, bucket)

            async with counter_lock:
                completed += 1

            if status is None:
                async with counter_lock:
                    errors += 1
                continue

            if status not in STATUSES_OF_INTEREST:
                append_hit(hits_path, domain, status)
                async with counter_lock:
                    hits += 1
                print(f"[HIT] {domain} -> {status}")

            # Periodic checkpoint + progress
            if completed % CHECKPOINT_INTERVAL == 0 and not _shutdown_flag:
                write_checkpoint(checkpoint_path, n)

            if completed % PROGRESS_INTERVAL == 0 or completed == 1:
                elapsed = time.monotonic() - start_time
                pct = (completed / total * 100) if total > 0 else 0
                rate_actual = completed / elapsed if elapsed > 0 else 0
                eta_sec = (total - completed) / rate_actual if rate_actual > 0 else 0
                print(
                    f"[PROGRESS] Worker#{worker_id} "
                    f"→ {completed:,}/{total:,} ({pct:.2f}%) "
                    f"| hits: {hits} | errors: {errors} "
                    f"| {rate_actual:.1f} req/s "
                    f"| ETA: {eta_sec/3600:.1f}h"
                )

        # Final checkpoint for this worker
        if not _shutdown_flag:
            write_checkpoint(checkpoint_path, n)

    # Start workers
    workers = [asyncio.create_task(worker(i)) for i in range(CONCURRENCY)]

    try:
        await asyncio.gather(*workers)
    except asyncio.CancelledError:
        pass
    finally:
        await bucket.stop()

    elapsed = time.monotonic() - start_time
    print(f"\n{'='*55}")
    print(f"  [SUMMARY] Scan {'stopped' if _shutdown_flag else 'complete'}")
    print(f"  [SUMMARY] Domains scanned: {completed:,}")
    print(f"  [SUMMARY] Non-available hits: {hits}")
    print(f"  [SUMMARY] Errors: {errors}")
    print(f"  [SUMMARY] Elapsed: {elapsed/3600:.1f}h ({elapsed:.0f}s)")
    print(f"  [SUMMARY] Avg rate: {completed/elapsed:.1f} req/s" if elapsed > 0 else "  [SUMMARY] Avg rate: N/A")
    print(f"  [SUMMARY] Hits saved to: {hits_path}")
    print(f"  [SUMMARY] Checkpoint at: {checkpoint_path}")
    print(f"{'='*55}")

    # Final checkpoint
    async with counter_lock:
        final_n = counter
    write_checkpoint(checkpoint_path, final_n)


def parse_args():
    p = argparse.ArgumentParser(description="DAS Scanner — Phone pattern (special-phones)")
    p.add_argument("--start", type=int, default=DEFAULT_START,
                    help=f"Starting number (default: {DEFAULT_START})")
    p.add_argument("--end", type=int, default=DEFAULT_END,
                    help=f"Ending number, inclusive (default: {DEFAULT_END})")
    p.add_argument("--checkpoint", default=CHECKPOINT_FILE,
                    help=f"Checkpoint file (default: {CHECKPOINT_FILE})")
    p.add_argument("--hits", default=HITS_FILE,
                    help=f"Hits output file (default: {HITS_FILE})")
    p.add_argument("--no-resume", action="store_true",
                    help="Ignore checkpoint file and start fresh")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main_async(args))
