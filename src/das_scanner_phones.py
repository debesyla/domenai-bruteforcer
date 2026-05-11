#!/usr/bin/env python3
"""
Domain DAS Scanner — Phone number pattern scan (special-phones branch)

Generates all 3706XXXXXXX.lt domains (10M total) and checks each against
the .lt Domain Availability Service. Almost all return 'available'; only
non-available results (registered, blocked, reserved, etc.) are logged.

Architecture: Uses 4 concurrent async workers with no artificial rate
limiting. The DAS server's natural response time (~130ms per query)
gives ~7-8 req/s throughput with <1% error rate at this concurrency.

Usage:
    python3 src/das_scanner_phones.py
"""

import argparse
import asyncio
import signal
import time
from pathlib import Path

# ------------------------
# Settings (tunable)
# ------------------------
CONCURRENCY = 4               # parallel workers (sweet spot for DAS server)
DAS_HOST = "das.domreg.lt"
DAS_PORT = 4343
DAS_QUERY_TEMPLATE = "get 1.0 {domain}\n"
CHECK_TIMEOUT = 6             # seconds per TCP query

PREFIX = "3706"               # phone number prefix
DIGITS = 7                    # digits after prefix → 37060000000 .. 37069999999

DEFAULT_START = 0
DEFAULT_END = 10_000_000 - 1  # inclusive (9999999)

CHECKPOINT_FILE = "assets/phone_scan_checkpoint.txt"
HITS_FILE = "assets/phone_hits.txt"

PROGRESS_INTERVAL = 5000      # log every N queries
CHECKPOINT_INTERVAL = 2000    # save position every N queries

# Only "available" is skipped; everything else (registered, blocked, etc.)
# or unrecognised responses are logged as hits.
SKIP_STATUSES = frozenset({"available"})


# ------------------------
# Helpers
# ------------------------

def domain_for(n: int) -> str:
    return f"{PREFIX}{n:0{DIGITS}d}.lt"


# ------------------------
# DAS query
# ------------------------

async def query_das(domain: str) -> str | None:
    """
    Query DAS and return status string or None on error.
    DAS response format (3 lines):
        % .lt registry DAS service
        Domain: example.lt
        Status: available
    """
    query = DAS_QUERY_TEMPLATE.format(domain=domain).encode()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(DAS_HOST, DAS_PORT),
            timeout=CHECK_TIMEOUT,
        )
        writer.write(query)
        await writer.drain()

        lines = []
        for _ in range(5):
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=CHECK_TIMEOUT / 2)
                if not line:
                    break
                lines.append(line.decode("utf-8", errors="replace").rstrip("\r\n"))
            except asyncio.TimeoutError:
                break

        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass

        return _parse_status("\n".join(lines))

    except (OSError, asyncio.TimeoutError):
        return None


def _parse_status(response: str) -> str:
    """Extract the Status: line value."""
    if not response:
        return "unknown"
    for line in response.splitlines():
        stripped = line.strip().lower()
        if stripped.startswith("status:"):
            parts = line.split(":", 1)
            if len(parts) > 1:
                return parts[1].strip().lower()
    return "unknown"


# ------------------------
# Persistence
# ------------------------

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


def append_hit(path: str, domain: str, status: str):
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
    end_num = args.end
    total = end_num - start_num + 1
    ckpt_path = args.checkpoint
    hits_path = args.hits

    # Resume logic
    current = read_checkpoint(ckpt_path)
    if current is not None and current >= start_num and not args.no_resume:
        print(f"[MAIN] Resuming from checkpoint: {current} ({domain_for(current)})")
        current += 1
    else:
        current = start_num
        write_checkpoint(ckpt_path, current)
        print(f"[MAIN] Starting fresh from {current} ({domain_for(current)})")

    expected_days = total / (CONCURRENCY * CHECK_TIMEOUT) / 3600 * 24
    print(f"[MAIN] Range: {start_num} to {end_num} ({total:,} domains)")
    print(f"[MAIN] Workers: {CONCURRENCY} | Target: ~7-8 req/s")
    print(f"[MAIN] Expected duration: roughly {total / 7 / 3600:.0f}h ({total / 7 / 3600 / 24:.1f}d)")
    print(f"[MAIN] Hits file: {hits_path}")
    print(f"[MAIN] Checkpoint file: {ckpt_path}")
    print(f"[MAIN] Start: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    install_signal_handlers()

    lock = asyncio.Lock()
    counter = current
    completed = 0
    hits = 0
    errors = 0
    start_time = time.monotonic()
    last_stats_time = start_time

    async def worker(worker_id: int):
        nonlocal counter, completed, hits, errors
        while not _shutdown_flag:
            async with lock:
                n = counter
                counter += 1

            if n > end_num:
                break

            domain = domain_for(n)
            status = await query_das(domain)

            async with lock:
                completed += 1

            if status is None:
                async with lock:
                    errors += 1
                continue

            if status not in SKIP_STATUSES:
                append_hit(hits_path, domain, status)
                async with lock:
                    hits += 1
                print(f"[HIT] {domain} -> {status}", flush=True)

            async with lock:
                c = completed
                e = errors
                h = hits

            # Periodic checkpoint & progress
            if c % CHECKPOINT_INTERVAL == 0 and not _shutdown_flag:
                write_checkpoint(ckpt_path, n)

            if c % PROGRESS_INTERVAL == 0 or c == 1:
                elapsed = time.monotonic() - start_time
                pct = (c / total * 100) if total > 0 else 0
                rate = c / elapsed if elapsed > 0 else 0
                eta_h = (total - c) / rate / 3600 if rate > 0 else 0
                print(
                    f"[PROGRESS] {c:,}/{total:,} ({pct:.2f}%) "
                    f"| hits: {h} | errors: {e} "
                    f"| {rate:.1f} req/s | ETA: {eta_h:.1f}h",
                    flush=True,
                )

        # Final checkpoint
        if not _shutdown_flag:
            async with lock:
                fn = counter
            write_checkpoint(ckpt_path, fn)

    workers = [asyncio.create_task(worker(i)) for i in range(CONCURRENCY)]

    try:
        await asyncio.gather(*workers)
    except asyncio.CancelledError:
        pass

    elapsed = time.monotonic() - start_time
    print(f"\n{'='*55}")
    print(f"  [SUMMARY] Scan {'stopped' if _shutdown_flag else 'complete'}")
    print(f"  [SUMMARY] Domains scanned: {completed:,}")
    print(f"  [SUMMARY] Non-available hits: {hits}")
    print(f"  [SUMMARY] Errors: {errors}")
    print(f"  [SUMMARY] Elapsed: {elapsed/3600:.1f}h ({elapsed:.0f}s)")
    rate = completed / elapsed if elapsed > 0 else 0
    print(f"  [SUMMARY] Avg rate: {rate:.1f} req/s")
    print(f"  [SUMMARY] Hits saved to: {hits_path}")
    print(f"  [SUMMARY] Checkpoint at: {ckpt_path}")
    print(f"  [SUMMARY] End: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*55}")

    async with lock:
        final_n = counter
    write_checkpoint(ckpt_path, final_n)


def parse_args():
    p = argparse.ArgumentParser(description="DAS Scanner — Phone pattern (special-phones)")
    p.add_argument("--start", type=int, default=DEFAULT_START)
    p.add_argument("--end", type=int, default=DEFAULT_END)
    p.add_argument("--checkpoint", default=CHECKPOINT_FILE)
    p.add_argument("--hits", default=HITS_FILE)
    p.add_argument("--no-resume", action="store_true")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main_async(args))
