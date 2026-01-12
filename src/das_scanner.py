#!/usr/bin/env python3
"""
Domain DAS Scanner — single-file implementation following IMPLEMENTATION_PLAN.md

Features:
- Import domains from assets/input.txt into SQLite (batch INSERT OR IGNORE)
- Picker thread: atomically selects pending domains and marks them in_progress
- Async worker tasks: rate-limited TCP queries to das.domreg.lt:4343
- Writer thread: batched DB updates and buffered per-status text files
- Progress logger
- Graceful shutdown and resume capability

No external dependencies — uses Python stdlib only.
Target: Python 3.10+
"""

import argparse
import asyncio
import os
import queue
import signal
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

# ------------------------
# Hardcoded settings (from plan)
# ------------------------
DB_PATH = "scan_state.db"
INPUT_PATH = "assets/input.txt"
OUTPUT_DIR = "assets/output"

# Performance / behavior
RATE = 30  # requests/sec (token bucket)
CONCURRENCY = 40  # worker tasks (reduced for stability)
CHECK_TIMEOUT = 6
MAX_RETRIES = 1
RETRY_BACKOFF = 2  # seconds

# Batching
BATCH_IMPORT_SIZE = 5000
PICK_BATCH_SIZE = 15
WRITE_BATCH_SIZE = 1000
FILE_BUFFER_SIZE = 10000

# Logging / progress
PROGRESS_INTERVAL = 1800  # domains between progress logs
IMPORT_LOG_INTERVAL = 100000

# DAS server
DAS_HOST = "das.domreg.lt"
DAS_PORT = 4343
DAS_QUERY_TEMPLATE = "get 1.0 {domain}\n"

# Valid statuses (canonical). Anything else -> 'unknown'
# Note: using lowercase normalized versions for comparison
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

# ------------------------
# Utilities
# ------------------------


def now_ts() -> float:
    return time.time()


def normalize_domain(d: str) -> str:
    return d.strip().lower()


# ------------------------
# Database helpers
# ------------------------


def get_db_conn(db_path: str, timeout: float = 30.0) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=timeout, check_same_thread=False)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    # return rows as tuples (default)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    cur.executescript(
        """
    CREATE TABLE IF NOT EXISTS domains (
      domain TEXT PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'pending',
      last_checked REAL,
      in_progress INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_status ON domains(status);
    -- Partial indexes not supported on sqlite < 3.8.0; keep generic index
    CREATE INDEX IF NOT EXISTS idx_pending ON domains(status, in_progress);
    """
    )
    conn.commit()


def get_total_domains(conn: sqlite3.Connection) -> int:
    """Get total number of domains in database."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM domains;")
    return cur.fetchone()[0]


def import_domains(conn: sqlite3.Connection, input_path: str, batch_size: int = BATCH_IMPORT_SIZE) -> int:
    """
    Read input file line-by-line and INSERT OR IGNORE into domains table.
    Returns number of NEW domains imported (not duplicates).
    """
    path = Path(input_path)
    if not path.exists():
        print(f"[IMPORT] Input file not found: {input_path}")
        return 0

    # Get current count before import
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM domains;")
    count_before = cur.fetchone()[0]

    # First, count total lines for percentage calculation
    print("[IMPORT] Counting domains in input file...")
    total_lines = sum(1 for line in path.open("r", encoding="utf-8", errors="ignore") if normalize_domain(line).endswith(".lt"))
    print(f"[IMPORT] Found {total_lines} .lt domains in input file")

    inserted = 0
    to_insert: List[Tuple[str]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for i, line in enumerate(fh, start=1):
            d = normalize_domain(line)
            if not d:
                continue
            # ensure .lt domains only (simple check)
            if not d.endswith(".lt"):
                continue
            to_insert.append((d,))
            if len(to_insert) >= batch_size:
                _batch_insert(conn, to_insert)
                inserted += len(to_insert)
                to_insert.clear()
                if inserted % IMPORT_LOG_INTERVAL == 0:
                    pct = (inserted / total_lines * 100) if total_lines > 0 else 0
                    print(f"[IMPORT] Processed {inserted}/{total_lines} domains ({pct:.2f}%)")
        if to_insert:
            _batch_insert(conn, to_insert)
            inserted += len(to_insert)

    # Get count after import to see how many were actually new
    cur.execute("SELECT COUNT(*) FROM domains;")
    count_after = cur.fetchone()[0]
    new_domains = count_after - count_before

    if new_domains > 0:
        print(f"[IMPORT] Import complete: {new_domains} new domains added (from {total_lines} in file)")
    else:
        print(f"[IMPORT] No new domains to import (all {total_lines} already in database)")

    return new_domains


def _batch_insert(conn: sqlite3.Connection, rows: List[Tuple[str]]) -> None:
    cur = conn.cursor()
    cur.executemany("INSERT OR IGNORE INTO domains(domain) VALUES (?);", rows)
    conn.commit()


def reset_in_progress(conn: sqlite3.Connection) -> int:
    cur = conn.cursor()
    cur.execute("UPDATE domains SET in_progress=0 WHERE in_progress=1;")
    cnt = cur.rowcount
    conn.commit()
    if cnt:
        print(f"[DB] Resetting {cnt} stuck domains...")
    else:
        print("[DB] No stuck domains to reset")
    return cnt


# ------------------------
# Picker thread (sync)
# ------------------------


class PickerThread(threading.Thread):
    """
    Runs in a separate thread, owns its own DB connection.
    When worker tasks need more work, they await on an asyncio.Queue (picker_queue).
    The picker thread fills that asyncio.Queue by calling loop.call_soon_threadsafe.
    """

    def __init__(self, db_path: str, picker_queue: "asyncio.Queue[List[str]]", shutdown_event: threading.Event, loop: asyncio.AbstractEventLoop):
        super().__init__(daemon=True, name="PickerThread")
        self.db_path = db_path
        self.picker_queue = picker_queue
        self.shutdown_event = shutdown_event
        self._conn = None  # set in run
        self.loop = loop  # passed from main asyncio loop

    def run(self):
        self._conn = get_db_conn(self.db_path)
        # Queue to store domains that need to be marked back
        self._requeue_domains = []

        try:
            while not self.shutdown_event.is_set():
                # First, handle any domains that need re-queuing
                if self._requeue_domains:
                    try:
                        self._mark_back(self._requeue_domains)
                        self._requeue_domains = []
                    except Exception as e:
                        print(f"[PICKER] Failed to re-queue domains: {e}")
                        time.sleep(0.5)
                        continue

                # small sleep to avoid busy spin when no pending rows exist
                pending_batch = self._pick_batch(PICK_BATCH_SIZE)
                if not pending_batch:
                    # no pending rows: sleep a bit
                    time.sleep(0.25)
                    continue

                # push to asyncio picker_queue thread-safely
                # Store reference to self for closure
                picker_self = self
                pending_batch_ref = pending_batch

                def safe_put():
                    try:
                        picker_self.picker_queue.put_nowait(pending_batch_ref)
                    except asyncio.QueueFull:
                        # Queue is full, add to requeue list (picker thread will handle it)
                        picker_self._requeue_domains.extend(pending_batch_ref)

                try:
                    self.loop.call_soon_threadsafe(safe_put)
                    # Small sleep to allow workers to consume
                    time.sleep(0.05)
                except Exception as e:
                    # fallback: if cannot schedule callback, mark them back
                    print(f"[PICKER] Failed to schedule batch: {e}. Re-queuing domains.")
                    self._requeue_domains.extend(pending_batch)
                    time.sleep(0.2)
        finally:
            # Final requeue attempt
            if self._requeue_domains:
                try:
                    self._mark_back(self._requeue_domains)
                except Exception:
                    pass
            try:
                self._conn.close()
            except Exception:
                pass
            print("[PICKER] Exiting picker thread.")

    def _pick_batch(self, size: int) -> List[str]:
        """
        Atomically pick up to `size` domains with status='pending' and in_progress=0
        and mark them in_progress=1 before returning.
        Returns list of domain strings.
        """
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE;")
            cur.execute(
                "SELECT domain FROM domains WHERE status='pending' AND in_progress=0 LIMIT ?;",
                (size,),
            )
            rows = [r[0] for r in cur.fetchall()]
            if not rows:
                self._conn.commit()
                return []
            # param expansion
            qmarks = ",".join("?" for _ in rows)
            cur.execute(f"UPDATE domains SET in_progress=1 WHERE domain IN ({qmarks});", tuple(rows))
            self._conn.commit()
            return rows
        except sqlite3.OperationalError as e:
            # possible lock contentions; rollback and return empty
            try:
                self._conn.rollback()
            except Exception:
                pass
            print(f"[PICKER] DB error during pick: {e}")
            return []

    def _mark_back(self, domains: List[str]) -> None:
        """
        Set in_progress=0 for given domains.
        Used when we failed to dispatch picked domains to workers.
        Must be called from the picker thread only.
        """
        if not domains:
            return
        cur = self._conn.cursor()
        try:
            qmarks = ",".join("?" for _ in domains)
            cur.execute(f"UPDATE domains SET in_progress=0 WHERE domain IN ({qmarks});", tuple(domains))
            self._conn.commit()
        except Exception as e:
            print(f"[PICKER] Error marking domains back: {e}")
            try:
                self._conn.rollback()
            except Exception:
                pass


# ------------------------
# Token Bucket (async)
# ------------------------


class TokenBucket:
    """
    Simple asyncio token bucket.
    Refill RATE tokens per second, up to bucket_capacity.
    Workers await get_token() before each request.
    """

    def __init__(self, rate_per_sec: float, capacity: Optional[int] = None):
        self.rate = rate_per_sec
        self.capacity = capacity if capacity is not None else int(max(1, rate_per_sec * 2))
        self._tokens = float(self.capacity)
        self._lock = asyncio.Lock()
        self._last = now_ts()
        self._refill_task = None
        self._running = False

    async def start(self):
        self._running = True
        self._refill_task = asyncio.create_task(self._refill_loop())

    async def stop(self):
        self._running = False
        if self._refill_task:
            self._refill_task.cancel()
            with context_ignore_cancel():
                await self._refill_task

    async def _refill_loop(self):
        try:
            while self._running:
                async with self._lock:
                    now = now_ts()
                    delta = now - self._last
                    self._last = now
                    # add tokens
                    add = delta * self.rate
                    self._tokens = min(self.capacity, self._tokens + add)
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            return

    async def get_token(self):
        # wait until at least 1 token is available
        while True:
            async with self._lock:
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            await asyncio.sleep(0.01)


# ------------------------
# DAS checker
# ------------------------


async def das_check(domain: str, timeout: int = CHECK_TIMEOUT) -> str:
    """
    Perform the TCP query to DAS service. Returns status string (canonical lowercased),
    or 'unknown' if parsing fails or other errors.
    Implements simple retry logic (MAX_RETRIES).
    """
    domain = domain.strip()
    for attempt in range(0, MAX_RETRIES + 1):
        try:
            # use asyncio.open_connection with timeout
            coro = asyncio.open_connection(DAS_HOST, DAS_PORT)
            reader, writer = await asyncio.wait_for(coro, timeout=timeout)
            q = DAS_QUERY_TEMPLATE.format(domain=domain)
            writer.write(q.encode("utf-8"))
            await writer.drain()

            # read response until EOF or timeout. We'll try to read moderately sized blocks.
            data_chunks = []
            try:
                # Give the server some time to respond; read until EOF
                # Some servers close after response; if not, the read will eventually time out.
                chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
                while chunk:
                    data_chunks.append(chunk)
                    # attempt to read again with small timeout
                    chunk = await asyncio.wait_for(reader.read(8192), timeout=0.5)
            except asyncio.TimeoutError:
                # treat partial read as final
                pass
            writer.close()
            with context_ignore_cancel():
                await writer.wait_closed()

            data = b"".join(data_chunks).decode("utf-8", errors="ignore")
            status = _parse_das_status(data)
            return status
        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF)
                continue
            else:
                return "unknown"
    return "unknown"


def _parse_das_status(response_text: str) -> str:
    """
    Parse the response for a 'Status:' line. Return canonical lowercase status or 'unknown'.
    """
    if not response_text:
        return "unknown"
    for line in response_text.splitlines():
        line_stripped = line.strip()
        if line_stripped.lower().startswith("status:"):
            # split after colon
            parts = line_stripped.split(":", 1)
            if len(parts) > 1:
                s = parts[1].strip().lower()
                # normalize some variants (remove spaces and hyphens)
                s_norm = s.replace(" ", "").replace("-", "")
                if s_norm in CANONICAL_STATUSES:
                    return s_norm
                # if the exact s is in canonical statuses, return it
                if s in CANONICAL_STATUSES:
                    return s
                # otherwise return raw (but safe)
                return s if s else "unknown"
    return "unknown"


# ------------------------
# Writer thread (sync)
# ------------------------


class WriterThread(threading.Thread):
    """
    Consumes results from a thread-safe queue.Queue (writer_q).
    Batches DB updates and writes buffered status files.
    """

    def __init__(self, db_path: str, writer_q: "queue.Queue", output_dir: str, shutdown_event: threading.Event):
        super().__init__(daemon=True, name="WriterThread")
        self.db_path = db_path
        self.writer_q = writer_q
        self.output_dir = Path(output_dir)
        self._conn = None
        self.shutdown_event = shutdown_event
        # in-memory buffers per status
        self.buffers: Dict[str, List[str]] = {}
        self._pending_updates: List[Tuple[str, float, str]] = []  # (status, last_checked, domain) -> we'll adapt
        # We'll accumulate tuples (status, last_checked, domain)
        # Flush thresholds:
        self.write_batch_size = WRITE_BATCH_SIZE
        self.file_buffer_size = FILE_BUFFER_SIZE

    def run(self):
        self._conn = get_db_conn(self.db_path)
        os.makedirs(self.output_dir, exist_ok=True)
        try:
            self._main_loop()
        finally:
            # flush buffers on exit
            print("[WRITER] Flushing buffers on shutdown...")
            self._flush_all_buffers()
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
            print("[WRITER] Writer thread exiting.")

    def _main_loop(self):
        """
        Continually consume results from writer_q until shutdown_event is set and queue empty.
        Each result is a tuple: (domain, status, timestamp)
        """
        while not (self.shutdown_event.is_set() and self.writer_q.empty()):
            try:
                item = self.writer_q.get(timeout=0.5)
            except queue.Empty:
                # Periodically flush smaller batches if needed
                if self._pending_updates:
                    self._flush_db_updates()
                continue
            if item is None:
                # sentinel to flush and exit
                break
            domain, status, ts = item
            status = status or "unknown"
            # accumulate update; store as (domain, status, ts)
            self._pending_updates.append((domain, status, ts))
            # buffer for file output
            buf = self.buffers.setdefault(status, [])
            buf.append(domain)
            # flush file if large
            if len(buf) >= self.file_buffer_size:
                self._flush_status_file(status)
            # flush DB if enough updates
            if len(self._pending_updates) >= self.write_batch_size:
                self._flush_db_updates()
        # final flush
        if self._pending_updates:
            self._flush_db_updates()
        self._flush_all_buffers()

    def _flush_db_updates(self):
        if not self._pending_updates:
            return
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE;")
            # Prepare updates
            # We'll do executemany with parameter sequence
            params = []
            for domain, status, ts in [(d, s, t) for (d, s, t) in self._pending_updates]:
                params.append((status, ts, 0, domain))
            cur.executemany(
                "UPDATE domains SET status=?, last_checked=?, in_progress=? WHERE domain=?;", params
            )
            self._conn.commit()
            # print progress? not here
            self._pending_updates.clear()
        except sqlite3.OperationalError as e:
            try:
                self._conn.rollback()
            except Exception:
                pass
            print(f"[WRITER] DB error during update: {e}")

    def _flush_status_file(self, status: str):
        buf = self.buffers.get(status)
        if not buf:
            return
        path = self.output_dir / f"{status}.txt"
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.writelines(f"{d}\n" for d in buf)
        except OSError as e:
            print(f"[WRITER] Failed to write status file {path}: {e}")
        buf.clear()

    def _flush_all_buffers(self):
        # flush DB first
        if self._pending_updates:
            self._flush_db_updates()
        # flush all files
        for status in list(self.buffers.keys()):
            self._flush_status_file(status)


# ------------------------
# Context manager utilities
# ------------------------
from contextlib import contextmanager


@contextmanager
def context_ignore_cancel():
    try:
        yield
    except Exception:
        # used to swallow cancellation on writer wait_closed
        pass


# ------------------------
# Async workers and progress logger
# ------------------------


async def worker_task(
    worker_id: int,
    picker_queue: "asyncio.Queue[List[str]]",
    writer_thread_q: "queue.Queue",
    token_bucket: TokenBucket,
    shutdown_flag: asyncio.Event,
    stats: Dict[str, int],
    stats_lock: asyncio.Lock,
):
    """
    Each worker requests batches from the picker_queue and processes domains.
    Results are pushed into writer_thread_q via run_in_executor to ensure thread-safe put.
    """
    loop = asyncio.get_running_loop()
    consecutive_empty_batches = 0

    while not shutdown_flag.is_set():
        try:
            batch: List[str] = await asyncio.wait_for(picker_queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            # no batch available; check if picker is done providing work
            consecutive_empty_batches += 1
            # If we've waited too long with no work, assume we're done
            if consecutive_empty_batches > 5:
                break
            continue

        if not batch:
            # empty batch -> continue
            consecutive_empty_batches += 1
            if consecutive_empty_batches > 5:
                break
            continue

        # Got work, reset counter
        consecutive_empty_batches = 0

        for domain in batch:
            if shutdown_flag.is_set():
                break
            await token_bucket.get_token()
            status = await das_check(domain)
            ts = now_ts()
            # update stats (with lock for thread safety)
            async with stats_lock:
                stats["completed"] += 1
                stats_key = f"status:{status}"
                stats[stats_key] = stats.get(stats_key, 0) + 1
            # send to writer thread queue
            # writer_thread_q is a standard queue.Queue which is thread-safe.
            # Use run_in_executor to perform blocking put without blocking event loop.
            await loop.run_in_executor(None, writer_thread_q.put, (domain, status, ts))
        # loop continues and requests more batches
    # worker exiting
    # print(f"[WORKER {worker_id}] Exiting.")


async def progress_logger(
    db_path: str,
    shutdown_flag: asyncio.Event,
    stats: Dict[str, int],
    stats_lock: asyncio.Lock,
    check_interval: int = PROGRESS_INTERVAL
):
    """
    Periodically check stats and log progress when PROGRESS_INTERVAL domains have been completed.
    For small datasets (< check_interval), logs every 5 seconds instead.
    """
    conn = get_db_conn(db_path)
    try:
        # Get total for adaptive logging
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM domains;")
        total_domains = cur.fetchone()[0]

        # For small datasets, use time-based logging
        use_time_based = total_domains < check_interval

        last_logged = 0
        last_log_time = time.time()
        start_time = time.time()

        # Log initial status immediately
        await asyncio.sleep(2)  # Give workers 2 seconds to start
        cur.execute(
            "SELECT "
            "SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as remaining, "
            "SUM(CASE WHEN status!='pending' THEN 1 ELSE 0 END) as completed, "
            "COUNT(*) as total "
            "FROM domains;"
        )
        row = cur.fetchone()
        remaining = int(row[0] or 0)
        db_completed = int(row[1] or 0)
        total = int(row[2] or 0)
        print(f"Starting: {db_completed}/{total} already completed, {remaining} remaining")

        while not shutdown_flag.is_set():
            await asyncio.sleep(5)  # check every 5 seconds

            async with stats_lock:
                completed = stats["completed"]

            cur = conn.cursor()
            cur.execute(
                "SELECT "
                "SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) as remaining, "
                "SUM(CASE WHEN status!='pending' THEN 1 ELSE 0 END) as completed, "
                "COUNT(*) as total "
                "FROM domains;"
            )
            row = cur.fetchone()
            remaining = int(row[0] or 0)
            db_completed = int(row[1] or 0)
            total = int(row[2] or 0)

            # Decide whether to log
            should_log = False
            now = time.time()

            if use_time_based:
                # For small datasets, log every 5 seconds if there's progress
                if db_completed > last_logged and (now - last_log_time) >= 5:
                    should_log = True
            else:
                # For large datasets, log every check_interval domains
                if db_completed - last_logged >= check_interval:
                    should_log = True

            if should_log:
                # Calculate req/sec based on domains completed since last log
                domains_since_last = db_completed - last_logged
                time_since_last = now - last_log_time
                rps = (domains_since_last / time_since_last) if time_since_last > 0 else 0.0
                eta_hours = (remaining / rps / 3600) if rps > 0 else float("inf")
                pct = (db_completed / total * 100) if total > 0 else 0.0

                # Status breakdown
                cur.execute("SELECT status, COUNT(*) FROM domains WHERE status != 'pending' GROUP BY status;")
                counts = cur.fetchall()
                status_parts = " ".join(f"{s}={c}" for s, c in counts)

                print(f"Processed {db_completed}/{total} ({pct:.2f}%) | {rps:.1f} req/sec | ETA: {eta_hours:.1f} hours")
                print(f"{status_parts}")

                last_logged = db_completed
                last_log_time = now
    finally:
        conn.close()


# ------------------------
# Main and orchestration
# ------------------------


def ensure_dirs():
    Path("assets").mkdir(parents=True, exist_ok=True)
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)


def install_signal_handlers(loop: asyncio.AbstractEventLoop, shutdown_event: threading.Event, shutdown_flag: asyncio.Event):
    """
    Signal handlers to coordinate graceful shutdown between threads and asyncio tasks.
    """

    def _handler(signum, frame):
        print(f"\n[SIGNAL] Caught signal {signum}. Shutting down gracefully...")
        shutdown_event.set()
        # set asyncio flag
        loop.call_soon_threadsafe(shutdown_flag.set)

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


async def main_async(args):
    ensure_dirs()
    # shared flags
    shutdown_event = threading.Event()  # for threads
    shutdown_flag = asyncio.Event()  # for async tasks

    # Setup DB and import if needed
    conn = get_db_conn(DB_PATH)
    init_db(conn)
    # Always attempt import (INSERT OR IGNORE handles duplicates)
    if Path(INPUT_PATH).exists():
        print("[MAIN] Checking for new domains to import...")
        import_domains(conn, INPUT_PATH)
    else:
        print(f"[MAIN] Warning: Input file not found at {INPUT_PATH}")
    # Reset stuck rows
    reset_in_progress(conn)
    conn.close()

    # Get the running loop
    loop = asyncio.get_running_loop()

    # Asyncio queues
    picker_queue: asyncio.Queue = asyncio.Queue(maxsize=CONCURRENCY * 2)
    # writer thread expects a thread-safe queue
    writer_thread_q: queue.Queue = queue.Queue()

    # Start picker thread with loop reference
    picker = PickerThread(DB_PATH, picker_queue, shutdown_event, loop)
    picker.start()

    # Start writer thread
    writer = WriterThread(DB_PATH, writer_thread_q, OUTPUT_DIR, shutdown_event)
    writer.start()

    # Token bucket
    token_bucket = TokenBucket(RATE)
    await token_bucket.start()

    # Stats dict (lightweight) with lock for thread safety
    stats: Dict[str, int] = {"completed": 0}
    stats_lock = asyncio.Lock()

    # Start worker tasks
    worker_tasks = [
        asyncio.create_task(worker_task(i, picker_queue, writer_thread_q, token_bucket, shutdown_flag, stats, stats_lock))
        for i in range(CONCURRENCY)
    ]

    # Start progress logger
    progress_task = asyncio.create_task(progress_logger(DB_PATH, shutdown_flag, stats, stats_lock))

    # Install signal handlers
    install_signal_handlers(loop, shutdown_event, shutdown_flag)

    print(f"[MAIN] Starting scanner: {CONCURRENCY} workers, {RATE} req/sec")

    # Initial status check
    conn_check = get_db_conn(DB_PATH)
    cur_check = conn_check.cursor()
    cur_check.execute("SELECT COUNT(*) FROM domains WHERE status='pending';")
    pending_count = cur_check.fetchone()[0]
    conn_check.close()

    if pending_count == 0:
        print(f"[MAIN] No pending domains to process. Exiting.")
        return

    print(f"[MAIN] {pending_count} domains pending")
    print(f"[MAIN] Progress will be logged every {PROGRESS_INTERVAL if pending_count >= PROGRESS_INTERVAL else '5 seconds for small datasets'}")

    # Wait for workers to finish (they stop when shutdown_flag set or no more work)
    try:
        await asyncio.gather(*worker_tasks)
        print("[MAIN] All workers completed. Shutting down...")
    except asyncio.CancelledError:
        pass
    finally:
        # workers done or cancelled — stop token bucket and progress logger
        await token_bucket.stop()
        if not progress_task.done():
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass

    # Signal writer thread to finish (set shutdown_event above)
    shutdown_event.set()
    # ensure writer_thread_q has sentinel? Writer will exit when shutdown_event and queue empty.
    # Wait for writer to finish
    print("[MAIN] Waiting for writer thread to flush...")
    writer.join(timeout=10.0)
    if writer.is_alive():
        print("[MAIN] Writer thread did not exit in time; forcing final flush.")
        # try to flush by putting sentinel
        try:
            writer_thread_q.put_nowait(None)
        except Exception:
            pass
        writer.join(timeout=5)

    # Stop picker thread
    picker.join(timeout=2.0)
    if picker.is_alive():
        print("[MAIN] Picker thread didn't exit cleanly; it will exit on next check.")

    print("[MAIN] Scan complete. All domains processed.")


def parse_args():
    p = argparse.ArgumentParser(description="DAS Scanner")
    p.add_argument("--db", default=DB_PATH, help="Path to SQLite DB")
    p.add_argument("--input", default=INPUT_PATH, help="Input domains file (one domain per line)")
    p.add_argument("--output", default=OUTPUT_DIR, help="Output folder for per-status text files")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    # override global paths if user passed args
    DB_PATH = args.db
    INPUT_PATH = args.input
    OUTPUT_DIR = args.output

    # ensure assets exist
    ensure_dirs()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("[MAIN] Interrupted by user. Exiting.")