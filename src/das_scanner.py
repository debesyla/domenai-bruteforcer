#!/usr/bin/env python3
"""
Domain DAS Scanner — All-TLD branch

Scans for .lt mirrors of domains from many TLD files.
For each TLD file in tld_lists/, forms .lt domain twins, checks availability
via DAS, and outputs a CSV and stats file.

Features:
- Imports from TLD files, forming .lt mirror domains
- Durable cross-TLD/cross-restart dedup (seen_twins table + in-memory bloom accelerator)
- Picker thread: atomically selects pending domains and marks them in_progress
- Async worker tasks: rate-limited TCP queries to das.domreg.lt:4343
- Writer thread: batched DB updates and buffered per-status text files
- Crash-resilient: skips already-processed TLDs on restart
- Exports per-TLD CSV and stats, then cleans up DB to keep it lean
- Progress logger
- Graceful shutdown and resume capability

Dependencies: Python 3.10+, pybloom_live
"""

import argparse
import asyncio
import csv
import os
import queue
import signal
import sqlite3
import threading
import re
import time
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pybloom_live import ScalableBloomFilter

# Optional: unidecode for character normalization (e.g., ë → e)
try:
    from unidecode import unidecode as _unidecode
except ImportError:
    _unidecode = None  # graceful fallback, no-op


# ------------------------
# Hardcoded settings (from plan)
# ------------------------
DB_PATH = "scan_state.db"
INPUT_PATH = "assets/input.txt"
OUTPUT_DIR = "assets/output"

# TLD scanner settings
TLD_INPUT_DIR = "tld_lists"
OUTPUT_ROOT = "output"

# Performance / behavior
RATE = 28  # requests/sec (token bucket)
CONCURRENCY = 40  # worker tasks (reduced for stability)
CHECK_TIMEOUT = 6
MAX_RETRIES = 1
RETRY_BACKOFF = 2  # seconds
MAX_UNKNOWN_RETRIES = 1  # how many times to re-scan domains that returned 'unknown'

# Batching
BATCH_IMPORT_SIZE = 5000
PICK_BATCH_SIZE = 15
WRITE_BATCH_SIZE = 1000
FILE_BUFFER_SIZE = 10000

# Dedup / bloom filter
# The seen_twins table is the AUTHORITATIVE dedup record; the bloom is only a fast
# in-memory accelerator, so a false positive just costs a DB confirm (never a dropped
# domain) and the capacity/error_rate can be modest.
BLOOM_INITIAL_CAPACITY = 50_000_000
BLOOM_ERROR_RATE = 0.01
# Max bound-parameters per "IN (...)" query; stay well under SQLITE_MAX_VARIABLE_NUMBER.
DB_QUERY_CHUNK = 900

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


def clean_domain(raw: str) -> tuple:
    """
    Returns (cleaned_domain, None) if valid,
    or (None, error_reason) if rejected.
    """
    if not raw or not raw.strip():
        return None, "empty"

    # Normalise: strip whitespace, remove trailing dot, lowercase
    domain = raw.strip().rstrip(".").lower()

    # 1. Turn non-Latin letters (ë, ü, 中文, etc.) into closest Latin chars
    if _unidecode is not None:
        domain = _unidecode(domain)

    # 2. Allow ONLY a-z, 0-9, hyphens and dots (already ASCII after unidecode)
    if not re.fullmatch(r"[a-z0-9\-\.]+", domain):
        return None, "invalid characters"

    # 3. Check each label (part between dots)
    labels = domain.split(".")

    # Must be at least SLD.TLD — reject dotless / bare-TLD input (a stray "com" line
    # would otherwise become the bogus twin "com.lt"). NOTE: subdomains (www.example.com)
    # and multi-part TLDs (example.co.uk) are NOT normalized here; handling those
    # correctly needs a public-suffix list. This only rejects the clearly-malformed case.
    if len(labels) < 2:
        return None, "not a domain (needs at least SLD.TLD)"

    for label in labels:
        if len(label) < 2:
            return None, "domain label too short (min 2 chars)"
        if len(label) > 63:
            return None, "label exceeds 63 characters"
        if label.startswith("-") or label.endswith("-"):
            return None, "hyphen at start or end of label"
        if "--" in label and not label.startswith("xn--"):
            return None, "consecutive hyphens"

    return domain, None


# ------------------------
# Database helpers
# ------------------------


def get_db_conn(db_path: str, timeout: float = 30.0) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=timeout, check_same_thread=False)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create schema with original_domain and source_tld tracking."""
    cur = conn.cursor()
    cur.executescript(
        """
    CREATE TABLE IF NOT EXISTS domains (
      domain TEXT PRIMARY KEY,          -- the .lt domain (e.g., 'google.lt')
      original_domain TEXT,             -- from TLD file (e.g., 'google.com')
      source_tld TEXT,                  -- e.g., 'com'
      status TEXT NOT NULL DEFAULT 'pending',
      last_checked REAL,
      in_progress INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_status ON domains(status);
    CREATE INDEX IF NOT EXISTS idx_pending ON domains(status, in_progress);
    CREATE INDEX IF NOT EXISTS idx_source_tld ON domains(source_tld);

    -- Durable dedup: every .lt twin that has been SCANNED (in any TLD, any run) is
    -- recorded here. This table is NEVER deleted by the per-TLD cleanup, so cross-TLD
    -- and cross-restart dedup survives crashes. The in-memory bloom is rebuilt from it
    -- on startup.
    CREATE TABLE IF NOT EXISTS seen_twins (
      domain TEXT PRIMARY KEY
    );
    """
    )
    conn.commit()


def get_total_domains(conn: sqlite3.Connection) -> int:
    """Get total number of domains in database."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM domains;")
    return cur.fetchone()[0]


# Backward-compat: import .lt domains from a flat file (original single-TLD flow)
def import_domains(conn: sqlite3.Connection, input_path: str, batch_size: int = BATCH_IMPORT_SIZE) -> int:
    """
    Read input file line-by-line and INSERT OR IGNORE into domains table.
    Falls back: sets original_domain = domain and source_tld = 'lt'.
    Returns number of NEW domains imported (not duplicates).
    """
    path = Path(input_path)
    if not path.exists():
        print(f"[IMPORT] Input file not found: {input_path}")
        return 0

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM domains;")
    count_before = cur.fetchone()[0]

    print("[IMPORT] Counting domains in input file...")
    total_lines = sum(
        1 for line in path.open("r", encoding="utf-8", errors="ignore")
        if normalize_domain(line).endswith(".lt")
    )
    print(f"[IMPORT] Found {total_lines} .lt domains in input file")

    inserted = 0
    to_insert: List[Tuple[str, str, str]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for i, line in enumerate(fh, start=1):
            d = normalize_domain(line)
            if not d:
                continue
            if not d.endswith(".lt"):
                continue
            to_insert.append((d, d, "lt"))  # domain, original_domain, source_tld
            if len(to_insert) >= batch_size:
                _batch_insert_mirror(conn, to_insert)
                inserted += len(to_insert)
                to_insert.clear()
                if inserted % IMPORT_LOG_INTERVAL == 0:
                    pct = (inserted / total_lines * 100) if total_lines > 0 else 0
                    print(f"[IMPORT] Processed {inserted}/{total_lines} domains ({pct:.2f}%)")
        if to_insert:
            _batch_insert_mirror(conn, to_insert)
            inserted += len(to_insert)

    cur.execute("SELECT COUNT(*) FROM domains;")
    count_after = cur.fetchone()[0]
    new_domains = count_after - count_before

    if new_domains > 0:
        print(f"[IMPORT] Import complete: {new_domains} new domains added (from {total_lines} in file)")
    else:
        print(f"[IMPORT] No new domains to import (all {total_lines} already in database)")

    return new_domains


def _batch_insert(conn: sqlite3.Connection, rows: List[Tuple[str]]) -> None:
    """Simple batch insert (legacy single-column domains)."""
    cur = conn.cursor()
    cur.executemany("INSERT OR IGNORE INTO domains(domain) VALUES (?);", rows)
    conn.commit()


def _batch_insert_mirror(conn: sqlite3.Connection, rows: List[Tuple[str, str, str]]) -> int:
    """Insert twins into the `domains` scan queue (INSERT OR IGNORE on the domain
    PRIMARY KEY). Returns the number of rows ACTUALLY inserted — collisions are not
    counted — so callers can report accurate import totals."""
    cur = conn.cursor()
    before = conn.total_changes
    cur.executemany(
        "INSERT OR IGNORE INTO domains(domain, original_domain, source_tld) VALUES (?, ?, ?);",
        rows,
    )
    inserted = conn.total_changes - before
    conn.commit()
    return inserted


def _existing_twins(conn: sqlite3.Connection, twins: List[str]) -> set:
    """Return the subset of `twins` already recorded in seen_twins (the authoritative
    dedup record). Chunked to stay under SQLite's bound-parameter limit."""
    found: set = set()
    cur = conn.cursor()
    for i in range(0, len(twins), DB_QUERY_CHUNK):
        chunk = twins[i:i + DB_QUERY_CHUNK]
        placeholders = ",".join("?" for _ in chunk)
        cur.execute(
            f"SELECT domain FROM seen_twins WHERE domain IN ({placeholders});", chunk
        )
        found.update(row[0] for row in cur.fetchall())
    return found


def rebuild_bloom_from_seen(db_path: str, bloom: ScalableBloomFilter) -> int:
    """Repopulate the in-memory bloom from the durable seen_twins table so cross-TLD
    dedup survives process restarts. Returns the number of twins loaded."""
    conn = get_db_conn(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM seen_twins;")
        total = cur.fetchone()[0]
        if not total:
            return 0
        print(f"[BLOOM] Rebuilding filter from {total} previously-seen twins...")
        cur.execute("SELECT domain FROM seen_twins;")
        loaded = 0
        for (domain,) in cur:
            bloom.add(domain)
            loaded += 1
            if loaded % 1_000_000 == 0:
                print(f"[BLOOM] Loaded {loaded}/{total}...")
        print(f"[BLOOM] Filter rebuilt with {loaded} twins.")
        return loaded
    finally:
        conn.close()


def record_seen_twins(db_path: str, tld: str, bloom: ScalableBloomFilter) -> int:
    """Mark a TLD's SCANNED twins as durably seen (seen_twins table + bloom) so they are
    never re-imported or re-scanned under a later TLD or after a restart. Only
    non-pending rows are recorded, so an interrupted scan never marks a twin done before
    it has actually been checked. Returns the number of twins recorded."""
    conn = get_db_conn(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO seen_twins(domain) "
            "SELECT domain FROM domains WHERE source_tld = ? AND status != 'pending';",
            (tld,),
        )
        conn.commit()
        cur.execute(
            "SELECT domain FROM domains WHERE source_tld = ? AND status != 'pending';",
            (tld,),
        )
        recorded = 0
        for (domain,) in cur:
            bloom.add(domain)
            recorded += 1
        return recorded
    finally:
        conn.close()


def delete_tld_rows(db_path: str, tld: str) -> None:
    """Remove a TLD's rows from the `domains` scan queue (idempotent). seen_twins is
    durable and intentionally left untouched."""
    conn = get_db_conn(db_path)
    try:
        conn.execute("DELETE FROM domains WHERE source_tld = ?;", (tld,))
        conn.commit()
    finally:
        conn.close()


def pending_count_for_tld(db_path: str, tld: str) -> int:
    """How many of a TLD's twins are still pending (i.e., not yet scanned)."""
    conn = get_db_conn(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM domains WHERE source_tld = ? AND status = 'pending';",
            (tld,),
        )
        return cur.fetchone()[0]
    finally:
        conn.close()


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
# TLD Importer with Bloom filter
# ------------------------


def import_domains_for_tld(
    conn: sqlite3.Connection,
    tld: str,
    file_path: str,
    bloom: ScalableBloomFilter,
    batch_size: int = BATCH_IMPORT_SIZE,
) -> int:
    """
    Read a TLD file, form .lt twins, and queue twins that have not been scanned yet.

    Dedup is authoritative via the persistent seen_twins table (survives restarts and
    the per-TLD cleanup). The in-memory `bloom` is a fast pre-filter kept as a superset
    of seen_twins (rebuilt at startup, updated when a TLD completes):
      * a bloom MISS means the twin has definitely never been scanned -> queue it;
      * a bloom HIT is confirmed against seen_twins, so a false positive never silently
        drops a real domain.
    Returns the count of new twins queued for scanning.
    """
    path = Path(file_path)
    if not path.exists():
        print(f"[IMPORT] File not found: {file_path}")
        return 0

    print(f"[IMPORT] Importing .{tld} from {file_path}...")
    inserted = 0      # new twins queued for scanning
    skipped = 0       # invalid / malformed input lines
    duplicates = 0    # twins already scanned before (deduped away)

    new_batch: Dict[str, Tuple[str, str, str]] = {}    # bloom miss -> definitely new
    check_batch: Dict[str, Tuple[str, str, str]] = {}  # bloom hit  -> confirm vs seen_twins

    def flush():
        nonlocal inserted, duplicates
        # Bloom misses are guaranteed new (the bloom is a superset of seen_twins).
        if new_batch:
            inserted += _batch_insert_mirror(conn, list(new_batch.values()))
            new_batch.clear()
        # Bloom hits may be false positives: only the ones NOT in seen_twins are new.
        if check_batch:
            twins = list(check_batch.keys())
            existing = _existing_twins(conn, twins)
            duplicates += len(existing)
            fresh = [check_batch[t] for t in twins if t not in existing]
            if fresh:
                inserted += _batch_insert_mirror(conn, fresh)
            check_batch.clear()

    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            original_domain = line.strip().lower()
            if not original_domain:
                continue

            # Validate & normalise domain before processing
            cleaned, reason = clean_domain(original_domain)
            if cleaned is None:
                skipped += 1
                continue
            original_domain = cleaned  # cleaned version (unidecoded, lowered, stripped)

            # Strip the original TLD suffix to get the SLD, then form the .lt twin
            sld = original_domain.rsplit(".", 1)[0]
            if not sld:
                skipped += 1
                continue
            lt_domain = f"{sld}.lt"

            # Intra-batch dedup: don't stage the same twin twice before a flush.
            if lt_domain in new_batch or lt_domain in check_batch:
                duplicates += 1
                continue

            if lt_domain in bloom:
                check_batch[lt_domain] = (lt_domain, original_domain, tld)
            else:
                new_batch[lt_domain] = (lt_domain, original_domain, tld)

            if len(new_batch) + len(check_batch) >= batch_size:
                flush()

    flush()

    if skipped:
        print(f"[IMPORT] Filtered out {skipped} invalid domains from .{tld}.")
    if duplicates:
        print(f"[IMPORT] Skipped {duplicates} already-scanned twins from .{tld}.")
    print(f"[IMPORT] Queued {inserted} new .lt domains for .{tld}.")
    return inserted


# ------------------------
# Export & Stats
# ------------------------


def export_results_for_tld(db_path: str, tld: str, output_dir: Path):
    """Save all checked domains for this TLD to a CSV."""
    conn = get_db_conn(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT original_domain, domain, status FROM domains WHERE source_tld = ?;",
        (tld,),
    )
    rows = cur.fetchall()
    conn.close()

    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "domains.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["original_domain", "lt_domain", "status"])
        writer.writerows(rows)
    print(f"[EXPORT] Wrote {len(rows)} rows to {csv_path}")


def calculate_mirror_index(db_path: str, tld: str) -> dict:
    """Calculate stats for a given TLD."""
    conn = get_db_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM domains WHERE source_tld = ?;", (tld,))
    total = cur.fetchone()[0]

    active_statuses = (
        "registered",
        "blocked",
        "reserved",
        "restricteddisposal",
        "restrictedrights",
    )
    placeholders = ",".join("?" for _ in active_statuses)
    cur.execute(
        f"SELECT COUNT(*) FROM domains WHERE source_tld = ? AND status IN ({placeholders});",
        (tld, *active_statuses),
    )
    active_lt = cur.fetchone()[0]
    conn.close()

    index = (active_lt / total * 100) if total > 0 else 0
    return {"total": total, "registered": active_lt, "index": index}


def write_stats(stats: dict, tld: str, output_dir: Path):
    """Write stats.txt for one TLD."""
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_dir / "stats.txt", "w") as f:
        f.write(f"TLD: .{tld}\n")
        f.write(f"Total: {stats['total']}\n")
        f.write(f"Active .lt mirrors: {stats['registered']}\n")
        f.write(f"Mirror Index: {stats['index']:.2f}%\n")


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
        self._requeue_domains = []

        try:
            while not self.shutdown_event.is_set():
                if self._requeue_domains:
                    try:
                        self._mark_back(self._requeue_domains)
                        self._requeue_domains = []
                    except Exception as e:
                        print(f"[PICKER] Failed to re-queue domains: {e}")
                        time.sleep(0.5)
                        continue

                pending_batch = self._pick_batch(PICK_BATCH_SIZE)
                if not pending_batch:
                    time.sleep(0.25)
                    continue

                picker_self = self
                pending_batch_ref = pending_batch

                def safe_put():
                    try:
                        picker_self.picker_queue.put_nowait(pending_batch_ref)
                    except asyncio.QueueFull:
                        picker_self._requeue_domains.extend(pending_batch_ref)

                try:
                    self.loop.call_soon_threadsafe(safe_put)
                    time.sleep(0.05)
                except Exception as e:
                    print(f"[PICKER] Failed to schedule batch: {e}. Re-queuing domains.")
                    self._requeue_domains.extend(pending_batch)
                    time.sleep(0.2)
        finally:
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
            qmarks = ",".join("?" for _ in rows)
            cur.execute(f"UPDATE domains SET in_progress=1 WHERE domain IN ({qmarks});", tuple(rows))
            self._conn.commit()
            return rows
        except sqlite3.OperationalError as e:
            try:
                self._conn.rollback()
            except Exception:
                pass
            print(f"[PICKER] DB error during pick: {e}")
            return []

    def _mark_back(self, domains: List[str]) -> None:
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
                    add = delta * self.rate
                    self._tokens = min(self.capacity, self._tokens + add)
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            return

    async def get_token(self):
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
            coro = asyncio.open_connection(DAS_HOST, DAS_PORT)
            reader, writer = await asyncio.wait_for(coro, timeout=timeout)
            q = DAS_QUERY_TEMPLATE.format(domain=domain)
            writer.write(q.encode("utf-8"))
            await writer.drain()

            data_chunks = []
            try:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
                while chunk:
                    data_chunks.append(chunk)
                    chunk = await asyncio.wait_for(reader.read(8192), timeout=0.5)
            except asyncio.TimeoutError:
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
# Writer thread (sync)
# ------------------------


class WriterThread(threading.Thread):
    """
    Consumes results from a thread-safe queue.Queue (writer_q).
    Batches DB updates and buffered per-status text files.
    """

    def __init__(self, db_path: str, writer_q: "queue.Queue", output_dir: str, shutdown_event: threading.Event):
        super().__init__(daemon=True, name="WriterThread")
        self.db_path = db_path
        self.writer_q = writer_q
        self.output_dir = Path(output_dir)
        self._conn = None
        self.shutdown_event = shutdown_event
        self.buffers: Dict[str, List[str]] = {}
        self._pending_updates: List[Tuple[str, float, str]] = []
        self.write_batch_size = WRITE_BATCH_SIZE
        self.file_buffer_size = FILE_BUFFER_SIZE

    def run(self):
        self._conn = get_db_conn(self.db_path)
        os.makedirs(self.output_dir, exist_ok=True)
        try:
            self._main_loop()
        finally:
            print("[WRITER] Flushing buffers on shutdown...")
            self._flush_all_buffers()
            if self._conn:
                try:
                    self._conn.close()
                except Exception:
                    pass
            print("[WRITER] Writer thread exiting.")

    def _main_loop(self):
        while not (self.shutdown_event.is_set() and self.writer_q.empty()):
            try:
                item = self.writer_q.get(timeout=0.5)
            except queue.Empty:
                if self._pending_updates:
                    self._flush_db_updates()
                continue
            if item is None:
                break
            domain, status, ts = item
            status = status or "unknown"
            self._pending_updates.append((domain, status, ts))
            buf = self.buffers.setdefault(status, [])
            buf.append(domain)
            if len(buf) >= self.file_buffer_size:
                self._flush_status_file(status)
            if len(self._pending_updates) >= self.write_batch_size:
                self._flush_db_updates()
        if self._pending_updates:
            self._flush_db_updates()
        self._flush_all_buffers()

    def _flush_db_updates(self):
        if not self._pending_updates:
            return
        cur = self._conn.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE;")
            params = [(status, ts, 0, domain) for (domain, status, ts) in self._pending_updates]
            cur.executemany(
                "UPDATE domains SET status=?, last_checked=?, in_progress=? WHERE domain=?;", params
            )
            self._conn.commit()
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
        if self._pending_updates:
            self._flush_db_updates()
        for status in list(self.buffers.keys()):
            self._flush_status_file(status)


# ------------------------
# Context manager utilities
# ------------------------


@contextmanager
def context_ignore_cancel():
    try:
        yield
    except Exception:
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
            consecutive_empty_batches += 1
            if consecutive_empty_batches > 5:
                break
            continue

        if not batch:
            consecutive_empty_batches += 1
            if consecutive_empty_batches > 5:
                break
            continue

        consecutive_empty_batches = 0

        for domain in batch:
            if shutdown_flag.is_set():
                break
            await token_bucket.get_token()
            status = await das_check(domain)
            ts = now_ts()
            async with stats_lock:
                stats["completed"] += 1
                stats_key = f"status:{status}"
                stats[stats_key] = stats.get(stats_key, 0) + 1
            await loop.run_in_executor(None, writer_thread_q.put, (domain, status, ts))
    # worker exiting


async def progress_logger(
    db_path: str,
    shutdown_flag: asyncio.Event,
    stats: Dict[str, int],
    stats_lock: asyncio.Lock,
    check_interval: int = PROGRESS_INTERVAL,
):
    """
    Periodically check stats and log progress when PROGRESS_INTERVAL domains have been completed.
    For small datasets (< check_interval), logs every 5 seconds instead.
    """
    conn = get_db_conn(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM domains;")
        total_domains = cur.fetchone()[0]

        use_time_based = total_domains < check_interval

        last_logged = 0
        last_log_time = time.time()
        start_time = time.time()

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
            await asyncio.sleep(5)

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

            should_log = False
            now = time.time()

            if use_time_based:
                if db_completed > last_logged and (now - last_log_time) >= 5:
                    should_log = True
            else:
                if db_completed - last_logged >= check_interval:
                    should_log = True

            if should_log:
                domains_since_last = db_completed - last_logged
                time_since_last = now - last_log_time
                rps = (domains_since_last / time_since_last) if time_since_last > 0 else 0.0
                eta_hours = (remaining / rps / 3600) if rps > 0 else float("inf")
                pct = (db_completed / total * 100) if total > 0 else 0.0

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
# Scanner engine (refactored from old main_async)
# ------------------------


async def run_scanner_on_pending(output_dir: str = OUTPUT_DIR):
    """
    Run the DAS scanner on all pending domains currently in the DB.
    Reuses the existing engine (picker, workers, writer, token bucket, progress logger).
    Returns only after all pending domains are processed (or shutdown).
    """
    # shared flags
    shutdown_event = threading.Event()  # for threads
    shutdown_flag = asyncio.Event()  # for async tasks

    # Reset stuck rows before starting
    conn = get_db_conn(DB_PATH)
    reset_in_progress(conn)
    conn.close()

    # Get the running loop
    loop = asyncio.get_running_loop()

    # Asyncio queues
    picker_queue: asyncio.Queue = asyncio.Queue(maxsize=CONCURRENCY * 2)
    writer_thread_q: queue.Queue = queue.Queue()

    # Start picker thread with loop reference
    picker = PickerThread(DB_PATH, picker_queue, shutdown_event, loop)
    picker.start()

    # Start writer thread
    writer = WriterThread(DB_PATH, writer_thread_q, output_dir, shutdown_event)
    writer.start()

    # Token bucket
    token_bucket = TokenBucket(RATE)
    await token_bucket.start()

    # Stats dict with lock
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

    print(f"[SCANNER] Starting: {CONCURRENCY} workers, {RATE} req/sec")

    # Check if there's work to do
    conn_check = get_db_conn(DB_PATH)
    cur_check = conn_check.cursor()
    cur_check.execute("SELECT COUNT(*) FROM domains WHERE status='pending';")
    pending_count = cur_check.fetchone()[0]
    conn_check.close()

    if pending_count == 0:
        print(f"[SCANNER] No pending domains to process.")
        # Clean shutdown
        await token_bucket.stop()
        progress_task.cancel()
        try:
            await progress_task
        except asyncio.CancelledError:
            pass
        shutdown_event.set()
        writer.join(timeout=10.0)
        picker.join(timeout=2.0)
        return

    print(f"[SCANNER] {pending_count} domains pending")
    print(f"[SCANNER] Progress will be logged every {PROGRESS_INTERVAL if pending_count >= PROGRESS_INTERVAL else '5 seconds'}")

    # Wait for workers to finish
    try:
        await asyncio.gather(*worker_tasks)
        print("[SCANNER] All workers completed. Shutting down...")
    except asyncio.CancelledError:
        pass
    finally:
        await token_bucket.stop()
        if not progress_task.done():
            progress_task.cancel()
            try:
                await progress_task
            except asyncio.CancelledError:
                pass

    # Signal writer thread to finish
    shutdown_event.set()
    print("[SCANNER] Waiting for writer thread to flush...")
    writer.join(timeout=10.0)
    if writer.is_alive():
        print("[SCANNER] Writer thread did not exit in time; forcing final flush.")
        try:
            writer_thread_q.put_nowait(None)
        except Exception:
            pass
        writer.join(timeout=5)

    picker.join(timeout=2.0)
    if picker.is_alive():
        print("[SCANNER] Picker thread didn't exit cleanly.")

    print("[SCANNER] Scan complete.")

    # --- Auto-retry unknown domains ---
    for retry in range(MAX_UNKNOWN_RETRIES):
        conn_retry = get_db_conn(DB_PATH)
        cur_retry = conn_retry.cursor()
        cur_retry.execute("SELECT COUNT(*) FROM domains WHERE status='unknown';")
        unknown_count = cur_retry.fetchone()[0]
        conn_retry.close()

        if unknown_count == 0:
            break

        print(f"[RETRY] {unknown_count} domain(s) returned 'unknown' — re-scanning (attempt {retry + 1}/{MAX_UNKNOWN_RETRIES})...")

        # Reset unknowns back to pending
        conn_retry = get_db_conn(DB_PATH)
        cur_retry = conn_retry.cursor()
        cur_retry.execute("UPDATE domains SET status='pending', in_progress=0, last_checked=NULL WHERE status='unknown';")
        conn_retry.commit()
        conn_retry.close()

        # Re-run scanner
        shutdown_event = threading.Event()
        shutdown_flag = asyncio.Event()
        loop = asyncio.get_running_loop()

        picker_queue: asyncio.Queue = asyncio.Queue(maxsize=CONCURRENCY * 2)
        writer_thread_q: queue.Queue = queue.Queue()

        picker = PickerThread(DB_PATH, picker_queue, shutdown_event, loop)
        picker.start()

        writer = WriterThread(DB_PATH, writer_thread_q, output_dir, shutdown_event)
        writer.start()

        token_bucket = TokenBucket(RATE)
        await token_bucket.start()

        stats_retry: Dict[str, int] = {"completed": 0}
        stats_lock = asyncio.Lock()

        worker_tasks = [
            asyncio.create_task(worker_task(i, picker_queue, writer_thread_q, token_bucket, shutdown_flag, stats_retry, stats_lock))
            for i in range(CONCURRENCY)
        ]
        progress_task = asyncio.create_task(progress_logger(DB_PATH, shutdown_flag, stats_retry, stats_lock))
        install_signal_handlers(loop, shutdown_event, shutdown_flag)

        print(f"[RETRY] Restarting scanner for {unknown_count} domains...")
        try:
            await asyncio.gather(*worker_tasks)
            print(f"[RETRY] Re-scan complete.")
        except asyncio.CancelledError:
            pass
        finally:
            await token_bucket.stop()
            if not progress_task.done():
                progress_task.cancel()
                try:
                    await progress_task
                except asyncio.CancelledError:
                    pass

        shutdown_event.set()
        writer.join(timeout=10.0)
        picker.join(timeout=2.0)


# ------------------------
# Main and orchestration
# ------------------------


def ensure_dirs():
    Path("assets").mkdir(parents=True, exist_ok=True)
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(TLD_INPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(OUTPUT_ROOT).mkdir(parents=True, exist_ok=True)


def install_signal_handlers(loop: asyncio.AbstractEventLoop, shutdown_event: threading.Event, shutdown_flag: asyncio.Event):
    """
    Signal handlers to coordinate graceful shutdown between threads and asyncio tasks.
    """

    def _handler(signum, frame):
        print(f"\n[SIGNAL] Caught signal {signum}. Shutting down gracefully...")
        shutdown_event.set()
        loop.call_soon_threadsafe(shutdown_flag.set)

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


async def main_async(args):
    """
    Crash-safe loop over TLD files:
    For each TLD file in tld_lists/:
      1. Import domains (forming .lt twins), skip twins already scanned (durable dedup)
      2. Scan pending domains via DAS engine
      3. Record this TLD's scanned twins as durably seen (seen_twins + bloom)
      4. Export results to CSV and calculate & save stats (the done-marker)
      5. Clean up the scan queue rows for this TLD
    Then write a global summary.
    """
    ensure_dirs()

    # Create tables if they don't exist
    conn = get_db_conn(DB_PATH)
    init_db(conn)
    conn.close()

    # Bloom filter: fast in-memory accelerator for dedup. The AUTHORITATIVE dedup record
    # is the persistent seen_twins table; rebuild the bloom from it so cross-TLD dedup
    # survives restarts (a false positive only triggers a DB confirm, never a drop).
    bloom = ScalableBloomFilter(
        initial_capacity=BLOOM_INITIAL_CAPACITY, error_rate=BLOOM_ERROR_RATE
    )
    rebuild_bloom_from_seen(DB_PATH, bloom)

    tld_input_dir = Path(TLD_INPUT_DIR)
    output_root = Path(OUTPUT_ROOT)

    tld_files = sorted(tld_input_dir.glob("*.txt"))
    if not tld_files:
        print(f"[MAIN] No .txt files found in {tld_input_dir}/")
        return

    all_stats = {}

    for tld_file in tld_files:
        tld = tld_file.stem
        # Skip files that look like they have dots in them (not a TLD name)
        if "." in tld:
            print(f"[SKIP] '{tld_file.name}' is not a TLD (contains dot).")
            continue

        output_dir = output_root / tld

        # --- Crash recovery: skip if already processed ---
        if (output_dir / "domains.csv").exists() and (output_dir / "stats.txt").exists():
            print(f"[SKIP] .{tld} already processed (output found). Delete {output_dir} to re-run.")
            # Read stats from file to include in final summary
            try:
                with open(output_dir / "stats.txt") as f:
                    for line in f:
                        if line.startswith("Total:"):
                            total = int(line.split(":")[1].strip())
                        elif line.startswith("Active .lt mirrors:"):
                            registered = int(line.split(":")[1].strip())
                        elif line.startswith("Mirror Index:"):
                            idx = float(line.split(":")[1].strip().rstrip("%"))
                    all_stats[tld] = {"total": total, "registered": registered, "index": idx}
            except Exception:
                pass
            # Idempotent cleanup: a crash between export and the per-TLD delete can leave
            # this completed TLD's rows in `domains`; drop them so they aren't re-scanned
            # under a later TLD. seen_twins is durable and left untouched.
            delete_tld_rows(DB_PATH, tld)
            continue

        print(f"\n=== Processing .{tld} ===")

        try:
            # 1. Import this TLD's domains (queue new twins; skip already-scanned ones)
            conn = get_db_conn(DB_PATH)
            try:
                import_domains_for_tld(conn, tld, str(tld_file), bloom)
            finally:
                conn.close()

            # 2. Scan all pending domains
            await run_scanner_on_pending(str(output_dir))

            # If the scan was interrupted (e.g. a shutdown signal), some twins are still
            # pending. Do NOT mark the TLD done — leave it un-exported so it fully resumes
            # next run — and stop processing further TLDs.
            if pending_count_for_tld(DB_PATH, tld) > 0:
                print(f"[MAIN] .{tld} scan incomplete (pending remain); will resume next run. Stopping.")
                break

            # 3. Record this TLD's scanned twins as durably seen BEFORE writing the
            #    done-marker, so a completed TLD is always reflected in seen_twins.
            record_seen_twins(DB_PATH, tld, bloom)

            # 4. Export results + stats (these files are the crash-recovery done-marker)
            export_results_for_tld(DB_PATH, tld, output_dir)
            stats = calculate_mirror_index(DB_PATH, tld)
            all_stats[tld] = stats
            write_stats(stats, tld, output_dir)

            # 5. Clean up the scan queue to keep the DB lean (seen_twins stays durable)
            delete_tld_rows(DB_PATH, tld)
            print(f"[CLEANUP] Removed .{tld} data from DB.\n")
        except Exception as e:
            # Don't let one bad TLD abort the whole multi-TLD run; it has no done-marker,
            # so it will be retried on the next run.
            print(f"[ERROR] Failed to process .{tld}: {e!r}. Skipping to next TLD.\n")
            continue

    # Final global summary
    if all_stats:
        summary_path = output_root / "all_stats.txt"
        with open(summary_path, "w") as f:
            f.write("TLD,Total,Active,MirrorIndex\n")
            for tld, s in all_stats.items():
                f.write(f".{tld},{s['total']},{s['registered']},{s['index']:.2f}\n")
        print(f"\n[DONE] Global summary saved to {summary_path}")


def parse_args():
    p = argparse.ArgumentParser(description="DAS Scanner — All TLD scanner")
    p.add_argument("--db", default=DB_PATH, help="Path to SQLite DB")
    p.add_argument("--input", default=INPUT_PATH, help="Input domains file (one domain per line) [legacy]")
    p.add_argument("--output", default=OUTPUT_DIR, help="Output folder for per-status text files [legacy]")
    p.add_argument("--tld-dir", default=TLD_INPUT_DIR, help="Directory with TLD .txt files")
    p.add_argument("--output-root", default=OUTPUT_ROOT, help="Root output directory for TLD results")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    # override globals
    DB_PATH = args.db
    INPUT_PATH = args.input
    OUTPUT_DIR = args.output
    TLD_INPUT_DIR = args.tld_dir
    OUTPUT_ROOT = args.output_root

    ensure_dirs()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("[MAIN] Interrupted by user. Exiting.")
