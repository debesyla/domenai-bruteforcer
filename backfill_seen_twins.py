#!/usr/bin/env python3
"""
Backfill the durable `seen_twins` dedup table from ALREADY-SCANNED results.

Use this once, before importing a big new TLD list (e.g. .com), when a prior run
already scanned other TLDs and you do NOT want to re-check the .lt twins that were
already checked. It reads the existing per-TLD result files under output/ and records
every .lt twin it finds into the `seen_twins` table. The scanner then rebuilds its
bloom from `seen_twins` on startup and skips those twins during import.

Sources, per output/<tld>/ directory:
  * domains.csv               (written when a TLD finishes; twin is the .lt column)
  * <status>.txt              (available.txt, registered.txt, ... — one twin per line;
                               used as a fallback when domains.csv is absent, e.g. a
                               TLD that was interrupted mid-scan)

Standalone: uses only the Python stdlib. It does NOT import the scanner and does NOT
need pybloom_live. Safe to re-run (idempotent — INSERT OR IGNORE).
"""
import argparse
import csv
import os
import sqlite3

COMMIT_EVERY = 50_000
PROGRESS_EVERY = 1_000_000


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    # Must match the scanner's schema (src/das_scanner.py: init_db).
    conn.execute("CREATE TABLE IF NOT EXISTS seen_twins (domain TEXT PRIMARY KEY);")
    conn.commit()


def iter_twins_from_csv(path: str):
    """Yield the .lt twin from each CSV row (robust to column order / missing header)."""
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            for cell in row:
                c = cell.strip().lower()
                if c.endswith(".lt"):
                    yield c
                    break


def iter_twins_from_txt(path: str):
    """Yield each .lt twin from a per-status text file (one domain per line)."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            c = line.strip().lower()
            if c.endswith(".lt"):
                yield c


def tld_dir_sources(tld_dir: str):
    """Pick the result files to read for one TLD dir: prefer domains.csv, else *.txt."""
    csv_path = os.path.join(tld_dir, "domains.csv")
    if os.path.isfile(csv_path):
        yield ("csv", csv_path)
        return
    for name in sorted(os.listdir(tld_dir)):
        if name.endswith(".txt") and name != "stats.txt":
            yield ("txt", os.path.join(tld_dir, name))


def main() -> None:
    ap = argparse.ArgumentParser(description="Backfill seen_twins from scanned results")
    ap.add_argument("--db", default="scan_state.db", help="SQLite DB path (default: scan_state.db)")
    ap.add_argument("--output-root", default="output", help="Root of per-TLD result dirs (default: output)")
    args = ap.parse_args()

    if not os.path.isdir(args.output_root):
        raise SystemExit(f"[BACKFILL] output root not found: {args.output_root}")

    tld_dirs = sorted(
        os.path.join(args.output_root, d)
        for d in os.listdir(args.output_root)
        if os.path.isdir(os.path.join(args.output_root, d))
    )
    if not tld_dirs:
        raise SystemExit(f"[BACKFILL] no per-TLD dirs under {args.output_root}/")

    conn = sqlite3.connect(args.db, timeout=60.0)
    ensure_schema(conn)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM seen_twins;")
    start = cur.fetchone()[0]
    print(f"[BACKFILL] seen_twins starts with {start:,} twins; reading {len(tld_dirs)} TLD dir(s)...")

    seen = 0
    pending = 0

    def flush():
        nonlocal pending
        if pending:
            conn.commit()
            pending = 0

    for tld_dir in tld_dirs:
        before_dir = seen
        for kind, path in tld_dir_sources(tld_dir):
            it = iter_twins_from_csv(path) if kind == "csv" else iter_twins_from_txt(path)
            for twin in it:
                cur.execute("INSERT OR IGNORE INTO seen_twins(domain) VALUES (?);", (twin,))
                seen += 1
                pending += 1
                if pending >= COMMIT_EVERY:
                    flush()
                if seen % PROGRESS_EVERY == 0:
                    print(f"[BACKFILL]   ...{seen:,} twins read so far")
        print(f"[BACKFILL] {os.path.basename(tld_dir)}: read {seen - before_dir:,} twins")

    flush()
    cur.execute("SELECT COUNT(*) FROM seen_twins;")
    end = cur.fetchone()[0]
    conn.close()
    print(
        f"[BACKFILL] Done. Read {seen:,} twin entries; "
        f"seen_twins now {end:,} unique (+{end - start:,} new)."
    )


if __name__ == "__main__":
    main()
