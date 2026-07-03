# Resuming the scan with `.com` (without re-checking already-scanned twins)

**Goal:** every TLD except `.com` has already been scanned; their results live under
`output/<tld>/`. We now want to scan the huge `.com` list, but **skip every `.lt` twin
that was already checked under another TLD** instead of re-querying ~100M domains. Twins
that previously came back `unknown` (timeouts / errors / unparseable replies) are the one
exception — those are **re-scanned**, not skipped.

How it works: a durable `seen_twins` table records every twin that has a clear result.
The scanner rebuilds its in-memory bloom filter from that table on startup and skips those
twins at import time. False positives are confirmed against the table, so no real domain is
ever silently dropped.

> These instructions are self-contained. Run them from the repo root
> (`/home/kaukas/.openclaw/workspace/domenai-bruteforcer` — adjust if different).

---

## 0. Be on the fixed code

The dedup fix and the backfill tool are on branch `claude/bloom-filter-review-ktar2z`.
Your scan data is safe — `output/` and `*.db` are gitignored, so switching branches will
not touch them.

```bash
git stash -u 2>/dev/null || true
git fetch origin claude/bloom-filter-review-ktar2z
git checkout claude/bloom-filter-review-ktar2z
git pull origin claude/bloom-filter-review-ktar2z
```

Sanity check you have the new code:

```bash
grep -c seen_twins src/das_scanner.py   # must be > 0
ls backfill_seen_twins.py               # must exist
```

Dependencies (`pybloom_live`, `unidecode`) are already installed from the previous scans.
If an import ever fails: `pip install -r requirements.txt`.

We use a dedicated DB `com_scan.db` for a clean slate — use the **same** `--db` for the
backfill and the scan.

## 1. Backfill the "already-checked" set from existing results

Reads `output/<tld>/domains.csv` (and per-status `.txt` files as a fallback) and records
every twin with a **clear** status into `seen_twins`. `unknown` twins are intentionally
left out so they get re-scanned.

```bash
python3 backfill_seen_twins.py --db com_scan.db --output-root output
```

Check the final line: `seen_twins now N unique`. **N should be roughly the number you
already scanned (~100M).** If N is near zero, stop and fix `--output-root`/`--db` before
continuing — otherwise everything would be re-scanned.

## 2. Confirm the `.com` list is in place

The list is at `tld_lists_holt/com.txt` (one domain per line, e.g. `example.com`). We point
`--tld-dir` at that folder so **only** `.com` is processed:

```bash
wc -l tld_lists_holt/com.txt   # expect ~160,000,000
```

## 3. Launch the scan (background, survives disconnects)

```bash
setsid python3 -u src/das_scanner.py \
    --db com_scan.db --tld-dir tld_lists_holt --output-root output \
    >> /tmp/com_scan.log 2>&1 &
echo $! > /tmp/com_scan.pid
echo "started PID $(cat /tmp/com_scan.pid)"
```

What the log shows, in order:
1. `[BLOOM] Rebuilding filter from ~100,000,000 previously-seen twins...` — a few minutes,
   happens on every start. Normal.
2. `[IMPORT] Skipped <~100M> already-scanned twins` and
   `[IMPORT] Queued <~60M> new .lt domains` — **this is the proof the dedup worked.**
   The import itself takes a while (it streams 160M lines and confirms the hits against the
   DB) before scanning visibly starts.
3. `[SCANNER] <~60M> domains pending` → scanning begins at 28 req/sec.

## 4. Monitoring & reporting duties (openclaw: do this, don't just launch and leave)

Do not block waiting — use your periodic self-check-in / loop, and **report to the user**:

- **Right after import:** report the exact `Skipped` and `Queued` numbers. If `Skipped` is
  ~0, raise the alarm — the backfill didn't take.
- **Every few hours:** report progress, hits, and ETA. Gather it with:

  ```bash
  # remaining vs done for .com
  sqlite3 com_scan.db "SELECT status, COUNT(*) FROM domains WHERE source_tld='com' GROUP BY status;"
  # free .lt twins found so far (the interesting output):
  wc -l output/com/available.txt 2>/dev/null
  # latest progress/ETA lines the scanner prints:
  grep -E "PROGRESS|ETA|remaining" /tmp/com_scan.log | tail -3
  ```

  Progress ≈ (queued − pending) / queued. Report % done, `available` count, and the ETA.
- **Liveness:** if the process is gone or the log has not advanced in a while, treat it as a
  crash — restart it (next section) and tell the user you did.
- **When finished:** `output/com/domains.csv` and `output/com/stats.txt` appear. Report the
  final counts (total scanned, active `.lt` mirrors, mirror index) and where the files are.

## 5. If it stops / crashes — just restart the same command

It is crash-safe and resumable. Re-run the **exact** launch command from step 3. On restart
the scanner rebuilds the bloom from `seen_twins` and picks up `.com`'s remaining pending
rows — nothing already scanned is redone.

**Do not re-run the backfill** on a restart (harmless but pointless). Only re-run it if you
wipe `com_scan.db`.

## Notes

- **Rate / ETA:** the scanner runs at **28 req/sec** (`RATE` in `src/das_scanner.py`). At
  that rate ~60M domains is on the order of **~25 days**. To go faster, raise `RATE` (and
  `CONCURRENCY`) — but only as far as `das.domreg.lt` tolerates without rate-limiting or
  banning. Changing it takes effect on the next restart.
- **Disk:** `seen_twins` at ~100M rows is a few GB in SQLite — make sure there's headroom.
- **Live results** stream to `output/com/available.txt` (and `registered.txt`, etc.) as they
  are found — you don't have to wait for the end.
