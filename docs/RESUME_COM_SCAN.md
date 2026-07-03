# Runbook: scan `.com` (for the operator agent)

Follow these steps **in order**. Copy-paste each command exactly. After each step, check
the "Expected" line. If reality does not match Expected, **stop and report to the humans**
instead of guessing.

Everything runs from the repo:
`/home/kaukas/.openclaw/workspace/domenai-bruteforcer` (adjust if your path differs).

### File map — where things live (do not move them)

| What | Where |
|---|---|
| Fixed scanner code | branch **`all-tld-scanner`** (git) |
| The `.com` list to scan (~160M lines) | `tld_lists_holt/com.txt` |
| Results from previously scanned TLDs | `output/<tld>/` (already on disk) |
| Working database (fresh, we create it) | `com_scan.db` |
| Scan log | `/tmp/com_scan.log` |
| Process id | `/tmp/com_scan.pid` |

---

## Step 1 — Update the code

```bash
cd /home/kaukas/.openclaw/workspace/domenai-bruteforcer
git stash -u 2>/dev/null || true          # park any local edits
git fetch origin all-tld-scanner
git checkout all-tld-scanner
git pull --ff-only origin all-tld-scanner
```

Expected: `git log --oneline -1` shows a recent commit mentioning "retry" or "backfill" or
"dedup". Verify the tools exist:

```bash
grep -c seen_twins src/das_scanner.py     # must be > 0
ls backfill_seen_twins.py                 # must exist
```

## Step 2 — Tune the machine (one-time, reduces failed requests)

```bash
ulimit -n 65535
sudo sysctl -w net.ipv4.tcp_tw_reuse=1 2>/dev/null || echo "no sudo — skip (still fine)"
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535" 2>/dev/null || true
```

Expected: `ulimit -n` now prints `65535`. (The sudo lines are best-effort; if they fail, continue.)

## Step 3 — Seed the dedup table from prior results

This records every already-checked `.lt` twin so we don't re-check it. Use `com_scan.db`
here and for the scan — **the same DB file for both.**

```bash
python3 backfill_seen_twins.py --db com_scan.db --output-root output
```

Expected: the last line says `seen_twins now N unique` with **N in the low millions**
(≈8–9M). If N is `0` or a few hundred, **stop and report** — the results folder is wrong.

> Note: N is only a few million, NOT ~100M. Most prior TLDs were only partly scanned, so
> there isn't much to skip. That's expected — do not treat a "small" N as an error.

## Step 4 — Start the scan (runs for weeks; survives disconnects)

```bash
setsid python3 -u src/das_scanner.py \
    --db com_scan.db --tld-dir tld_lists_holt --output-root output \
    >> /tmp/com_scan.log 2>&1 &
echo $! > /tmp/com_scan.pid
echo "started PID $(cat /tmp/com_scan.pid)"
```

## Step 5 — Verify it actually started deduping (do this ~15 min after Step 4)

```bash
grep -E "Skipped|Queued" /tmp/com_scan.log | tail -3
```

Expected two lines like:
```
[IMPORT] Skipped <a few million> already-scanned twins from .com.
[IMPORT] Queued  ~150,000,000 new .lt domains for .com.
```

- If you see them → **good, report to humans that the scan is running** (see Step 6).
- If `Skipped` is `0` → **stop and report** (dedup didn't load).
- If the import is still running (no lines yet) → wait, it streams 160M lines and takes a while.

## Step 6 — Report back to the humans

**Report immediately when:** import finishes (Step 5 numbers), the process dies, a scan
finishes, or you restart it.

**Otherwise report every 6 hours.** Gather the numbers:

```bash
kill -0 "$(cat /tmp/com_scan.pid)" 2>/dev/null && echo "ALIVE" || echo "DEAD"
sqlite3 com_scan.db "SELECT status, COUNT(*) FROM domains WHERE source_tld='com' GROUP BY status;"
wc -l output/com/available.txt 2>/dev/null     # free .lt twins found so far
grep -E "PROGRESS|ETA|remaining" /tmp/com_scan.log | tail -2
grep -c THROTTLE /tmp/com_scan.log             # how many times it auto-slowed for failures
```

Then post this exact template, filled in:

```
.com scan status
- process: ALIVE / DEAD
- pending (left to scan): <number>
- done this run: <available + registered + blocked + ... counts>
- available .lt found: <wc -l of available.txt>
- unknown so far: <unknown count>
- throttle events: <grep -c THROTTLE>
- latest ETA from log: <paste line>
```

**Raise a flag (report now, don't wait 6h) if:** process is DEAD, `pending` hasn't dropped
between two reports, or `throttle events` keeps climbing fast (means it's getting blocked —
the humans may want to lower `RATE`).

## Step 7 — If it dies or stalls, restart it

It is crash-safe. Re-run the **Step 4** command exactly. It rebuilds its filter from
`seen_twins` and resumes `.com`'s remaining `pending` rows — nothing already scanned is
redone. **Do NOT re-run Step 3 (backfill)** on a restart.

---

## Reference — normal log lines (do not panic)

- `[BLOOM] Rebuilding filter from N previously-seen twins...` — startup, a few minutes. Normal.
- `[THROTTLE] 25 failures in a row — pausing 15s to recover.` — the scanner auto-slowed
  because domreg dropped some requests. Normal and good; it protects the run. Only worry if
  it happens constantly.
- `[RETRY] ... re-scanning (attempt X/5)` — after the main pass, it re-tries the `unknown`
  results up to 5 times with waits between. Normal; this is what drives the failure count down.

## Reference — settings (in `src/das_scanner.py`, change only if a human asks)

- `RATE = 30` — requests/sec. This is the registrar's sanctioned max. Do not exceed 30.
- `MAX_UNKNOWN_RETRIES = 5`, `UNKNOWN_RETRY_BACKOFF = 20` — retry passes for failed lookups.
- `ADAPTIVE_FAIL_STREAK = 25`, `ADAPTIVE_COOLDOWN = 15` — auto-slowdown on failure bursts.

## Reality check — this is a long run

`.com` is ~160M domains and dedup only removes a few million, so ~150M get scanned. At 30/s
that first pass is **~8 weeks**, plus retry passes. That is expected. Keep it alive, keep
reporting, and let the humans decide if they want to narrow the scope.
