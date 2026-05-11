# special-phones branch — Phone-number-pattern DAS scan

This branch adds a second scanner (`src/das_scanner_phones.py`) alongside
the original. It is optimized for checking all `3706XXXXXXX.lt` domain
names (10M total) against the .lt DAS service.

## Key differences from main

| Aspect | Original (`das_scanner.py`) | Phone scanner (`das_scanner_phones.py`) |
|---|---|---|
| Input | `assets/input.txt` (one domain per line) | Auto-generated from `3706` + incrementing 7-digit numbers |
| Database | SQLite (`scan_state.db`) tracks every domain | No database — only hits are logged |
| Rate | 30 req/sec | 20 req/sec (gentler) |
| Batching | Batch inserts + batch file writes | Immediate per-hit file append |
| Output | Per-status text files for ALL results | Single `assets/phone_hits.txt` with only non-available domains |
| Resume | Via SQLite `in_progress` markers | Via checkpoint file (`assets/phone_scan_checkpoint.txt`) |
| Dependencies | Python 3.10+ stdlib | Same |

## How to run

```bash
# Full scan (37060000000.lt → 37069999999.lt, ~6 days)
python3 src/das_scanner_phones.py

# Partial scan (testing)
python3 src/das_scanner_phones.py --start 0 --end 9999

# Resume from checkpoint (automatic)
python3 src/das_scanner_phones.py

# Force fresh start (ignore checkpoint)
python3 src/das_scanner_phones.py --no-resume
```

## Output

- `assets/phone_hits.txt` — One line per non-available domain: `3706XXXXXXX.lt -> registered|blocked|reserved|...`
- `assets/phone_scan_checkpoint.txt` — Last scanned number (auto-resume on next run)

## Expected results

Out of 10M phone-pattern domains, ~99.99999% will return `available`.
Only vanity/hijacked domains show up as hits. The hits file should stay
tiny — that's the needle-in-a-haystack dynamic.
