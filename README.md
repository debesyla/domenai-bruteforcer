# Domain DAS Scanner

A simple, robust scanner for querying the .lt Domain Availability Service (DAS). It processes a large list of .lt domains from a text file, checks their status via the DAS protocol, and stores results in a SQLite database and separate text files per status.

## AI notice

This readme.md and most of the code was AI-generated, human reviewed.

## Features

- Processes 60M+ domains efficiently
- Asynchronous workers with rate limiting (28 req/sec)
- Durable cross-TLD/cross-restart dedup (`seen_twins` table + bloom accelerator)
- Resume capability after interruptions
- Outputs to SQLite DB and per-status text files

## Quick Start

1. Prepare `assets/input.txt` with one domain per line (e.g., `example.lt`). See `assets/input_example.txt` for a sample input file.
2. Run: `python3 src/das_scanner.py`
3. Results in `scan_state.db` and `assets/output/`.

## Requirements

- Python 3.10+

## Resuming with a new TLD (e.g. `.com`) without re-checking

To scan a large new TLD while skipping every `.lt` twin already checked under other TLDs,
follow [RESUME_COM_SCAN.md](docs/RESUME_COM_SCAN.md). In short: run
`backfill_seen_twins.py` to seed the durable dedup table from existing results, then start
the scanner — it skips the already-checked twins automatically.

## Details

See [IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md) for full specifications, architecture, and usage examples.

## License

Do whatever.
