#!/bin/bash
# Daemonize the phone scanner — survives shell/tool disconnection
set -e

cd /home/kaukas/.openclaw/workspace/domenai-bruteforcer

# Clean old state
rm -f assets/phone_scan_checkpoint.txt assets/phone_hits.txt assets/phone_scan_log.txt

# Run in a new session (setsid) so signals don't propagate
setsid python3 -u src/das_scanner_phones.py --start 0 --no-resume \
    >> /tmp/phone_scan.log 2>&1 &
PID=$!

echo "Started scanner (PID: $PID)" >&2
echo "$PID" > /tmp/phone_scanner_pid.txt
echo "$PID"
