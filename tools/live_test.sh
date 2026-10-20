#!/usr/bin/env bash
# Phase 1 live test: start the ETW pipeline, run curl, print both views.
cd /g/OutboundWin
CTL=src/outboundctl/bin/Debug/net8.0/outboundctl.exe
URL=${1:-https://example.com}; HOSTF=${2:-example}; SECS=${3:-12}
rm -f "$TMPDIR/w.out" "$TMPDIR/w.err"
OUTBOUND_DB="${RULES_DB:-C:/Users/THE M/AppData/Local/hermes/cache/scratch/ob_test.db}" $CTL watch --seconds $SECS ${FILTER:---host "$HOSTF"} > "$TMPDIR/w.out" 2> "$TMPDIR/w.err" &
for i in $(seq 1 40); do grep -q READY "$TMPDIR/w.err" 2>/dev/null && break; sleep 0.5; done
sleep 1
echo "=== ground truth (curl)"
if [ -n "$CMD" ]; then eval "$CMD"; else powershell -NoProfile -File tools/curl_test.ps1 -Url "$URL"; fi
wait
echo "=== outboundctl watch (stderr)"; cat "$TMPDIR/w.err"
echo "=== outboundctl watch (rows)"; cat "$TMPDIR/w.out"
echo "=== leftover Outbound* ETW sessions after exit:"; logman query -ets | grep -i outbound || echo "(none)"
