#!/bin/bash
# Extraction Volatility3 — un JSON par plugin
cd /Users/julientaste/testsplunk
IMG=/Users/julientaste/Downloads/base-dc-memory/base-dc-memory.img
VOL=.venv/bin/vol
for plugin in windows.pslist windows.psscan windows.cmdline windows.netscan windows.sessions; do
  out="artifacts/${plugin//./_}.json"
  echo "=== $plugin → $out ($(date +%H:%M:%S)) ==="
  $VOL -q -f "$IMG" -r json "$plugin" > "$out" 2> "artifacts/${plugin//./_}.err" && echo "OK $(wc -c < $out) bytes" || echo "ECHEC (voir .err)"
done
echo "EXTRACTION TERMINEE $(date +%H:%M:%S)"
