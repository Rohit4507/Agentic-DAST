#!/usr/bin/env bash
# Reset the demo state and make sure the bundled target is answering.
# Run this a minute before you hit record.  Nothing here touches a network
# other than 127.0.0.1.
#
#   bash deck/video/prepare.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PORT="${PORT:-8080}"
BASE="http://127.0.0.1:${PORT}"

health() {
  python3 - "$BASE" <<'PY' >/dev/null 2>&1
import sys, urllib.request
urllib.request.urlopen(sys.argv[1] + "/healthz", timeout=1.5).read()
PY
}

if health; then
  echo "target already answering on ${BASE}"
else
  echo "starting target on port ${PORT} ..."
  nohup python3 -m target.app --port "${PORT}" > /tmp/dast-target.log 2>&1 &
  for _ in $(seq 1 40); do
    sleep 0.25
    if health; then break; fi
  done
  if ! health; then
    echo "target did not come up; see /tmp/dast-target.log" >&2
    exit 2
  fi
  echo "target up"
fi

# A stale work/ double-counts audit entries (that is how 47 becomes 60 on camera).
rm -rf work work2 work-[0-9]* 2>/dev/null || true
echo "work/ reset"

cat > deck/video/event.json <<'JSON'
{
  "sha": "9f3c1ab77d2e4c55",
  "service": "tbo-orders-api",
  "at": "2026-11-19T09:14:00Z",
  "actor": "ci-bot",
  "changed_paths": ["/api/refund", "/api/rebook", "/api/pay"],
  "bundle_urls": []
}
JSON
echo "deploy event written to deck/video/event.json"

cat <<'NEXT'

Ready.  Record these, in this order (see deck/VIDEO_SCRIPT.md for the shot list).
The deploy-scoped run uses its own directory so the full run's report stays on
disk for the artefacts shot.

  1  python3 run.py all --approve-writes
  2  sed -n '1,22p' work/findings/F-006/report.md
  3  python3 run.py guard-demo
  4  cat deck/video/event.json
  5  mkdir -p work-delta && cp work/inventory.json work-delta/
  6  python3 run.py diff --deploy-event deck/video/event.json --out work-delta
  7  python3 run.py scan --out work-delta --changed-only --approve-writes
  8  python3 run.py retest
  9  sed -n '1,22p' work/REPORT.md
NEXT
