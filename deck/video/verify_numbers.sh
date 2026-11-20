#!/usr/bin/env bash
# Assert that the numbers on the deck are the numbers this machine prints.
#
# Every figure on the slides has to come from a real run.  This script runs the
# full demo sequence against the bundled target, compares each figure the deck
# claims, and exits non-zero on the first mismatch.  Run it immediately before
# recording; the state it leaves behind is the state you want on camera.
#
#   bash deck/video/verify_numbers.sh
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
PORT="${PORT:-8080}"
BASE="http://127.0.0.1:${PORT}"

fails=0
check() { # label expected actual
  if [ "$2" = "$3" ]; then
    printf '  PASS  %-28s %s\n' "$1" "$3"
  else
    printf '  FAIL  %-28s expected %s, got %s\n' "$1" "$2" "${3:-<nothing>}"
    fails=$((fails + 1))
  fi
}

[ -f deck/video/event.json ] || { echo "deck/video/event.json is missing" >&2; exit 2; }

python3 - "$BASE" <<'PY' >/dev/null 2>&1 || { echo "target not answering on $BASE — run: bash deck/video/prepare.sh" >&2; exit 2; }
import sys, urllib.request
urllib.request.urlopen(sys.argv[1] + "/healthz", timeout=1.5).read()
PY

rm -rf work work-delta
echo "== full run =="
full="$(python3 run.py all --approve-writes 2>&1)"
echo "$full" | tail -4

check "verified findings"        "7"  "$(echo "$full" | grep -cE '^F-0[0-9][0-9] ')"
check "dedupe"                   "8 raw hits -> 7 findings" "$(echo "$full" | grep -oE '8 raw hits -> 7 findings')"
check "endpoints"                "13 endpoints: 9 active, 1 shadow, 3 zombie" "$(echo "$full" | grep -oE '13 endpoints: 9 active, 1 shadow, 3 zombie')"
check "requests sent"            "39" "$(echo "$full" | grep -oE '"sent": [0-9]+' | head -1 | grep -oE '[0-9]+')"
check "requests denied"          "0"  "$(echo "$full" | grep -oE '"denied": [0-9]+' | head -1 | grep -oE '[0-9]+')"
check "budget left"              "81" "$(echo "$full" | grep -oE '"budget_remaining": [0-9]+' | head -1 | grep -oE '[0-9]+')"
check "audit entries"            "47" "$(echo "$full" | grep -oE 'audit: [0-9]+ entries' | grep -oE '[0-9]+')"
check "chain"                    "chain intact" "$(echo "$full" | grep -oE 'chain intact')"
elapsed="$(echo "$full" | grep -oE 'elapsed: [0-9.]+s' | grep -oE '[0-9.]+')"
if python3 -c "import sys; sys.exit(0 if ${elapsed:-99} <= 5.0 else 1)"; then
  printf '  PASS  %-28s %ss (deck says 3.89 s)\n' "elapsed" "$elapsed"
else
  printf '  FAIL  %-28s %ss is more than 5 s\n' "elapsed" "$elapsed"; fails=$((fails + 1))
fi

echo "== guard-demo =="
guard="$(python3 run.py guard-demo 2>&1)"
check "out-of-scope refused"     "8/8 out-of-scope attempts refused, 2/2 in-scope requests allowed" \
      "$(echo "$guard" | grep -oE '8/8 out-of-scope attempts refused, 2/2 in-scope requests allowed')"

echo "== deploy-scoped run =="
mkdir -p work-delta && cp work/inventory.json work-delta/
python3 run.py diff --deploy-event deck/video/event.json --out work-delta >/dev/null 2>&1
delta="$(python3 run.py scan --out work-delta --changed-only --approve-writes 2>&1)"
check "requests instead of 39"   "17" "$(echo "$delta" | grep -oE '"sent": [0-9]+' | head -1 | grep -oE '[0-9]+')"
check "findings on those routes" "2"  "$(echo "$delta" | grep -cE '^F-0[0-9][0-9] ')"
check "deferred"                 "11" "$(echo "$delta" | grep -oE '[0-9]+ deferred' | grep -oE '[0-9]+')"

echo "== retest =="
retest="$(python3 run.py retest 2>&1)"
check "retested"                 "7 retested, 0 now fixed, 7 still open" \
      "$(echo "$retest" | grep -oE '7 retested, 0 now fixed, 7 still open')"

echo "== test suite =="
suite="$(python3 -m unittest discover -s tests 2>&1)"
check "tests"                    "228" "$(echo "$suite" | grep -oE 'Ran [0-9]+ tests' | grep -oE '[0-9]+')"
check "tests green"              "OK"  "$(echo "$suite" | grep -oE '^OK$' | head -1)"

echo
if [ "$fails" -eq 0 ]; then
  echo "All deck numbers reproduced from a real run. You are clear to record."
  echo "State on disk: work/ (full run, 7 findings) and work-delta/ (deploy-scoped run)."
  exit 0
fi
echo "$fails figure(s) do not match. Fix the deck or the code before recording." >&2
exit 1
