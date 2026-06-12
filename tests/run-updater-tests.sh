#!/usr/bin/env bash
# Tests for scripts/update-list.py. No network: gh is stubbed via UPDATE_LIST_FIXTURE.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UPD="$ROOT/scripts/update-list.py"
FIX="$ROOT/tests/fixtures/updater"
PASS=0; FAIL=0; CURRENT=""

begin() { CURRENT="$1"; }
ok()    { PASS=$((PASS + 1)); printf 'ok   - %s: %s\n' "$CURRENT" "$1"; }
failed() { FAIL=$((FAIL + 1)); printf 'FAIL - %s: %s\n' "$CURRENT" "$1"; }

assert_rc() {
  if [[ "$RC" -eq "$1" ]]; then ok "exit code $1"
  else failed "expected exit $1, got $RC. output: $OUT"; fi
}
assert_contains() {
  if [[ "$OUT" == *"$1"* ]]; then ok "output contains '$1'"
  else failed "output missing '$1'. output: $OUT"; fi
}
assert_not_contains() {
  if [[ "$OUT" != *"$1"* ]]; then ok "output lacks '$1'"
  else failed "output unexpectedly contains '$1'. output: $OUT"; fi
}

test_help() {
  begin "help"
  OUT="$(python3 "$UPD" --help 2>&1)"; RC=$?
  assert_rc 0
  assert_contains "update-list"
  assert_contains "--apply"
  assert_contains "network"
}

test_load_signatures() {
  begin "load signatures"
  # --print-signatures is a hidden debug flag added in this task.
  OUT="$(ACC_INDICATORS="$FIX/indicators-sample.tsv" python3 "$UPD" --print-signatures 2>&1)"; RC=$?
  assert_rc 0
  assert_contains "atomic-lockfile"
  assert_contains "src/hooks/deps"
  assert_not_contains "evil.example.test"   # domains are NOT signatures
}

test_discover() {
  begin "discover from fixture activity"
  OUT="$(UPDATE_LIST_FIXTURE="$FIX" ACC_INDICATORS="$FIX/indicators-sample.tsv" \
         python3 "$UPD" --print-discovered 2>&1)"; RC=$?
  assert_rc 0
  assert_contains "evil-new-pkg"      # push: compare diff ADDS 'atomic-lockfile'
  assert_contains "reset-victim"      # force_push: compare diff REMOVES 'src/hooks/deps' (cleanup still flags it)
  assert_contains "new-evil-pkg"      # branch_creation (null before): diffed via commit, adds 'lockfile-js'
  assert_not_contains "innocent-pkg"  # its diff has no signature
}

test_dry_run_writes_nothing() {
  begin "dry-run writes nothing"
  local tmp; tmp="$(mktemp -d)"
  cp "$FIX/findings-min.json" "$tmp/findings.json"
  : > "$tmp/compromised-packages.tsv"; : > "$tmp/indicators.tsv"
  local before; before="$(cat "$tmp/findings.json")"
  OUT="$(UPDATE_LIST_FIXTURE="$FIX" ACC_INDICATORS="$FIX/indicators-sample.tsv" \
         ACC_FINDINGS="$tmp/findings.json" ACC_PKG_TSV="$tmp/compromised-packages.tsv" \
         ACC_IOC_TSV="$tmp/indicators.tsv" python3 "$UPD" 2>&1)"; RC=$?
  assert_rc 0
  assert_contains "DRY RUN"
  assert_contains "evil-new-pkg"          # shown as a would-be addition
  # findings.json must be byte-identical after a dry run
  if [[ "$(cat "$tmp/findings.json")" == "$before" ]]; then ok "findings.json unchanged"
  else failed "dry run modified findings.json"; fi
  # dry run must NOT write the freshness stamp
  if [[ ! -e "$tmp/last-updated.txt" ]]; then ok "no last-updated.txt on dry run"
  else failed "dry run wrote last-updated.txt"; fi
  rm -rf "$tmp"
}

test_apply_writes() {
  begin "--apply writes the new package"
  local tmp; tmp="$(mktemp -d)"
  cp "$FIX/findings-min.json" "$tmp/findings.json"
  : > "$tmp/compromised-packages.tsv"; : > "$tmp/indicators.tsv"
  OUT="$(UPDATE_LIST_FIXTURE="$FIX" ACC_INDICATORS="$FIX/indicators-sample.tsv" \
         ACC_FINDINGS="$tmp/findings.json" ACC_PKG_TSV="$tmp/compromised-packages.tsv" \
         ACC_IOC_TSV="$tmp/indicators.tsv" python3 "$UPD" --apply 2>&1)"; RC=$?
  assert_rc 0
  assert_contains "Wrote"
  if grep -q "^evil-new-pkg	" "$tmp/compromised-packages.tsv"; then ok "evil-new-pkg in data file"
  else failed "evil-new-pkg not written. file: $(cat "$tmp/compromised-packages.tsv")"; fi
  # --apply must write the freshness stamp (ISO 8601 UTC) next to the data files
  if [[ -s "$tmp/last-updated.txt" ]] && grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]+Z$' "$tmp/last-updated.txt"; then ok "last-updated.txt written"
  else failed "last-updated.txt missing/malformed: [$(cat "$tmp/last-updated.txt" 2>/dev/null)]"; fi
  rm -rf "$tmp"
}

test_max_events_cap() {
  begin "--max-events caps the scan"
  # activity.json order: evil-new-pkg, reset-victim, innocent-pkg. With a cap of
  # 1, only the first event is diffed, so reset-victim is never reached.
  OUT="$(UPDATE_LIST_FIXTURE="$FIX" ACC_INDICATORS="$FIX/indicators-sample.tsv" \
         python3 "$UPD" --print-discovered --max-events 1 2>&1)"; RC=$?
  assert_rc 0
  assert_contains "evil-new-pkg"
  assert_not_contains "reset-victim"
}

test_malformed_activity_errors_cleanly() {
  begin "malformed activity -> clean error, exit 2 (no traceback)"
  local tmp; tmp="$(mktemp -d)"
  printf 'this is not json' > "$tmp/activity.json"
  OUT="$(UPDATE_LIST_FIXTURE="$tmp" ACC_INDICATORS="$FIX/indicators-sample.tsv" \
         python3 "$UPD" --print-discovered 2>&1)"; RC=$?
  assert_rc 2
  assert_contains "error: discovery failed"
  assert_not_contains "Traceback"
  rm -rf "$tmp"
}

test_gh_missing_preflight() {
  begin "missing gh -> preflight exit 3 (no fixture)"
  local tmp; tmp="$(mktemp -d)"
  ln -s "$(command -v python3)" "$tmp/python3"   # python3 present, gh absent from PATH
  # No UPDATE_LIST_FIXTURE, so gh_preflight runs for real and finds no gh.
  OUT="$(PATH="$tmp" ACC_INDICATORS="$FIX/indicators-sample.tsv" \
         "$tmp/python3" "$UPD" --days 1 2>&1)"; RC=$?
  assert_rc 3
  assert_contains "gh"
  rm -rf "$tmp"
}

test_help
test_load_signatures
test_discover
test_dry_run_writes_nothing
test_apply_writes
test_max_events_cap
test_malformed_activity_errors_cleanly
test_gh_missing_preflight

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
