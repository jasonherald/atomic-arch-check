#!/usr/bin/env bash
# Test suite for check-aur-compromise.sh.
# Uses ONLY harmless fixture data — fake package names, empty marker files.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/check-aur-compromise.sh"
FIX="$ROOT/tests/fixtures"
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

# run_check <fixture-dir-name> [extra script args...]
# Captures combined output in OUT and exit code in RC.
run_check() {
  local fixture="$1"; shift
  OUT="$(ACC_DATA_DIR="$FIX/data" \
         ACC_QM_FILE="$FIX/$fixture/qm.txt" \
         ACC_PACMAN_LOG="$FIX/$fixture/pacman.log" \
         ACC_CACHE_DIRS="$FIX/$fixture/cache" \
         ACC_HOME_ROOTS="$FIX/$fixture/home" \
         ACC_HOSTS_FILE="$FIX/$fixture/hosts" \
         ACC_SYSTEMD_DIRS="$FIX/$fixture/systemd" \
         bash "$SCRIPT" --no-color "$@" 2>&1)"
  RC=$?
}

test_help() {
  begin "help"
  OUT="$(bash "$SCRIPT" --help 2>&1)"; RC=$?
  assert_rc 0
  assert_contains "Usage:"
  assert_contains "read-only"
}

test_clean_system() {
  begin "clean system"
  run_check clean
  assert_rc 0
  assert_contains "CLEAN"
}

test_data_loaded() {
  begin "data loading"
  run_check clean
  # fixture data has 2 packages and 7 indicators
  assert_contains "(2 packages, 7 indicators)"
}

test_malformed_rows_skipped() {
  begin "malformed data rows"
  OUT="$(ACC_DATA_DIR="$FIX/malformed/data" \
         ACC_QM_FILE="$FIX/malformed/qm.txt" \
         ACC_PACMAN_LOG="$FIX/malformed/pacman.log" \
         ACC_CACHE_DIRS="$FIX/malformed/cache" \
         ACC_HOME_ROOTS="$FIX/malformed/home" \
         ACC_HOSTS_FILE="$FIX/malformed/hosts" \
         ACC_SYSTEMD_DIRS="$FIX/malformed/systemd" \
         bash "$SCRIPT" --no-color 2>&1)"
  RC=$?
  assert_rc 0
  assert_contains "malformed row"
  assert_contains "(1 packages, 1 indicators)"
}

test_missing_data_dir_errors() {
  begin "missing data dir"
  OUT="$(ACC_DATA_DIR=/nonexistent-acc-test bash "$SCRIPT" --no-color 2>&1)"
  RC=$?
  assert_rc 3
  assert_contains "cannot read"
}

test_installed_bad_version() {
  begin "installed at known-bad version"
  run_check bad-version
  assert_rc 1
  assert_contains "[CRIT]"
  assert_contains "evil-pkg"
  assert_contains "1.2.3-1"
}

test_installed_other_version() {
  begin "installed listed pkg, other version"
  run_check listed-other-version
  assert_rc 2
  assert_contains "[WARN]"
  assert_contains "evil-pkg"
  assert_not_contains "[CRIT]"
}

test_history_bad_version() {
  begin "history: bad version was installed"
  run_check history-bad-version
  assert_rc 1
  assert_contains "[CRIT]"
  assert_contains "evil-pkg"
}

test_history_in_window() {
  begin "history: installed inside malicious window"
  run_check history-in-window
  assert_rc 2
  assert_contains "[WARN]"
  assert_contains "2026-06-10"
}

test_history_outside_window() {
  begin "history: installed outside window"
  run_check history-outside-window
  assert_rc 0
  assert_contains "[INFO]"
  assert_contains "evil-pkg"
}

test_missing_pacman_log_skipped() {
  begin "missing pacman.log -> SKIP"
  run_check no-log
  assert_rc 0
  assert_contains "[SKIP]"
  assert_contains "pacman.log"
}

test_cache_malicious_pattern() {
  begin "cache: PKGBUILD contains malicious pattern (even unlisted pkg)"
  run_check cache-pattern
  assert_rc 1
  assert_contains "[CRIT]"
  assert_contains "fake-malicious-npm"
}

test_cache_listed_clone_info() {
  begin "cache: clean clone of listed package -> INFO"
  run_check cache-listed
  assert_rc 0
  assert_contains "[INFO]"
  assert_contains "evil-pkg"
}

test_ioc_file_path() {
  begin "ioc: dropped file present"
  run_check ioc-file
  assert_rc 1
  assert_contains "[CRIT]"
  assert_contains ".fake-marker"
}

test_ioc_npm_module() {
  begin "ioc: malicious npm module present"
  run_check ioc-npm
  assert_rc 1
  assert_contains "node_modules/fake-malicious-npm"
}

test_ioc_npm_cache() {
  begin "ioc: npm cache references malicious package"
  run_check ioc-npm-cache
  assert_rc 1
  assert_contains "npm cache"
}

test_ioc_systemd_unit() {
  begin "ioc: suspicious systemd unit"
  run_check ioc-systemd
  assert_rc 1
  assert_contains "fake-evil.service"
}

test_ioc_hash_match() {
  begin "ioc: file matches known-bad sha256"
  run_check ioc-hash
  assert_rc 1
  assert_contains "sha256"
}

test_ioc_domain_in_hosts() {
  begin "ioc: indicator domain in hosts file"
  run_check ioc-hosts
  assert_rc 2
  assert_contains "evil.example.test"
}

test_ioc_domain_manual_review() {
  begin "ioc: domain emits manual-review INFO on clean system"
  run_check clean
  assert_contains "Manual review"
}

test_quiet_mode() {
  begin "quiet mode"
  run_check bad-version --quiet
  assert_rc 1
  assert_contains "VERDICT: CRITICAL"
  assert_not_contains "[CRIT]"
}

test_real_data_files_lint() {
  begin "real data files parse cleanly"
  OUT="$(ACC_DATA_DIR="$ROOT/data" \
         ACC_QM_FILE="$FIX/clean/qm.txt" \
         ACC_PACMAN_LOG="$FIX/clean/pacman.log" \
         ACC_CACHE_DIRS="$FIX/clean/cache" \
         ACC_HOME_ROOTS="$FIX/clean/home" \
         ACC_HOSTS_FILE="$FIX/clean/hosts" \
         ACC_SYSTEMD_DIRS="$FIX/clean/systemd" \
         bash "$SCRIPT" --no-color 2>&1)"
  RC=$?
  assert_rc 0
  assert_not_contains "malformed row"
}

test_help
test_clean_system
test_data_loaded
test_malformed_rows_skipped
test_missing_data_dir_errors
test_installed_bad_version
test_installed_other_version
test_history_bad_version
test_history_in_window
test_history_outside_window
test_missing_pacman_log_skipped
test_cache_malicious_pattern
test_cache_listed_clone_info
test_ioc_file_path
test_ioc_npm_module
test_ioc_npm_cache
test_ioc_systemd_unit
test_ioc_hash_match
test_ioc_domain_in_hosts
test_ioc_domain_manual_review
test_quiet_mode
test_real_data_files_lint

test_history_downgrade_to_bad() {
  begin "history: downgrade TO known-bad version -> CRIT"
  run_check history-downgrade
  assert_rc 1
  assert_contains "[CRIT]"
  assert_contains "downgraded"
}

test_history_rotated_gz() {
  begin "history: bad install only in rotated .gz log is found"
  run_check history-rotated
  assert_rc 1
  assert_contains "[CRIT]"
  assert_contains "evil-pkg"
}

test_domain_substring_no_false_positive() {
  begin "domain: substring in hosts must NOT warn"
  run_check domain-substr
  assert_rc 0
  assert_not_contains "[WARN]"
}

test_data_no_field_whitespace() {
  begin "real data files: no leading/trailing whitespace in fields"
  local out
  out="$(awk -F'\t' '/^#/||/^[[:space:]]*$/{next}{for(i=1;i<=NF;i++){f=$i; if(f ~ /^[[:space:]]/ || f ~ /[[:space:]]$/){print FILENAME": field "i" [\""f"\"]"}}}' "$ROOT/data/compromised-packages.tsv" "$ROOT/data/indicators.tsv")"
  if [[ -z "$out" ]]; then ok "no padded fields"
  else failed "padded fields found: $out"; fi
}

test_history_downgrade_to_bad
test_history_rotated_gz
test_domain_substring_no_false_positive
test_data_no_field_whitespace

test_cache_dirs_from_home_roots() {
  begin "cache: derived from HOME_ROOTS when ACC_CACHE_DIRS unset"
  # ACC_CACHE_DIRS intentionally UNSET so CACHE_DIRS derives from ACC_HOME_ROOTS.
  OUT="$(ACC_DATA_DIR="$FIX/data" \
         ACC_QM_FILE="$FIX/clean/qm.txt" \
         ACC_PACMAN_LOG="$FIX/clean/pacman.log" \
         ACC_HOME_ROOTS="$FIX/cache-from-homeroots/home" \
         ACC_HOSTS_FILE="$FIX/clean/hosts" \
         ACC_SYSTEMD_DIRS="$FIX/clean/cache" \
         bash "$SCRIPT" --no-color 2>&1)"
  RC=$?
  assert_rc 1
  assert_contains "[CRIT]"
  assert_contains "fake-malicious-npm"
}

test_domain_blocklist_not_warning() {
  begin "domain: blackhole/blocklist hosts entry must NOT warn"
  run_check domain-blocklist
  assert_rc 0
  assert_not_contains "[WARN]"
  assert_contains "BLOCKING"
}

test_history_rotated_xz() {
  begin "history: bad install only in rotated .xz log is found"
  run_check history-rotated-xz
  assert_rc 1
  assert_contains "[CRIT]"
  assert_contains "evil-pkg"
}

test_history_rotated_zst() {
  begin "history: bad install only in rotated .zst log is found"
  run_check history-rotated-zst
  assert_rc 1
  assert_contains "[CRIT]"
  assert_contains "evil-pkg"
}

test_history_rotated_bz2() {
  begin "history: bad install only in rotated .bz2 log is found"
  run_check history-rotated-bz2
  assert_rc 1
  assert_contains "[CRIT]"
  assert_contains "evil-pkg"
}

test_cache_dirs_from_home_roots
test_domain_blocklist_not_warning
test_history_rotated_xz
test_history_rotated_zst
test_history_rotated_bz2

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
checker_ok=$(( FAIL == 0 ))

# Also run the standalone updater suite (no network; uses fixtures).
printf '\n--- updater tests ---\n'
bash "$ROOT/tests/run-updater-tests.sh"
updater_rc=$?

(( checker_ok )) && (( updater_rc == 0 ))
