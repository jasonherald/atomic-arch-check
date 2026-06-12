#!/usr/bin/env bash
# =============================================================================
# check-aur-compromise.sh — detect exposure to the June 2026 "Atomic Arch"
# AUR compromise (and related incidents) on Arch-based systems.
#
# WHAT THIS IS
#   A detector. It tells you whether your machine shows signs of the AUR
#   supply-chain compromise: are any compromised packages installed, were any
#   ever installed/built (even if since removed), and are any payload artifacts
#   present. It identifies; it does not clean up, and it does not attack.
#
# TRUST MODEL (the whole point — you are running this on a possibly-dirty box)
#   * It is strictly READ-ONLY: it never modifies the system.
#   * It makes ZERO network connections.
#   * It NEVER executes anything it discovers (it reads/greps/hashes files only).
#   Don't take our word for it — read this file. It is deliberately plain and
#   commented so you can audit it in a few minutes before trusting it. Never
#   pipe an unread script into a shell (`curl ... | bash`); blindly running
#   unread code is exactly how this incident spread.
#
# HOW IT'S ORGANIZED
#   Two plain-text data files drive everything (so updating the threat data
#   never means touching code):
#     data/compromised-packages.tsv  — the list of compromised AUR packages
#     data/indicators.tsv            — payload indicators (files, hashes, etc.)
#   The checks run in main() near the bottom; read that first for the overview.
#
# Requires: bash 4.3+ (associative arrays and `[[ -v arr[idx] ]]`); Arch ships bash 5.x.
# =============================================================================

set -o nounset      # referencing an unset variable is an error (catches typos)
set -o pipefail     # a pipeline fails if ANY stage fails, not just the last one

VERSION="1.0.0"

# --- configuration -----------------------------------------------------------
# Every external input is read through an ACC_* environment override. In normal
# use the overrides are unset and the real-system defaults apply; the test suite
# sets them to point at harmless fixtures, which is how the tool is tested
# without needing a real infected machine.

# Directory holding this script, so the default data/ dir is found regardless of
# the caller's working directory. (cd in a subshell; never changes our own cwd.)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
DATA_DIR="${ACC_DATA_DIR:-$SCRIPT_DIR/data}"          # where the .tsv data lives
PACMAN_LOG="${ACC_PACMAN_LOG:-/var/log/pacman.log}"   # install/upgrade history
QM_FILE="${ACC_QM_FILE:-}"   # if set, read `pacman -Qm` output from here (tests)
HOSTS_FILE="${ACC_HOSTS_FILE:-/etc/hosts}"            # checked for IOC domains/IPs

# Home directories to scan. An explicit ACC_HOME_ROOTS override wins. Otherwise,
# when running as root, scan every real user's home plus /root so that `sudo`
# INCREASES coverage rather than narrowing it to /root; as a normal user, scan
# only our own home.
if [[ -n "${ACC_HOME_ROOTS:-}" ]]; then
  IFS=':' read -r -a HOME_ROOTS <<< "$ACC_HOME_ROOTS"   # colon-separated list -> array
elif (( EUID == 0 )); then
  HOME_ROOTS=()
  for _h in /home/* /root; do [[ -d "$_h" ]] && HOME_ROOTS+=("$_h"); done
  (( ${#HOME_ROOTS[@]} )) || HOME_ROOTS=("${HOME:-/root}")   # fallback if /home empty
else
  HOME_ROOTS=("${HOME:-/root}")
fi

# AUR-helper cache dirs. An explicit ACC_CACHE_DIRS override wins; otherwise
# derive yay/paru cache locations from EACH home root (not just $HOME), so a
# multi-user or root run actually scans every user's build cache.
if [[ -n "${ACC_CACHE_DIRS:-}" ]]; then
  IFS=':' read -r -a CACHE_DIRS <<< "$ACC_CACHE_DIRS"
else
  CACHE_DIRS=()
  for _r in "${HOME_ROOTS[@]}"; do
    CACHE_DIRS+=("$_r/.cache/yay" "$_r/.cache/paru/clone")
  done
fi

# Where systemd unit files live (system-wide + transient). Used by the
# systemd-unit indicator check.
IFS=':' read -r -a SYSTEMD_DIRS <<< "${ACC_SYSTEMD_DIRS:-/etc/systemd/system:/usr/lib/systemd/system:/run/systemd/system}"

# Runtime flags, toggled by parse_args.
QUIET=0; COLOR=1; DEEP=0

# --- findings accumulators ---------------------------------------------------
# Each check appends human-readable strings into one of four severity buckets.
# Nothing is printed until the end; the verdict/exit code is derived from which
# buckets are non-empty.
declare -a F_CRIT=() F_WARN=() F_INFO=() F_SKIP=()
crit() { F_CRIT+=("$1"); }   # strong evidence of compromise   -> exit 1
warn() { F_WARN+=("$1"); }   # possible exposure, investigate   -> exit 2
info() { F_INFO+=("$1"); }   # context / manual-review pointer   (no exit change)
skip() { F_SKIP+=("$1"); }   # a check could NOT run (coverage gap, not a finding)

# --- data loaded from the .tsv files at startup ------------------------------
# Associative arrays keyed by package name; parallel indexed arrays for IOCs.
declare -A PKG_VERSIONS=() PKG_INCIDENT=() PKG_CONF=() PKG_SOURCE=()  # per package
declare -A WINDOW_START=() WINDOW_END=()                              # per incident
declare -a IOC_TYPES=() IOC_VALUES=() IOC_DESCS=() IOC_SOURCES=()     # one entry per IOC

# Print usage/help. (Single-quoted heredoc: contents are emitted verbatim.)
usage() {
  cat <<'EOF'
Usage: check-aur-compromise.sh [options]

Strictly read-only checker for the June 2026 "Atomic Arch" AUR compromise.
Makes no network connections and never modifies the system.

Options:
  --quiet       print only the final verdict line
  --no-color    disable colored output
  --deep        also deep-scan home dirs for malicious node_modules (slower)
  --data-dir D  read data files from D (default: ./data next to the script)
  --version     print version and exit
  -h, --help    show this help

Exit codes: 0 clean, 1 critical findings, 2 warnings only, 3 error
EOF
}

# Parse command-line options. Unknown options are a usage error (exit 3).
parse_args() {
  while (( $# )); do
    case "$1" in
      --quiet) QUIET=1 ;;                 # suppress the full report, keep verdict
      --no-color) COLOR=0 ;;              # disable ANSI color (also auto-off when not a TTY)
      --deep) DEEP=1 ;;                   # enable the slower recursive node_modules scan
      --data-dir)
        shift                             # consume the flag; next arg is the value
        [[ $# -gt 0 ]] || { echo "error: --data-dir needs an argument" >&2; exit 3; }
        DATA_DIR="$1" ;;
      --version) echo "atomic-arch-check $VERSION"; exit 0 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "error: unknown option: $1" >&2; usage >&2; exit 3 ;;
    esac
    shift                                  # advance to the next argument
  done
}

# Populate the RED/YELLOW/GREEN/BOLD/RESET vars. Colors are enabled only when
# requested AND stdout is a terminal AND tput is available — so piping or
# redirecting output yields clean, color-code-free text.
setup_colors() {
  if (( COLOR )) && [[ -t 1 ]] && command -v tput >/dev/null 2>&1; then
    RED="$(tput setaf 1)"; YELLOW="$(tput setaf 3)"
    GREEN="$(tput setaf 2)"; BOLD="$(tput bold)"; RESET="$(tput sgr0)"
  else
    RED=""; YELLOW=""; GREEN=""; BOLD=""; RESET=""
  fi
}

# Refuse to run on non-Arch systems (no pacman) unless a fixture QM_FILE is set.
# Catches the "ran this on the wrong distro" mistake early.
require_arch() {
  if [[ -z "$QM_FILE" ]] && ! command -v pacman >/dev/null 2>&1; then
    echo "error: pacman not found — this tool checks Arch-based systems." >&2
    exit 3
  fi
}

# Load data/compromised-packages.tsv into the PKG_* arrays.
# File format (tab-separated): name <TAB> bad_versions(comma-sep or *) <TAB>
#                              incident <TAB> confidence <TAB> sources
# Special line "#%window <incident> <start> <end>" records each incident's
# malicious-commit date window. Other "#" lines and blanks are comments.
load_packages() {
  local file="$DATA_DIR/compromised-packages.tsv"
  local line name versions incident conf source _tag inc start end
  if [[ ! -r "$file" ]]; then
    echo "error: cannot read $file (use --data-dir or run from the repo)" >&2
    exit 3
  fi
  # `|| [[ -n "$line" ]]` ensures a final line without a trailing newline is read.
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == '#%window '* ]]; then           # window directive, not a package
      read -r _tag inc start end <<< "$line"          # split on whitespace
      WINDOW_START["$inc"]="$start"
      WINDOW_END["$inc"]="$end"
      continue
    fi
    [[ -z "$line" || "$line" == '#'* ]] && continue   # skip blanks and comments
    IFS=$'\t' read -r name versions incident conf source <<< "$line"   # split on TAB
    # A row missing any required column is reported and skipped (the run continues).
    if [[ -z "$name" || -z "${versions:-}" || -z "${incident:-}" ]]; then
      echo "warning: malformed row in compromised-packages.tsv: $line" >&2
      continue
    fi
    PKG_VERSIONS["$name"]="$versions"                 # "*" means "any version is suspect"
    PKG_INCIDENT["$name"]="$incident"
    PKG_CONF["$name"]="${conf:-unknown}"              # default if column omitted
    PKG_SOURCE["$name"]="${source:-unattributed}"
  done < "$file"
}

# Load data/indicators.tsv into the parallel IOC_* arrays.
# File format (tab-separated): type <TAB> value <TAB> description <TAB> source
load_indicators() {
  local file="$DATA_DIR/indicators.tsv" line type value desc source
  if [[ ! -r "$file" ]]; then
    echo "error: cannot read $file (use --data-dir or run from the repo)" >&2
    exit 3
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == '#'* ]] && continue   # skip blanks and comments
    IFS=$'\t' read -r type value desc source <<< "$line"
    if [[ -z "$type" || -z "${value:-}" ]]; then       # type and value are required
      echo "warning: malformed row in indicators.tsv: $line" >&2
      continue
    fi
    IOC_TYPES+=("$type")                              # arrays stay index-aligned
    IOC_VALUES+=("$value")
    IOC_DESCS+=("${desc:-}")
    IOC_SOURCES+=("${source:-unattributed}")
  done < "$file"
}

# Emit the list of foreign (AUR / non-official-repo) packages, one "name version"
# per line. From a fixture file when testing, otherwise from pacman. This is a
# read-only query — `pacman -Qm` only reads the local package database.
get_foreign_packages() {
  if [[ -n "$QM_FILE" ]]; then
    cat -- "$QM_FILE" 2>/dev/null
  else
    pacman -Qm 2>/dev/null
  fi
}

# Does installed version $2 exactly match any known-bad version of package $1?
# PKG_VERSIONS[$1] is a comma-separated list; we set a function-local IFS so the
# split is scoped here, and trim incidental whitespace around each entry.
version_matches() {  # $1=pkg name, $2=installed version
  local v IFS=','
  for v in ${PKG_VERSIONS[$1]}; do
    v="${v#"${v%%[![:space:]]*}"}"   # strip leading whitespace
    v="${v%"${v##*[![:space:]]}"}"   # strip trailing whitespace
    [[ "$v" == "$2" ]] && return 0   # exact match
  done
  return 1
}

# LAYER 1 — currently-installed packages.
# Cross-references `pacman -Qm` against the compromised list. Exact known-bad
# version => CRITICAL; listed package at any other/unknown version => WARNING
# (a past install of the bad version may have already run the payload — Layer 2
# digs into history).
check_installed() {
  local name ver qm err
  qm="$(get_foreign_packages)"
  # Distinguish a genuine query failure (corrupt DB) from the benign "this
  # system has zero foreign packages" case: pacman returns exit 1 for BOTH,
  # but only a real error writes an "error:" line to stderr.
  if [[ -z "$QM_FILE" ]] && command -v pacman >/dev/null 2>&1; then
    err="$(pacman -Qm 2>&1 >/dev/null)"   # capture stderr only (stdout -> /dev/null)
    [[ "$err" == *error:* ]] && skip "Installed-package check: 'pacman -Qm' errored (${err%%$'\n'*}) — layer 1 may be incomplete"
  fi
  while read -r name ver; do
    [[ -z "$name" ]] && continue                       # ignore blank lines
    [[ -v "PKG_VERSIONS[$name]" ]] || continue         # not on the list -> ignore
    local versions="${PKG_VERSIONS[$name]}"
    local inc="${PKG_INCIDENT[$name]}" src="${PKG_SOURCE[$name]}" conf="${PKG_CONF[$name]}"
    if [[ "$versions" != "*" ]] && version_matches "$name" "$ver"; then
      crit "Installed package '$name' is at known-compromised version $ver [$inc] (confidence: $conf; source: $src)"
    elif [[ "$versions" == "*" ]]; then
      warn "Installed package '$name' is on the compromised list (installed: $ver; exact bad version unrecorded) [$inc] — check install history below (confidence: $conf; source: $src)"
    else
      warn "Installed package '$name' is on the compromised list (installed: $ver; known-bad: $versions) [$inc] — version differs, but check install history below (confidence: $conf; source: $src)"
    fi
  done <<< "$qm"
}

# Build the fixed-string prefilter patterns for the pacman.log scan: for every
# listed package, the four action verbs pacman logs. Feeding these to `grep -F`
# first makes the log scan fast even on a multi-thousand-package list.
gen_history_patterns() {
  local n
  for n in "${!PKG_VERSIONS[@]}"; do
    printf '] installed %s (\n] upgraded %s (\n] reinstalled %s (\n] downgraded %s (\n' "$n" "$n" "$n" "$n"
  done
}

# Is calendar day $1 within incident $2's malicious-commit window (inclusive)?
# ISO YYYY-MM-DD strings sort lexically the same as chronologically, so plain
# string comparison is correct. Unknown incident (no window) => not in window.
date_in_window() {  # $1=YYYY-MM-DD, $2=incident
  local start="${WINDOW_START[$2]:-}" end="${WINDOW_END[$2]:-}"
  [[ -n "$start" && -n "$end" ]] || return 1
  [[ ! "$1" < "$start" && ! "$1" > "$end" ]]            # start <= $1 <= end
}

# Return the read-only decompressor command for a log filename, by extension
# (empty string = plain text, use cat). pacman/logrotate may compress rotated
# logs with any of these; all four commands only read and decompress to stdout.
log_decompressor() {  # $1 = filename
  case "$1" in
    *.gz)  echo zcat ;;
    *.xz)  echo xzcat ;;
    *.zst) echo zstdcat ;;
    *.bz2) echo bzcat ;;
    *)     echo "" ;;
  esac
}

# Emit the content of each given log file, decompressing by extension. Read-only:
# every branch only reads/decompresses to stdout — nothing is written or executed.
# (check_history has already confirmed any needed decompressor is installed.)
cat_logs() {
  local f tool
  for f in "$@"; do
    tool="$(log_decompressor "$f")"
    if [[ -n "$tool" ]]; then
      "$tool" -- "$f" 2>/dev/null
    else
      cat -- "$f" 2>/dev/null
    fi
  done
}

# LAYER 2a — install history.
# The payload runs at BUILD/INSTALL time, so a package that was installed and
# later removed/upgraded can still have compromised the machine. We scan
# pacman.log (and rotated pacman.log.* incl. .gz). For each install/upgrade/
# reinstall/downgrade of a listed package: resulting version is known-bad =>
# CRITICAL; else event date inside the malicious window => WARNING; else => INFO.
# Rotated logs (pacman.log.1, .gz/.xz/.zst/.bz2) are folded in too.
check_history() {
  local logs=() f tool
  [[ -r "$PACMAN_LOG" ]] && logs+=("$PACMAN_LOG")
  for f in "$PACMAN_LOG".*; do                          # rotated logs, if any
    [[ -e "$f" ]] || continue                           # literal-glob (no matches) falls through
    if [[ ! -r "$f" ]]; then
      skip "History check: rotated log not readable: $f (rerun with sudo for full coverage)"
      continue
    fi
    # Only include a compressed log if its decompressor is installed; otherwise
    # report the gap (this validation is in the main shell, where skip() sticks).
    tool="$(log_decompressor "$f")"
    if [[ -n "$tool" ]] && ! command -v "$tool" >/dev/null 2>&1; then
      skip "History check: $f present but '$tool' is not installed — cannot read this rotated log"
      continue
    fi
    logs+=("$f")
  done
  if (( ${#logs[@]} == 0 )); then                       # nothing readable -> report, don't pretend clean
    skip "History check: cannot read pacman.log at $PACMAN_LOG"
    return 0
  fi
  (( ${#PKG_VERSIONS[@]} )) || return 0                 # empty list -> nothing to grep for
  local line ts action name ver newver day inc
  # Capture groups: 1=timestamp 2=action 3=package 4=version-field("old -> new").
  while IFS= read -r line; do
    if [[ "$line" =~ ^\[([0-9Tt:+.-]+)\]\ \[ALPM\]\ (installed|upgraded|reinstalled|downgraded)\ ([^\ ]+)\ \((.*)\)[[:space:]]*$ ]]; then
      ts="${BASH_REMATCH[1]}"; action="${BASH_REMATCH[2]}"
      name="${BASH_REMATCH[3]}"; ver="${BASH_REMATCH[4]}"
      [[ -v "PKG_VERSIONS[$name]" ]] || continue        # the prefilter can over-match; confirm
      newver="${ver##* -> }"                            # "old -> new" -> "new" (no-op if no arrow)
      day="${ts:0:10}"                                  # YYYY-MM-DD prefix of the timestamp
      inc="${PKG_INCIDENT[$name]}"
      if [[ "${PKG_VERSIONS[$name]}" != "*" ]] && version_matches "$name" "$newver"; then
        crit "History: '$name' $action at known-compromised version $newver on $ts [$inc] (${PKG_SOURCE[$name]})"
      elif date_in_window "$day" "$inc"; then
        warn "History: '$name' $action on $ts — inside the malicious-commit window for $inc; a build in this window may have executed the payload (${PKG_SOURCE[$name]})"
      else
        info "History: '$name' $action on $ts (outside known window for $inc) — verify which commit was built"
      fi
    fi
  done < <(cat_logs "${logs[@]}" | grep -F -f <(gen_history_patterns) 2>/dev/null)
}

# LAYER 2b — AUR-helper build caches (yay/paru).
# A cached PKGBUILD/.install/.SRCINFO containing a known-malicious pattern is
# hard evidence the bad commit reached this machine, regardless of install
# state. We grep ALL cached recipes (listed or not, since the public list may be
# incomplete) for every pkgbuild-pattern IOC => CRITICAL; and note the mere
# presence of a cache clone for any listed package => INFO. Unreadable cache
# subdirs are reported as SKIP so coverage gaps are visible. (grep -F = fixed
# strings: pattern text is matched literally, never as a regex; nothing is run.)
check_caches() {
  local dir name i hit unreadable
  for dir in "${CACHE_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    # Report any unreadable subdirectory so a silently-skipped clone is visible.
    while IFS= read -r unreadable; do
      [[ -n "$unreadable" ]] && skip "Cache path not readable, malicious-pattern scan skipped: $unreadable (rerun with sudo for full coverage)"
    done < <(find "$dir" -type d ! -readable 2>/dev/null)
    # (a) any cached build recipe containing a known-malicious pattern —
    #     checked for ALL cached packages, listed or not, since the public
    #     list may be incomplete.
    for i in "${!IOC_TYPES[@]}"; do
      [[ "${IOC_TYPES[$i]}" == "pkgbuild-pattern" ]] || continue
      while IFS= read -r hit; do
        [[ -n "$hit" ]] || continue
        crit "Cached build recipe contains known-malicious pattern '${IOC_VALUES[$i]}': $hit — ${IOC_DESCS[$i]} (source: ${IOC_SOURCES[$i]})"
      done < <(grep -RlF --include='PKGBUILD' --include='*.install' --include='.SRCINFO' -e "${IOC_VALUES[$i]}" -- "$dir" 2>/dev/null)
    done
    # (b) clones of listed packages present at all
    for name in "${!PKG_VERSIONS[@]}"; do
      [[ -d "$dir/$name" ]] || continue
      info "Build cache for listed package '$name' exists at $dir/$name — inspect its git log / PKGBUILD history for the malicious commit"
    done
  done
}

# Expand an indicator path that may contain a glob, returning matching paths.
# A leading "~/" is expanded against EACH home root (so multi-user runs check
# every home). `compgen -G` prints glob matches; `|| true` keeps a no-match
# (exit 1) from tripping `set -o pipefail`/`-o errexit`-style aborts.
expand_candidate_paths() {  # $1 = path or glob
  local value="$1" root
  # The leading ~/ here is a LITERAL sentinel in the data format, matched as
  # text and expanded manually against HOME_ROOTS below — not a shell tilde.
  # shellcheck disable=SC2088
  if [[ "$value" == '~/'* ]]; then
    for root in "${HOME_ROOTS[@]}"; do
      compgen -G "$root/${value#\~/}" || true
    done
  else
    compgen -G "$value" || true
  fi
}

# Check for a malicious npm package by name across the likely install locations:
# the npm content cache index, fixed node_modules/global dirs per home, an
# optional deep recursive scan (--deep), and the system-wide module dirs. These
# package names are malware-only, so any presence is genuine evidence => CRIT.
check_npm_package() {  # $1=npm package name, $2=description, $3=source
  local name="$1" desc="$2" src="$3" root d cache
  for root in "${HOME_ROOTS[@]}"; do
    cache="$root/.npm/_cacache"
    # cacache stores registry URLs like ".../<pkg>/-/..."; the slashes anchor the
    # match to a whole path segment, so "/foo/" won't match "/foo-bar/".
    if [[ -d "$cache" ]] && grep -RqsF -- "/$name/" "$cache" 2>/dev/null; then
      crit "npm cache under $root references malicious package '$name' — $desc (source: $src)"
    fi
    for d in "$root/node_modules/$name" "$root/.npm-global/lib/node_modules/$name"; do
      [[ -d "$d" ]] && crit "Malicious npm package present: $d — $desc (source: $src)"
    done
    if (( DEEP )); then                                 # opt-in: catches custom locations, slower
      while IFS= read -r d; do
        [[ -n "$d" ]] && crit "Malicious npm package present: $d — $desc (source: $src)"
      done < <(find "$root" -maxdepth 8 -type d -path "*/node_modules/$name" 2>/dev/null)
    fi
  done
  for d in "/usr/lib/node_modules/$name" "/usr/local/lib/node_modules/$name"; do
    [[ -d "$d" ]] && crit "Malicious npm package present (system-wide): $d — $desc (source: $src)"
  done
  return 0
}

# LAYER 3 — resident payload indicators.
# Dispatches each IOC by type. Adding a new indicator means adding a data row,
# not editing code. Every branch is read-only (existence tests, hashing, grep,
# pgrep) — nothing discovered is ever executed.
check_indicators() {
  local i type value desc src p d root want path have addr
  for i in "${!IOC_TYPES[@]}"; do
    type="${IOC_TYPES[$i]}"; value="${IOC_VALUES[$i]}"
    desc="${IOC_DESCS[$i]}"; src="${IOC_SOURCES[$i]}"
    case "$type" in
      file-path)
        # A dropped file (glob-aware, ~/-expanded) existing at all => CRITICAL.
        while IFS= read -r p; do
          [[ -n "$p" && -e "$p" ]] || continue
          crit "Indicator file present: $p — $desc (source: $src)"
        done < <(expand_candidate_paths "$value")
        ;;
      hash)  # value format: <sha256hex>:<path-or-glob>
        # Only hash files that actually exist at the indicator's path; compare
        # the sha256 against the known-malicious one.
        want="${value%%:*}"; path="${value#*:}"          # split on the first ':'
        while IFS= read -r p; do
          [[ -n "$p" && -r "$p" && -f "$p" ]] || continue
          have="$(sha256sum -- "$p" 2>/dev/null)"; have="${have%% *}"   # keep just the digest
          [[ "$have" == "$want" ]] && crit "File $p matches known-malicious sha256 — $desc (source: $src)"
        done < <(expand_candidate_paths "$path")
        ;;
      systemd-unit)
        # A unit file with this exact name in a system or per-user unit dir.
        # (NB: this campaign's persistence uses RANDOMIZED unit names, so this
        # catches only fixed-name units — see README limitations.)
        for d in "${SYSTEMD_DIRS[@]}"; do
          [[ -e "$d/$value" ]] && crit "Suspicious systemd unit installed: $d/$value — $desc (source: $src)"
        done
        for root in "${HOME_ROOTS[@]}"; do
          [[ -e "$root/.config/systemd/user/$value" ]] && crit "Suspicious user systemd unit: $root/.config/systemd/user/$value — $desc (source: $src)"
        done
        ;;
      npm-package)
        check_npm_package "$value" "$desc" "$src"
        ;;
      process-name)
        # Best-effort, point-in-time only: cannot detect dormant/timer-driven
        # processes, and is unreliable against a rootkit that hides PIDs.
        if command -v pgrep >/dev/null 2>&1 && pgrep -x -- "$value" >/dev/null 2>&1; then
          crit "Process matching indicator is RUNNING: $value — $desc (source: $src)"
        fi
        ;;
      domain|ip)
        # We never resolve or contact the domain (that would break the
        # zero-network promise). We only look it up in /etc/hosts as a whole
        # token. If it's mapped to a blackhole address it's a blocklist entry
        # (you're BLOCKING it -> informational); a routable mapping is unexpected
        # -> WARNING; absent -> tell the operator to review their own logs.
        addr=""
        if [[ -r "$HOSTS_FILE" ]]; then
          # print the address (field 1) of the first non-comment line whose
          # whitespace-delimited fields contain the indicator as a whole token
          addr="$(awk -v d="$value" '/^[[:space:]]*#/ {next} {for (i=1;i<=NF;i++) if ($i==d) {print $1; exit}}' "$HOSTS_FILE" 2>/dev/null)"
        fi
        if [[ -n "$addr" ]]; then
          case "$addr" in
            0.0.0.0|127.0.0.1|::1|::|0:0:0:0:0:0:0:1)
              info "Indicator $type '$value' is in $HOSTS_FILE mapped to $addr — looks like a blocklist/blackhole entry (you appear to be BLOCKING it), not evidence of compromise (source: $src)" ;;
            *)
              warn "Indicator $type '$value' in $HOSTS_FILE maps to $addr — unexpected mapping, review this entry (source: $src)" ;;
          esac
        else
          info "Manual review: check firewall/DNS/proxy logs for $type '$value' — $desc (source: $src)"
        fi
        ;;
      pkgbuild-pattern) : ;;   # handled by check_caches (Layer 2b); no-op here
      *)
        echo "warning: unknown indicator type '$type' in indicators.tsv" >&2
        ;;
    esac
  done
}

# Tell a normal user that they only saw their own home and can get full coverage
# with sudo. Silent when the caller set ACC_HOME_ROOTS (they chose the scope) or
# when already root (root scans all homes + /root, so coverage is already full).
note_coverage() {
  [[ -n "${ACC_HOME_ROOTS:-}" ]] && return 0
  (( EUID != 0 )) && skip "Running as a normal user — only your home (${HOME:-?}) was scanned. For all users + /root, rerun: sudo $0"
}

# Print the grouped report (unless --quiet). Sections are printed only when they
# contain findings. SKIP is labeled as coverage gaps, NOT findings, so an
# unreadable path is never mistaken for evidence.
print_report() {
  (( QUIET )) && return 0
  local entry
  printf '%satomic-arch-check v%s%s\n' "$BOLD" "$VERSION" "$RESET"
  printf 'Data: %s (%d packages, %d indicators)\n\n' \
    "$DATA_DIR" "${#PKG_VERSIONS[@]}" "${#IOC_TYPES[@]}"
  if (( ${#F_CRIT[@]} )); then
    printf '%sCRITICAL findings:%s\n' "$RED" "$RESET"
    for entry in "${F_CRIT[@]}"; do printf '  [CRIT] %s\n' "$entry"; done
    printf '\n'
  fi
  if (( ${#F_WARN[@]} )); then
    printf '%sWarnings:%s\n' "$YELLOW" "$RESET"
    for entry in "${F_WARN[@]}"; do printf '  [WARN] %s\n' "$entry"; done
    printf '\n'
  fi
  if (( ${#F_INFO[@]} )); then
    printf 'Informational:\n'
    for entry in "${F_INFO[@]}"; do printf '  [INFO] %s\n' "$entry"; done
    printf '\n'
  fi
  if (( ${#F_SKIP[@]} )); then
    printf 'Skipped checks (coverage gaps, NOT findings):\n'
    for entry in "${F_SKIP[@]}"; do printf '  [SKIP] %s\n' "$entry"; done
    printf '\n'
  fi
}

# Print the one-line verdict and exit with the matching code:
#   any CRITICAL -> 1, else any WARNING -> 2, else CLEAN -> 0.
# (Usage/runtime errors exit 3 elsewhere.) CRITICAL outranks WARNING.
verdict_and_exit() {
  local code=0 verdict
  if (( ${#F_CRIT[@]} )); then
    code=1
    verdict="${RED}${BOLD}VERDICT: CRITICAL — evidence of compromise (${#F_CRIT[@]} finding(s)). Treat this machine as compromised; see README.${RESET}"
  elif (( ${#F_WARN[@]} )); then
    code=2
    verdict="${YELLOW}${BOLD}VERDICT: WARNING — possible exposure (${#F_WARN[@]} finding(s)); review the report above.${RESET}"
  else
    verdict="${GREEN}${BOLD}VERDICT: CLEAN — no indicators of the AUR compromise were found.${RESET}"
  fi
  printf '%s\n' "$verdict"
  exit "$code"
}

# Orchestration: parse args, set up, load data, run the three detection layers,
# note coverage gaps, print the report, and exit with the verdict code.
main() {
  parse_args "$@"
  setup_colors
  require_arch
  load_packages
  load_indicators
  check_installed     # Layer 1: currently installed
  check_history       # Layer 2a: install/build history (incl. rotated logs)
  check_caches        # Layer 2b: AUR-helper build caches
  check_indicators    # Layer 3: resident payload indicators
  note_coverage
  print_report
  verdict_and_exit
}

main "$@"
