#!/usr/bin/env python3
"""update-list.py — refresh the compromised-AUR-package data files from the
authoritative AUR git mirror (github.com/archlinux/aur).

This is a STANDALONE maintainer/advanced-user tool. It is NEVER invoked by
check-aur-compromise.sh, which stays strictly offline. This tool DOES make
network calls (to the GitHub API, via the `gh` CLI) — that is the whole point,
and it announces exactly what it will do before doing it.

What it does, and only this:
  1. Read payload signatures from data/indicators.tsv.
  2. Scan recent archlinux/aur ref-update activity via the GitHub API and grep
     each push's diff TEXT for those signatures (never builds/executes anything).
  3. Merge newly-discovered package names into research/findings.json.
  4. Re-run scripts/curate-findings.py to regenerate data/*.tsv.
  5. Print an added/removed diff. Writes nothing unless --apply is given.

Requires: python3 (stdlib only) and the `gh` CLI, authenticated (`gh auth login`).
"""
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDICATORS = os.environ.get("ACC_INDICATORS", os.path.join(ROOT, "data", "indicators.tsv"))
FINDINGS = os.environ.get("ACC_FINDINGS", os.path.join(ROOT, "research", "findings.json"))
CURATE = os.path.join(ROOT, "scripts", "curate-findings.py")
PKG_TSV = os.environ.get("ACC_PKG_TSV", os.path.join(ROOT, "data", "compromised-packages.tsv"))
IOC_TSV = os.environ.get("ACC_IOC_TSV", os.path.join(ROOT, "data", "indicators.tsv"))
# Freshness stamp, written on --apply, beside the data files (so test overrides of
# PKG_TSV redirect it too). Records when the list was last refreshed from source.
LAST_UPDATED = os.path.join(os.path.dirname(PKG_TSV), "last-updated.txt")
REPO = "archlinux/aur"

# Default cap on how many recent ref-updates a single run will diff. archlinux/aur
# is extremely active, so an unbounded scan could mean thousands of compare API
# calls. This is a "catch new compromises" tool meant to be run frequently; the
# maintainer's `git pull` data is the authoritative baseline for older history.
DEFAULT_MAX_EVENTS = 200

ANNOUNCE = """\
update-list — refresh compromised-AUR-package data from the AUR git mirror

  * This tool MAKES NETWORK CALLS to the GitHub API (api.github.com) for the
    {repo} repository, via the `gh` CLI.
  * It reads and parses TEXT ONLY (API JSON and commit diffs). It never builds,
    executes, or installs anything, and it does not run any PKGBUILD or payload.
  * It writes data/*.tsv and research/findings.json ONLY when you pass --apply.
    Without --apply this is a dry run that changes nothing.

This tool is separate from check-aur-compromise.sh, which makes no network calls.
""".format(repo=REPO)


def eprint(*a):
    print(*a, file=sys.stderr)


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="update-list",
        description="Refresh compromised-AUR-package data from the AUR git mirror "
                    "(github.com/archlinux/aur) via the GitHub API. Dry-run by "
                    "default; writes data files only with --apply. Makes network calls.",
    )
    p.add_argument("--apply", action="store_true",
                   help="write the discovered changes to data/*.tsv and "
                        "research/findings.json (default: dry run, write nothing)")
    p.add_argument("--days", type=int, default=2,
                   help="how many days of recent AUR activity to scan (default: 2)")
    p.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS,
                   help="cap on how many recent ref-updates to diff in one run "
                        "(default: %d). This tool scans a recent window and is "
                        "meant to be run often; `git pull` is the full baseline."
                        % DEFAULT_MAX_EVENTS)
    p.add_argument("--print-signatures", action="store_true",
                   help=argparse.SUPPRESS)  # debug: print loaded signatures and exit
    p.add_argument("--print-discovered", action="store_true",
                   help=argparse.SUPPRESS)  # debug: print discovered package names and exit
    return p.parse_args(argv)


def gh_preflight():
    """Verify `gh` is installed and authenticated. Skipped when a fixture is set."""
    if os.environ.get("UPDATE_LIST_FIXTURE"):
        return
    from shutil import which
    if which("gh") is None:
        eprint("error: the `gh` CLI is required but was not found.")
        eprint("       install it (https://cli.github.com/) and run `gh auth login`.")
        sys.exit(3)
    rc = subprocess.run(["gh", "auth", "status"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    if rc != 0:
        eprint("error: `gh` is not authenticated. Run `gh auth login` first.")
        sys.exit(3)


def load_signatures():
    """Return the set of payload signature strings to search for: the values of
    every npm-package and pkgbuild-pattern row in indicators.tsv. These are the
    single source of truth — adding a signature there extends discovery here."""
    sigs = set()
    with open(INDICATORS, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            typ, value = parts[0], parts[1]
            if typ in ("npm-package", "pkgbuild-pattern") and value:
                sigs.add(value)
    return sorted(sigs)


NULL_SHA = "0" * 40   # the "before" SHA of a branch-creation event


def _fixture_path(endpoint, fixture_key=None):
    """Map a gh api endpoint to a fixture file under UPDATE_LIST_FIXTURE.
       .../activity...        -> activity.json   (a list of pages, like --slurp)
       .../compare/<a>...<b>  -> compare-<fixture_key>.json (key = package name)
       .../commits/<sha>      -> commits-<fixture_key>.json (key = package name)"""
    fx = os.environ["UPDATE_LIST_FIXTURE"]
    if "/activity" in endpoint:
        return os.path.join(fx, "activity.json")
    if "/compare/" in endpoint:
        return os.path.join(fx, "compare-%s.json" % (fixture_key or ""))
    if "/commits/" in endpoint:
        return os.path.join(fx, "commits-%s.json" % (fixture_key or ""))
    raise ValueError("no fixture mapping for endpoint: %s" % endpoint)


def gh_api(endpoint, fixture_key=None):
    """Return parsed JSON from a single GitHub API call. Uses `gh api`, or a canned
    fixture file when UPDATE_LIST_FIXTURE is set (no network in tests)."""
    if os.environ.get("UPDATE_LIST_FIXTURE"):
        with open(_fixture_path(endpoint, fixture_key), encoding="utf-8") as f:
            return json.load(f)
    proc = subprocess.run(["gh", "api", endpoint], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("gh api %s failed: %s" % (endpoint, proc.stderr.strip()))
    return json.loads(proc.stdout)


def gh_api_paginated(endpoint):
    """Fetch ALL pages of a cursor-paginated array endpoint (the GitHub activity
    API uses cursor, not ?page=, pagination) and return one flat list. Uses
    `gh api --paginate --slurp`, which wraps the pages into an outer JSON array
    that parses reliably across gh versions; we then flatten it. The fixture file
    mirrors that shape (a list of pages)."""
    if os.environ.get("UPDATE_LIST_FIXTURE"):
        with open(_fixture_path(endpoint), encoding="utf-8") as f:
            pages = json.load(f)
    else:
        proc = subprocess.run(["gh", "api", "--paginate", "--slurp", endpoint],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError("gh api --paginate %s failed: %s"
                               % (endpoint, proc.stderr.strip()))
        pages = json.loads(proc.stdout)
    return [item for page in pages for item in page]


def _time_period(days):
    """Map --days to the GitHub activity API's coarse time_period window."""
    if days <= 1:
        return "day"
    if days <= 7:
        return "week"
    if days <= 31:
        return "month"
    return "year"


def event_patch(before, after, pkg):
    """Return the combined diff TEXT for a ref update. A normal push is diffed via
    the compare API; a branch creation (null `before`) — or a force-push whose old
    base is gone — is diffed via the head commit, since compare 404s without a
    valid base. Reads text only; never builds or executes anything."""
    if before and before != NULL_SHA:
        try:
            cmp = gh_api("repos/%s/compare/%s...%s" % (REPO, before, after), fixture_key=pkg)
            return "\n".join(f.get("patch", "") for f in cmp.get("files", []))
        except (RuntimeError, ValueError, OSError):
            pass   # base missing (e.g. reset/force-push) — fall back to the commit diff
    commit = gh_api("repos/%s/commits/%s" % (REPO, after), fixture_key=pkg)
    return "\n".join(f.get("patch", "") for f in commit.get("files", []))


def discover_packages(signatures, days, max_events=DEFAULT_MAX_EVENTS):
    """Scan recent archlinux/aur ref-update activity; return the set of package
    names whose ref-update diff contains any signature (added OR removed). Reads
    diff TEXT only — never builds or executes anything. Bounded: at most
    max_events ref-updates are diffed; each (pkg, before, after) is fetched once."""
    found = set()
    period = _time_period(days)
    events = gh_api_paginated("repos/%s/activity?per_page=100&time_period=%s" % (REPO, period))
    truncated = len(events) > max_events
    events = events[:max_events]
    if truncated:
        eprint("note: scanning the most recent %d ref-update(s) of the last %d day(s) "
               "(--max-events); more activity exists. Run more often (or rely on "
               "`git pull`) for fuller coverage." % (max_events, days))
    checked = set()
    for ev in events:
        ref = ev.get("ref", "")
        if not ref.startswith("refs/heads/"):
            continue
        pkg = ref[len("refs/heads/"):]
        if pkg in found:
            continue                       # already flagged — no need to re-diff it
        after = ev.get("after")
        before = ev.get("before") or ""
        if not after or after == NULL_SHA:
            continue                       # branch deletion — nothing to diff
        key = (pkg, before, after)
        if key in checked:
            continue                       # avoid a duplicate diff for the same push
        checked.add(key)
        try:
            patch = event_patch(before, after, pkg)
        except (RuntimeError, FileNotFoundError, ValueError, OSError) as e:
            eprint("warning: skipping %s (%s)" % (pkg, e))
            continue
        if any(sig in patch for sig in signatures):
            found.add(pkg)
    return found


def read_pkg_names(path):
    """Return the set of package names in a compromised-packages.tsv (col 1,
    skipping comments). Missing file -> empty set."""
    names = set()
    if not os.path.exists(path):
        return names
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            names.add(line.split("\t", 1)[0])
    return names


def merge_findings(discovered):
    """Add newly-discovered package names to findings.json (in memory). Returns
    (data, added_names). Existing entries are preserved; only genuinely new names
    are appended, tagged aur-git-mirror."""
    with open(FINDINGS, encoding="utf-8") as f:
        data = json.load(f)
    existing = {p["name"] for p in data.get("packages", [])}
    added = sorted(n for n in discovered if n not in existing)
    for name in added:
        data["packages"].append({
            "name": name,
            "bad_versions": [],
            "incident": "atomic-arch-2026-06",
            "confidence": "single-source",
            "sources": ["aur-git-mirror"],
        })
    data["package_count"] = len(data["packages"])
    return data, added


def run_curation():
    """Regenerate data/*.tsv from findings.json via curate-findings.py, passing
    the same path overrides we use so it writes to our (possibly temp) targets."""
    env = dict(os.environ, ACC_FINDINGS=FINDINGS, ACC_PKG_TSV=PKG_TSV, ACC_IOC_TSV=IOC_TSV)
    proc = subprocess.run([sys.executable, CURATE], env=env,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("curate-findings.py failed: %s" % proc.stderr.strip())


def stamp_last_updated():
    """Record when the list was last refreshed from source (UTC, ISO 8601), so
    raw-URL consumers can see freshness. Written only on --apply; kept out of
    curate-findings.py so that script's output stays deterministic."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(LAST_UPDATED, "w", encoding="utf-8") as f:
        f.write(now + "\n")


def main(argv):
    args = parse_args(argv)
    print(ANNOUNCE)
    # Offline operations run before the gh preflight, so signature inspection
    # needs no network and no authenticated gh.
    if args.print_signatures:
        for s in load_signatures():
            print(s)
        return 0
    gh_preflight()
    try:
        if args.print_discovered:
            for p in sorted(discover_packages(load_signatures(), args.days, args.max_events)):
                print(p)
            return 0
        signatures = load_signatures()
        discovered = discover_packages(signatures, args.days, args.max_events)
    except (RuntimeError, ValueError, OSError) as e:
        # ValueError covers json.JSONDecodeError (malformed API response).
        eprint("error: discovery failed: %s" % e)
        return 2

    before_names = read_pkg_names(PKG_TSV)
    data, _added = merge_findings(discovered)
    # Names that are new vs the current data file (candidate additions to show).
    new_vs_data = sorted(n for n in discovered if n not in before_names)

    if not new_vs_data:
        print("Already up to date — no new compromised packages found.")
        if args.apply:
            stamp_last_updated()   # record that we refreshed today, even with no new finds
        return 0

    print("New compromised package candidates (%d):" % len(new_vs_data))
    for n in new_vs_data:
        print("  + %s" % n)

    if not args.apply:
        print("\nDRY RUN — nothing was written. Re-run with --apply to update the data files.")
        return 0

    # Write findings.json, then regenerate the TSVs through curation. Report the
    # ACTUAL package rows added to the data file (post-curation), which may differ
    # from the candidate list if curation filters a name.
    with open(FINDINGS, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    try:
        run_curation()
    except RuntimeError as e:
        eprint("error: curation failed after writing findings.json: %s" % e)
        eprint("       re-run `python3 scripts/curate-findings.py` to regenerate data/*.tsv.")
        return 2
    stamp_last_updated()
    after_names = read_pkg_names(PKG_TSV)
    print("\nWrote %d new package(s) to %s (via curate-findings.py)." %
          (len(after_names - before_names), os.path.relpath(PKG_TSV, ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
