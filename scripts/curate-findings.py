#!/usr/bin/env python3
"""Dev-time curation: research/raw/findings-full.json -> data/*.tsv.

This is NOT part of the audited runtime — it is the reproducible record of how
the shipped data files were derived from the research artifacts, with every
inclusion/exclusion decision spelled out as an explicit allow/deny rule.

Design rules (see docs/.../design.md and the README "Data provenance" section):
  * The PACKAGE list is intentionally broad (erring toward catching exposure):
    every reported compromised AUR package, tagged with confidence + sources.
    Most have no recorded bad version, so they match at version "*" -> WARNING,
    which prompts investigation rather than asserting compromise.
  * The INDICATOR list is intentionally NARROW and high-precision: only
    attacker-side artifacts that a clean machine will essentially never have.
    Decoy npm packages, legitimate services, loopback, randomized unit names,
    and git-commit SHAs are EXCLUDED to avoid false positives / dead rows.
"""
import json, os, sys, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Committed, reproducible input. (research/raw/findings-full.json is the larger
# untrimmed original kept locally / gitignored.)
SRC = os.environ.get("ACC_FINDINGS", os.path.join(ROOT, "research", "findings.json"))

# --- malicious-commit windows (UTC days, inclusive; conservative supersets) ---
WINDOWS = [
    # incident                start        end           (covers both waves + cleanup + tz edges)
    ("atomic-arch-2026-06", "2026-06-09", "2026-06-13"),
    ("chaos-rat-2025",      "2025-07-16", "2025-07-18"),
]

# --- source URL -> short provenance tag --------------------------------------
SOURCE_TAGS = [
    ("lists.archlinux.org", "aur-general-thread"),
    ("cscs.pastes.sh",      "cscs-list"),
    ("github.com/archlinux/aur", "aur-git-mirror"),
    ("cachyos",             "cachyos-forum"),
    ("ioctl.fail",          "ioctl-analysis"),
    ("sonatype",            "sonatype"),
    ("socket.dev",          "socket"),
    ("gr.ht",               "grht-list"),
    ("phoronix",            "phoronix"),
    ("linuxiac",            "linuxiac"),
    ("ifin",                "ifin-discourse"),
    ("discourse",           "ifin-discourse"),
    ("bbs.archlinux",       "arch-bbs"),
]

def tag_sources(sources):
    """Map raw source URLs to short tags. Inputs may already be short tags
    (research/findings.json stores them pre-tagged), in which case pass through."""
    tags = []
    for s in sources or []:
        mapped = None
        for needle, tag in SOURCE_TAGS:
            if needle in s:
                mapped = tag
                break
        mapped = mapped or s  # already a short tag
        if mapped not in tags:
            tags.append(mapped)
    return ",".join(tags) if tags else "research-2026-06-12"

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9@._+-]*$")

# ============================ INDICATOR CURATION =============================
# Only these npm package names are genuinely malicious. Everything else named in
# the campaign ("axios", "minimist", "chalk", "yargs", ...) is a LEGIT decoy and
# must never be flagged.
MAL_NPM = {"atomic-lockfile", "js-digest", "lockfile-js"}

# Concrete attacker-dropped paths. Excludes /proc/self/exe (always present),
# /usr/bin/monero-wallet-gui (legit if installed), and any "<generated_name>".
FILE_PATHS = [
    ("/sys/fs/bpf/hidden_pids",   "eBPF rootkit pinned map (hides PIDs) — payload artifact"),
    ("/sys/fs/bpf/hidden_names",  "eBPF rootkit pinned map (hides filenames) — payload artifact"),
    ("/sys/fs/bpf/hidden_inodes", "eBPF rootkit pinned map (hides socket inodes) — payload artifact"),
    ("~/.local/bin/sudo",         "credential-theft sudo shim reported by analysts"),
    ("/tmp/node_modules/atomic-lockfile", "resident wave-1 install (payload runs 'cd /tmp; npm install')"),
    ("/tmp/node_modules/js-digest",       "resident wave-2 install (payload runs 'cd /tmp; bun add')"),
    ("/tmp/node_modules/lockfile-js",     "resident wave-2 install (payload runs 'cd /tmp; bun add')"),
]

# (sha256hex, path-or-glob, desc). Only file-content hashes paired with a path
# the script can stat. The 'deps' ELF lives at <pkg>/package/src/hooks/deps.
DEPS_SHA = "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b"
HASHES = [
    (DEPS_SHA, "/tmp/node_modules/*/package/src/hooks/deps", "'deps' ELF credential-stealer (3,040,376 bytes) in /tmp install"),
    (DEPS_SHA, "~/node_modules/*/package/src/hooks/deps",    "'deps' ELF credential-stealer in a home node_modules"),
]

# Attacker-side network indicators only. Loopback and every legitimate service
# the stealer contacts (openai/slack/github/discord/teams/npm) are EXCLUDED.
DOMAINS = [
    ("domain", "olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid.onion",
     "attacker Tor C2 host (manual review: check Tor/proxy/DNS logs)"),
    ("domain", "temp.sh", "exfil upload destination used by the payload (manual review)"),
    ("domain", "raw.gitubusercontent.com",
     "typosquat domain posted in-thread (NOT githubusercontent); manual review"),
]

# Exact substrings that should never appear in a legitimate PKGBUILD/.install.
PKGBUILD_PATTERNS = [
    ("atomic-lockfile",     "wave-1 malicious npm package name in a build recipe"),
    ("js-digest",           "wave-2 malicious npm package name in a build recipe"),
    ("lockfile-js",         "wave-2 malicious npm package name in a build recipe"),
    ("src/hooks/deps",      "atomic-lockfile preinstall hook path (executes the ELF)"),
    ("lib/install-deps.mjs","js-digest preinstall hook path"),
]
# Deliberately NOT emitted as active rows (documented as limitations in README):
#   process-name  -> rootkit hides PIDs; 'npm'/'bun'/'deps' too generic (false positives)
#   systemd-unit  -> persistence uses RANDOMIZED unit names; no literal to match

def build_indicator_rows():
    rows = []
    for n in sorted(MAL_NPM):
        rows.append(("npm-package", n, f"malicious npm package installed at build time ({n})", "sonatype,socket,aur-general-thread"))
    for path, desc in FILE_PATHS:
        rows.append(("file-path", path, desc, "ioctl-analysis,arch-bbs"))
    for h, path, desc in HASHES:
        rows.append(("hash", f"{h}:{path}", desc, "ioctl-analysis"))
    for typ, val, desc in DOMAINS:
        rows.append((typ, val, desc, "ioctl-analysis,aur-general-thread"))
    for pat, desc in PKGBUILD_PATTERNS:
        rows.append(("pkgbuild-pattern", pat, desc, "aur-general-thread,sonatype"))
    return rows

# ============================ PACKAGE CURATION ===============================
def build_package_rows(data):
    rows, dropped = [], []
    for p in data.get("packages", []):
        name = (p.get("name") or "").strip()
        if not NAME_RE.match(name):
            dropped.append(name)
            continue
        vers = [v for v in (p.get("bad_versions") or []) if re.search(r"\d", v)]
        versions = ",".join(vers) if vers else "*"
        incident = p.get("incident") or "atomic-arch-2026-06"
        conf = p.get("confidence") or "single-source"
        rows.append((name, versions, incident, conf, tag_sources(p.get("sources"))))
    rows.sort(key=lambda r: r[0])
    # de-dup by name (keep first)
    seen, uniq = set(), []
    for r in rows:
        if r[0] in seen:
            continue
        seen.add(r[0]); uniq.append(r)
    return uniq, dropped

def tsv(path, header_lines, rows):
    with open(path, "w") as f:
        for h in header_lines:
            f.write(h + "\n")
        for r in rows:
            f.write("\t".join(r) + "\n")

def main():
    data = json.load(open(SRC))
    pkg_rows, dropped = build_package_rows(data)
    ioc_rows = build_indicator_rows()

    pkg_header = [
        "# Compromised AUR packages — \"Atomic Arch\" campaign (June 2026) + related incidents.",
        "# Compiled 2026-06-12. Provenance, update process, and corrections: see README.md.",
        "# Columns: name<TAB>bad_versions(comma-sep or *)<TAB>incident<TAB>confidence<TAB>sources(comma-sep)",
        "# confidence: primary-source (aur-general thread / official Arch) | multi-source | single-source",
    ] + [f"#%window {inc} {s} {e}" for inc, s, e in WINDOWS]

    ioc_header = [
        "# Defensive indicators for the \"Atomic Arch\" AUR compromise (June 2026).",
        "# Values come ONLY from published analyses; this repo contains no payload content.",
        "# Curated for HIGH PRECISION: decoy npm pkgs, legit services (openai/slack/github),",
        "# loopback, randomized systemd unit names, and git-commit SHAs are deliberately excluded.",
        "# Columns: type<TAB>value<TAB>description<TAB>source",
        "# types: npm-package | file-path | hash | systemd-unit | process-name | pkgbuild-pattern | domain | ip",
    ]

    out_pkg = os.environ.get("ACC_PKG_TSV", os.path.join(ROOT, "data", "compromised-packages.tsv"))
    out_ioc = os.environ.get("ACC_IOC_TSV", os.path.join(ROOT, "data", "indicators.tsv"))
    tsv(out_pkg, pkg_header, pkg_rows)
    tsv(out_ioc, ioc_header, ioc_rows)

    print(f"packages written : {len(pkg_rows)}")
    print(f"indicators written: {len(ioc_rows)}")
    if dropped:
        print(f"dropped non-package-name entries ({len(dropped)}): {dropped}", file=sys.stderr)

if __name__ == "__main__":
    main()
