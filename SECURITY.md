# Security policy

## What this project is

`atomic-arch-check` is a **detection-only, read-only** tool. The checker
(`check-aur-compromise.sh`) makes no network connections, never modifies the
system, and never executes anything it finds. The updater (`scripts/update-list.py`)
is a separate, deliberately-invoked tool that *does* make read-only GitHub API
calls and is never run by the checker. See the README "Trust properties" section.

## Reporting a problem with the tool

Open a GitHub issue for: false positives, false negatives, bugs, or packaging
problems. Please include your distro, `bash --version`, and the relevant
(redacted) output.

If you believe you've found a security issue **in this tool itself** (e.g. a way
it could write, execute, or exfiltrate), please report it privately via GitHub's
"Report a vulnerability" (Security → Advisories) rather than a public issue.

## Reporting a newly-compromised AUR package

If you find a compromised AUR package not on the list, please open an issue or PR
against `data/compromised-packages.tsv` with the package name and a link to the
evidence (e.g. the malicious commit on the AUR git mirror). The maintainer also
runs `scripts/update-list.py` to discover new ones from the authoritative mirror.

## Data integrity

Updates to the data files are run on the maintainer's machine and committed by
hand — there is no CI or automation that could be spoofed into injecting a bad
entry. Every change is in the git history. For the strongest assurance, verify
the signed release tag.

## If you think you're compromised

This tool does not remediate. If you get a CRITICAL result, follow the README
"If you get a CRITICAL" steps: disconnect, rotate credentials from a clean
device, and consult official Arch guidance.
