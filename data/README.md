# Data files

Plain tab-separated tables, each with a column-header row and uniform columns
(so GitHub renders them as searchable tables, and any tool can parse them). No
in-file comments — provenance and methodology live in the top-level `README.md`
("Data provenance" and "How this was built") and in `scripts/curate-findings.py`.

## `compromised-packages.tsv`
The list of compromised AUR packages. Columns:

| column | meaning |
|---|---|
| `name` | exact AUR package name |
| `bad_versions` | comma-separated known-bad versions, or `*` if no specific version is recorded (matches at WARNING level) |
| `incident` | `atomic-arch-2026-06` (this campaign) or `chaos-rat-2025` (an unrelated earlier AUR incident) |
| `confidence` | `primary-source` (aur-general thread / official Arch / mirror) or `single-source` |
| `sources` | comma-separated short source tags |

## `indicators.tsv`
High-precision payload indicators. Columns: `type`, `value`, `description`, `source`.
`type` ∈ `npm-package`, `file-path`, `hash`, `systemd-unit`, `process-name`,
`pkgbuild-pattern`, `domain`, `ip`. Curated to exclude decoy npm packages,
legitimate services, loopback, randomized systemd unit names, and git-commit
SHAs, so it does not produce false positives. Contains only indicator metadata
from published analyses — no payload content.

## `incident-windows.tsv`
Per-incident malicious-commit date windows used by the history layer. Columns:
`incident`, `window_start`, `window_end` (inclusive, `YYYY-MM-DD`).

## `last-updated.txt`
UTC ISO-8601 timestamp of the last refresh, written by `scripts/update-list.py
--apply`.

## Regenerating
`data/compromised-packages.tsv`, `indicators.tsv`, and `incident-windows.tsv`
are generated from `research/findings.json` by `scripts/curate-findings.py`.
Don't hand-edit them; edit the source/curation and regenerate.
