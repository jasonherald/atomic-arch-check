# atomic-arch-check

A single-file, strictly read-only bash script that checks an Arch-based system for exposure to the June 2026 **"Atomic Arch" AUR compromise** — including *historical* exposure that a check of currently installed packages would miss.

> **Do not pipe this (or any) script into your shell.** No `curl ... | bash`. Blindly executing unread code is exactly how this incident spread. Clone the repo, read `check-aur-compromise.sh` (it is short), then run it.

## What happened

In June 2026, attackers pushed malicious commits to a large number of AUR packages, impersonating the identity of each package's prior commit author. The commits added a post-install step to `PKGBUILD`/`.install` files that, **at build/install time**, changed into `/tmp` and installed a malicious npm/bun package whose `preinstall` hook executed a bundled ELF binary — a credential stealer (browser, SSH, cloud, and developer credentials) paired with an eBPF rootkit and Tor-based C2.

There were two waves:

- **Wave 1** (~June 10–11): `npm install atomic-lockfile`
- **Wave 2** (~June 12): `bun add js-digest` / `lockfile-js`

Roughly 400+ packages were reported initially, growing to **1700+** as analysis continued. Arch staff reset the malicious commits and banned the attacker accounts. **The official Arch repositories were NOT affected** — this involved AUR (user-submitted) content only.

Canonical status thread: [aur-general "AUR REPORT THREAD"](https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/).

## Why current-version checks aren't enough

The payload runs when the package is **built or installed**. A machine can therefore be compromised even if the bad package was since upgraded or removed — checking only what is installed right now gives false assurance. This tool checks three layers:

1. **Installed packages** — foreign packages (`pacman -Qm`) matched against the compromised-package list. An exact known-bad version is CRITICAL; a listed name at an unknown/different version is a WARNING.
2. **Historical exposure** — `/var/log/pacman.log` (including rotated logs, compressed `.gz`/`.xz`/`.zst`/`.bz2`) is parsed for installs/upgrades of listed packages; an install inside the malicious-commit window is a WARNING. AUR-helper caches (`~/.cache/yay`, `~/.cache/paru/clone`) are scanned for cached `PKGBUILD`/`.install`/`.SRCINFO` files containing known-malicious patterns — a hit there is hard evidence (CRITICAL), and it is checked for *all* cached packages, listed or not, since the public list may be incomplete.
3. **Resident payload indicators** — ~20 high-precision indicators from `data/indicators.tsv`: malicious npm package names (caches, `node_modules`, global installs), dropped-file paths (eBPF pinned maps, the `/tmp` installs, a `sudo` shim), the payload ELF's sha256, and attacker Tor/exfiltration domains.

## Usage

```bash
git clone https://github.com/jasonherald/atomic-arch-check
cd atomic-arch-check
less check-aur-compromise.sh   # audit it first — it is short and has no surprises
./check-aur-compromise.sh
```

Run as a normal user. Anything the tool could not read (other users' homes, `/root`, rotated logs, unreadable caches) is reported as a `[SKIP]` line — these are **coverage gaps, not findings**. For full coverage of a multi-user machine:

```bash
sudo ACC_HOME_ROOTS="$(ls -d /home/* | tr '\n' ':')/root" ./check-aur-compromise.sh
```

### Options

| Option | Effect |
|---|---|
| `--quiet` | print only the final verdict line |
| `--no-color` | disable colored output |
| `--deep` | also deep-scan home directories for malicious `node_modules` in non-standard locations (slower) |
| `--data-dir D` | read data files from `D` (default: `./data` next to the script) |
| `--version` | print version and exit |
| `-h`, `--help` | show help |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | clean — no indicators found |
| `1` | CRITICAL findings — evidence of compromise |
| `2` | warnings only — possible exposure, review the report |
| `3` | usage or runtime error |

Findings are graded: **CRITICAL** (exact known-bad version installed/in history, malicious pattern in a cached build recipe, or a resident payload indicator), **WARNING** (listed package at an unrecorded/different version, or an install inside the malicious-commit window), **INFO** (manual-review notes, e.g. which domains to look for in your network logs), and **SKIP** (checks that could not run).

Requires bash 4.3+ and standard coreutils; Arch ships bash 5.x.

## Get the list (or check without cloning)

The list is plain text in the repo, served directly over GitHub's CDN — there is no separate server to trust or depend on. The raw URLs always reflect the latest commit:

- Full data: `https://raw.githubusercontent.com/jasonherald/atomic-arch-check/main/data/compromised-packages.tsv`
- Indicators: `https://raw.githubusercontent.com/jasonherald/atomic-arch-check/main/data/indicators.tsv`
- Last refreshed (UTC): `https://raw.githubusercontent.com/jasonherald/atomic-arch-check/main/data/last-updated.txt`

Updates are run **on the maintainer's machine and committed by hand** (no CI, no automation) and pushed roughly once or twice a day, so the history is a tamper-evident record of exactly what changed and when.

Quick "is one installed right now?" check — no clone, audit the one-liner before running it:

```bash
comm -12 \
  <(pacman -Qqm | sort -u) \
  <(curl -fsSL https://raw.githubusercontent.com/jasonherald/atomic-arch-check/main/data/compromised-packages.tsv \
      | grep -v '^#' | cut -f1 | sort -u)
```

Any package name it prints is one you have installed that's on the list — investigate it. **This quick check only compares currently-installed names**; it does *not* cover historical/build-time exposure (a bad package since removed), cached malicious PKGBUILDs, or resident payload indicators. For those, clone the repo and run `check-aur-compromise.sh` — that's what the three layers are for.

## Trust properties

These are the core guarantees, and the script is deliberately short so you can verify each one yourself by reading it:

- **Zero network calls.** No `curl`, `wget`, or any other network access. List updates come only via `git pull`.
- **Strictly read-only.** It never writes to, modifies, quarantines, or deletes anything on the system.
- **It never executes anything it discovers.** Suspicious files are stat'ed, hashed, or grepped — never run.
- **No payload content in this repo.** The data files contain only names, paths, hashes, and patterns from published analyses — nothing that helps reproduce the attack.

## If you get a CRITICAL

Treat the machine as compromised:

1. **Disconnect it from the network.**
2. **Rotate credentials, API tokens, and SSH keys from a different, trusted device.** The payload steals browser, SSH, cloud, and developer credentials, so anything stored or cached on the machine should be considered exposed.
3. Follow official Arch guidance for reinstalling affected packages and assessing the system, and check the [aur-general thread](https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/) for current status.

This tool deliberately does **not** auto-remediate. Cleanup of a rootkit-backed compromise is risky to automate; if added later it will be a separate, separately-reviewed feature.

## Data provenance & updates

Compiled **2026-06-12** from: the aur-general "AUR REPORT THREAD" (primary), the community cscs.pastes.sh list, force-push analysis of the read-only AUR git mirror ([github.com/archlinux/aur](https://github.com/archlinux/aur)), the CachyOS forum thread, and published analyses (ioctl.fail, Sonatype, socket.dev).

- `data/compromised-packages.tsv` — **1716 packages**: 1713 from the 2026 Atomic Arch incident plus 3 from an unrelated earlier 2025 AUR incident (tagged `chaos-rat-2025`). Each row carries a confidence tier (`primary-source` / `single-source`) and the source tags it was derived from.
- `data/indicators.tsv` — **20 high-precision indicators** (npm package names, file paths, the payload sha256, domains, PKGBUILD patterns). Indicators are intentionally narrow: decoy packages, legitimate services, and randomized artifact names are excluded to avoid false positives.

The derivation is reproducible: `research/findings.json` + `scripts/curate-findings.py` → `data/*.tsv`, with every inclusion/exclusion rule spelled out in the script. Update the list with `git pull`; report corrections or new findings via issues/PRs.

### Keeping the list current

Two ways to update, with different trust trade-offs:

- **`git pull`** — zero setup. Gets the maintainer's curated data. This is the
  path for everyone, and the only one most people need.
- **`scripts/update-list.py`** — advanced/live-from-source, and a **separate tool
  from the checker** (the checker never calls it and stays offline). It queries
  the authoritative AUR git mirror (`github.com/archlinux/aur`) via the GitHub
  API for recent commits whose diffs contain the known payload signatures, then
  re-curates the list locally through the same rules as `git pull` data. It
  requires the [`gh`](https://cli.github.com/) CLI, authenticated
  (`gh auth login`) — by design, so running it is a deliberate act.

  ```bash
  scripts/update-list.py            # dry run: show what WOULD change, write nothing
  scripts/update-list.py --apply    # write the changes, then review with `git diff`
  ```

  It **makes network calls** (announced on every run), but only reads and parses
  *text* — it never builds, executes, or installs anything. All discovered data
  still passes through curation, so a noisy source cannot inject decoys or false
  indicators. It scans a recent activity window (`--days`, default 2) and is meant
  to be run periodically; `git pull` remains the authoritative baseline.

## How this was built (AI-assisted, human-reviewed)

I'm telling you exactly how this was made so you can decide for yourself how much to trust it.

This tool was built by a human (the author) working with an AI coding assistant: **Anthropic's Claude — specifically the Claude Fable 5 model (`claude-fable-5`)**, driven through the [Claude Code](https://www.anthropic.com/claude-code) agent harness. The same model was used throughout — both as the main assistant and as the many parallel sub-agents that did the research and the code reviews described below. No other AI model was involved. The division of labor was roughly:

- **AI did the heavy lifting:** drafting the detection script, writing the test suite, and compiling the compromised-package list and indicators from source material.
- **The human directed and reviewed it:** set the goals and the strict detection-only/read-only constraints, made the design and curation decisions, reviewed the code and data by hand, and ran the tool on a real Arch system before publishing. The human is accountable for what ships here.

How the threat data was gathered: the package list and indicators were compiled by AI agents performing **read-only** analysis of primary and community sources — the aur-general mailing-list archive, the force-push history of the read-only [AUR git mirror](https://github.com/archlinux/aur), the community cscs.pastes.sh list, the CachyOS forum thread, and published technical analyses (ioctl.fail, Sonatype, socket.dev). **No malicious package was ever built, installed, or executed during development** — by design and by deliberate constraint. The repo contains only indicator metadata, never payload content.

Quality process before release: the script was written test-first (71 tests), put through multiple independent adversarial review passes that found and fixed real bugs (including multi-user/`sudo` coverage gaps and a `/etc/hosts` blocklist false positive), made `shellcheck`-clean, and its indicator set was curated with explicit allow/deny rules to keep out decoys and legitimate services that would cause false positives.

**What this means for you:** don't take any of the above on faith. The script is short and commented so you can audit it in a few minutes; every data row cites the sources it came from; and the test suite and the curation rules (`scripts/curate-findings.py`) are in the repo. Read them and judge for yourself. Treat the package list as a researched, best-effort, point-in-time snapshot — not an authoritative registry — and weight entries using their confidence tiers.

## Limitations

Honest scope notes — read these before trusting a CLEAN verdict:

- **The list is a point-in-time snapshot of a still-live campaign.** It may be incomplete (new packages were still being found at compilation time) and, because it errs toward catching exposure, may over-include. Most entries have no recorded bad version and match at version `*`, producing a WARNING that prompts investigation rather than asserting compromise. Use the confidence tiers to weight entries.
- **Absence of findings is NOT proof of safety.**
- **Persistence uses randomized systemd unit names**, so units cannot be matched by name; the tool relies on the concrete file/hash/npm indicators instead. The malicious process is hidden by the rootkit, so the process check is best-effort and point-in-time only.
- **Domains/IPs are checked only against `/etc/hosts`.** True network-level detection requires manually reviewing your Tor/proxy/DNS/firewall logs; the tool prints exactly which indicators to look for.
- **Non-standard JS package-manager caches** (yarn/pnpm, custom npm prefixes) are best covered with `--deep`, which scans home directories for malicious `node_modules` anywhere.

## Related tools — use this, or fold it into yours

This exists to help, not to plant a flag. If another tool fits you better, use it. And if you maintain one, please take whatever's useful from here — the curated package list (`data/compromised-packages.tsv`, every row sourced and confidence-tiered), the indicator set (`data/indicators.tsv`), or the live-updater approach (`scripts/update-list.py`) — and fold it into your project. It's MIT-licensed precisely so you can. Corrections and PRs are welcome too.

The most complete sibling project is **[lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check)** — a solid multi-layer checker consolidated from the community gists, well worth using. It overlaps heavily with this one. The differences, as of 2026-06-12:

- **List breadth:** this repo's list is a strict superset (~1,700 packages vs ~500), from additionally mining the AUR git-mirror force-push history rather than only aggregating gists.
- **Staying current:** this repo ships a separate **live updater** that discovers newly-compromised packages from the authoritative AUR mirror on demand (it caught `vidalia` the day it was hijacked, which static lists hadn't yet listed), instead of shipping a frozen list.

If you only want one tool, either is a reasonable choice — and the two lists are easy to merge.

Other community resources (audit before running, as with anything here):

- cscs.pastes.sh `aurvulnlist` / `aurvulntest`
- [github.com/fpafumi/aur-scan](https://github.com/fpafumi/aur-scan)
- [`show-aur-changes` — archlinux/contrib PR #108](https://github.com/archlinux/contrib/pull/108)

## License & disclaimer

Provided **as-is, without warranty of any kind**. It is a detection aid, not a guarantee of system integrity.

License: [MIT](LICENSE) — © 2026 Jason Herald.
