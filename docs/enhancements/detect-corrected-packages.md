# Enhancement: detect & annotate "corrected" (upstream-fixed) packages

**Status:** proposed (planned first issue)
**Type:** detection precision + data schema

## Summary

When a compromised AUR package is reset by Arch staff back to a clean commit
(a force-push removing the malicious commit), record that it was **corrected**
and *when*. Use that metadata to make the checker more precise and more
informative — **not** to stop flagging it.

## The non-negotiable constraint

**"Fixed on the AUR" does NOT mean "safe on the user's machine."**

Example (real, 2026-06-12): `vidalia` was compromised at 12:15 UTC and reset at
12:48 UTC. The AUR branch is clean now — but anyone who ran `yay -S vidalia`
in that 33-minute window built the malicious commit and ran the payload. Their
machine is still compromised. The entire reason this tool exists is that
upstream correction does not undo a local, build-time compromise.

So a "corrected" package must **still flag** any user who installed/built it
during its bad window. "Corrected" annotates upstream state; it never suppresses
a package from the check.

## Proposed behavior

1. **Per-package bad window.** Record `compromised_at` → `corrected_at` per
   package (the malicious push time and the staff reset time). The history layer
   then warns only for installs inside *that package's* specific window, instead
   of the broad campaign-wide window (`2026-06-09..13`) used today — fewer false
   WARNINGs.
2. **"Fixed upstream" status on the published list.** A `corrected_at` value
   answers a different question users ask — "is it safe to reinstall now?" — and
   improves the list's readability. It marks the row; it does not remove it.
3. **Severity nuance (carefully).** If a package is corrected AND the user's
   installed version matches the current clean HEAD AND nothing in their pacman
   history falls in the window → downgrade that finding to INFO ("compromised
   historically, fixed upstream, your install looks clean"). An in-window install
   still flags, always.

## Guardrails

- **Re-compromise is real.** The campaign saw packages reset and then hit again.
  "Corrected" cannot be permanent or single-window — support multiple windows and
  keep re-checking; never treat a past correction as a permanent all-clear.
- **Verify the reset actually removed the signature.** A force-push by
  `archlinux-github` to a pre-malicious SHA is a strong signal, but confirm the
  new HEAD lacks the payload signature (the updater's diff already shows the
  signature in the *removed* lines of a reset — reuse that).
- **Never suppress outright.** Corrected → annotate + refine severity. A package
  is never delisted or skipped on the basis of being corrected.

## Implementation sketch

- **Updater (`scripts/update-list.py`):** it already observes both events of a
  reset package (malicious push, then staff force-push to clean). Extend it to
  record `compromised_at`/`corrected_at` (and per-package window) when it sees a
  reset whose diff removes a signature.
- **Schema (`data/compromised-packages.tsv` + `research/findings.json`):** add a
  per-package window / `corrected_at` field (new column, or a parallel record).
  Keep `curate-findings.py` deterministic.
- **Checker (`check-aur-compromise.sh`):** consume per-package windows in the
  history layer; add the "fixed upstream" annotation and the INFO-downgrade rule
  for clearly-clean current installs.

## Acceptance criteria

- A package reset upstream is shown as corrected (with date) on the list.
- A user who installed it **inside** its window is still flagged (CRITICAL/WARN).
- A user whose only install is **outside** the window, on a clean current
  version, sees at most INFO — not a WARNING.
- Re-compromised packages are re-flagged (correction is not permanent).
- `curate-findings.py` output stays deterministic; all existing tests pass.

## Out of scope

- Auto-remediation / cleanup of an infected machine (separate, larger design).
