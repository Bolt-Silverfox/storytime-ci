# Config-injection defense (anti-worm gate)

Layered defense against the self-propagating build-time worm that appends an
obfuscated RCE payload to auto-run config files (postcss/eslint/jest/next/…) and
executes it on every lint/build. It has hit this org three times, each time
evading the previous gate by picking an **unlisted config filename** and
**mutating its marker**. This gate is therefore **filename-agnostic and
marker-agnostic** — it detects the injection *structurally*.

## Components

| Piece | Where | Role |
|---|---|---|
| `scripts/scan-injection.sh` | every repo (identical, hash-pinned) | The detector. Scans git-tracked files. |
| `.githooks/pre-commit` | every repo | Local early-warning (scans staged files). Bypassable. |
| `.github/workflows/malware-scan.yml` | `storytime_be` (canonical, reusable) | CI gate + weekly deep scan. Other repos call it. |
| thin caller workflow | every other repo | 5 lines; invokes the reusable workflow. |
| branch protection | GitHub settings (owner) | Makes the CI scan **required** → merge-blocking. |

## How detection works (no filename list, no single marker)

`scan-injection.sh` walks `git ls-files` (so `node_modules`/build output are
excluded automatically) and flags a file on **any** of:

1. **Overlong line** (>500 chars) in an **executable** JS/TS module — the
   obfuscated blob is always one absurd line. Not applied to `.json`/data, which
   is legitimately minified and inert.
2. **Require-hijack / obfuscation hallmarks** — `global[...]=require`,
   `global.X=require`, `String.fromCharCode(`, dense `_0x…` hex identifiers.
   Grepped in **all** scanned files (code + json + vue/svelte).
3. **Known marker families** — `global['!']`, `A8-2503` (cheap fast-path).

False positives (a genuinely minified/vendored *tracked* file) are cleared by
adding its `sha256␠␠path` to `.ci-scan-allow.txt` **after review**.

## Enable the local hook (one-time, per clone)

```bash
git config core.hooksPath .githooks
```

Bypassable with `git commit --no-verify` — it is convenience, not the guarantee.
The **CI required check is the real gate**.

## Single source, no drift

The logic lives only in `scripts/scan-injection.sh`. Every repo vendors an
**identical** copy; the reusable workflow pins its `sha256`
(`SCAN_SCRIPT_SHA256`) and fails the build if a repo's copy is missing, stale, or
tampered. This is exactly the drift that let the scanner arrive *infected* in one
repo before.

### Updating the detector

1. Edit `scripts/scan-injection.sh` in `storytime_be`.
2. In the **same PR**, bump `SCAN_SCRIPT_SHA256` in
   `.github/workflows/malware-scan.yml` to the new
   `sha256sum scripts/scan-injection.sh`.
3. Re-vendor the identical script to every other repo (a small PR each). Until a
   repo is re-vendored, its scan fails closed (drift) — intended.

## Rollout to another repo

1. Copy `scripts/scan-injection.sh` (identical bytes) and `.githooks/pre-commit`.
2. Add the thin caller workflow (see `docs/security/malware-scan-caller.example.yml`).
3. Push; confirm the `malware-scan` check runs green.
4. **Owner:** add the check to branch protection (below).

## Make it merge-blocking (owner action — GitHub UI)

For each repo, for each protected/deploy branch (`dev`, `develop-v1.3.0`,
`main`, `staging`, release branches):

1. **Settings → Branches → Branch protection rules → Add/Edit** for the branch
   (or branch pattern).
2. Enable **Require status checks to pass before merging**.
3. Search and require the check by name. **The name differs by repo:**
   - in **storytime_be** (runs the workflow directly): `config-injection + disguised-font scan`
   - in **every other repo** (thin caller job named `scan`): `scan / config-injection + disguised-font scan`
4. Recommended: also enable **Require branches to be up to date before merging**
   and protect `.github/` + `scripts/scan-injection.sh` with a CODEOWNERS review
   so the gate itself can't be quietly weakened.

Until step 2–3 are done the scan runs but does **not** block merges.
