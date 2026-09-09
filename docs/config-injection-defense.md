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
| `.github/workflows/malware-scan.yml` | `storytime-ci` (canonical, reusable) | CI gate + weekly deep scan. Other repos call it. |
| thin caller workflow | every other repo | 5 lines; invokes the reusable workflow. |
| branch protection | GitHub settings (owner) | Makes the CI scan **required** → merge-blocking. |

## The 2026-09 variant (why checks 4 and 5 exist)

Found live on `main` of the public repo `Bolt-Silverfox/storytime-devops`. It put
nothing in a config file at all, so checks 1–3 as they stood could not see it:

* **Payload**: `public/fonts/fa-solid-400.woff2` — 31,303 bytes of JavaScript.
  Leading bytes `20202020` (four spaces), not `wOF2`; `file(1)` reports
  "JavaScript source"; marker `global.i="A8-*#new"`; uses `spawn`. It was the
  only `fa-solid-400.*` file in a directory where every other font family ships
  five formats.
* **Trigger**: a `.vscode/tasks.json` task labelled `eslint-check` with
  `"hide": true`, `"reveal": "never"` and `"runOn": "folderOpen"`, running
  `node ./public/fonts/fa-solid-400.woff2` on folder open — with
  `"task.allowAutomaticTasks": true` in `.vscode/settings.json` so VS Code never
  prompted.
* **Delivery**: split across two commits months apart — the trigger in
  `fdf5255d`, whose title claimed to *delete* `ansible/group_vars/staging.yml`
  while quietly adding `.vscode/*` and `public/fonts/*`, and the payload blob in
  `70f065de`. Neither half looks malicious alone.

An EVM-based C2 was reported for this family; the payload here is obfuscated and
that was **not** confirmed from strings, so it is not claimed as fact. The
disguise, the hidden auto-run trigger, the marker and `spawn` are confirmed.

Root cause of the miss: **marker-string matching**. Hence checks 4 and 5 are
structural.

## How detection works (no filename list, no single marker)

`scan-injection.sh` walks `git ls-files` (so `node_modules`/build output are
excluded automatically) and flags a file on **any** of:

1. **Overlong line** (>500 chars) in an **executable** JS/TS module — the
   obfuscated blob is always one absurd line. Not applied to `.json`/data, which
   is legitimately minified and inert.
2. **Require-hijack / obfuscation hallmarks** — `global[...]=require`,
   `global.X=require`, `String.fromCharCode(`, dense `_0x…` hex identifiers.
   Grepped in **all** scanned files (code + json + vue/svelte).
3. **Known marker families** — `global['!']`, `A8-2503`, and the `A8-` campaign
   tag generically wherever it is *assigned to a global* (`global.x = "A8-…"` or
   `global['x'] = "A8-…"`). Not one literal string: the 2026-09 variant mutated
   `global['!']` into `global.i="A8-*#new"` and so matched nothing. Requiring the
   "assigned to a global" shape keeps it from firing on an ordinary string that
   merely contains `A8-` (a SKU, a ticket id, an instance type).
4. **Disguised binary assets** — any `.woff2`/`.woff`/`.ttf`/`.otf`/`.png`/
   `.gif`/`.jpg`/`.ico` whose leading bytes contradict its extension, plus any
   of those (and `.eot`, which has no stable signature) that `file(1)` reports
   as text/JavaScript/script. **This is marker-free**: a `.woff2` that does not
   begin with `wOF2` is not a font whatever it contains. The same marker /
   `=require(` grep still runs over these assets, to catch a payload appended
   *after* valid font data.
5. **VS Code auto-execution** — `runOn: folderOpen` in any `.vscode/*.json` or
   `*.code-workspace` (flagged harder when combined with `hide: true` /
   `reveal: never`), and `"task.allowAutomaticTasks": true`, which removes VS
   Code's run-on-open prompt. Grep-based on purpose: `tasks.json` is JSONC
   (comments and trailing commas), so `jq` cannot parse it — the live malicious
   file had a trailing comma. Because those greps are literal, any `\uXXXX`
   escape in one of these files is rejected outright: JSON lets a property name
   or value be written `"run\u004fn": "folder\u004fpen"`, VS Code decodes it
   before use, and no literal grep could see it. In JSON the only way to write an
   ASCII alphanumeric other than literally is `\uXXXX`, so rejecting the escape
   closes the whole class without needing a JSONC parser. `"\\"` is not matched,
   so Windows paths are unaffected.

False positives (a genuinely minified/vendored *tracked* file) are cleared by
adding its `sha256␠␠path` to `.ci-scan-allow.txt` **after review**.

### Path handling (two bypasses found by review, both fixed)

The checks above are only as good as the list of files they are applied to. Two
ways of naming a file made the scan skip it *silently*, reporting `clean` and
exiting 0 — verified against a real marker payload before the fix:

* **Non-ASCII / quoted paths.** `git ls-files` applies `core.quotePath` and
  prints `café.js` as the 12-character string `"caf\303\251.js"`, quotes
  included. That names no file, so the `[ -f ]` guard skipped it. Both file
  lists are now read **NUL-delimited** (`git ls-files -z`,
  `git diff --cached -z`), which is never quoted or escaped and also handles a
  path containing a newline or a double quote.
* **Paths beginning with `-`.** A file named `-e.js` was parsed by `grep` as the
  `-e` option: the regex became the *filename* and the payload was never read.
  Paths are now passed to external tools as `./-e.js`. (`--` alone was not used:
  `awk` and `shasum` handle it inconsistently across implementations.)

Findings are printed with `printf '%s'`, not `%b`, since the accumulated message
now contains attacker-chosen paths and `%b` would expand backslash escapes in
them.

Extension/magic-byte checking accepts **PNG magic for `.ico`**: shipping a bare
PNG named `favicon.ico` is standard practice and every browser accepts it, so
rejecting it was a false positive that would have failed CI in every consumer
repo. Such a file is still a real image, and remains covered by the `file(1)`
text/code check and the marker grep.

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

1. Edit `scripts/scan-injection.sh` in `storytime-ci` (the canonical home — the workflow header says so, and this repo exists precisely so a history rewrite elsewhere cannot orphan it).
2. In the **same PR**, bump `SCAN_SCRIPT_SHA256` in
   `.github/workflows/malware-scan.yml` to the new
   `sha256sum scripts/scan-injection.sh`.
3. Re-vendor the identical script to every other repo (a small PR each). Until a
   repo is re-vendored, its scan fails closed (drift) — intended.

> The path-handling fixes above changed the script, so `SCAN_SCRIPT_SHA256` moved
> to `5d6cdf43932b522e96305ef3d2846875582a9e080e6a3dc86871604381413419`. **Every
> consumer repo needs re-vendoring**; until then its scan fails closed on drift,
> which is the intended, visible failure mode rather than a silent weakening.

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
