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
| `scripts/scan-injection.sh` | **`storytime-ci` only** — CI fetches it at run time | The detector. Scans git-tracked files. |
| `.github/workflows/malware-scan.yml` | `storytime-ci` (canonical, reusable) | CI gate + weekly deep scan. Other repos call it. |
| thin caller workflow | every other repo | 5 lines, pin only. **Nothing else to vendor.** |
| `.githooks/pre-commit` + a local `scripts/scan-injection.sh` | `storytime_be`, `storytime-fe` | Local early-warning (scans staged files). Convenience, **allowed to drift** — see below. |
| branch protection / ruleset | GitHub settings (owner) | Makes the CI scan **required** → merge-blocking. |

Consumer repos used to vendor a byte-identical copy of the script, kept honest by a
`SCAN_SCRIPT_SHA256` gate in the workflow. That is **gone**: every scanner change
meant a pin bump *and* a script re-vendor in nine repos, and a repo that had only
half of it failed closed on drift. The reusable workflow now checks the script out
of `storytime-ci` itself, so the pinned `uses:` line is the whole integration.

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

### Path and token handling (five bypasses found by review, all fixed)

The checks above are only as good as (a) the list of files they are applied to
and (b) the assumption that a token sits on one physical line. Five ways of
naming or formatting a file made the scan skip it *silently*, reporting `clean`
and exiting 0 — each verified against a real marker payload before the fix, and
each covered by a regression test in `tests/scan-injection.test.sh`:

* **Non-ASCII / quoted paths.** `git ls-files` applies `core.quotePath` and
  prints `café.js` as the C-quoted string `"caf\303\251.js"`, quotes
  included. That names no file, so the `[ -f ]` guard skipped it. Both file
  lists are now read **NUL-delimited** (`git ls-files -z`,
  `git diff --cached -z`), which is never quoted or escaped and also handles a
  path containing a newline or a double quote.
* **Paths beginning with `-`.** A file named `-e.js` was parsed by `grep` as the
  `-e` option: the regex became the *filename* and the payload was never read.
  Paths are now passed to external tools as `./-e.js`. (`--` alone was not used:
  `awk` and `shasum` handle it inconsistently across implementations.)
* **Uppercase extensions.** bash `case` is case-sensitive and this script does
  not set `nocasematch`, so `fa-solid-400.WOFF2` matched neither
  `is_binary_asset` nor `asset_magic` — and `is_scan_target` lists no font/image
  extensions either, so the file also fell out of checks 1–3. **No check examined
  it at all**: capitalising one letter defeated the exact magic-byte comparison
  that caught the live 2026-09 payload. All three classifiers are now fed a
  lowercased copy of the path (`lc`), as is the `.vscode/` path match — on the
  case-insensitive filesystems VS Code also runs on, `.VSCode/tasks.JSON` loads
  just like `.vscode/tasks.json`. `nocasematch` was deliberately *not* used: it
  is a global shell option that would silently change every unrelated `case` in
  the script, including the argument parser and the magic-byte comparison.
  `lc` uses `tr`, not `${var,,}`, because the latter is bash 4.0+ and this script
  is bash 3.2-safe for the macOS pre-commit hook.
* **Paths ending in a newline.** Fixing the quoting above made this reachable:
  `git ls-files -z` hands over a name ending in `\n` intact, but bash command
  substitution strips *all* trailing newlines from its output, so
  `sf=$(safe_path "$f")` produced a path one byte short of the real filename.
  `awk`, `head` and `file` then reported "No such file or directory" — check (1)
  errored out, and the magic-byte comparison ran on an empty string, flagging a
  *genuine* font as a mismatch. Captures that feed file access now go through
  `capture`, which appends a sentinel byte inside the same substitution and
  strips only that byte. Classification captures (`lc`) deliberately keep plain
  substitution: dropping the trailing newline there is what lets
  `payload.js\n` still match `*.js` and be scanned rather than skipped — read the
  path exactly, classify it leniently.

* **Structural tokens split across lines.** `grep` is line-oriented, but the
  payload's syntax is not: `global.i =` on one line and `"A8-…"` on the next is
  valid JS, and `"runOn":` / `"folderOpen"` on two lines is valid JSONC. Both
  were reported clean. Those greps now run through `grep_folded`, which matches
  against the file with newlines folded to spaces, so the patterns' existing
  `[[:space:]]*` spans cover a line break (and CRLF files, for free). This does
  **not** broaden what matches: the value must still be *adjacent* to its
  key/operator with only whitespace between, so `"runOn": "default"` followed by
  a separate `"detail": "folderOpen"` still does not fire. Folding is a strict
  superset of the per-line match, so it *replaces* the line-oriented greps rather
  than adding a second parallel mechanism. The overlong-line rule in check 1 is
  intentionally not folded — it is a statement about physical line length.
  `grep_folded` counts with `grep -c` instead of `grep -q` for the same reason
  check 1 does: under `pipefail`, `-q` closes the pipe early, `tr` dies of
  SIGPIPE, and a real detection would be discarded as a miss.

Findings are printed with `printf '%s'`, not `%b`, since the accumulated message
now contains attacker-chosen paths and `%b` would expand backslash escapes in
them. For the same reason every printed pathname goes through `render_path`: the
findings block is written to a GitHub Actions step's stderr, which Actions parses
line by line for workflow commands, so a tracked file named `::error::spoofed.js`
or one with an embedded newline could forge annotations (it cannot hide the
failure — the exit code is unaffected — but it can make the log lie about what was
found). CR/LF are rendered as visible `\r`/`\n` escapes and every path is emitted
behind a fixed `path=` prefix so it can never begin a line. The escaping is bash
pattern substitution rather than `awk`: `awk` is record-oriented, so a name
ending in a newline has no record after the separator and `evil.js\n` rendered
identically to `evil.js` — the one distinction the function exists to make. The
regression test asserts the stronger invariant that the scanner's own header is
the only output line beginning with `::` at all, which covers a forged
`::warning::` or `::stop-commands::` and not just `::error::`.

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

## Single source: the scanner lives in one repo only

`scripts/scan-injection.sh` exists in `storytime-ci` and nowhere else that CI
reads. The reusable workflow runs two checkouts:

1. `actions/checkout` of the **caller** — the tree to be scanned, in
   `$GITHUB_WORKSPACE`.
2. `actions/checkout` of **`Bolt-Silverfox/storytime-ci`** at the immutable
   `SCANNER_REF` commit, into `.storytime-ci/` with `sparse-checkout: scripts`.
   `storytime-ci` is public, so no token is involved.

Then `bash .storytime-ci/scripts/scan-injection.sh` runs with the working
directory still at `$GITHUB_WORKSPACE`. That distinction matters: the scanner
picks its files from `git ls-files` of the repo it is *run in*, so it scans the
caller and **not** `storytime-ci`. A nested clone is untracked in the outer repo,
so nothing under `.storytime-ci/` is ever scanned — which also means this repo's
own scanner and docs cannot self-flag (that has caused false positives here
before). Verified in a real run: `git ls-files` listed 8 caller paths and zero
under `.storytime-ci/`.

If that checkout fails or the script is absent, the job **fails closed** with an
actionable annotation before the scan step. A malware scan that quietly does
nothing is the worst possible outcome, and this workflow has shipped that bug
twice (a `grep -q` SIGPIPE under `pipefail` discarding a real detection, and a
`Review skipped` status that read as a pass).

### Why `SCANNER_REF` is a hardcoded SHA

Ideally the workflow would check the scanner out at *its own* commit, so the two
could never disagree and there would be nothing to maintain. **That value is not
reachable from a workflow expression.** Measured in a real cross-workflow run
(2026-09-10), inside a `workflow_call` job:

* `github.job_workflow_sha` → **empty string**. The claim of that name belongs to
  the OIDC token, not the `github` context; reading it would require
  `id-token: write` in every consumer's caller.
* `github.workflow_sha` / `github.workflow_ref` → the **top-level (calling)**
  workflow. The probe resolved `workflow_ref` to the caller's own file, so in a
  real consumer these name the *consumer's* repo and commit, and checking
  `storytime-ci` out at a consumer's SHA would 404.

So `SCANNER_REF` is a hardcoded 40-char SHA, and the maintenance cost is honest:
**one value, in one repo**, replacing a checksum that had to be bumped in nine.
It is not a movable ref, deliberately — an account with write access has planted
malware in these repos three times and the vector is unresolved, so the malware
scanner must not resolve through a mutable tag or branch.

The one way it can rot is someone changing the script and forgetting the bump,
leaving consumers on the old detector. The workflow therefore has a self-check
step, gated to `github.repository == 'Bolt-Silverfox/storytime-ci'` (skipped in
every consumer), that fails if `scripts/scan-injection.sh` at HEAD is not
byte-identical to the copy at `SCANNER_REF`.

### Updating the detector

1. Edit `scripts/scan-injection.sh` in `storytime-ci` (the canonical home — this
   repo exists precisely so a history rewrite elsewhere cannot orphan it) and
   push. Add a regression test in `tests/scan-injection.test.sh`.
2. In a **second commit on the same branch**, set `SCANNER_REF` in
   `.github/workflows/malware-scan.yml` to the SHA of commit 1. The self-check
   step goes green again at that point.
3. Land it with **"Create a merge commit"** only. Squash *and* rebase rewrite
   commit 1 into a new SHA and orphan the one `SCANNER_REF` names — while the
   byte-comparison self-check still passes, so the breakage surfaces later, in
   consumers. Do not amend or rebase commit 1 after step 2 either. An orphaned pin
   is the exact accident that silently disabled scanning org-wide in 2026-09.
4. Bump the pinned SHA in each consumer's caller to the new `storytime-ci` tip.
   Dependabot already watches the `github-actions` ecosystem in all consumers and
   opens these PRs; you can also bump by hand. **There is no script to re-vendor
   and no hash to bump in a consumer** — a consumer still on an older pin keeps
   running that older, self-consistent scanner instead of failing on drift.

### The local pre-commit hook keeps a copy, and that copy may drift

`storytime_be` and `storytime-fe` run the scanner from `.githooks/pre-commit`
against *staged* files, which needs the script on disk before any CI exists. Those
repos therefore keep a local `scripts/scan-injection.sh`, and it is **allowed to
be out of date**. This is deliberate:

* it is a **convenience, not a security control** — the hook is opt-in
  (`git config core.hooksPath .githooks`) and bypassable
  (`git commit --no-verify`);
* **CI is the gate that actually blocks**, and CI no longer looks at that file at
  all — it fetches the pinned copy from `storytime-ci`. A stale local copy can
  therefore only mean a *weaker local warning*, never a weaker merge gate;
* the hook already degrades safely: if the script is missing or not executable it
  prints a notice and exits 0 rather than blocking a commit.

So do **not** add a drift check for it, and do not treat "the local copy is
behind" as a security finding. Refresh it when convenient — but fetch it at the
**same commit that repo's caller workflow already pins**, never from `main`. This
file is executable code that the hook then runs on your machine, so pulling it
from a movable branch would be a developer-machine execution path that a
write-access compromise could change without an immutable reference (the very
threat model this whole document exists for):

```bash
# the SHA this repo already trusts, taken from its own caller workflow
SHA=$(grep -oE 'storytime-ci/\.github/workflows/malware-scan\.yml@[0-9a-f]{40}' \
        .github/workflows/malware-scan.yml | head -n1 | cut -d@ -f2)
curl -fsSL "https://raw.githubusercontent.com/Bolt-Silverfox/storytime-ci/${SHA}/scripts/scan-injection.sh" \
  -o scripts/scan-injection.sh && chmod +x scripts/scan-injection.sh
git diff -- scripts/scan-injection.sh   # read it before you commit it
```

*Suggestion, not implemented here:* the hook could stop tracking a copy entirely
and instead fetch the script once into a cache (e.g.
`.git/cache/scan-injection-<sha>.sh`, keyed on the SHA pinned in that repo's
caller workflow, downloaded on a miss and reused otherwise), falling back to
"skip with a notice" when offline. That would make the local and CI detectors the
same bytes without tracking the file, but it puts a network fetch in the commit
path, so it is left as a follow-up decision.

### Regression tests

`tests/scan-injection.test.sh` runs the scanner against generated throwaway git
repos. It takes the scanner path as its only argument, which is the point: aim it
at the previous revision to prove a bypass really existed, and at the current one
to prove it is closed.

```bash
tests/scan-injection.test.sh                       # current script
git show <old-sha>:scripts/scan-injection.sh > /tmp/old.sh
tests/scan-injection.test.sh /tmp/old.sh           # should FAIL the bypass cases
```

Every positive case is paired with a negative one — a genuine `Inter.WOFF2` and
`Logo.PNG`, ordinary source containing `global.foo = "bar"` and split multi-line
strings, an ordinary `tasks.json`. The negative cases carry equal weight: this
scanner is a required check in ten repos, so a false positive is its own outage.
Fixtures are generated at runtime and never committed — a committed fixture
carrying a real marker would be a tracked file here and would (correctly) fail
this repo's own scan.

## Rollout to another repo

1. Add the thin caller workflow below as `.github/workflows/malware-scan.yml`.
   That is the whole integration — **no script to copy, no hash to set.**
2. Push; confirm the `malware-scan` check runs green.
3. **Owner:** add the check to branch protection / the ruleset (below).
4. Optional: `.githooks/pre-commit` + a local copy of the script, for a local
   early warning. Only worth it in repos people actively develop in, and see the
   drift note above.

### The consumer caller (copy verbatim, then set the pin)

```yaml
name: malware-scan
on:
  push:
  pull_request:
  workflow_dispatch:
  schedule:
    - cron: '0 3 * * 1'
permissions:
  contents: read
jobs:
  scan:
    uses: Bolt-Silverfox/storytime-ci/.github/workflows/malware-scan.yml@<40-char-sha>  # malware-scan-vN
```

Always a **full 40-char commit SHA**, never a bare tag — tags are mutable. The
`# malware-scan-vN` comment is for humans and for Dependabot's PR titles. The job
is named `scan`, so the required check appears as
`scan / config-injection + disguised-font scan`.

Add `github-actions` to that repo's `.github/dependabot.yml` if it is not there
already, so pin bumps arrive as PRs:

```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
```

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
