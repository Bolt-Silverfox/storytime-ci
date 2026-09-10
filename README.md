# storytime-ci

Shared, reusable GitHub Actions workflows for the Storytime repos.

This repo exists so that the commit consumers pin can **never be orphaned by a
history rewrite in an application repo** (that happened in storytime_be in
2026-08 and silently disabled malware scanning on every consumer for a week).

**Rules for this repo**
- Never force-push or rewrite history here.
- Every change is a PR. When `scripts/scan-injection.sh` changes: push that
  commit, then bump `SCANNER_REF` in `.github/workflows/malware-scan.yml` to it
  in a **second commit**, and **merge — never squash** (a squash orphans the SHA
  that `SCANNER_REF` names). A self-check step in the workflow fails the build if
  you skip the bump.
- Land changes with **"Create a merge commit"** only. Squash and rebase rewrite
  commit SHAs, which orphans anything pinned to them (`SCANNER_REF` here, and the
  consumers' `uses:` pins).
- Tag releases (`malware-scan-vN`) for humans; consumers must always pin the
  full 40-char commit SHA (a `# malware-scan-vN` comment may annotate it).
  Never pin a bare tag: tags are mutable.

## malware-scan

`.github/workflows/malware-scan.yml` - structural config-injection scan +
disguised-font check on every push/PR, weekly deep scan with shai-hulud-detect.

Consumer caller (`.github/workflows/malware-scan.yml` in each repo):

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

That pinned line is the **entire** integration: the reusable workflow checks
`scripts/scan-injection.sh` out of this repo at run time, so consumers vendor no
script and carry no checksum. See `docs/config-injection-defense.md`.

Take `<40-char-sha>` from `git rev-parse origin/main` (or the tag's commit) at the
time you add the caller. It must be a commit **at or after** the change that
removed the vendored-script requirement — earlier pins, including
`39ed211bd06d47dfd1d5011ba5f32f6b7e6c4a5d` (`malware-scan-v1`), run the old
workflow, which requires a caller-local `scripts/scan-injection.sh` and fails the
checksum gate without one.
