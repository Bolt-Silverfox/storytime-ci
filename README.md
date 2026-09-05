# storytime-ci

Shared, reusable GitHub Actions workflows for the Storytime repos.

This repo exists so that the commit consumers pin can **never be orphaned by a
history rewrite in an application repo** (that happened in storytime_be in
2026-08 and silently disabled malware scanning on every consumer for a week).

**Rules for this repo**
- Never force-push or rewrite history here.
- Every change is a PR; bump `SCAN_SCRIPT_SHA256` in the workflow in the same
  PR whenever `scripts/scan-injection.sh` changes, then re-vendor the script to
  consumers.
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
    uses: Bolt-Silverfox/storytime-ci/.github/workflows/malware-scan.yml@<full 40-char commit sha> # malware-scan-vN
```

Each consumer must also vendor an identical `scripts/scan-injection.sh`; the
workflow verifies its sha256 and fails on drift. See
`docs/config-injection-defense.md`.
