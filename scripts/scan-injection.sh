#!/usr/bin/env bash
#
# scan-injection.sh — structural detector for build-time config-injection worms.
#
# Detects the self-propagating worm family that appends an obfuscated RCE payload
# to auto-run config files (postcss/eslint/jest/next/babel/…) and executes it on
# every lint/build. Unlike the old check, this does NOT enumerate config
# filenames and does NOT depend on a single marker string — the worm has evaded
# both by picking an unlisted filename (eslint.config.mjs) and mutating its
# marker. Instead it scans every git-TRACKED text file for structural hallmarks.
#
# It also covers the 2026-09 variant found on Bolt-Silverfox/storytime-devops,
# which hid nothing in a config file at all:
#   * the payload was 31,303 bytes of JavaScript committed as
#     public/fonts/fa-solid-400.woff2 — magic bytes "    " (spaces), not wOF2;
#   * the trigger was a hidden .vscode/tasks.json task (hide/reveal:never) with
#     runOn: folderOpen, so merely opening the folder in VS Code ran it, with
#     "task.allowAutomaticTasks": true in settings.json to suppress the prompt;
#   * its marker was global.i="A8-..." — the marker-string check greps
#     global['!'], so it matched nothing.
# Hence the three checks below: binary assets whose magic bytes contradict their
# extension, VS Code auto-execution config, and a marker check that matches the
# A8- family generically rather than one literal string.
#
# Canonical source: Bolt-Silverfox/storytime-ci:scripts/scan-injection.sh
# Vendored copies in other repos are hash-verified against this one in CI.
#
# Usage:
#   scan-injection.sh            # scan all tracked files (CI)
#   scan-injection.sh --staged   # scan only staged files (pre-commit hook)
#
# Exit 0 = clean, 1 = indicator(s) found, 2 = usage/environment error.

set -uo pipefail

MAX_LINE=500                      # obfuscated blobs are always one absurd line

# Worm marker families. Deliberately NOT one literal string: the 2026-08 wave
# used global['!'] / A8-2503, the 2026-09 wave used global.i="A8-*#new". The
# third alternative matches the A8- campaign tag generically, but only in the
# "assigned to a global" shape, so ordinary strings containing "A8-" don't fire.
MARKER_RE="global\['!'\]|A8-2503|global(\.[A-Za-z_\$][A-Za-z0-9_\$]*|\[[^]]{1,32}\])[[:space:]]*=[[:space:]]*[\"'][[:space:]]*A8-"

ALLOW_FILE=".ci-scan-allow.txt"   # "sha256␠␠path" per line: reviewed minified/vendored files

# Extension matching must be case-INSENSITIVE, and this was a TOTAL bypass, not a
# partial one. bash `case` is case-sensitive unless `nocasematch` is set (this
# script deliberately does not set it — a global shell option silently changes
# every unrelated `case` in the file, including the mode parser and the magic-byte
# comparison). So `fa-solid-400.WOFF2` matched neither is_binary_asset nor
# asset_magic, and is_scan_target lists no font/image extensions either — the file
# therefore fell out of check (4) AND was never picked up by checks (1)-(3), so NO
# check examined it at all. Capitalising one letter defeated the exact magic-byte
# comparison that caught the live 2026-09 payload. Verified before the fix.
# Every classifier below is fed lc "$f" instead of "$f"; the real path is still
# used for file access, so behaviour on a case-sensitive filesystem is unchanged.
# `tr`, not `${f,,}`: parameter-expansion case conversion is bash 4.0+, and this
# script is deliberately bash 3.2-safe (see the mapfile note below) because it also
# runs as a pre-commit hook on stock macOS. The explicit A-Z/a-z ranges avoid
# locale-dependent multibyte behaviour in [:upper:]/[:lower:].
lc() {
  # shellcheck disable=SC2018,SC2019  # ASCII-only is intentional: file extensions
  # are ASCII, and [:upper:]/[:lower:] are locale-dependent for multibyte input.
  printf '%s' "$1" | tr 'A-Z' 'a-z'
}

# Structural tokens split across physical lines evaded every grep below. All of
# these checks inspected ONE physical line, yet the payload's own syntax does not
# have to be on one line to run:
#     global.i =
#       "A8-2503#new"
#   "runOn":
#     "folderOpen"
# Both are valid JS / JSONC and both were reported clean. So the greps now match
# against a copy of the file with newlines folded to spaces, which lets the
# patterns' existing [[:space:]]* spans cover a line break too.
#
# This does NOT over-broaden. The patterns still require the value to be ADJACENT
# to its key/operator with nothing but whitespace between, so folding
#     "runOn": "build",
#     "label": "folderOpen"
# gives `"runOn": "build", "label": "folderOpen"` — intervening text, no match.
# Folding is a strict superset of the per-line match (a newline becomes a space,
# which [[:space:]]* already accepted), so it REPLACES the line-oriented greps
# rather than adding a second parallel mechanism. It also fixes CRLF files for
# free. The overlong-line rule in check (1) is intentionally NOT folded: it is a
# statement about physical line length.
#
# `grep -c` + count test, never `grep -q`: under `pipefail`, grep -q closes the
# pipe on its first match, `tr` dies of SIGPIPE (141), and pipefail turns the whole
# pipeline non-zero — so a REAL detection would be discarded as a miss. That trap
# already bit this script once (see check (1)). Reading from a redirect rather
# than passing a filename also makes this immune to option injection, so no
# safe_path is needed here.
grep_folded() {
  local _hits
  _hits=$(tr '\n' ' ' < "$2" | grep -caE -- "$1" || true)
  [ "${_hits:-0}" -gt 0 ]
}

mode="all"
case "${1:-}" in
  --staged) mode="staged" ;;
  ""|--all) mode="all" ;;
  # `sed 1d` drops the shebang, which would otherwise print as "!/usr/bin/env bash".
  -h|--help) sed 1d "$0" | grep '^#' | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown arg: $1" >&2; exit 2 ;;
esac

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "::error::scan-injection.sh must run inside a git work tree" >&2
  exit 2
fi

# Tracked files only → node_modules and build output are excluded for free, and
# we inspect exactly what is (or is about to be) committed.
# NOTE: no `mapfile` — it is bash 4+, and stock macOS still ships bash 3.2, where
# the hook would abort (and under `set -u` the later "${files[@]}" expansion of an
# unset array aborts too). A plain read loop is portable.
#
# `-z` (NUL-delimited) is REQUIRED, not a nicety. Without it git applies
# core.quotePath and emits a non-ASCII path as a C-quoted string with the quotes
# INCLUDED — `git ls-files` prints "caf\303\251.js" for café.js. That string
# names no file, so the `[ -f "$f" ]` guard below skipped it and the payload was
# never scanned, silently, with the run still reporting "clean". Verified: a
# marker-carrying café.js and a disguised logó.woff2 both passed. NUL-delimited
# output is never quoted or escaped, which also handles a path containing a
# newline or a double quote. `read -d ''` is bash 3.2-safe (unlike mapfile -d).
files=()
while IFS= read -r -d '' _line; do
  files+=("$_line")
done < <(if [ "$mode" = "staged" ]; then
           git diff --cached --name-only --diff-filter=ACM -z
         else
           git ls-files -z
         fi)

# Guard the empty case explicitly: on bash < 4.4, "${files[@]}" on an empty array
# is an "unbound variable" error under `set -u`.
if [ "${#files[@]}" -eq 0 ]; then
  echo "scan-injection: clean — no $([ "$mode" = staged ] && echo 'staged' || echo 'tracked') files to scan."
  exit 0
fi

# Text files worth scanning: code + config + data. Broad on purpose (no filename list).
is_scan_target() {
  case "$1" in
    *.js|*.mjs|*.cjs|*.ts|*.tsx|*.jsx|*.cts|*.mts|*.json|*.vue|*.svelte) return 0 ;;
    *.config.*|*rc.js|*rc.cjs|*rc.mjs|*rc.ts) return 0 ;;
    *) return 1 ;;
  esac
}

# Executable code (the worm's actual target). The overlong-line rule applies
# ONLY here: a long line in an executable module is an obfuscated code blob. It
# does NOT apply to .json/data, which is legitimately minified onto one line and
# is inert (not executed by build tooling). Code-injection SIGNATURES are still
# grepped in every scan target, so a payload disguised in data is caught too.
is_executable_code() {
  case "$1" in
    *.js|*.mjs|*.cjs|*.ts|*.tsx|*.jsx|*.cts|*.mts|*.vue|*.svelte) return 0 ;;
    *.config.js|*.config.mjs|*.config.cjs|*.config.ts) return 0 ;;
    *rc.js|*rc.cjs|*rc.mjs|*rc.ts) return 0 ;;
    *) return 1 ;;
  esac
}

# Binary assets that have a well-known file signature. A payload disguised as
# one of these is caught by the magic-byte mismatch alone, with no marker and no
# knowledge of the payload's contents. Values are the expected leading bytes as
# lowercase hex; multiple alternatives are separated by "|".
#   woff2 -> "wOF2"        woff -> "wOFF"
#   ttf   -> 00 01 00 00 (TrueType) | "true" | "ttcf" (collection)
#   otf   -> "OTTO"       | 00 01 00 00 (CFF outlines in a TrueType wrapper)
# .eot has no stable leading signature (it starts with length fields), so it gets
# the text/JavaScript check below but no magic comparison.
asset_magic() {
  case "$1" in
    *.woff2) echo '774f4632' ;;
    *.woff)  echo '774f4646' ;;
    *.ttf)   echo '00010000|74727565|74746366' ;;
    *.otf)   echo '4f54544f|00010000' ;;
    *.png)   echo '89504e47' ;;
    *.gif)   echo '47494638' ;;
    *.jpg|*.jpeg) echo 'ffd8ff' ;;
    # .ico also accepts PNG magic on purpose. Shipping a bare PNG named
    # favicon.ico is standard practice (every browser accepts it, and favicon
    # generators / Next.js app/favicon.ico routinely emit one), so treating it
    # as a mismatch was a false positive that would have failed CI in every
    # consumer repo. A PNG is still a real image, and such a file remains
    # covered by the file(1) text/code check and the marker grep below.
    *.ico)   echo '00000100|00000200|89504e47' ;;
    *)       return 1 ;;
  esac
}

# Assets we inspect even when they carry no magic comparison.
is_binary_asset() {
  case "$1" in
    *.woff2|*.woff|*.ttf|*.otf|*.eot|*.png|*.gif|*.jpg|*.jpeg|*.ico) return 0 ;;
    *) return 1 ;;
  esac
}

# macOS has no sha256sum; it ships `shasum`. Without this the allowlist silently
# never matches on a Mac, so a reviewed false positive keeps blocking commits.
sha256_of() {
  local t
  capture t safe_path "$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$t" 2>/dev/null | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$t" 2>/dev/null | awk '{print $1}'
  else
    return 1
  fi
}

is_allowed() {
  [ -f "$ALLOW_FILE" ] || return 1
  local h
  h=$(sha256_of "$1") || return 1
  [ -n "$h" ] && grep -qE -- "^${h}[[:space:]]" "$ALLOW_FILE"
}

# Option-injection guard. A tracked path that begins with "-" is parsed by every
# downstream tool as an OPTION, not a file. This was a complete bypass, not a
# cosmetic issue: a file named `-e.js` carrying the live marker made grep read
# `-e` as its pattern flag and the regex as the filename, so the scan printed
# "clean" and exited 0. Verified before the fix. `--` alone is not enough (awk
# and shasum handle it inconsistently across implementations), so paths are
# passed as `./-e.js`, which no tool can mistake for an option. git only ever
# emits repo-relative paths here, so prefixing is always valid.
safe_path() {
  case "$1" in
    -*) printf './%s' "$1" ;;
    *)  printf '%s' "$1" ;;
  esac
}

# Command substitution strips ALL trailing newline bytes from its output, and a
# git pathname really can END in one — that is exactly what the -z change above
# made reachable. So `sf=$(safe_path "$f")` silently handed every downstream tool
# a path one byte short of the real filename: verified, `awk`/`head`/`file` then
# reported "No such file or directory" and the magic-byte comparison ran on an
# empty string. `capture VAR cmd...` appends a sentinel byte INSIDE the same
# substitution and strips only that byte, so the value arrives byte-exact.
# `printf -v` is bash 3.1+, so it is safe here (the script targets bash 3.2 for
# the macOS pre-commit hook); `eval` is deliberately avoided.
capture() {
  local _target=$1 _out
  shift
  _out=$("$@"; printf x)
  printf -v "$_target" '%s' "${_out%x}"
}

# Output-only escaping for a pathname that is about to be PRINTED. git pathnames
# are arbitrary bytes, and now that the file list is NUL-delimited they really can
# contain LF and CR (that was the point of the -z fix). The findings block is
# written to stderr of a GitHub Actions step, and Actions parses every LINE of it
# for workflow commands — so a tracked file named
#   $'x\n::error::spoofed'   or   '::error::spoofed.js'
# could forge annotations or emit ::stop-commands:: to derail command processing.
# It cannot hide the failure (the exit code is unaffected), but it can make the
# log lie about WHAT was found, which is the part a human acts on. So CR/LF are
# rendered as visible two-character escapes and every pathname is emitted behind a
# fixed `path=` prefix, which also means an attacker-chosen name can never sit at
# the start of a line where Actions would look for `::`.
# Done with bash pattern substitution (bash 2.0+, so 3.2-safe) rather than awk or
# sed. sed is out because BSD sed (macOS, where the pre-commit hook runs) does not
# understand \r in a regex and would match a literal "r", corrupting every path
# containing that letter. awk is out because it is record-oriented: a name ending
# in a newline has no record after the separator, so `evil.js\n` and `evil.js`
# rendered IDENTICALLY — the one distinction this function exists to make.
render_path() {
  local p=$1
  p=${p//$'\r'/'\r'}
  p=${p//$'\n'/'\n'}
  printf 'path=%s' "$p"
}

# Findings accumulate with REAL newlines and are printed with printf '%s', not
# '%b'. Pathnames inside them go through render_path (above) first.
# '%b'. '%b' expands backslash escapes in its argument, and the argument now
# contains attacker-chosen file PATHS (the -z change above means paths with
# backslashes actually reach here) — a file named 'x\u0041.js' would have been
# mangled, and printf warns on a malformed escape. '%s' prints paths verbatim.
nl='
'
bad=""
for f in "${files[@]}"; do
  [ -f "$f" ] || continue           # deleted/renamed away
  # sf is captured byte-exact (see capture() above) because it is used to READ
  # the file. lf is captured with plain substitution ON PURPOSE: it is only used
  # to CLASSIFY, and dropping a trailing newline there is what makes a file named
  # `payload.js<newline>` still match `*.js` and get scanned rather than skipped.
  capture sf safe_path "$f"
  lf=$(lc "$f")                     # extension matching is case-insensitive
  is_scan_target "$lf" || continue
  is_allowed "$f" && continue        # reviewed known-good minified/vendored file

  # (1) Obfuscated CODE blob: an overlong line that ALSO carries obfuscation /
  # dynamic-exec hallmarks. Overlong ALONE is legit in real source (SVG path
  # data in icon components, long className strings, data URIs), so we require a
  # malicious signature ON the long line. The worm's payload line is packed with
  # _0x… hex identifiers and =require(, so it is caught; a shadcn icon's long
  # SVG line is not. JSON/data is inert and excluded from this rule entirely.
  # `grep -c`, NOT `grep -q`: with `pipefail`, grep -q closes the pipe on its
  # first match, awk dies of SIGPIPE (141), and pipefail then makes the whole
  # pipeline non-zero — so a REAL detection is silently discarded as a miss.
  # Verified: on a large file with an early match the -q form returns 141.
  # (Dropping just the -q does not help — GNU grep optimises `>/dev/null` the
  # same way.) grep -c has to read every line to count, so it never early-exits.
  if is_executable_code "$lf"; then
    long_hits=$(awk -v m="$MAX_LINE" 'length($0) > m' "$sf" \
      | grep -caE "_0x[0-9a-fA-F]{4,}|=[[:space:]]*require\(|String\.fromCharCode\(|eval\(|atob\(|Function\(" || true)
    if [ "${long_hits:-0}" -gt 0 ]; then
      bad+="$(render_path "$f"): overlong obfuscated code line (blob payload)${nl}"
      continue
    fi
  fi

  # (2) Require-hijack / char-code obfuscation hallmarks anywhere (line length
  # independent — the stager's require shim/hijack may sit on short lines too).
  if grep_folded "global\[[^]]+\][[:space:]]*=[[:space:]]*require|global\.[A-Za-z_\$][A-Za-z0-9_\$]*[[:space:]]*=[[:space:]]*require|String\.fromCharCode\([^)]*,[^)]*,[^)]*,|(_0x[0-9a-fA-F]{4,}[^_]*){4,}" "$f"; then
    bad+="$(render_path "$f"): require-hijack / char-code / hex-identifier obfuscation${nl}"
    continue
  fi

  # (3) Known marker families — cheap fast-path for the observed waves. Not a
  # single literal: the 2026-09 variant mutated global['!'] into global.i="A8-…",
  # so the A8- campaign tag is matched generically wherever it is assigned to a
  # global (dot OR bracket form). Requiring the "global<assignment>'A8-" shape
  # keeps it from firing on an ordinary string that happens to contain "A8-"
  # (a colour, a hash, an AWS instance type).
  if grep_folded "$MARKER_RE" "$f"; then
    bad+="$(render_path "$f"): known worm marker family${nl}"
    continue
  fi
done

# ---------------------------------------------------------------------------
# (4) Binary assets whose magic bytes contradict their extension.
#
# This is what catches a payload committed as a font: no marker, no filename
# list, no knowledge of the payload — a .woff2 that does not begin with "wOF2"
# is not a font, whatever it contains. file(1), when present, additionally
# rejects any such asset it reports as text/JavaScript (covering .eot and any
# format without a stable signature). Real fonts/images are untouched.
# ---------------------------------------------------------------------------
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  capture sf safe_path "$f"         # byte-exact: used to read the file
  lf=$(lc "$f")                     # .WOFF2 must classify exactly like .woff2
  is_binary_asset "$lf" || continue
  is_allowed "$f" && continue

  if magic=$(asset_magic "$lf"); then
    head_hex=$(head -c 4 -- "$sf" | od -An -tx1 -v | tr -d ' \n')
    matched=no
    while IFS= read -r want; do
      [ -n "$want" ] || continue
      case "$head_hex" in "$want"*) matched=yes; break ;; esac
    done < <(printf '%s\n' "$magic" | tr '|' '\n')
    if [ "$matched" = no ]; then
      bad+="$(render_path "$f"): extension/magic-byte mismatch — expected ${magic}, got ${head_hex} (payload disguised as an asset)${nl}"
      continue
    fi
  fi

  if command -v file >/dev/null 2>&1; then
    desc=$(file -b -- "$sf" 2>/dev/null || true)
    case "$desc" in
      *JavaScript*|*"ASCII text"*|*"Unicode text"*|*"shell script"*|*"Python script"*|*"UTF-8 text"*)
        bad+="$(render_path "$f"): binary asset that file(1) reports as text/code — \"${desc}\" (payload disguised as an asset)${nl}"
        continue ;;
    esac
  fi

  # Keep the pre-existing content grep too: an asset with VALID magic bytes and
  # a payload appended after the real font data would pass both checks above.
  if grep_folded "$MARKER_RE|=[[:space:]]*require\(" "$f"; then
    bad+="$(render_path "$f"): worm marker / require-hijack inside a binary asset${nl}"
    continue
  fi
done

# ---------------------------------------------------------------------------
# (5) VS Code auto-execution config.
#
# The delivery half of the 2026-09 variant: a hidden tasks.json task with
# runOn: folderOpen executed the disguised payload on folder open. Nothing in
# these repos legitimately needs a task to auto-run on folder open, or needs
# automatic tasks pre-approved, so both are hard failures. tasks.json is JSONC
# (comments + trailing commas — the live malicious file had one), so this is
# grep-based on purpose: jq cannot parse it.
# ---------------------------------------------------------------------------
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  capture sf safe_path "$f"         # byte-exact: used to read the file
  # Lowercased: on the case-insensitive filesystems VS Code also runs on (macOS,
  # Windows) `.VSCode/tasks.JSON` is loaded exactly like `.vscode/tasks.json`.
  lf=$(lc "$f")
  case "$lf" in
    .vscode/*.json|*/.vscode/*.json|*.code-workspace) ;;
    *) continue ;;
  esac

  # Escape-obfuscation guard, and it must come FIRST. JSON property names and
  # string values may carry \uXXXX escapes, and VS Code decodes them before use:
  # {"runOptions":{"run\u004fn":"folder\u004fpen"}} is a live folderOpen task
  # that no literal grep below can see. In JSON the ONLY way to write an ASCII
  # alphanumeric other than literally is \uXXXX, so rejecting \u in these files
  # closes the entire evasion class without needing a JSONC parser (which this
  # script cannot assume — it also runs as a pre-commit hook). Legitimate VS Code
  # config has no reason to \u-escape ASCII; note this does NOT match "\\" , so
  # Windows paths like "C:\\tools" are unaffected.
  if grep -qaE -- '\\u[0-9a-fA-F]{4}' "$sf"; then
    bad+="$(render_path "$f"): JSON unicode escape (backslash-u) in a VS Code config — unescape it so it can be reviewed literally (escapes can hide runOn/folderOpen from this scan)${nl}"
    continue
  fi

  if grep_folded '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f"; then
    detail="auto-running task (runOn: folderOpen)"
    if grep_folded '"hide"[[:space:]]*:[[:space:]]*true' "$f"; then
      detail="$detail, hidden from the task list"
    fi
    if grep_folded '"reveal"[[:space:]]*:[[:space:]]*"never"' "$f"; then
      detail="$detail, output suppressed (reveal: never)"
    fi
    bad+="$(render_path "$f"): ${detail}${nl}"
    continue
  fi

  if grep_folded '"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*"?(true|on)"?' "$f"; then
    bad+="$(render_path "$f"): automatic tasks pre-approved (task.allowAutomaticTasks) — removes VS Code's run-on-open prompt${nl}"
    continue
  fi
done

if [ -n "$bad" ]; then
  echo "::error::Config-injection indicators found ($([ "$mode" = staged ] && echo staged || echo tracked) scan):" >&2
  printf '%s' "$bad" >&2
  echo "If a flagged file is a legitimate minified/vendored asset, add its 'sha256  path' to ${ALLOW_FILE} after review." >&2
  exit 1
fi

echo "scan-injection: clean — no indicators in $([ "$mode" = staged ] && echo 'staged' || echo 'tracked') files."
exit 0
