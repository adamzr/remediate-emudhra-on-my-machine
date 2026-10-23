#!/usr/bin/env bash
# Run the repository's lint, format, and validation checks locally: the same checks CI runs in its
# "Lint and validate" job, except PSScriptAnalyzer, which needs pwsh (CI runs it).
#
#   - shellcheck: every .sh, warnings and errors
#   - shfmt: formatting of every .sh, from .editorconfig (-d shows the diff; --fix rewrites)
#   - bash -n: syntax under /bin/bash, which is the stock 3.2 on macOS
#   - markdownlint: every .md, from .markdownlint-cli2.jsonc
#   - actionlint: the GitHub workflows
#   - validate: tools/validate_skill.py, with --since when a base ref is given
#   - skills-ref: the Agent Skills reference validator
#
# Usage: tools/lint.sh [--fix] [--since REF]   (from anywhere in the repository)
# Tools that are not installed are reported and skipped; CI runs all of them.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
FIX=0 SINCE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --fix) FIX=1 ;;
    --since)
      SINCE="${2:?--since needs a git ref}"
      shift
      ;;
    *)
      echo "usage: tools/lint.sh [--fix] [--since REF]" >&2
      exit 2
      ;;
  esac
  shift
done

status=0
skipped=0
step() { printf '== %s\n' "$1"; }
missing() {
  echo "   skipped: $1 is not installed (CI runs it)"
  skipped=$((skipped + 1))
}
shs=(skills/*/scripts/*.sh tools/*.sh)

step shellcheck
if command -v shellcheck > /dev/null; then shellcheck -x -S warning "${shs[@]}" || status=1; else missing shellcheck; fi

step shfmt
if command -v shfmt > /dev/null; then
  if [ "$FIX" = 1 ]; then shfmt -w "${shs[@]}"; else shfmt -d "${shs[@]}" || status=1; fi
else
  missing shfmt
fi

step "bash -n (/bin/bash $(/bin/bash -c 'echo $BASH_VERSION'))"
for f in "${shs[@]}"; do /bin/bash -n "$f" || status=1; done

step markdownlint
if command -v npx > /dev/null; then
  if [ "$FIX" = 1 ]; then npx --yes markdownlint-cli2@0.24.0 --fix > /dev/null; fi
  npx --yes markdownlint-cli2@0.24.0 || status=1
else
  missing npx
fi

step actionlint
if command -v actionlint > /dev/null; then actionlint || status=1; else missing actionlint; fi

step validate
if python3 -c 'import yaml' 2> /dev/null; then
  python3 tools/validate_skill.py ${SINCE:+--since "$SINCE"} || status=1
else
  missing "PyYAML (python3 -m pip install pyyaml)"
fi

step skills-ref
if command -v npx > /dev/null; then npx --yes skills-ref@0.1.5 validate skills/remediate-emudhra-on-my-machine || status=1; else missing npx; fi

if [ "$status" != 0 ]; then
  echo "Some checks failed."
elif [ "$skipped" -gt 0 ]; then
  echo "All checks that ran passed ($skipped skipped)."
else
  echo "All checks passed."
fi
exit "$status"
