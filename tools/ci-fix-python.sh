#!/usr/bin/env bash
# CI test of scripts/fix-python-env.sh against throwaway virtualenvs (needs python3 with venv, and network
# access to PyPI). Never touches an existing environment.
#
#   1. a plain venv with an old pip and certifi: both are upgraded, logged, and the logged undo restores them
#   2. a venv dressed as a conda environment whose certifi says conda installed it (INSTALLER = conda):
#      the script leaves it alone, prints a conda install command, and exits 3
#
# Usage: tools/ci-fix-python.sh   (from the repository root)
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$REPO/skills/remediate-emudhra-on-my-machine/scripts/fix-python-env.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export REMEDIATE_EMUDHRA_STATE_DIR="$T/state"
PY3="$(command -v python3)"
ver() { "$1" -c "import $2; print($2.__version__)"; }

echo "== 1. plain venv"
"$PY3" -m venv "$T/plain"
"$T/plain/bin/python" -m pip install -q --disable-pip-version-check 'pip==25.2' 'certifi==2024.8.30'
bash "$FIX" "$T/plain/bin/python"
[ "$(ver "$T/plain/bin/python" certifi)" = 2026.10.19 ] || { echo "certifi was not upgraded" >&2; exit 1; }
undo="$(tail -1 "$T/state/actions.log" | sed 's/.*\tundo: //')"
echo "+ $undo"; bash -c "$undo" >/dev/null
[ "$(ver "$T/plain/bin/python" certifi)" = 2024.08.30 ] || { echo "the logged undo did not restore certifi" >&2; exit 1; }

echo "== 2. conda-owned certifi"
"$PY3" -m venv "$T/conda"
"$T/conda/bin/python" -m pip install -q --disable-pip-version-check 'certifi==2024.8.30'
mkdir "$T/conda/conda-meta"
for f in "$T"/conda/lib/python*/site-packages/certifi-*.dist-info/INSTALLER; do echo conda > "$f"; done
rc=0; out="$(bash "$FIX" "$T/conda/bin/python")" || rc=$?
printf '%s\n' "$out"
[ "$rc" -eq 3 ] || { echo "expected exit 3, got $rc" >&2; exit 1; }
printf '%s\n' "$out" | grep -q "conda install -p .*'certifi>=2026.10.19'" || { echo "no conda install advice" >&2; exit 1; }
[ "$(ver "$T/conda/bin/python" certifi)" = 2024.08.30 ] || { echo "pip touched a conda-owned certifi" >&2; exit 1; }

echo "OK: fix-python-env.sh upgrades pip-owned packages with an undo, and leaves conda-owned ones to conda"
