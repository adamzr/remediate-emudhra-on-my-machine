#!/usr/bin/env bash
# Upgrade pip and certifi inside ONE Python interpreter or virtualenv, without admin rights.
# Usage: fix-python-env.sh /path/to/python
# Records the versions it replaced so the change can be undone. Never uses --break-system-packages:
# interpreters owned by the OS or a package manager are reported with the right command instead. In a conda
# environment, packages pip installed are upgraded with pip, and packages conda installed get a conda command.
# Exit codes: 0 fixed or nothing needed, 3 deliberately skipped (message says why), 4 still vulnerable.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
PY="${1:?usage: fix-python-env.sh /path/to/python}"
[ -x "$PY" ] || { echo "Not an executable: $PY" >&2; exit 2; }

info="$("$PY" - <<'PY'
import sys, sysconfig, os, glob
def ver(mod):
    try:
        return __import__(mod).__version__
    except Exception:
        return ""
def installer(mod):
    # Who installed the copy that is actually imported ("conda", "pip", "uv"), from its dist-info.
    try:
        site = os.path.dirname(os.path.dirname(os.path.abspath(__import__(mod).__file__)))
        for f in glob.glob(os.path.join(site, mod + "-*.dist-info", "INSTALLER")):
            return open(f).read().strip()
    except Exception:
        pass
    return ""
managed = os.path.exists(os.path.join(sysconfig.get_path("stdlib"), "EXTERNALLY-MANAGED")) and sys.prefix == sys.base_prefix
conda = os.path.isdir(os.path.join(sys.prefix, "conda-meta"))
# A virtualenv python is often a link to the OS python, but its packages are its own.
venv = hasattr(sys, "real_prefix") or sys.prefix != getattr(sys, "base_prefix", sys.prefix)
print("%d.%d|%s|%s|%s|%s|%s|%s|%s|%s" % (sys.version_info[0], sys.version_info[1], ver("pip"), ver("certifi"),
      "managed" if managed else "free", "conda" if conda else "", sys.prefix, installer("pip"), installer("certifi"),
      "venv" if venv else ""))
PY
)"
IFS='|' read -r pyver old_pip old_certifi managed conda prefix pip_inst certifi_inst venv <<EOF
$info
EOF

# The OS's own Python: decided by its prefix, not by where its symlink points, because a virtualenv made
# with the OS python links to it but is the user's to fix.
if [ -z "$venv" ]; then
  case "$prefix" in
    /usr|/System/*|/Library/Developer/*|/Applications/Xcode*.app/*)
      echo "SKIP: $PY belongs to the operating system and must not be modified. Its pip uses the system trust store, which the admin script fixes."
      echo "If the check reported certifi in your own user site-packages, use the OS-owned Python recipe in fix-recipes instead."
      exit 3 ;;
  esac
fi
QPY="$(rem_q "$PY")"

major="${pyver%%.*}"; minor="${pyver#*.}"
py310=0; if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 10 ]; }; then py310=1; fi

# In a conda environment, upgrade each package with whatever installed the copy Python imports. Its
# dist-info INSTALLER file says "conda" or "pip"; a conda-meta record alone can be stale, because pip
# can replace a conda package and leave the record behind. Without an INSTALLER file, fall back to it.
conda_pkgs=""; skip_pip=0; skip_certifi=0
if [ -n "$conda" ]; then
  conda_owned() { # NAME INSTALLER
    if [ -n "$2" ]; then [ "$2" = conda ]; else ls "$prefix/conda-meta/$1"-[0-9]*.json >/dev/null 2>&1; fi
  }
  if [ -n "$old_pip" ] && conda_owned pip "$pip_inst"; then
    skip_pip=1
    if [ "$py310" = 1 ] && ! rem_ver_ge "$old_pip" 26.2.2; then conda_pkgs="'pip>=26.2.2'"; fi
  fi
  if [ -n "$old_certifi" ] && conda_owned certifi "$certifi_inst"; then
    skip_certifi=1
    if ! rem_ver_ge "$old_certifi" 2026.10.19; then
      # The fixed certifi needs Python 3.10+, so conda cannot install it here; it would report success
      # and change nothing.
      if [ "$py310" = 0 ]; then
        echo "FAIL: certifi $old_certifi in $PY is vulnerable, and the fixed certifi needs Python 3.10 or later (this is $pyver). Retire this environment, or rebuild it on Python 3.10 or later."
        exit 4
      fi
      conda_pkgs="${conda_pkgs:+$conda_pkgs }'certifi>=2026.10.19'"
    fi
  fi
fi
# conda_advice -> prints the conda command for the conda-owned packages, if any, and exits 3. It uses
# conda install with a minimum version, which fails loudly if conda cannot reach it (conda update can
# report success and change nothing).
conda_advice() {
  [ -n "$conda_pkgs" ] || return 0
  echo "SKIP: conda installed these in this environment, so upgrade them with conda to keep the environment consistent:"
  echo "  conda install -p $(rem_q "$prefix") $conda_pkgs"
  exit 3
}
if [ "$managed" = managed ]; then
  echo "SKIP: $PY is marked EXTERNALLY-MANAGED (Homebrew or uv owns it)."
  case "$PY" in
    */homebrew/*|*/Cellar/*|/usr/local/*)
      # Homebrew's Pythons import the certifi formula when another formula installed it; upgrading python@3.X leaves it old.
      formulae=""
      if [ -n "$old_pip" ] && ! rem_ver_ge "$old_pip" 26.2.2; then formulae="python@$pyver"; fi
      if [ -n "$old_certifi" ] && ! rem_ver_ge "$old_certifi" 2026.10.19; then
        if ! brew list --versions certifi >/dev/null 2>&1; then
          echo "Its certifi $old_certifi is old and was not installed by Homebrew's certifi formula. Report it at $REM_ISSUES"
          exit 4
        fi
        formulae="${formulae:+$formulae }certifi"
      fi
      [ -n "$formulae" ] || { echo "Its pip and certifi are already fixed. Nothing to do."; exit 0; }
      echo "Preview with: HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew upgrade --dry-run $formulae"
      echo "Fix with: HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew upgrade $formulae" ;;
    */uv/python/*) echo "Fix with: uv python upgrade $pyver" ;;
    *) echo "Its package manager owns it; upgrade certifi with that package manager." ;;
  esac
  exit 3
fi

if [ -z "$old_pip" ]; then
  # conda environments can lack pip too; a conda-owned certifi there is conda's to upgrade.
  if [ "$skip_certifi" = 1 ]; then conda_advice; echo "certifi $old_certifi in $PY is already fixed."; exit 0; fi
  # Virtualenvs created by uv have no pip. Upgrade certifi with uv instead.
  if [ -z "$old_certifi" ]; then echo "Nothing to upgrade in $PY (no pip, no certifi)."; exit 0; fi
  if rem_ver_ge "$old_certifi" 2026.10.19; then echo "certifi $old_certifi in $PY is already fixed."; exit 0; fi
  if ! command -v uv >/dev/null; then
    echo "FAIL: certifi $old_certifi in $PY is vulnerable, and this environment has neither pip nor uv to upgrade it."
    exit 4
  fi
  echo "Upgrading certifi in $PY with uv (this environment has no pip)"
  uv pip install --python "$PY" 'certifi>=2026.10.19'
  new_certifi="$("$PY" -c 'import certifi; print(certifi.__version__)')"
  rem_log "vetted-script:fix-python-env.sh" "upgraded certifi in $PY (uv)" "certifi $old_certifi -> $new_certifi" \
    "uv pip install --python $QPY certifi==$old_certifi"
  echo "Done. certifi $new_certifi. Logged to $REM_LOG"
  exit 0
fi

pkgs=""
if [ "$skip_pip" = 0 ]; then
  if [ "$py310" = 1 ]; then pkgs="pip>=26.2.2"
  else echo "NOTE: Python $pyver cannot run the fixed pip (needs 3.10+). Upgrading certifi only."; fi
fi
if [ -n "$old_certifi" ] && [ "$skip_certifi" = 0 ]; then pkgs="${pkgs:+$pkgs }certifi>=2026.10.19"; fi
if [ -z "$pkgs" ]; then conda_advice; echo "Nothing to upgrade in $PY."; exit 0; fi

echo "Upgrading in $PY with its own pip: $pkgs"
# shellcheck disable=SC2086
if ! "$PY" -m pip install --disable-pip-version-check --upgrade $pkgs; then
  echo "FAIL: pip could not install the fixed versions in $PY. Python $pyver may be too old for them: retire this environment, or rebuild it on Python 3.10 or later."
  exit 4
fi

undo="$QPY -m pip install"; detail=""
case "$pkgs" in pip*)
  new_pip="$("$PY" -c 'import pip; print(pip.__version__)')"
  undo="$undo pip==$old_pip"; detail="pip $old_pip -> $new_pip" ;;
esac
case "$pkgs" in *certifi*)
  new_certifi="$("$PY" -c 'import certifi; print(certifi.__version__)')"
  undo="$undo certifi==$old_certifi"; detail="${detail:+$detail, }certifi $old_certifi -> $new_certifi" ;;
esac
rem_log "vetted-script:fix-python-env.sh" "upgraded pip/certifi in $PY" "$detail" "$undo"
echo "Done. $detail. Logged to $REM_LOG"
conda_advice
