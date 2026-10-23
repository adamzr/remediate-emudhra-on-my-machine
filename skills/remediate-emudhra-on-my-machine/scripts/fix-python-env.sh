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
[ -x "$PY" ] || {
  echo "Not an executable: $PY" >&2
  exit 2
}

# Apple's /usr/bin/python3 opens an "install developer tools" dialog when the tools are missing.
rem_mac_tool_ok "$PY" || {
  echo "SKIP: $PY needs Apple's Command Line Tools, which are not installed. Nothing to do here."
  exit 3
}
info="$(
  "$PY" - << 'PY'
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
IFS='|' read -r pyver old_pip old_certifi managed conda prefix pip_inst certifi_inst venv << EOF
$info
EOF

# The OS's own Python: decided by its prefix, not by where its symlink points, because a virtualenv made
# with the OS python links to it but is the user's to fix.
if [ -z "$venv" ]; then
  case "$prefix" in
    /usr | /System/* | /Library/Developer/* | /Applications/Xcode*.app/*)
      echo "SKIP: $PY belongs to the operating system and must not be modified. Its pip uses the system trust store, which the admin script fixes."
      echo "If the check reported certifi in your own user site-packages, use the OS-owned Python recipe in fix-recipes instead."
      exit 3
      ;;
  esac
fi
QPY="$(rem_q "$PY")"

major="${pyver%%.*}"
minor="${pyver#*.}"
py310=0
if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 10 ]; }; then py310=1; fi

# In a conda environment, upgrade each package with whatever installed the copy Python imports. Its
# dist-info INSTALLER file says "conda" or "pip"; a conda-meta record alone can be stale, because pip
# can replace a conda package and leave the record behind. Without an INSTALLER file, fall back to it.
conda_pkgs=""
conda_channel=""
open_msgs="" # FAIL lines for what stays vulnerable; printed last, and they make the exit code 4
skip_pip=0
skip_certifi=0
add_open() { open_msgs="${open_msgs:+$open_msgs
}FAIL: $1"; }
if [ -n "$conda" ]; then
  conda_owned() { # NAME INSTALLER
    if [ -n "$2" ]; then [ "$2" = conda ]; else ls "$prefix/conda-meta/$1"-[0-9]*.json > /dev/null 2>&1; fi
  }
  from_forge() { grep -qs 'conda-forge' "$prefix"/conda-meta/"$1"-[0-9]*.json; }
  # conda's OpenSSL, and Python's ssl module in a conda environment, read $prefix/ssl/cacert.pem, which comes
  # from conda's ca-certificates package, not from certifi. Each environment has its own copy.
  cav="$({ ls "$prefix"/conda-meta/ca-certificates-[0-9]*.json 2> /dev/null || true; } | head -1 | sed -E 's#.*/ca-certificates-([0-9][0-9.]*)-.*#\1#')"
  if [ -n "$cav" ]; then
    ca_fixed=2026.10.20
    ca_forge=0
    if from_forge ca-certificates; then
      ca_fixed=2026.10.19
      ca_forge=1
    fi
    if ! rem_ver_ge "$cav" "$ca_fixed"; then
      # Anaconda's defaults channel has no fixed build for its retired platforms. The record's subdir is the
      # environment's own platform, which uname gets wrong for an osx-64 conda running under Rosetta.
      subdir="$(sed -n 's/.*"subdir": *"\([^"]*\)".*/\1/p' "$prefix"/conda-meta/ca-certificates-"$cav"-*.json 2> /dev/null | head -1)"
      case "$ca_forge:$subdir" in
        0:osx-64 | 0:linux-ppc64le | 0:linux-s390x)
          add_open "conda's ca-certificates $cav in $prefix is vulnerable, and Anaconda's defaults channel has no fixed build for $subdir. Move this environment to conda-forge, or retire it."
          ;;
        *)
          conda_pkgs="'ca-certificates>=$ca_fixed'"
          if [ "$ca_forge" = 1 ]; then conda_channel="-c conda-forge "; fi
          ;;
      esac
    fi
  fi
  if [ -n "$old_pip" ] && conda_owned pip "$pip_inst"; then
    skip_pip=1
    if [ "$py310" = 1 ] && ! rem_ver_ge "$old_pip" 26.2.2; then conda_pkgs="${conda_pkgs:+$conda_pkgs }'pip>=26.2.2'"; fi
  fi
  if [ -n "$old_certifi" ] && conda_owned certifi "$certifi_inst"; then
    skip_certifi=1
    if ! rem_ver_ge "$old_certifi" 2026.10.19; then
      # conda's builds of the fixed certifi need Python 3.10+ on the defaults channel and 3.11+ on
      # conda-forge (the PyPI one needs only 3.7). Below that, conda cannot install it: it fails, or it
      # offers to upgrade Python itself, which is far beyond this fix.
      floor=3.10
      if from_forge certifi; then
        floor=3.11
        conda_channel="-c conda-forge "
      fi
      if rem_ver_ge "$pyver" "$floor"; then
        conda_pkgs="${conda_pkgs:+$conda_pkgs }'certifi>=2026.10.19'"
      else
        add_open "certifi $old_certifi in $PY is vulnerable, and conda's build of the fixed certifi for this channel needs Python $floor or later (this is $pyver). Retire this environment, or rebuild it on Python $floor or later."
      fi
    fi
  fi
fi
# finish CODE -> the last step on every path. Prints the conda command for conda-owned packages (exit 3)
# and then whatever stays vulnerable (exit 4); otherwise exits CODE. The conda command uses conda install
# with minimum versions, which fails loudly if conda cannot reach them (conda update can report success and
# change nothing), and pins the Python version so conda never upgrades Python.
finish() {
  local rc="$1" cm=conda
  if [ -n "$conda_pkgs" ]; then
    echo "SKIP: conda installed these in this environment, so upgrade them with conda to keep the environment consistent:"
    # micromamba-only machines have no conda command; the same arguments work for mamba and micromamba.
    if ! command -v conda > /dev/null; then
      if command -v mamba > /dev/null; then cm=mamba; elif command -v micromamba > /dev/null; then cm=micromamba; fi
    fi
    echo "  $cm install ${conda_channel}-p $(rem_q "$prefix") $conda_pkgs 'python=$pyver'"
    rc=3
  fi
  if [ -n "$open_msgs" ]; then
    printf '%s\n' "$open_msgs"
    rc=4
  fi
  exit "$rc"
}
if [ "$managed" = managed ]; then
  echo "SKIP: $PY is marked EXTERNALLY-MANAGED (Homebrew or uv owns it)."
  case "$PY" in
    */homebrew/* | */Cellar/* | /usr/local/*)
      # Homebrew's Pythons import the certifi formula when another formula installed it; upgrading python@3.X leaves it old.
      formulae=""
      if [ -n "$old_pip" ] && ! rem_ver_ge "$old_pip" 26.2.2; then formulae="python@$pyver"; fi
      if [ -n "$old_certifi" ] && ! rem_ver_ge "$old_certifi" 2026.10.19; then
        if ! brew list --versions certifi > /dev/null 2>&1; then
          echo "Its certifi $old_certifi is old and was not installed by Homebrew's certifi formula. Report it at $REM_ISSUES"
          exit 4
        fi
        formulae="${formulae:+$formulae }certifi"
      fi
      [ -n "$formulae" ] || {
        echo "Its pip and certifi are already fixed. Nothing to do."
        exit 0
      }
      echo "Preview with: HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew upgrade --dry-run $formulae"
      echo "Fix with: HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 brew upgrade $formulae"
      ;;
    */uv/python/*) echo "Fix with: uv python upgrade $pyver" ;;
    *) echo "Its package manager owns it; upgrade certifi with that package manager." ;;
  esac
  exit 3
fi

if [ -z "$old_pip" ]; then
  # conda environments can lack pip too; a conda-owned certifi there is conda's to upgrade.
  if [ "$skip_certifi" = 1 ]; then
    if [ -z "$conda_pkgs$open_msgs" ]; then echo "certifi $old_certifi in $PY is fixed, and conda manages it. Nothing to do."; fi
    finish 0
  fi
  # Virtualenvs created by uv have no pip. Upgrade certifi with uv instead.
  if [ -z "$old_certifi" ]; then
    echo "Nothing for pip or uv to upgrade in $PY (no pip, no certifi)."
    finish 0
  fi
  if rem_ver_ge "$old_certifi" 2026.10.19; then
    echo "certifi $old_certifi in $PY is already fixed."
    finish 0
  fi
  if ! command -v uv > /dev/null; then
    add_open "certifi $old_certifi in $PY is vulnerable, and this environment has neither pip nor uv to upgrade it."
    finish 4
  fi
  echo "Upgrading certifi in $PY with uv (this environment has no pip)"
  if ! uv pip install --python "$PY" 'certifi>=2026.10.19'; then
    add_open "uv could not install the fixed certifi in $PY; nothing was changed."
    finish 4
  fi
  new_certifi="$("$PY" -c 'import certifi; print(certifi.__version__)')"
  rem_log "vetted-script:fix-python-env.sh" "upgraded certifi in $PY (uv)" "certifi $old_certifi -> $new_certifi" \
    "uv pip install --python $QPY certifi==$old_certifi"
  echo "Done. certifi $new_certifi. Logged to $REM_LOG"
  finish 0
fi

pkgs=""
# Only what is still old: reinstalling a fixed package would log a no-op change.
if [ "$skip_pip" = 0 ] && ! rem_ver_ge "$old_pip" 26.2.2; then
  if [ "$py310" = 1 ]; then
    pkgs="pip>=26.2.2"
  else echo "NOTE: Python $pyver cannot run the fixed pip (needs 3.10+). Upgrading certifi only."; fi
fi
if [ -n "$old_certifi" ] && [ "$skip_certifi" = 0 ] && ! rem_ver_ge "$old_certifi" 2026.10.19; then pkgs="${pkgs:+$pkgs }certifi>=2026.10.19"; fi
# A pip that is vulnerable and cannot be fixed (the fixed pip needs Python 3.10+) stays open.
if [ "$py310" = 0 ] && [ -n "$old_pip" ] && ! rem_ver_ge "$old_pip" 26.2.2; then
  add_open "pip $old_pip in $PY stays vulnerable: the fixed pip needs Python 3.10 or later (this is $pyver). Retire this environment, or rebuild it on Python 3.10 or later."
fi
if [ -z "$pkgs" ]; then
  echo "Nothing for pip to upgrade in $PY."
  finish 0
fi

echo "Upgrading in $PY with its own pip: $pkgs"
# shellcheck disable=SC2086
if ! "$PY" -m pip install --disable-pip-version-check --upgrade $pkgs; then
  add_open "pip could not install the fixed versions in $PY. Python $pyver may be too old for them: retire this environment, or rebuild it on Python 3.10 or later."
  finish 4
fi

undo="$QPY -m pip install"
detail=""
case "$pkgs" in pip*)
  new_pip="$("$PY" -c 'import pip; print(pip.__version__)')"
  undo="$undo pip==$old_pip"
  detail="pip $old_pip -> $new_pip"
  ;;
esac
case "$pkgs" in *certifi*)
  new_certifi="$("$PY" -c 'import certifi; print(certifi.__version__)')"
  undo="$undo certifi==$old_certifi"
  detail="${detail:+$detail, }certifi $old_certifi -> $new_certifi"
  ;;
esac
rem_log "vetted-script:fix-python-env.sh" "upgraded pip/certifi in $PY" "$detail" "$undo"
echo "Done. $detail. Logged to $REM_LOG"
finish 0
