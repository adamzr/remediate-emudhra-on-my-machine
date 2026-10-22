# shellcheck shell=bash disable=SC2034
# Shared helpers for the remediate-emudhra-on-my-machine scripts. Source, don't execute.
# Bash 3.2 compatible (stock macOS).

REM_STATE_DIR="${REMEDIATE_EMUDHRA_STATE_DIR:-$HOME/.remediate-emudhra}"
REM_BACKUP_DIR="$REM_STATE_DIR/backups"
REM_LOG="$REM_STATE_DIR/actions.log"
REM_ISSUES="https://github.com/adamzr/remediate-emudhra-on-my-machine/issues"

# Test hosts from https://emudhra.we-have-a-problem.com/ that serve compromised chains.
REM_BAD_EMSIGN="https://dv-g3b-emudhra.we-have-a-problem.com/"
REM_BAD_AAA="https://dv-g3b-aaa-emudhra.we-have-a-problem.com/"
REM_CONTROL="https://github.com/"

# SHA-256 fingerprints of AAA Certificate Services and emSign ECC Root CA - G3 (roots.json on the incident site).
REM_BAD_ROOT_FPS="D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4|86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B"
REM_BAD_ROOT_CNS="AAA Certificate Services|emSign ECC Root CA - G3"

rem_init() { mkdir -p "$REM_BACKUP_DIR"; touch "$REM_LOG"; }

# rem_log SOURCE ACTION DETAIL UNDO
# SOURCE is "vetted-script:<name>", "vetted-recipe", or "improvised". Undo entries are replayed newest first.
rem_log() {
  rem_init
  printf '%s\t%s\t%s\t%s\tundo: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2" "$3" "${4:-n/a}" >> "$REM_LOG"
}

# rem_q ARG... -> shell-quoted words, safe to paste into an undo command.
rem_q() { printf '%q ' "$@" | sed 's/ $//'; }

# rem_owner_mode PATH -> "uid:gid mode" of an existing file (macOS and Linux).
# GNU stat -c first: on Linux, "stat -f" means filesystem status and succeeds with the wrong output.
rem_owner_mode() {
  if stat -c '%u:%g %a' "$1" >/dev/null 2>&1; then stat -c '%u:%g %a' "$1"; else stat -f '%u:%g %Lp' "$1"; fi
}

# rem_backup PATH [sudo] -> prints the backup path. A missing file is recorded as "<backup>.absent".
# Backups are owned by the user so they stay readable; restore with rem_restore_cmd, which resets owner and mode.
REM_BACKUP_SEQ=0
rem_backup() {
  rem_init
  local src="$1" use_sudo="${2:-}" dest
  REM_BACKUP_SEQ=$((REM_BACKUP_SEQ + 1))
  dest="$REM_BACKUP_DIR/$(date -u +%Y%m%dT%H%M%SZ)-$$-$REM_BACKUP_SEQ$(printf '%s' "$src" | tr '/ ' '__')"
  if [ ! -e "$src" ]; then
    printf '%s\n' "$src did not exist" > "$dest.absent"
    printf '%s\n' "$dest.absent"
    return 0
  fi
  if [ -n "$use_sudo" ]; then
    sudo cp "$src" "$dest" && sudo chown "$(id -u):$(id -g)" "$dest"
  else
    cp "$src" "$dest"
  fi
  printf '%s\n' "$dest"
}

# rem_restore_cmd BACKUP DEST [sudo] -> a runnable undo command that restores DEST's content and its
# current owner and mode (never leaves a system file owned by the user).
rem_restore_cmd() {
  local bak="$1" dest="$2" s="${3:+sudo }" om owner mode
  case "$bak" in *.absent) printf '%srm -f %s' "$s" "$(rem_q "$dest")"; return ;; esac
  om="$(rem_owner_mode "$dest")"; owner="${om% *}"; mode="${om#* }"
  printf '%scp %s %s && %schown %s %s && %schmod %s %s' "$s" "$(rem_q "$bak")" "$(rem_q "$dest")" \
    "$s" "$owner" "$(rem_q "$dest")" "$s" "$mode" "$(rem_q "$dest")"
}

# rem_ver_ge A B -> true when version A >= B (dotted numeric; non-numeric suffixes ignored).
rem_ver_ge() {
  local a b i x y
  a=$(printf '%s' "$1" | sed -E 's/[^0-9.].*$//')
  b=$(printf '%s' "$2" | sed -E 's/[^0-9.].*$//')
  for i in 1 2 3 4; do
    x=$(printf '%s' "$a" | cut -d. -f$i); y=$(printf '%s' "$b" | cut -d. -f$i)
    x=${x:-0}; y=${y:-0}
    [ "$x" -gt "$y" ] 2>/dev/null && return 0
    [ "$x" -lt "$y" ] 2>/dev/null && return 1
  done
  return 0
}

# rem_project_dirs -> existing directories to scan for project virtualenvs and lock files, one per line.
# REMEDIATE_EMUDHRA_PROJECTS (colon-separated) replaces the common defaults.
REM_DEFAULT_PROJECTS="$HOME/Development:$HOME/dev:$HOME/src:$HOME/code:$HOME/projects:$HOME/repos:$HOME/git:$HOME/workspace"
rem_project_dirs() {
  printf '%s\n' "${REMEDIATE_EMUDHRA_PROJECTS:-$REM_DEFAULT_PROJECTS}" | tr ':' '\n' |
    while IFS= read -r d; do if [ -n "$d" ] && [ -d "$d" ]; then rem_realpath "$d"; fi; done | awk '!seen[$0]++'
}

# rem_conda_pythons -> the python of every conda, mamba, and micromamba environment found, base and named,
# one per line. Named environments live under <root>/envs/, and conda also lists every environment it
# created (wherever it is) in ~/.conda/environments.txt.
rem_conda_pythons() {
  local root e
  for root in "$HOME"/miniconda3 "$HOME"/anaconda3 "$HOME"/miniforge3 "$HOME"/mambaforge "$HOME"/micromamba \
              "$HOME"/opt/miniconda3 "$HOME"/opt/anaconda3 "$HOME"/.conda "$HOME"/.local/share/mamba \
              /opt/conda /opt/miniconda3 /opt/anaconda3 /opt/miniforge3 \
              /opt/homebrew/Caskroom/miniconda/base /opt/homebrew/Caskroom/miniforge/base \
              /usr/local/Caskroom/miniconda/base /usr/local/Caskroom/miniforge/base; do
    [ -d "$root" ] || continue
    for e in "$root" "$root"/envs/*; do
      if [ -x "$e/bin/python" ]; then printf '%s\n' "$e/bin/python"; fi
    done
  done
  if [ -r "$HOME/.conda/environments.txt" ]; then
    while IFS= read -r e; do
      if [ -n "$e" ] && [ -x "$e/bin/python" ]; then printf '%s\n' "$e/bin/python"; fi
    done < "$HOME/.conda/environments.txt"
  fi
}

rem_realpath() { readlink -f "$1" 2>/dev/null || printf '%s\n' "$1"; }

# rem_mac_tool_ok PATH -> false for Apple's /usr/bin developer shims when Command Line Tools are not
# installed (running them pops an "install developer tools" dialog).
rem_mac_tool_ok() {
  [ "$(uname -s)" = Darwin ] || return 0
  case "$1" in /usr/bin/git|/usr/bin/python3|/usr/bin/pip3) xcode-select -p >/dev/null 2>&1 ;; *) return 0 ;; esac
}

# rem_jdk_homes -> one JDK home per line, deduplicated, for macOS and Linux.
rem_jdk_homes() {
  {
    [ -n "${JAVA_HOME:-}" ] && printf '%s\n' "$JAVA_HOME"
    if [ -x /usr/libexec/java_home ]; then
      # java_home -V exits non-zero in some setups; never let that end the list under set -e.
      { /usr/libexec/java_home -V 2>&1 || true; } | sed -nE 's#^.*[[:space:]](/.*/Contents/Home)$#\1#p'
    fi
    for d in /Library/Java/JavaVirtualMachines/*/Contents/Home "$HOME"/Library/Java/JavaVirtualMachines/*/Contents/Home \
             /opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home /usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home \
             "$HOME"/.sdkman/candidates/java/* /usr/lib/jvm/* "$HOME"/.jdks/*; do
      if [ -d "$d" ] && [ ! -L "$d" ]; then printf '%s\n' "$d"; fi
    done
  } | while IFS= read -r h; do if [ -n "$h" ]; then rem_realpath "$h"; fi; done | awk '!seen[$0]++'
}

# rem_cacerts HOME -> path of the JDK's cacerts file, if any.
rem_cacerts() {
  local f
  for f in "$1/lib/security/cacerts" "$1/jre/lib/security/cacerts"; do
    [ -f "$f" ] && { rem_realpath "$f"; return 0; }
  done
  return 1
}

# rem_bad_aliases KEYTOOL CACERTS -> aliases (one per line, may contain spaces) of the two affected roots.
rem_bad_aliases() {
  "$1" -list -v -keystore "$2" -storepass changeit </dev/null 2>/dev/null |
    awk -v bad="$REM_BAD_ROOT_FPS" '/^Alias name: /{a=substr($0, 13)} /SHA256:/{ if ($2 ~ "^(" bad ")$") print a }'
}

# rem_pem_bundle_has_bad_roots FILE -> 0 if a PEM bundle contains either affected root (by fingerprint),
# 1 if it contains neither, 2 if it could not be inspected (unreadable, or no openssl command).
rem_pem_bundle_has_bad_roots() {
  local f="$1" tmp
  [ -r "$f" ] || return 2
  command -v openssl >/dev/null || return 2
  tmp="$(mktemp -d)"
  awk -v d="$tmp" '/BEGIN CERTIFICATE/{n++} n{print > (d "/c" n ".pem")}' "$f"
  for c in "$tmp"/c*.pem; do
    [ -e "$c" ] || continue
    if openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | tr 'a-f' 'A-F' | grep -qE "=($REM_BAD_ROOT_FPS)$"; then
      rm -rf "$tmp"; return 0
    fi
  done
  rm -rf "$tmp"; return 1
}
