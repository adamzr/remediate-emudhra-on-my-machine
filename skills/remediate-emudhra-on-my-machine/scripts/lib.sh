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
# The same chains, never logged to Certificate Transparency: for browsers, whose blocks can rely on CT.
REM_BAD_EMSIGN_NOCT="https://dv-g3b-noct-emudhra.we-have-a-problem.com/"
REM_BAD_AAA_NOCT="https://dv-g3b-aaa-noct-emudhra.we-have-a-problem.com/"
REM_CONTROL="https://github.com/"

# SHA-256 fingerprints of AAA Certificate Services and emSign ECC Root CA - G3 (roots.json on the incident site).
# roots.json lists two more emSign G3 roots that only Windows trusts; there the Disallowed intermediates cover them.
REM_BAD_ROOT_FPS="D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4|86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B"
REM_BAD_ROOT_CNS="AAA Certificate Services|emSign ECC Root CA - G3"
# SHA-256 of the 16 compromised intermediates (impacted-intermediates.json on the incident site), the same
# list lib.ps1 pins. A patched JDK blocks them in lib/security/blocked.certs.
REM_INTERMEDIATE_SHA256="
42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493 45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B 5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699
E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838 579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512
0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19 62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72
CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F 7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489
432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3 FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F
9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4 A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8
4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1 84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"
# Fixed JDK releases, per the incident site. Shown to users; versions are not compared, because the
# live test and blocked.certs decide.
REM_JDK_FIXED="27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, or 8u511"

rem_init() {
  mkdir -p "$REM_BACKUP_DIR"
  touch "$REM_LOG"
}

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
  if stat -c '%u:%g %a' "$1" > /dev/null 2>&1; then stat -c '%u:%g %a' "$1"; else stat -f '%u:%g %Lp' "$1"; fi
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
  case "$bak" in *.absent)
    printf '%srm -f %s' "$s" "$(rem_q "$dest")"
    return
    ;;
  esac
  om="$(rem_owner_mode "$dest")"
  owner="${om% *}"
  mode="${om#* }"
  printf '%scp %s %s && %schown %s %s && %schmod %s %s' "$s" "$(rem_q "$bak")" "$(rem_q "$dest")" \
    "$s" "$owner" "$(rem_q "$dest")" "$s" "$mode" "$(rem_q "$dest")"
}

# rem_ver_ge A B -> true when version A >= B (dotted numeric; non-numeric suffixes ignored).
rem_ver_ge() {
  local a b i x y
  a=$(printf '%s' "$1" | sed -E 's/[^0-9.].*$//')
  b=$(printf '%s' "$2" | sed -E 's/[^0-9.].*$//')
  for i in 1 2 3 4; do
    x=$(printf '%s' "$a" | cut -d. -f$i)
    y=$(printf '%s' "$b" | cut -d. -f$i)
    x=${x:-0}
    y=${y:-0}
    [ "$x" -gt "$y" ] 2> /dev/null && return 0
    [ "$x" -lt "$y" ] 2> /dev/null && return 1
  done
  return 0
}

# rem_project_dirs -> existing directories to scan for project virtualenvs and lock files, one per line.
# REMEDIATE_EMUDHRA_PROJECTS replaces the common defaults. It is colon-separated, except under Git Bash and
# other Windows shells, where it is semicolon-separated Windows paths, as in check.ps1.
REM_DEFAULT_PROJECTS="$HOME/Development:$HOME/dev:$HOME/src:$HOME/code:$HOME/projects:$HOME/repos:$HOME/git:$HOME/workspace:$HOME/source/repos"
rem_project_dirs() {
  local sep=':' list d
  list="${REMEDIATE_EMUDHRA_PROJECTS:-}"
  case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) [ -n "$list" ] && sep=';' ;; esac
  [ -n "$list" ] || list="$REM_DEFAULT_PROJECTS"
  printf '%s\n' "$list" | tr "$sep" '\n' | while IFS= read -r d; do
    if [ "$sep" = ';' ] && command -v cygpath > /dev/null; then d="$(cygpath -u "$d")"; fi
    if [ -n "$d" ] && [ -d "$d" ]; then rem_realpath "$d"; fi
  done | awk '!seen[$0]++'
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

rem_realpath() { readlink -f "$1" 2> /dev/null || printf '%s\n' "$1"; }

# rem_mac_tool_ok PATH -> false for Apple's /usr/bin developer shims when Command Line Tools are not
# installed (running them pops an "install developer tools" dialog).
rem_mac_tool_ok() {
  [ "$(uname -s)" = Darwin ] || return 0
  case "$1" in /usr/bin/git | /usr/bin/python3 | /usr/bin/pip3) xcode-select -p > /dev/null 2>&1 ;; *) return 0 ;; esac
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
    [ -f "$f" ] && {
      rem_realpath "$f"
      return 0
    }
  done
  return 1
}

# rem_bad_aliases KEYTOOL CACERTS -> aliases (one per line, may contain spaces) of the two affected roots.
rem_bad_aliases() {
  "$1" -list -v -keystore "$2" -storepass changeit < /dev/null 2> /dev/null |
    awk -v bad="$REM_BAD_ROOT_FPS" '/^Alias name: /{a=substr($0, 13)} /SHA256:/{ if ($2 ~ "^(" bad ")$") print a }'
}

# rem_jdk_major HOME -> the JDK's feature version (8, 11, 17, ...) from its release file, or nothing.
rem_jdk_major() {
  local v
  v="$(sed -n 's/^JAVA_VERSION="\(.*\)"$/\1/p' "$1/release" 2> /dev/null | head -1)"
  case "$v" in 1.*) v="${v#1.}" ;; esac
  printf '%s' "${v%%[._+-]*}"
}

# rem_jdk_blocked_count HOME -> how many of the 16 compromised intermediates the JDK's blocked.certs
# (blacklisted.certs on JDK 8) lists.
rem_jdk_blocked_count() {
  local f fp n=0
  for f in "$1/lib/security/blocked.certs" "$1/jre/lib/security/blacklisted.certs" "$1/lib/security/blacklisted.certs"; do
    [ -r "$f" ] || continue
    for fp in $REM_INTERMEDIATE_SHA256; do
      if tr -d ':' < "$f" | tr 'a-f' 'A-F' | grep -q "$fp"; then n=$((n + 1)); fi
    done
    break
  done
  printf '%s' "$n"
}

# rem_java_probe HOME URL... -> one line per URL: trusted, rejected, or error, from a live TLS connection
# made by that JDK. Prints nothing when the JDK cannot run a single-file program (JDK 10 and older).
rem_java_probe() {
  local home="$1" major dir
  shift
  major="$(rem_jdk_major "$home")"
  [ -n "$major" ] && [ "$major" -ge 11 ] 2> /dev/null && [ -x "$home/bin/java" ] || return 0
  dir="$(mktemp -d)"
  cat > "$dir/RemProbe.java" << 'JAVA'
public class RemProbe {
    public static void main(String[] urls) {
        for (String u : urls) {
            String r;
            try {
                javax.net.ssl.HttpsURLConnection c = (javax.net.ssl.HttpsURLConnection) new java.net.URL(u).openConnection();
                c.setConnectTimeout(20000); c.setReadTimeout(20000); c.getResponseCode(); r = "trusted";
            } catch (javax.net.ssl.SSLHandshakeException e) {
                String m = String.valueOf(e.getMessage()).toLowerCase();
                r = (m.contains("pkix") || m.contains("certif") || m.contains("trust") || m.contains("revoked")) ? "rejected" : "error";
            } catch (Exception e) { r = "error"; }
            System.out.println(r);
        }
    }
}
JAVA
  "$home/bin/java" -Djava.net.useSystemProxies=true "$dir/RemProbe.java" "$@" 2> /dev/null < /dev/null
  rm -rf "$dir"
}

# rem_jdk_verdict HOME NET -> "pass|DETAIL" or "fail|DETAIL" for one JDK. A live test decides when it can
# run (NET=1, JDK 11+); otherwise a JDK is safe when blocked.certs lists all 16 intermediates (a patched
# JDK, or a manual block) or when cacerts no longer has the two affected roots (the admin script's fix).
rem_jdk_verdict() {
  local home="$1" net="$2" res c k bad v
  v="$(sed -n 's/^JAVA_VERSION="\(.*\)"$/\1/p' "$home/release" 2> /dev/null | head -1)"
  if [ "$net" = 1 ]; then
    res="$(rem_java_probe "$home" "$REM_CONTROL" "$REM_BAD_EMSIGN" "$REM_BAD_AAA" | tr '\n' ' ')"
    case "$res" in
      "trusted rejected rejected ")
        printf 'pass|Java %s rejects both test hosts (live test)' "$v"
        return
        ;;
      "trusted "*trusted*)
        printf 'fail|Java %s TRUSTS a compromised chain (live test). Upgrade to %s (preferred), or run the admin script' "$v" "$REM_JDK_FIXED"
        return
        ;;
    esac
  fi
  if [ "$(rem_jdk_blocked_count "$home")" -ge 16 ]; then
    printf 'pass|Java %s blocks all 16 compromised intermediates in blocked.certs' "$v"
    return
  fi
  c="$(rem_cacerts "$home")" || {
    printf 'pass|no cacerts file'
    return
  }
  k="$home/bin/keytool"
  [ -x "$k" ] || {
    printf 'fail|Java %s: no keytool to inspect cacerts, and no live test possible. Upgrade to %s' "$v" "$REM_JDK_FIXED"
    return
  }
  bad="$(rem_bad_aliases "$k" "$c" | tr '\n' ',' | sed 's/,$//')"
  if [ -z "$bad" ]; then
    printf 'pass|Java %s: affected roots absent from cacerts' "$v"
    return
  fi
  printf 'fail|Java %s: cacerts still trusts %s. Upgrade to %s (preferred), or run the admin script' "$v" "$bad" "$REM_JDK_FIXED"
}

# rem_pem_bundle_has_bad_roots FILE -> 0 if a PEM bundle contains either affected root (by fingerprint),
# 1 if it contains neither, 2 if it could not be inspected (unreadable, or no openssl command).
rem_pem_bundle_has_bad_roots() {
  local f="$1" tmp
  [ -r "$f" ] || return 2
  command -v openssl > /dev/null || return 2
  tmp="$(mktemp -d)"
  awk -v d="$tmp" '/BEGIN CERTIFICATE/{n++} n{print > (d "/c" n ".pem")}' "$f"
  for c in "$tmp"/c*.pem; do
    [ -e "$c" ] || continue
    if openssl x509 -in "$c" -noout -fingerprint -sha256 2> /dev/null | tr 'a-f' 'A-F' | grep -qE "=($REM_BAD_ROOT_FPS)$"; then
      rm -rf "$tmp"
      return 0
    fi
  done
  rm -rf "$tmp"
  return 1
}
