#!/usr/bin/env bash
# Admin-level eMudhra remediation for macOS. Run it yourself in Terminal or iTerm2 (it asks for your
# password through sudo); an AI agent cannot answer sudo prompts. Safe to run more than once: steps
# already done are skipped.
#
# What it changes, each step backed up and logged with an undo command in ~/.remediate-emudhra/:
#   1. /etc/ssl/cert.pem: removes AAA Certificate Services and emSign ECC Root CA - G3, exactly as
#      https://emudhra.we-have-a-problem.com/ prescribes. Used by Apple's curl, git, python3, perl, ruby, openssl.
#   2. Apple's built-in pip: points it at the fixed /etc/ssl/cert.pem (also from the incident site).
#   3. System keychain: marks the 16 compromised intermediates "Never Trust". Apple's tools fall back to the
#      keychain roots without checking revocation, so step 1 alone leaves the emSign chain trusted.
#      Only those intermediates are blocked; legitimate emSign and Sectigo sites keep working.
#   4. JDK cacerts: removes the same two roots from every JDK that still trusts a compromised chain.
#      Patched JDKs block the intermediates in blocked.certs instead and are left alone.
#
# A macOS update rewrites /etc/ssl/cert.pem and brings the two roots back: run this again after one.
#
# Usage: admin-fix-macos.sh [--dry-run]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
SRC="vetted-script:admin-fix-macos.sh"
DRY=0; [ "${1:-}" = "--dry-run" ] && DRY=1
CERTDIR="$HERE/../assets/compromised-intermediates"

[ "$(uname -s)" = Darwin ] || { echo "This script is for macOS." >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || { echo "Run it as yourself, not with sudo; it asks for sudo only where needed." >&2; exit 2; }
if [ "$DRY" = 0 ] && [ ! -t 0 ]; then
  echo "Run this in a real terminal window (Terminal or iTerm2) so sudo can ask for your password." >&2; exit 2
fi
rem_init
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
[ "$DRY" = 1 ] && echo "DRY RUN: nothing will be changed."

echo "== 1. /etc/ssl/cert.pem"
if ! grep -qE "^=== .*/CN=($REM_BAD_ROOT_CNS)\$" /etc/ssl/cert.pem && rem_pem_bundle_has_bad_roots /etc/ssl/cert.pem; then
  echo "   STOP: the file contains an affected root but not in the expected format, so it was not changed. Report it at $REM_ISSUES" >&2
  exit 1
fi
if grep -qE "^=== .*/CN=($REM_BAD_ROOT_CNS)\$" /etc/ssl/cert.pem; then
  awk '/^(###|===) /{skip=0}
    /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}
    !skip' /etc/ssl/cert.pem > "$WORK/cert.pem"
  before="$(grep -c 'BEGIN CERTIFICATE' /etc/ssl/cert.pem)"; after="$(grep -c 'BEGIN CERTIFICATE' "$WORK/cert.pem")"
  if [ "$after" -lt 100 ] || [ $((before - after)) -gt 2 ] || grep -qE "^=== .*/CN=($REM_BAD_ROOT_CNS)\$" "$WORK/cert.pem" || rem_pem_bundle_has_bad_roots "$WORK/cert.pem"; then
    echo "   STOP: the filtered file looks wrong ($before -> $after certificates). Nothing was changed. Report it at $REM_ISSUES" >&2
    exit 1
  fi
  if [ "$DRY" = 1 ]; then echo "   would remove $((before - after)) roots ($before -> $after certificates)"; else
    undo="$(rem_restore_cmd "$(rem_backup /etc/ssl/cert.pem)" /etc/ssl/cert.pem sudo)"
    sudo cp "$WORK/cert.pem" /etc/ssl/cert.pem
    rem_log "$SRC" "removed 2 roots from /etc/ssl/cert.pem" "$before -> $after certificates" "$undo"
    echo "   removed $((before - after)) roots ($before -> $after certificates)"
  fi
else
  echo "   already fixed"
fi

echo "== 2. Apple's built-in pip"
if xcode-select -p >/dev/null 2>&1; then
  F="$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')/sitecustomize.py"
  if grep -qs 'PIP_CERT' "$F"; then echo "   already present in $F"
  elif [ "$DRY" = 1 ]; then echo "   would append PIP_CERT=/etc/ssl/cert.pem to $F"; else
    bak="$(rem_backup "$F")"
    case "$bak" in *.absent) undo="sudo rm -f $(rem_q "$F")" ;; *) undo="$(rem_restore_cmd "$bak" "$F" sudo)" ;; esac
    echo 'import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")' | sudo tee -a "$F" > /dev/null
    sudo chmod 644 "$F"
    rem_log "$SRC" "set PIP_CERT for Apple's python3" "$F" "$undo"
    echo "   added to $F (an Xcode or Command Line Tools update may undo this; re-run the script then)"
  fi
else
  echo "   Command Line Tools not installed; nothing to do"
fi

echo "== 3. Never Trust the 16 compromised intermediates in the System keychain"
# Refuse to touch the keychain unless every file is one of the 16 pinned certificates.
for f in "$CERTDIR"/*.pem; do
  h="$(openssl x509 -in "$f" -outform DER 2>/dev/null | shasum -a 256 | awk '{print toupper($1)}')"
  case " $(printf '%s' "$REM_INTERMEDIATE_SHA256" | tr '\n' ' ') " in *" $h "*) ;; *)
    echo "   STOP: $(basename "$f") is not one of the 16 pinned compromised intermediates, so the keychain was not changed. Report it at $REM_ISSUES" >&2
    exit 1 ;;
  esac
done
security trust-settings-export -d "$WORK/trust.plist" >/dev/null 2>&1 || : > "$WORK/trust.plist"
for f in "$CERTDIR"/*.pem; do
  name="$(basename "$f")"
  sha1="$(openssl x509 -in "$f" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')"
  res="$(/usr/libexec/PlistBuddy -c "Print :trustList:$sha1:trustSettings:0:kSecTrustSettingsResult" "$WORK/trust.plist" 2>/dev/null || true)"
  if [ "$res" = 3 ]; then echo "   already denied: $name"; continue; fi
  if [ "$DRY" = 1 ]; then echo "   would deny $name"; continue; fi
  keep="$REM_BACKUP_DIR/$name"; cp "$f" "$keep"
  if sudo security add-trusted-cert -d -r deny -k /Library/Keychains/System.keychain "$keep"; then
    rem_log "$SRC" "keychain deny $name" "SHA-1 $sha1" \
      "sudo security remove-trusted-cert -d $(rem_q "$keep") && sudo security delete-certificate -Z $sha1 /Library/Keychains/System.keychain"
    echo "   denied $name"
  else
    echo "   could not deny $name (the approval was cancelled or failed). Run the script again to retry."
  fi
done

echo "== 4. JDK cacerts, for JDKs that are not patched (fixed releases: $REM_JDK_FIXED)"
NET=0; curl -sS -o /dev/null -m 20 "$REM_CONTROL" 2>/dev/null && NET=1
rem_jdk_homes | while IFS= read -r J; do
  C="$(rem_cacerts "$J")" || continue
  K="$J/bin/keytool"; [ -x "$K" ] || continue
  # A patched JDK (or one blocked by hand) is left alone: its fix is in blocked.certs, not cacerts.
  verdict="$(rem_jdk_verdict "$J" "$NET")"
  case "$verdict" in pass\|*) echo "   $J: already safe (${verdict#pass|})"; continue ;; esac
  aliases="$(rem_bad_aliases "$K" "$C")"
  [ -n "$aliases" ] || { echo "   $J: already fixed"; continue; }
  if [ "$DRY" = 1 ]; then echo "   would remove from $C: $(echo "$aliases" | tr '\n' ',')"; continue; fi
  S=""; [ -w "$C" ] || S=sudo
  undo="$(rem_restore_cmd "$(rem_backup "$C" $S)" "$C" $S)"
  while IFS= read -r a; do
    [ -n "$a" ] && $S "$K" -delete -keystore "$C" -storepass changeit -alias "$a" </dev/null
  done <<< "$aliases"
  rem_log "$SRC" "removed affected roots from JDK cacerts" "$C: $(echo "$aliases" | tr '\n' ',')" "$undo"
  echo "   $J: removed $(echo "$aliases" | tr '\n' ' ')"
done
echo "   Upgrading to a patched JDK is the better fix. An upgrade to an older, unpatched JDK brings the roots back."

echo
echo "A macOS update puts the two roots back in /etc/ssl/cert.pem; run this script again after any macOS update."
echo "Done. Go back to your AI agent and say 'done' so it re-runs the check."
echo "Action log with undo commands (undo newest first): $REM_LOG"
