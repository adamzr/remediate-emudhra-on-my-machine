#!/usr/bin/env bash
# Admin-level eMudhra remediation for Linux. Run it yourself in a terminal; it asks for your password
# through sudo. Safe to run more than once. Every change is backed up and logged with an undo command in
# ~/.remediate-emudhra/.
#
# Debian/Ubuntu family (Debian, Ubuntu, Pop!_OS, Mint):
#   1. Upgrades the ca-certificates package (the distribution fix, when it has shipped).
#   2. Only if the system store still trusts a compromised chain: distrusts the two affected roots in
#      /etc/ca-certificates.conf, exactly as https://emudhra.we-have-a-problem.com/ prescribes, and rebuilds
#      the ca-certificates-java store when that package is installed, as the site also advises.
# Fedora/RHEL family (Fedora, RHEL, CentOS Stream, Rocky, Alma, Amazon Linux 2023):
#   1. Upgrades the ca-certificates package with dnf.
#   2. Only if the system store still trusts a compromised chain: copies the two affected roots into the
#      p11-kit blocklist and runs update-ca-trust, exactly as the incident site prescribes.
# Arch family:
#   1. Upgrades the whole system with pacman -Syu (Arch does not support upgrading one package alone),
#      which brings in ca-certificates-mozilla. pacman shows the list and asks before it changes anything.
#   2. Only if the system store still trusts a compromised chain: blocklists the emSign root and runs
#      update-ca-trust, as the incident site prescribes. If the AAA chain is still trusted after that, it
#      also blocklists the AAA root, which goes beyond the site's Arch command (the site blocks it on Fedora).
# All of the above: 3. Removes the two roots from the cacerts of any JDK that still trusts a compromised
#    chain. Patched JDKs (27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511) block the
#    intermediates in blocked.certs instead and are left alone; upgrading a JDK is the better fix.
# NixOS: changes nothing. Prints the configuration.nix setting and the rebuild command to apply yourself.
# Anything else: changes nothing and points to the manual steps.
#
# Usage: admin-fix-linux.sh [--dry-run]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
SRC="vetted-script:admin-fix-linux.sh"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

[ "$(uname -s)" = Linux ] || {
  echo "This script is for Linux." >&2
  exit 2
}

if [ -e /etc/NIXOS ]; then
  cat << 'NIX'
NixOS manages its trust store from configuration.nix, so this script does not edit system files.
Add this to /etc/nixos/configuration.nix (or your flake's NixOS module):

  security.pki.caCertificateBlacklist = [
    "Comodo AAA Services root"
    "emSign ECC Root CA - G3"
  ];

Then apply it with:

  sudo nixos-rebuild switch

To undo, remove those lines and run the same command. Also update your channel or flake inputs so
nixpkgs picks up cacert 3.131.1 or later when it lands.
NIX
  rem_log "$SRC" "printed NixOS instructions" "no system change made" "nothing to undo"
  exit 0
fi

[ -r /etc/os-release ] && . /etc/os-release
case " ${ID:-} ${ID_LIKE:-} " in
  *" debian "* | *" ubuntu "*) FAMILY=debian ;;
  *" fedora "* | *" rhel "* | *" centos "* | *" amzn "*) FAMILY=fedora ;;
  *" arch "*) FAMILY=arch ;;
  *)
    echo "Unsupported distribution (${PRETTY_NAME:-unknown}). Nothing was changed. See the manual steps at https://emudhra.we-have-a-problem.com/, or request support at $REM_ISSUES" >&2
    exit 2
    ;;
esac
# The system's PEM bundle. Its path differs by distribution and release (Fedora 41+ dropped the
# /etc/pki/tls/certs/ca-bundle.crt link), so use the first that exists.
BUNDLE=""
for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; do
  if [ -r "$b" ]; then
    BUNDLE="$b"
    break
  fi
done
[ -n "$BUNDLE" ] || {
  echo "Could not find the system CA bundle. Nothing was changed. Report it at $REM_ISSUES" >&2
  exit 2
}
[ "$(id -u)" -ne 0 ] || {
  echo "Run it as yourself, not with sudo; it asks for sudo only where needed." >&2
  exit 2
}
if [ "$DRY" = 0 ] && [ ! -t 0 ]; then
  echo "Run this in a real terminal window so sudo can ask for your password." >&2
  exit 2
fi
rem_init

# trusts_bad_chain -> 0 if the system store trusts either chain, 1 if it rejects both. Exits the script when
# the result can't be determined (offline, DNS, proxy), so a network problem is never mistaken for safety.
trusts_bad_chain() {
  local u rc err
  if ! curl -sS -o /dev/null -m 20 "$REM_CONTROL" 2> /dev/null; then
    echo "   STOP: cannot reach $REM_CONTROL, so the system store cannot be tested. Reconnect and run this script again." >&2
    exit 3
  fi
  for u in "$REM_BAD_EMSIGN" "$REM_BAD_AAA"; do
    rc=0
    err="$(curl -sS -o /dev/null -m 20 --cacert "$BUNDLE" "$u" 2>&1 > /dev/null)" || rc=$?
    [ "$rc" -eq 0 ] && return 0
    if [ "$rc" -ne 60 ] && ! printf '%s' "$err" | grep -qiE 'certificate|issuer'; then
      echo "   STOP: could not test $u (curl exit $rc: $err). Reconnect and run this script again." >&2
      exit 3
    fi
  done
  return 1
}
# trusts_url URL -> 0 if the system store trusts that one test host (call only after trusts_bad_chain).
trusts_url() { curl -sS -o /dev/null -m 20 --cacert "$BUNDLE" "$1" > /dev/null 2>&1; }

# blocklist_root DIR LABEL FILE -> copies one root out of the system store into the p11-kit blocklist
# (Fedora and Arch), exactly as the incident site's commands do. Verifies the extracted file really is
# one of the two affected roots before keeping it.
blocklist_root() {
  local label="$2" f="$1/$3" enc rc=0
  if [ -e "$f" ]; then
    echo "   already blocklisted: $label"
    return 0
  fi
  enc="$(printf '%s' "$label" | sed 's/ /%20/g')"
  sudo trust extract --overwrite --format=pem-bundle --filter="pkcs11:object=$enc;type=cert" "$f"
  # Fingerprint check when openssl exists (rc 2 means it doesn't); otherwise require exactly one certificate.
  rem_pem_bundle_has_bad_roots "$f" || rc=$?
  if [ "$rc" -eq 2 ] && [ "$(grep -c 'BEGIN CERTIFICATE' "$f" 2> /dev/null)" = 1 ]; then rc=0; fi
  if [ "$rc" -ne 0 ]; then
    sudo rm -f "$f"
    echo "   STOP: extracting \"$label\" did not produce the expected certificate, so nothing was blocklisted. Report it at $REM_ISSUES" >&2
    exit 1
  fi
  rem_log "$SRC" "blocklisted $label" "$f" "sudo rm -f $(rem_q "$f") && sudo update-ca-trust"
  echo "   blocklisted: $label"
}

command -v curl > /dev/null || {
  echo "curl is required. Install it with your package manager and run this again." >&2
  exit 2
}

echo "== 1. Upgrade the ca-certificates package"
case "$FAMILY" in
  debian)
    old="$(dpkg-query -W -f='${Version}' ca-certificates 2> /dev/null || echo none)"
    if [ "$DRY" = 1 ]; then
      echo "   would run: sudo apt-get update && sudo apt-get install --only-upgrade -y ca-certificates (installed: $old)"
    elif apt-mark showhold 2> /dev/null | grep -qx ca-certificates; then
      echo "   ca-certificates is on hold on this machine; leaving the hold in place. Step 2 still protects you."
      rem_log "$SRC" "skipped apt upgrade" "ca-certificates is held (apt-mark hold)" "nothing to undo"
    elif ! { sudo apt-get update -qq && sudo apt-get install --only-upgrade --no-remove -y -qq ca-certificates; }; then
      echo "   apt could not upgrade ca-certificates (offline, locked, or broken sources). Continuing with step 2."
      rem_log "$SRC" "apt upgrade failed" "ca-certificates stays at $old" "nothing to undo"
    else
      new="$(dpkg-query -W -f='${Version}' ca-certificates)"
      if [ "$new" = "$old" ]; then
        rem_log "$SRC" "apt upgrade ca-certificates" "already newest available: $new" "nothing to undo"
        echo "   ca-certificates $new is the newest available"
      else
        rem_log "$SRC" "apt upgrade ca-certificates" "$old -> $new (undo works only while $old is still in the apt sources)" "sudo apt-get install --allow-downgrades --no-remove -y ca-certificates=$old"
        echo "   ca-certificates $old -> $new"
      fi
    fi
    ;;
  fedora)
    PM=dnf
    command -v dnf > /dev/null || PM=yum
    old="$(rpm -q --qf '%{VERSION}-%{RELEASE}' ca-certificates 2> /dev/null || echo none)"
    if [ "$DRY" = 1 ]; then
      echo "   would run: sudo $PM upgrade -y ca-certificates (installed: $old)"
    elif ! sudo "$PM" upgrade -y -q ca-certificates; then
      echo "   $PM could not upgrade ca-certificates (offline, locked, or broken repositories). Continuing with step 2."
      rem_log "$SRC" "$PM upgrade failed" "ca-certificates stays at $old" "nothing to undo"
    else
      new="$(rpm -q --qf '%{VERSION}-%{RELEASE}' ca-certificates)"
      if [ "$new" = "$old" ]; then
        rem_log "$SRC" "$PM upgrade ca-certificates" "already newest available: $new" "nothing to undo"
        echo "   ca-certificates $new is the newest available"
      else
        rem_log "$SRC" "$PM upgrade ca-certificates" "$old -> $new (undo works only while $old is still in the repositories)" "sudo $PM downgrade -y ca-certificates-$old"
        echo "   ca-certificates $old -> $new"
      fi
    fi
    ;;
  arch)
    old="$(pacman -Q ca-certificates-mozilla 2> /dev/null | awk '{print $2}')"
    old="${old:-none}"
    if [ "$DRY" = 1 ]; then
      echo "   would run: sudo pacman -Syu --needed ca-certificates-mozilla (installed: $old)"
      echo "   This upgrades the whole system, because Arch does not support upgrading one package alone."
    elif ! sudo pacman -Syu --needed ca-certificates-mozilla; then
      echo "   pacman did not finish the upgrade (declined, offline, or a conflict). Continuing with step 2."
      rem_log "$SRC" "pacman -Syu did not finish" "ca-certificates-mozilla stays at $old" "nothing to undo"
    else
      new="$(pacman -Q ca-certificates-mozilla | awk '{print $2}')"
      rem_log "$SRC" "pacman -Syu (full system upgrade)" "ca-certificates-mozilla $old -> $new" \
        "no one-step undo for a full upgrade; an old package can be reinstalled from /var/cache/pacman/pkg with sudo pacman -U"
      echo "   ca-certificates-mozilla $old -> $new"
    fi
    ;;
esac

echo "== 2. Distrust the affected roots if the system store still trusts a compromised chain"
if [ "$DRY" = 1 ]; then
  case "$FAMILY" in
    debian) echo "   would test the system store and, only if needed, edit /etc/ca-certificates.conf" ;;
    *) echo "   would test the system store and, only if needed, blocklist the affected roots and run update-ca-trust" ;;
  esac
elif trusts_bad_chain; then
  case "$FAMILY" in
    debian)
      conf=/etc/ca-certificates.conf
      bak="$(rem_backup "$conf")"
      undo="$(rem_restore_cmd "$bak" "$conf" sudo) && sudo update-ca-certificates --fresh"
      # The incident site: the Java store from ca-certificates-java can fall out of sync, so rebuild it too.
      javasync=""
      if dpkg-query -W -f='${Status}' ca-certificates-java 2> /dev/null | grep -q 'install ok installed'; then
        javasync="sudo touch /var/lib/ca-certificates-java/fresh && sudo dpkg-reconfigure ca-certificates-java"
        undo="$undo && $javasync"
      fi
      sudo sed -i \
        -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
        -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \
        "$conf"
      sudo update-ca-certificates
      if [ -n "$javasync" ]; then
        sudo touch /var/lib/ca-certificates-java/fresh && sudo dpkg-reconfigure ca-certificates-java > /dev/null
        echo "   rebuilt the Java certificate store (ca-certificates-java)"
      fi
      rem_log "$SRC" "distrusted 2 roots in $conf" "backup $bak" "$undo"
      echo "   distrusted; backup at $bak"
      ;;
    fedora)
      command -v trust > /dev/null || {
        echo "   STOP: the trust command (p11-kit) is missing. Install p11-kit-trust and run this again." >&2
        exit 2
      }
      d=/etc/pki/ca-trust/source/blocklist
      [ -d "$d" ] || d=/etc/pki/ca-trust/source/blacklist
      blocklist_root "$d" "Comodo AAA Services root" Comodo_AAA_Services_root.pem
      blocklist_root "$d" "emSign ECC Root CA - G3" emSign_ECC_Root_CA_-_G3.pem
      sudo update-ca-trust
      ;;
    arch)
      command -v trust > /dev/null || {
        echo "   STOP: the trust command (p11-kit) is missing. Install p11-kit and run this again." >&2
        exit 2
      }
      d=/etc/ca-certificates/trust-source/blocklist
      [ -d "$d" ] || [ ! -d /etc/ca-certificates/trust-source/blacklist ] || d=/etc/ca-certificates/trust-source/blacklist
      blocklist_root "$d" "emSign ECC Root CA - G3" emSign_ECC_Root_CA_-_G3.pem
      sudo update-ca-trust
      if trusts_url "$REM_BAD_AAA"; then
        echo "   the AAA chain is still trusted; also blocklisting the AAA root (beyond the incident site's Arch command)"
        blocklist_root "$d" "Comodo AAA Services root" Comodo_AAA_Services_root.pem
        sudo update-ca-trust
      fi
      ;;
  esac
  if trusts_bad_chain; then echo "   WARNING: the system store still trusts a compromised chain. Report it at $REM_ISSUES"; fi
else
  echo "   not needed: the system store already rejects both chains"
fi

echo "== 3. JDK cacerts, for JDKs that are not patched (fixed releases: $REM_JDK_FIXED)"
NET=0
curl -sS -o /dev/null -m 20 "$REM_CONTROL" 2> /dev/null && NET=1
rem_jdk_homes | while IFS= read -r J; do
  C="$(rem_cacerts "$J")" || continue
  K="$J/bin/keytool"
  [ -x "$K" ] || continue
  # A patched JDK (or one blocked by hand) is left alone: its fix is in blocked.certs, not cacerts.
  verdict="$(rem_jdk_verdict "$J" "$NET")"
  case "$verdict" in pass\|*)
    echo "   $J: already safe (${verdict#pass|})"
    continue
    ;;
  esac
  aliases="$(rem_bad_aliases "$K" "$C")"
  [ -n "$aliases" ] || {
    echo "   $J: already fixed"
    continue
  }
  if [ "$DRY" = 1 ]; then
    echo "   would remove from $C: $(echo "$aliases" | tr '\n' ',')"
    continue
  fi
  S=""
  [ -w "$C" ] || S=sudo
  undo="$(rem_restore_cmd "$(rem_backup "$C" $S)" "$C" $S)"
  while IFS= read -r a; do
    [ -n "$a" ] && $S "$K" -delete -keystore "$C" -storepass changeit -alias "$a" < /dev/null
  done <<< "$aliases"
  rem_log "$SRC" "removed affected roots from JDK cacerts" "$C: $(echo "$aliases" | tr '\n' ',')" "$undo"
  echo "   $J: removed $(echo "$aliases" | tr '\n' ' ')"
done

echo
echo "Done. Go back to your AI agent and say 'done' so it re-runs the check."
echo "Action log with undo commands (undo newest first): $REM_LOG"
