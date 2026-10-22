#!/usr/bin/env bash
# End-to-end test of scripts/admin-fix-linux.sh in a disposable Linux container. Run as root inside the
# container (CI does this); it creates an unprivileged user with passwordless sudo, because the admin
# script refuses to run as root.
#
#   1. installs the script's prerequisites
#   2. runs the read-only check, the admin script's dry run, then the real run (under a pseudo-terminal,
#      since the script requires one)
#   3. re-runs the check and fails if the system store or curl still trusts a compromised chain
#   4. replays the logged undo commands for the trust-store changes, newest first, and checks that the
#      store is back to its original state
#
# With HOLD=1 it first holds the distribution's CA package (apt-mark hold or a dnf exclude). That simulates
# a distribution that has not shipped its fix yet, so the script's workaround (step 2) must run, and the
# test fails if it doesn't. On Arch, a test-only pacman wrapper declines every prompt instead, the way a
# user who answers "n" to the full system upgrade would (pacman discards typed-ahead answers, so they
# can't be fed in advance).
#
# Usage: [HOLD=1] tools/ci-linux-admin.sh   (from the repository root)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root inside a disposable container" >&2; exit 2; }
REPO="$(cd "$(dirname "$0")/.." && pwd)"

. /etc/os-release
echo "== Container: $PRETTY_NAME"
case " $ID ${ID_LIKE:-} " in
  *" debian "*|*" ubuntu "*)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq && apt-get install -y -qq curl sudo ca-certificates openssl util-linux >/dev/null ;;
  *" fedora "*|*" rhel "*|*" centos "*)
    dnf install -y -q sudo openssl p11-kit-trust util-linux-script >/dev/null 2>&1 || dnf install -y -q sudo openssl p11-kit-trust util-linux
    command -v curl >/dev/null || dnf install -y -q curl ;;
  *" arch "*)
    # pacman's download sandbox needs seccomp and Landlock, which container runtimes (and emulation) often
    # block. This is test-container setup only; it does not change what the admin script does.
    sed -i 's/^#\?DisableSandboxSyscalls/DisableSandboxSyscalls/; s/^#\?DisableSandboxFilesystem/DisableSandboxFilesystem/; s/^DownloadUser/#DownloadUser/' /etc/pacman.conf
    pacman -Sy --noconfirm --needed sudo curl openssl p11-kit util-linux >/dev/null ;;
  *) echo "unsupported test container: $ID" >&2; exit 2 ;;
esac
if [ "${HOLD:-0}" = 1 ]; then
  echo "== Holding the CA package to simulate a distribution without its fix"
  case " $ID ${ID_LIKE:-} " in
    *" debian "*|*" ubuntu "*) apt-mark hold ca-certificates ;;
    *" fedora "*|*" rhel "*|*" centos "*) echo 'exclude=ca-certificates' >> /etc/dnf/dnf.conf ;;
    *" arch "*)
      printf '%s\n' '#!/bin/sh' '# Test only: decline every pacman prompt.' 'yes n | /usr/bin/pacman "$@"' > /usr/local/bin/pacman
      chmod 755 /usr/local/bin/pacman ;;
  esac
fi

id tester >/dev/null 2>&1 || useradd -m tester
echo 'tester ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/tester
chmod 440 /etc/sudoers.d/tester
SKILL="$REPO/skills/remediate-emudhra-on-my-machine"
STATE=/home/tester/.remediate-emudhra
as_tester() { sudo -u tester -H env REMEDIATE_EMUDHRA_PROJECTS=/nonexistent bash -c "$1"; }

check() { as_tester "bash '$SKILL/scripts/check.sh'" | tee "/tmp/check-$1.txt" | grep -E '^(FAIL|PASS)\|(truststore|curl|network)\|' || true; }

echo "== Check before"
check before
grep -q '^FAIL|network|' /tmp/check-before.txt && { echo "no network in the container; cannot test" >&2; exit 1; }

echo "== Dry run"
as_tester "bash '$SKILL/scripts/admin-fix-linux.sh' --dry-run"

echo "== Real run"
script -qec "sudo -u tester -H bash '$SKILL/scripts/admin-fix-linux.sh'" /dev/null < /dev/null
echo
echo "== Action log"
cat "$STATE/actions.log"

echo "== Check after"
check after
if grep -E '^FAIL\|(truststore|curl)\|' /tmp/check-after.txt; then
  echo "FAILED: the system store still trusts a compromised chain after the admin script" >&2
  exit 1
fi

echo "== Undo the trust-store changes, newest first"
undos="$({ grep -E $'\t(distrusted|blocklisted) ' "$STATE/actions.log" || true; } | sed 's/.*\tundo: //' | sed '1!G;h;$!d')"
if [ -z "$undos" ]; then
  if [ "${HOLD:-0}" = 1 ]; then
    echo "FAILED: with the package held, the workaround should have changed the trust store, but nothing was logged" >&2
    exit 1
  fi
  echo "OK: no trust-store change was needed (the distribution's package already rejects both chains)"
  exit 0
fi
printf '%s\n' "$undos" | while IFS= read -r u; do echo "+ $u"; as_tester "$u"; done
# Debian's undo regenerates the bundle itself; Fedora and Arch need one update-ca-trust after the files go.
command -v update-ca-trust >/dev/null && update-ca-trust

echo "== Check after undo"
check undone
if ! grep -qE '^FAIL\|(truststore|curl)\|' /tmp/check-undone.txt; then
  echo "FAILED: after the undo, the system store should trust the compromised chain again, as before" >&2
  exit 1
fi
echo "OK: fixed, then restored by the logged undo commands"
