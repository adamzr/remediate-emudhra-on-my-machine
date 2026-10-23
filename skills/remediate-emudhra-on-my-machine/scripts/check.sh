#!/usr/bin/env bash
# Read-only check of every TLS client this script can find on macOS or Linux.
# Changes nothing on the system. Writes its report to ~/.remediate-emudhra/.
# Output lines: STATUS|AREA|ITEM|DETAIL, where STATUS is PASS, FAIL, WARN, or INFO.
# A run without network access reports FAIL|network so it can never be read as an all-clear.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
rem_init
REPORT="$REM_STATE_DIR/check-$(date -u +%Y%m%dT%H%M%SZ)-$$.txt"
exec > >(tee "$REPORT") 2>&1

OS="$(uname -s)"
emit() { printf '%s|%s|%s|%s\n' "$1" "$2" "$3" "$4"; }

# curl_verdict BIN URL -> trusted | rejected | error. Only a certificate verification failure counts as rejected.
# A test host's reply contains this text; any other reply came from a TLS-intercepting proxy, so it says
# nothing about this machine's trust (the incident site's own checker treats it the same way).
REM_SUCCESS_TEXT="Your client successfully connected to the site."
curl_verdict() {
  local err rc=0 body
  body="$(mktemp)"
  err="$("$1" -sS -o "$body" -m 20 "$2" 2>&1 > /dev/null)" || rc=$?
  if [ "$rc" -eq 0 ] && [ "$2" != "$REM_CONTROL" ] && ! grep -qF "$REM_SUCCESS_TEXT" "$body"; then
    rm -f "$body"
    echo inconclusive
  elif [ "$rc" -eq 0 ]; then
    rm -f "$body"
    echo trusted
  elif [ "$rc" -eq 77 ]; then
    echo error
  elif [ "$rc" -eq 60 ] || printf '%s' "$err" | grep -qiE 'certificate|unable to get local issuer|self.signed|revoked'; then
    echo rejected
  else echo error; fi
  rm -f "$body"
}

echo "# eMudhra remediation check $(date -u +%Y-%m-%dT%H:%M:%SZ) on $OS"
NET=1
if ! curl -sS -o /dev/null -m 20 "$REM_CONTROL" 2> /dev/null; then
  NET=0
  emit FAIL network control "UNVERIFIED: cannot reach $REM_CONTROL. Live tests were skipped, so this run cannot confirm the machine is safe. Reconnect and run the check again"
fi

# ---- Operating system and static trust-store checks (work offline) ----
if [ "$OS" = Darwin ]; then
  v="$(sw_vers -productVersion)"
  major="${v%%.*}"
  if [ "$major" -ge 27 ] || { [ "$major" -eq 26 ] && rem_ver_ge "$v" 26.7; } || { [ "$major" -eq 15 ] && rem_ver_ge "$v" 15.8; }; then
    emit PASS os macOS "$v"
  elif [ "$major" -le 14 ]; then
    emit WARN os macOS "$v is no longer getting all security fixes. Apple's block (since October 22) arrives as background trust data, not in an OS release, but a separate Apple certificate fix (CVE-2026-86881) shipped only in 15.8, 26.7, and 27. Plan an upgrade"
  else
    emit WARN os macOS "$v: install the latest update in System Settings > General > Software Update (a separate Apple certificate fix, CVE-2026-86881, is in 15.8, 26.7, and 27)"
  fi
  if [ ! -r /etc/ssl/cert.pem ]; then
    emit WARN truststore /etc/ssl/cert.pem "missing or unreadable; rely on the live curl results"
  else
    # By header line and by fingerprint, so a change to the file's format can never read as fixed.
    fp=0
    rem_pem_bundle_has_bad_roots /etc/ssl/cert.pem || fp=$?
    if grep -qE "^=== .*/CN=($REM_BAD_ROOT_CNS)\$" /etc/ssl/cert.pem || [ "$fp" -eq 0 ]; then
      emit FAIL truststore /etc/ssl/cert.pem "still contains AAA Certificate Services or emSign ECC Root CA - G3 (Apple's curl, git, python3 use it; admin script fixes it)"
    elif [ "$fp" -eq 2 ]; then
      emit WARN truststore /etc/ssl/cert.pem "could not inspect by fingerprint (no openssl command); rely on the live curl results"
    else
      emit PASS truststore /etc/ssl/cert.pem "affected roots removed"
    fi
  fi
elif [ -e /etc/NIXOS ]; then
  emit INFO os NixOS "$(
    . /etc/os-release
    echo "$PRETTY_NAME"
  )"
else
  emit INFO os Linux "$([ -r /etc/os-release ] && . /etc/os-release && echo "$PRETTY_NAME")"
fi
if [ "$OS" = Darwin ] && [ -r /opt/local/share/curl/curl-ca-bundle.crt ]; then
  # MacPorts curl and git read their own bundle (fixed in MacPorts curl-ca-bundle 8.23.0_1).
  rc=0
  rem_pem_bundle_has_bad_roots /opt/local/share/curl/curl-ca-bundle.crt || rc=$?
  case "$rc" in
    0) emit FAIL macports /opt/local/share/curl/curl-ca-bundle.crt "MacPorts bundle contains an affected root (fixed: curl-ca-bundle 8.23.0_1; sudo port selfupdate && sudo port upgrade curl-ca-bundle)" ;;
    1) emit PASS macports /opt/local/share/curl/curl-ca-bundle.crt "MacPorts bundle: affected roots absent" ;;
    *) emit WARN macports /opt/local/share/curl/curl-ca-bundle.crt "could not inspect the MacPorts bundle (no openssl command)" ;;
  esac
fi
if [ "$OS" = Linux ] && grep -qi microsoft /proc/version 2> /dev/null; then
  emit WARN os WSL "This is a WSL distribution inside Windows. Windows itself needs its own check: run check.ps1 with powershell.exe, and check any other WSL distributions too"
fi
if [ "$OS" = Linux ]; then
  seen_bundles=" "
  for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; do
    [ -r "$b" ] || continue
    # These are often links to one file; inspect each real file once.
    r="$(rem_realpath "$b")"
    case "$seen_bundles" in *" $r "*) continue ;; esac
    seen_bundles="$seen_bundles$r "
    rc=0
    rem_pem_bundle_has_bad_roots "$b" || rc=$?
    case "$rc" in
      0) emit FAIL truststore "$b" "contains an affected root (admin script fixes it)" ;;
      1) emit PASS truststore "$b" "affected roots absent" ;;
      *) emit WARN truststore "$b" "could not inspect (unreadable, or no openssl command); rely on the live curl results" ;;
    esac
  done
  # The distribution's own fix. Informational: the bundle and live tests above decide PASS or FAIL.
  if command -v dpkg-query > /dev/null && v="$(dpkg-query -W -f='${Version}' ca-certificates 2> /dev/null)"; then
    emit INFO truststore ca-certificates "Debian/Ubuntu package $v"
  elif command -v rpm > /dev/null && v="$(rpm -q --qf '%{VERSION}-%{RELEASE}' ca-certificates 2> /dev/null)"; then
    # Fixed version numbers differ by distribution (Oracle Linux's fixed builds are numbered 2025.2.80_...),
    # so only Fedora's is compared here; the bundle and live tests decide everywhere.
    if [ "$(. /etc/os-release 2> /dev/null && echo "${ID:-}")" != fedora ]; then
      emit INFO truststore ca-certificates "package $v (see fix-recipes for this distribution's fixed release)"
    elif rem_ver_ge "$v" 2026.2.92; then
      emit INFO truststore ca-certificates "package $v (the fixed release is 2026.2.92_v9.0.319 or later)"
    else emit INFO truststore ca-certificates "package $v; the fixed release is 2026.2.92_v9.0.319 (admin script upgrades it)"; fi
  elif command -v pacman > /dev/null && v="$(pacman -Q ca-certificates-mozilla 2> /dev/null | awk '{print $2}')" && [ -n "$v" ]; then
    if rem_ver_ge "$v" 3.131.1; then
      emit INFO truststore ca-certificates-mozilla "package $v (fixed: 3.131.1-1)"
    else emit INFO truststore ca-certificates-mozilla "package $v; the fixed release is 3.131.1-1 (admin script upgrades it)"; fi
  fi
fi

# ---- Live tests of curl and git against the test hosts ----
if [ "$NET" = 1 ]; then
  curls="$(command -v curl || true)"
  [ "$OS" = Darwin ] && [ -x /usr/bin/curl ] && curls="$(printf '%s\n%s' /usr/bin/curl "$curls")"
  printf '%s\n' "$curls" | awk 'NF && !seen[$0]++' | while IFS= read -r c; do
    if [ "$(curl_verdict "$c" "$REM_CONTROL")" != trusted ]; then
      emit WARN curl "$c" "cannot reach $REM_CONTROL with this curl; not tested"
      continue
    fi
    for u in "$REM_BAD_EMSIGN" "$REM_BAD_AAA"; do
      case "$(curl_verdict "$c" "$u")" in
        rejected) emit PASS curl "$c" "rejects $u" ;;
        trusted) emit FAIL curl "$c" "TRUSTS $u (system trust store needs the admin fix)" ;;
        inconclusive) emit WARN curl "$c" "reached something other than the test site at $u (a proxy may be intercepting TLS); not a certificate result" ;;
        *) emit WARN curl "$c" "could not test $u (network error, not a certificate result)" ;;
      esac
    done
  done
  gits="$(command -v git || true)"
  [ "$OS" = Darwin ] && gits="$(printf '%s\n%s' /usr/bin/git "$gits")"
  printf '%s\n' "$gits" | awk 'NF && !seen[$0]++' | while IFS= read -r g; do
    rem_mac_tool_ok "$g" || continue
    [ -x "$g" ] || continue
    if ! GIT_TERMINAL_PROMPT=0 "$g" ls-remote https://github.com/git/git.git HEAD > /dev/null 2>&1; then
      emit WARN git "$g" "cannot reach GitHub with this git; not tested"
      continue
    fi
    for u in "$REM_BAD_EMSIGN" "$REM_BAD_AAA"; do
      out="$(GIT_TERMINAL_PROMPT=0 "$g" ls-remote "$u" 2>&1 || true)"
      if printf '%s' "$out" | grep -qiE 'SSL certificate problem|certificate verify failed|server certificate verification failed'; then
        emit PASS git "$g" "rejects $u"
      elif printf '%s' "$out" | grep -qiE 'not valid: is this a git repository|not found|returned error: 4'; then
        emit FAIL git "$g" "TRUSTS $u"
      else
        emit WARN git "$g" "could not test $u"
      fi
    done
  done
fi

# ---- Python interpreters ----
PYTEST="$(mktemp)"
cat > "$PYTEST" << 'PY'
import sys, os
label, net, bad1, bad2, control = sys.argv[1:6]
FIX_PIP, FIX_CERTIFI = (26, 2, 2), (2026, 10, 19)
SYSTEM_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                  "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem")
def vt(s):
    out = []
    for p in str(s).split(".")[:3]:
        d = "".join(ch for ch in p if ch.isdigit())
        out.append(int(d or 0))
    return tuple(out)
def emit(st, detail): print("%s|python|%s|%s" % (st, label, detail))
system_owned = label.startswith(("/usr/bin/", "/usr/lib/", "/System/", "/Library/Developer/", "/Applications/Xcode"))
ver = sys.version.split()[0]
# CPython itself has patched releases on these lines (per the incident site).
FIX_PY = {(3, 13): (3, 13, 17), (3, 14): (3, 14, 9), (3, 15): (3, 15, 1)}
fixed_py = FIX_PY.get(tuple(sys.version_info[:2]))
if fixed_py and tuple(sys.version_info[:3]) < fixed_py and not system_owned:
    emit("WARN", "Python %s: the patched release on this line is %s; upgrade when you can" % (sys.version.split()[0], ".".join(map(str, fixed_py))))
if sys.version_info < (3, 10) and not system_owned:
    emit("WARN", "Python %s is end of life; the fixed pip needs 3.10+%s. Remove it if nothing uses it" % (ver, " and Python 2 cannot run the fixed certifi (the last release for it is 2021.10.8)" if sys.version_info[0] < 3 else ""))
import re
def pip_probe(u):
    # A live test of this interpreter's pip: an SSL verification error means it rejects the host. pip keeps
    # its own certificate list alongside any PIP_CERT or system store, so only a live test is conclusive.
    import subprocess, tempfile, shutil
    d = tempfile.mkdtemp()
    try:
        env = dict(os.environ, PIP_REQUIRE_VIRTUALENV="0")
        # -vv makes pip log urllib3's request lines, which show whether an HTTP response really came back.
        p = subprocess.Popen([sys.executable, "-B", "-m", "pip", "download", "-vv", "--no-input", "--no-deps",
                              "--no-cache-dir", "--disable-pip-version-check", "--retries", "0", "--timeout", "20",
                              "-d", d, "--index-url", u.rstrip("/") + "/simple/", "remediate-emudhra-probe"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        out = p.communicate()[0].decode("utf-8", "replace")
    except Exception:
        return "error"
    finally:
        shutil.rmtree(d, ignore_errors=True)
    # Only a certificate verification failure counts as rejected: a firewall that drops the connection
    # also raises an SSLError (EOF), which says nothing about trust.
    if re.search(r"CERTIFICATE_VERIFY_FAILED|certificate verify failed|SSLCertVerificationError", out):
        return "rejected"
    # Trusted only when the server's HTTP response came back; pip prints "No matching distribution" for DNS
    # and connection failures too.
    if re.search(r'"GET /simple/[^/ ]+/ HTTP/1\.[01]" \d{3}', out):
        return "trusted"
    return "error"
try:
    import pip
    pv = pip.__version__
    if vt(pv) >= FIX_PIP:
        emit("PASS", "pip %s" % pv)
    elif "/uv/python/" in label:
        emit("INFO", "pip %s in a uv-managed Python; uv and its virtualenvs don't use it. Optional: uv python upgrade" % pv)
    else:
        live = [pip_probe(control)] if net == "1" else []
        if live == ["trusted"]:
            live += [pip_probe(bad1), pip_probe(bad2)]
        if live == ["trusted", "rejected", "rejected"]:
            emit("PASS", "pip %s rejects both test hosts (live test)" % pv)
        elif live[:1] == ["trusted"] and "trusted" in live[1:]:
            emit("FAIL", "pip %s TRUSTS a compromised chain (live test; fixed: 26.2.2)" % pv)
        else:
            emit("FAIL", "pip %s (fixed: 26.2.2; no conclusive live test)" % pv)
except Exception:
    pass
meta = os.path.join(sys.prefix, "conda-meta")
if os.path.isdir(meta):
    # conda's OpenSSL and the ssl module in a conda environment read $PREFIX/ssl/cacert.pem, from this package.
    import glob, json
    recs = [f for f in glob.glob(os.path.join(meta, "ca-certificates-*.json")) if re.match(r"ca-certificates-\d", os.path.basename(f))]
    if recs:
        try:
            rec = json.load(open(recs[0]))
            cav, chan = rec.get("version", ""), "%s %s" % (rec.get("channel", ""), rec.get("url", ""))
        except Exception:
            cav, chan = "", ""
        need = (2026, 10, 19) if "conda-forge" in chan else (2026, 10, 20)
        if cav:
            emit("PASS" if vt(cav) >= need else "FAIL", "conda ca-certificates %s (fixed: %s)" % (cav, ".".join(map(str, need))))
try:
    import certifi
    cv, cwhere = certifi.__version__, certifi.where()
    if vt(cv) >= FIX_CERTIFI:
        emit("PASS", "certifi %s" % cv)
    elif cwhere in SYSTEM_BUNDLES:
        emit("PASS", "certifi %s is the distribution's copy and uses the system trust store" % cv)
    elif system_owned:
        # Apple's python3 ships no certifi, so one found here was almost always added by pip (user site,
        # PYTHONPATH, or sudo pip). Only a copy without a pip/uv INSTALLER record counts as the OS's own.
        import site
        cdir = os.path.dirname(os.path.realpath(cwhere))
        user_site = site.getusersitepackages() if hasattr(site, "getusersitepackages") else ""
        try:
            from importlib.metadata import distribution
            installer = (distribution("certifi").read_text("INSTALLER") or "").strip()
        except Exception:
            installer = ""
        if user_site and cdir.startswith(os.path.realpath(user_site) + os.sep):
            emit("FAIL", "certifi %s in your user site-packages (%s); upgrade it there (fix-recipes: OS-owned Python)" % (cv, os.path.dirname(cdir)))
        elif installer in ("pip", "uv") or not cdir.startswith(os.path.realpath(sys.prefix) + os.sep):
            emit("FAIL", "certifi %s in %s was added by %s, not shipped with the OS (fix-recipes: OS-owned Python)" % (cv, os.path.dirname(cdir), installer or "a package installer"))
        else:
            emit("WARN", "certifi %s in %s shipped with this OS-owned Python, which must not be modified. Only scripts that use requests with this interpreter are affected; run those with a pyenv, uv, or Homebrew Python" % (cv, os.path.dirname(cdir)))
    else:
        emit("FAIL", "certifi %s (fixed: 2026.10.19)" % cv)
except Exception:
    pass
if net == "1":
    try:
        from urllib.request import urlopen
    except ImportError:  # Python 2, still found in old conda environments
        from urllib2 import urlopen
    def probe(u):
        try:
            body = urlopen(u, timeout=20).read(4096).decode("utf-8", "replace")
            # The test hosts answer with this text; anything else came from a TLS-intercepting proxy.
            return "trusted" if (u == control or "successfully connected" in body) else "inconclusive"
        except Exception as e:
            s = repr(e)
            return "rejected" if ("CERTIFICATE_VERIFY_FAILED" in s or "SSLCertVerificationError" in s) else "error"
    c = probe(control)
    if c == "rejected":
        emit("WARN", "Python %s cannot verify any site (no CA bundle configured); not a security exposure" % ver)
    elif c == "error":
        emit("WARN", "Python %s could not reach %s; urllib not tested" % (ver, control))
    else:
        for u in (bad1, bad2):
            r = probe(u)
            emit({"rejected": "PASS", "trusted": "FAIL"}.get(r, "WARN"), "urllib %s %s" % ({"rejected": "rejects", "trusted": "TRUSTS", "inconclusive": "reached something other than the test site at"}.get(r, "could not test"), u))
PY
pys=""
for p in $(type -ap python3 2> /dev/null) "$HOME"/.pyenv/versions/*/bin/python3 /opt/homebrew/bin/python3* /usr/local/bin/python3* \
  /Library/Frameworks/Python.framework/Versions/*/bin/python3 "$HOME"/.local/share/uv/python/*/bin/python3; do
  case "$p" in *-config | *-intel64 | */shims/*) continue ;; esac
  [ -x "$p" ] || continue
  rem_mac_tool_ok "$p" || continue
  pys="$pys
$(rem_realpath "$p")"
done
# conda environments are read line by line: their paths can contain spaces.
pys="$pys
$(rem_conda_pythons | while IFS= read -r p; do if [ -x "$p" ]; then rem_realpath "$p"; fi; done)"
printf '%s\n' "$pys" | awk 'NF && !seen[$0]++' | while IFS= read -r py; do
  rem_mac_tool_ok "$py" || continue
  "$py" -B "$PYTEST" "$py" "$NET" "$REM_BAD_EMSIGN" "$REM_BAD_AAA" "$REM_CONTROL" 2> /dev/null || emit WARN python "$py" "could not run"
done
rm -f "$PYTEST"
DEVS="$(rem_project_dirs)"
WHERE="$(printf '%s' "$DEVS" | tr '\n' ',' | sed 's/,/, /g')"
if [ -z "$DEVS" ]; then
  emit INFO projects none "no project folder found (looked for ~/Development, ~/dev, ~/src, ~/code, ~/projects, ~/repos, ~/git, ~/workspace, ~/source/repos); set REMEDIATE_EMUDHRA_PROJECTS to scan yours for virtualenvs and lock files"
fi
venvs="$(printf '%s\n' "$DEVS" | while IFS= read -r d; do [ -n "$d" ] && find "$d" -maxdepth 4 -name pyvenv.cfg 2> /dev/null; done | wc -l | tr -d ' ')"
[ "$venvs" -gt 0 ] && emit INFO python virtualenvs "$venvs project virtualenvs under $WHERE; each has its own certifi (see fix-recipes)"
# A uv.lock pin puts the old certifi back on the next "uv sync", and into any image built from the repo.
# One summary line; the full list goes next to the report, since a developer can have hundreds of repos.
LOCKS="${REPORT%.txt}-lockfiles.txt"
printf '%s\n' "$DEVS" | while IFS= read -r d; do [ -n "$d" ] && find "$d" -maxdepth 3 -name uv.lock -not -path '*/node_modules/*' 2> /dev/null; done | while IFS= read -r f; do
  # Every certifi entry (a forked lock can have more than one), CRLF-safe; keep the oldest.
  v="$(awk '{ sub(/\r$/, "") } want && $1 == "version" { gsub(/"/, "", $3); print $3 } { want = ($0 == "name = \"certifi\"") }' "$f" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)"
  [ -n "$v" ] || continue
  rem_ver_ge "$v" 2026.10.19 || printf '%s %s\n' "$v" "$(dirname "$f")"
done > "$LOCKS"
locks="$(wc -l < "$LOCKS" | tr -d ' ')"
if [ "$locks" -gt 0 ]; then
  emit WARN lockfile uv.lock "$locks repositories under $WHERE pin certifi older than 2026.10.19, so uv sync reverts their virtualenv fix until the pin is bumped. List: $LOCKS (fix-recipes: lock files)"
else
  rm -f "$LOCKS"
fi
# Tools installed with pipx or uv tool live in their own virtualenvs, each with its own certifi. pipx keeps
# one shared pip for all of them. Ask the tools where they keep them, then try the usual defaults.
tool_roots="$({
  if command -v pipx > /dev/null; then pipx environment --value PIPX_LOCAL_VENVS 2> /dev/null; fi
  if command -v uv > /dev/null; then uv tool dir 2> /dev/null; fi
  printf '%s\n' "$HOME/.local/share/pipx/venvs" "$HOME/Library/Application Support/pipx/venvs" "$HOME/.local/pipx/venvs" "$HOME/.local/share/uv/tools"
} | awk 'NF && !seen[$0]++')"
pipx_shared="$({
  if command -v pipx > /dev/null; then pipx environment --value PIPX_SHARED_LIBS 2> /dev/null; fi
  printf '%s\n' "$HOME/.local/share/pipx/shared" "$HOME/Library/Application Support/pipx/shared" "$HOME/.local/pipx/shared"
} | awk 'NF && !seen[$0]++')"
printf '%s\n' "$tool_roots" | while IFS= read -r root; do
  [ -d "$root" ] || continue
  for tv in "$root"/*; do printf '%s\n' "$tv"; done
done | while IFS= read -r tv; do
  [ -x "$tv/bin/python" ] || continue
  for di in "$tv"/lib/python*/site-packages/certifi-*.dist-info "$tv"/lib/python*/site-packages/pip-*.dist-info; do
    [ -d "$di" ] || continue
    n="$(basename "$di" .dist-info)"
    pkg="${n%%-*}" v="${n#*-}"
    case "$pkg" in certifi) need=2026.10.19 ;; *) need=26.2.2 ;; esac
    if ! rem_ver_ge "$v" "$need"; then emit FAIL python "$tv/bin/python" "tool environment: $pkg $v (fixed: $need; fix with fix-python-env.sh on this python)"; fi
  done
done
printf '%s\n' "$pipx_shared" | while IFS= read -r sh; do
  [ -x "$sh/bin/python" ] || continue
  for di in "$sh"/lib/python*/site-packages/pip-*.dist-info; do
    [ -d "$di" ] || continue
    v="$(basename "$di" .dist-info)"
    v="${v#pip-}"
    if ! rem_ver_ge "$v" 26.2.2; then emit FAIL python "$sh/bin/python" "pipx's shared pip $v, used by every pipx tool (fixed: 26.2.2; fix with fix-python-env.sh on this python)"; fi
  done
done

# ---- Node.js ----
node_fixed() { # VERSION -> prints required minimum or "none"
  case "${1%%.*}" in 22) echo 22.23.4 ;; 24) echo 24.22.1 ;; 26) echo 26.12.1 ;; *) echo none ;; esac
}
# The default node is the one a new terminal gets. Ask node itself for its binary: Volta, mise, and asdf put
# a shim on PATH, not node. When PATH's node is an nvm version, or there is none (an agent started from an
# IDE or the desktop app), the default is "nvm alias default": the agent keeps the PATH it started with.
DEFAULT_NODE="$(node -p process.execPath 2> /dev/null || true)"
nvm_dir="${NVM_DIR:-$HOME/.nvm}"
if [ -s "$nvm_dir/nvm.sh" ]; then
  case "$DEFAULT_NODE" in "" | "$(rem_realpath "$nvm_dir")"/versions/node/* | "$nvm_dir"/versions/node/*)
    d="$(NVM_DIR="$nvm_dir" bash -c '. "$NVM_DIR/nvm.sh" --no-use >/dev/null 2>&1 && nvm which default 2>/dev/null' | tail -1)"
    if [ -x "$d" ] && [ "$(rem_realpath "${DEFAULT_NODE:-none}")" != "$(rem_realpath "$d")" ]; then
      [ -n "$DEFAULT_NODE" ] && emit INFO node PATH "this session's node is $("$DEFAULT_NODE" -v 2> /dev/null), but new terminals use the nvm default $("$d" -v 2> /dev/null). Restart the agent to pick it up"
      DEFAULT_NODE="$d"
    fi
    ;;
  esac
fi
[ -n "$DEFAULT_NODE" ] && DEFAULT_NODE="$(rem_realpath "$DEFAULT_NODE")"
nodes="$(
  type -ap node 2> /dev/null
  ls -d "$HOME"/.nvm/versions/node/*/bin/node "$HOME"/.volta/tools/image/node/*/bin/node \
    "$HOME"/.local/share/fnm/node-versions/*/installation/bin/node 2> /dev/null
)"
[ -z "$DEFAULT_NODE" ] && [ -n "$nodes" ] && emit WARN node default "could not determine the default node; every vulnerable node counts as a FAIL and the live test was not run"
# Canonical path of each candidate, from node itself, so a shim and the binary it runs are one entry.
printf '%s\n' "$nodes" "$DEFAULT_NODE" | while IFS= read -r n; do
  [ -n "$n" ] || continue
  rem_realpath "$("$n" -p process.execPath 2> /dev/null || printf '%s' "$n")"
done | awk 'NF && !seen[$0]++' | while IFS= read -r n; do
  v="$("$n" -v 2> /dev/null | tr -d v)"
  [ -n "$v" ] || continue
  need="$(node_fixed "$v")"
  if [ "$need" != none ] && rem_ver_ge "$v" "$need"; then
    emit PASS node "$n" "Node $v"
    continue
  fi
  [ "$need" = none ] && why="no fixed release on this line; use 22.23.4+, 24.22.1+, or 26.12.1+" || why="fixed: $need"
  if [ -z "$DEFAULT_NODE" ] || [ "$n" = "$DEFAULT_NODE" ]; then
    emit FAIL node "$n" "Node $v ($why)"
  else emit WARN node "$n" "Node $v ($why). Not the default node, but anything that selects it (an .nvmrc, nvm use, a full path) is still exposed; remove it once unused"; fi
done
if [ "$NET" = 1 ] && [ -n "$DEFAULT_NODE" ]; then
  NODEJS="require('https').get(process.argv[1],()=>console.log('trusted')).on('error',e=>console.log(/CERT|ISSUER|SELF_SIGNED|REVOKED/.test(e.code||'')?'rejected':'error'))"
  dv="$("$DEFAULT_NODE" -v 2> /dev/null)"
  if [ "$("$DEFAULT_NODE" -e "$NODEJS" "$REM_CONTROL" 2> /dev/null)" = trusted ]; then
    for u in "$REM_BAD_EMSIGN" "$REM_BAD_AAA"; do
      case "$("$DEFAULT_NODE" -e "$NODEJS" "$u" 2> /dev/null)" in
        rejected) emit PASS node default "default node $dv rejects $u" ;;
        trusted) emit FAIL node default "default node $dv TRUSTS $u" ;;
        *) emit WARN node default "could not test $u" ;;
      esac
    done
  else
    emit WARN node default "default node $dv ($DEFAULT_NODE) cannot reach $REM_CONTROL; live test not run"
  fi
fi

# ---- Java ----
rem_jdk_homes | while IFS= read -r j; do
  rem_cacerts "$j" > /dev/null || continue
  verdict="$(rem_jdk_verdict "$j" "$NET")"
  case "$verdict" in pass\|*) emit PASS java "$j" "${verdict#pass|}" ;; *) emit FAIL java "$j" "${verdict#fail|}" ;; esac
done

# ---- Other developer tools ----
if command -v go > /dev/null; then
  v="$(go version | awk '{print $3}' | sed 's/^go//')"
  case "$v" in 1.27.*) need=1.27.3 ;; 1.26.*) need=1.26.10 ;; *) need=none ;; esac
  if [ "$need" = none ]; then
    emit FAIL go go "Go $v: upgrade to 1.27.3+ or 1.26.10+"
  elif rem_ver_ge "$v" "$need"; then emit PASS go go "Go $v"; else emit FAIL go go "Go $v (fixed: $need)"; fi
fi
if command -v uv > /dev/null; then
  v="$(uv --version | awk '{print $2}')"
  if ! rem_ver_ge "$v" 0.13.4; then
    emit FAIL uv uv "uv $v (fixed: 0.13.4; 0.13.5 also distrusts the compromised keys)"
  elif ! rem_ver_ge "$v" 0.13.5; then
    emit WARN uv uv "uv $v rejects the test hosts, but 0.13.5 also distrusts the compromised keys and ships fixed Pythons; upgrade, then run uv python upgrade"
  else emit PASS uv uv "uv $v"; fi
fi
if command -v rustup > /dev/null; then
  v="$(rustup --version 2> /dev/null | awk '{print $2}')"
  if rem_ver_ge "$v" 1.29.2; then emit PASS rust rustup "rustup $v"; else emit FAIL rust rustup "rustup $v (fixed: 1.29.2)"; fi
fi
if command -v deno > /dev/null; then
  v="$(deno --version | awk 'NR==1{print $2}')"
  if rem_ver_ge "$v" 2.9.8; then emit PASS deno deno "Deno $v"; else emit FAIL deno deno "Deno $v (fixed: 2.9.8)"; fi
fi
# tool_ver AREA NAME FIXED VERSION -> PASS or FAIL line for a tool with one fixed release.
tool_ver() {
  case "$4" in [0-9]*) ;; *)
    emit WARN "$1" "$2" "installed, but its version could not be read (fixed: $3)"
    return
    ;;
  esac
  if rem_ver_ge "$4" "$3"; then emit PASS "$1" "$2" "$2 $4"; else emit FAIL "$1" "$2" "$2 $4 (fixed: $3)"; fi
}
if command -v bun > /dev/null; then tool_ver bun bun 1.4.4 "$(bun --version 2> /dev/null)"; fi
if command -v conda > /dev/null; then tool_ver conda conda 26.9.4 "$(conda --version 2> /dev/null | awk '{print $2}')"; fi
if command -v mise > /dev/null; then tool_ver mise mise 2026.10.17 "$(mise --version 2> /dev/null | awk '{print $1}')"; fi
if command -v pixi > /dev/null; then tool_ver pixi pixi 0.82.1 "$(pixi --version 2> /dev/null | awk '{print $2}')"; fi
# The agent running this skill may itself be exposed.
if command -v claude > /dev/null; then tool_ver agent "Claude Code" 2.1.303 "$(claude --version 2> /dev/null | awk '{print $1}')"; fi
if command -v cloudflared > /dev/null; then tool_ver cloudflared cloudflared 2026.10.2 "$(cloudflared --version 2> /dev/null | awk '{print $3}')"; fi
command -v az > /dev/null && emit WARN azure-cli az "Azure CLI bundles an old certifi and has no fixed release yet; avoid it on untrusted networks"
# Firefox: the release channel is fixed in 158.0.1, the ESR channels in 153.5.1 and 115.43.1.
ff=""
if [ -r /Applications/Firefox.app/Contents/Info.plist ]; then
  ff="$(defaults read /Applications/Firefox.app/Contents/Info CFBundleShortVersionString 2> /dev/null)"
elif command -v firefox > /dev/null; then
  ff="$(firefox --version 2> /dev/null | awk '{print $NF}')"
fi
if [ -n "$ff" ]; then
  case "$ff" in 153.* | 115.*) case "$ff" in 153.*) need=153.5.1 ;; *) need=115.43.1 ;; esac ;; *) need=158.0.1 ;; esac
  # OneCRL protects Firefox without an update, so an older version is a WARN, not a FAIL.
  if rem_ver_ge "$ff" "$need"; then emit PASS browser Firefox "Firefox $ff"; else emit WARN browser Firefox "Firefox $ff: OneCRL blocks the chains without an update, but $need or later is the fixed release"; fi
fi
if command -v brew > /dev/null; then
  BREW_PREFIX="$(brew --prefix)"
  # brew_ver FORMULA -> the version in use (the linked keg), else the newest installed. The fix recipes keep
  # old kegs for undo, and "brew list --versions" lists them too, oldest first.
  # The opt link is one level (../Cellar/<formula>/<version>), so plain readlink works on every macOS.
  brew_ver() {
    local v=""
    [ -L "$BREW_PREFIX/opt/$1" ] && v="$(basename "$(readlink "$BREW_PREFIX/opt/$1")")"
    case "$v" in [0-9]*) ;; *) v="$(brew list --versions "$1" 2> /dev/null | tr ' ' '\n' | sed 1d | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)" ;; esac
    printf '%s' "$v"
  }
  brew_has() { brew list --versions "$1" > /dev/null 2>&1; }
  if brew_has ca-certificates; then
    v="$(brew_ver ca-certificates)"
    case "$v" in
      [0-9]*) if [ "$(printf '%s\n%s\n' "$v" 2026-09-25_1 | sort | head -1)" = 2026-09-25_1 ]; then
        emit PASS homebrew ca-certificates "$v"
      else emit FAIL homebrew ca-certificates "$v (fixed: 2026-09-25_1)"; fi ;;
      *) emit WARN homebrew ca-certificates "installed, but its version could not be read; check with: brew info ca-certificates" ;;
    esac
  else
    emit INFO homebrew ca-certificates "not installed"
  fi
  # Another formula (oci-cli, semgrep, ...) can install the certifi formula, which Homebrew's Pythons then
  # import. Upgrading python@3.X does not upgrade it.
  if brew_has certifi; then
    v="$(brew_ver certifi)"
    case "$v" in
      [0-9]*) if rem_ver_ge "$v" 2026.10.19; then
        emit PASS homebrew certifi "$v"
      else emit FAIL homebrew certifi "$v (fixed: 2026.10.19; Homebrew's Pythons import it)"; fi ;;
      *) emit WARN homebrew certifi "installed, but its version could not be read; check with: brew info certifi" ;;
    esac
  fi
fi

emit INFO browsers manual "Open $REM_BAD_EMSIGN, $REM_BAD_AAA, $REM_BAD_EMSIGN_NOCT, and $REM_BAD_AAA_NOCT in every browser; each must show a certificate error"
emit INFO apps manual "Update Electron apps (Slack 4.52.182 or later, Zoom, VS Code, 1Password, Claude Desktop) and Docker Desktop (4.96.3 or later; Docker ships its fix in batches, so install each patch release)"
echo "# Report saved to $REPORT"
rem_log "vetted-script:check.sh" "read-only check" "report $REPORT" "nothing to undo"
