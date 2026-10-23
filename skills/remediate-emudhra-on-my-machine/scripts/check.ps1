# Read-only check of every TLS client this script can find on Windows. Changes nothing on the system.
# Writes its report to %USERPROFILE%\.remediate-emudhra\. Windows PowerShell 5.1 compatible.
# Output lines: STATUS|AREA|ITEM|DETAIL, where STATUS is PASS, FAIL, WARN, or INFO.
# Run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File check.ps1
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot 'lib.ps1')
Initialize-RemState
$report = Join-Path $RemStateDir ("check-{0}.txt" -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
$lines = New-Object System.Collections.Generic.List[string]
function Emit($status, $area, $item, $detail) {
    $line = "$status|$area|$item|$detail"; $lines.Add($line); Write-Output $line
}

# .NET WebRequest uses Schannel and the Windows certificate stores, including the Untrusted store.
function Test-Schannel($url) {
    try { $r = [System.Net.WebRequest]::Create($url); $r.Timeout = 20000; $r.GetResponse().Close(); return 'trusted' }
    catch [System.Net.WebException] {
        if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure) { return 'rejected' }
        if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::SecureChannelFailure -and "$($_.Exception.InnerException)" -match 'certificate|trust|revoked') { return 'rejected' }
        if ($_.Exception.Response) { return 'trusted' }
        return 'error'
    }
    catch { return 'error' }
}

try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { $null = $_ }  # deliberately ignored
Write-Output "# eMudhra remediation check $((Get-Date).ToUniversalTime().ToString('s'))Z on Windows"
$net = (Test-Schannel $RemControl) -eq 'trusted'
if (-not $net) { Emit FAIL network control "UNVERIFIED: cannot reach $RemControl. Live tests were skipped, so this run cannot confirm the machine is safe. Reconnect and run the check again" }

# ---- Operating system and Windows trust store ----
$os = Get-CimInstance Win32_OperatingSystem
Emit INFO os Windows "$($os.Caption) build $($os.BuildNumber)"
$pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' -ErrorAction SilentlyContinue
if ($pol -and $pol.DisableRootAutoUpdate -eq 1) {
    Emit FAIL os auto-root-update "Automatic root certificate updates are disabled by policy, so Microsoft's block cannot arrive; the admin script adds it locally"
}
$have = @(Get-ChildItem Cert:\LocalMachine\Disallowed -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Thumbprint)
$need = Get-RemIntermediate | ForEach-Object { $_.Thumbprint }
$missing = @($need | Where-Object { $have -notcontains $_ }).Count
Emit INFO os untrusted-store "$((16 - $missing)) of 16 compromised intermediates are in LocalMachine\Disallowed (Microsoft's own update blocks them separately, invisibly in certlm.msc)"
# Microsoft's block arrives with the automatic untrusted-certificate list (no KB); this is when Windows last synced it.
$au = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate' -ErrorAction SilentlyContinue
if ($au -and $au.DisallowedCertLastSyncTime -is [byte[]] -and $au.DisallowedCertLastSyncTime.Length -ge 8) {
    $sync = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($au.DisallowedCertLastSyncTime, 0))
    if ($sync -ge [DateTime]::new(2026, 10, 21, 0, 0, 0, [DateTimeKind]::Utc)) { Emit PASS os untrusted-list "Windows synced its untrusted-certificate list on $($sync.ToString('yyyy-MM-dd')) UTC, after Microsoft's block shipped" }
    else { Emit WARN os untrusted-list "Windows last synced its untrusted-certificate list on $($sync.ToString('yyyy-MM-dd')) UTC, before Microsoft's block had reached all machines (2026-10-21); the admin script adds the block locally" }
}
if ($net) {
    foreach ($u in @($RemBadEmsign, $RemBadAaa)) {
        switch (Test-Schannel $u) {
            'rejected' { Emit PASS windows schannel "rejects $u" }
            'trusted'  { Emit FAIL windows schannel "TRUSTS $u (run the admin script, then Windows Update)" }
            default    { Emit WARN windows schannel "could not test $u" }
        }
    }
}

# ---- WSL distributions (separate Linux systems with their own trust stores and tools) ----
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if ($wsl) {
    $raw = @(Invoke-RemNative $wsl.Source @('--list', '--quiet'))
    $distros = @()
    if ($LASTEXITCODE -eq 0) {
        $distros = @($raw | ForEach-Object { ($_ -replace "`0", '').Trim() } | Where-Object { $_ -and $_ -notmatch '\s' -and $_ -notmatch '^docker-desktop' })
    }
    foreach ($d in $distros) { Emit WARN wsl $d "WSL distribution found. It has its own trust store and tools; run the Linux check inside it" }
    if ($distros.Count -eq 0) { Emit INFO wsl none 'WSL is available but no Linux distributions are installed' }
}

# ---- curl.exe and git ----
if ($net) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        Invoke-RemNative $curl.Source @('-sS', '-o', 'NUL', '-m', '20', $RemControl) | Out-Null
        if ($LASTEXITCODE -ne 0) { Emit WARN curl $curl.Source "cannot reach $RemControl with curl.exe; not tested" }
        else {
            foreach ($u in @($RemBadEmsign, $RemBadAaa)) {
                $err = Invoke-RemCapture $curl.Source @('-sS', '-o', 'NUL', '-m', '20', $u)
                if ($LASTEXITCODE -eq 0) { Emit FAIL curl $curl.Source "TRUSTS $u" }
                elseif ($LASTEXITCODE -eq 60 -or $err -match 'certificate|CRYPT_E_|SEC_E_|CERT_E_|revok') { Emit PASS curl $curl.Source "rejects $u" }
                else { Emit WARN curl $curl.Source "could not test $u (curl exit $LASTEXITCODE)" }
            }
        }
    }
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($git) {
        $backend = (Invoke-RemNative $git.Source @('config', '--global', '--get', 'http.sslBackend'))
        $env:GIT_TERMINAL_PROMPT = '0'
        Invoke-RemNative $git.Source @('ls-remote', 'https://github.com/git/git.git', 'HEAD') | Out-Null
        if ($LASTEXITCODE -ne 0) { Emit WARN git $git.Source 'cannot reach GitHub with git; not tested' }
        else { foreach ($u in @($RemBadEmsign, $RemBadAaa)) {
            $env:GIT_TERMINAL_PROMPT = '0'
            $out = Invoke-RemCapture $git.Source @('ls-remote', $u)
            if ($out -match 'SSL certificate problem|certificate verify failed|SEC_E_|CERT_E_|schannel: ') { Emit PASS git $git.Source "rejects $u" }
            elseif ($out -match 'not valid: is this a git repository|not found|returned error: 4') { Emit FAIL git $git.Source "TRUSTS $u (sslBackend: $(if ($backend) { $backend } else { 'openssl default' })). Upgrade to Git for Windows 2.56.0.windows.3 or later, or switch it to the Windows store (fix-recipes)" }
            else { Emit WARN git $git.Source "could not test $u" }
        } }
    }
}

# ---- Python interpreters ----
$pyTest = Join-Path $env:TEMP 'remediate-emudhra-pytest.py'
@'
import sys, os, re
label, net, bad1, bad2, control = sys.argv[1:6]
FIX_PIP, FIX_CERTIFI = (26, 2, 2), (2026, 10, 19)
def vt(s):
    return tuple(int("".join(c for c in p if c.isdigit()) or 0) for p in str(s).split(".")[:3])
def emit(st, d): print("%s|python|%s|%s" % (st, label, d))
ver = sys.version.split()[0]
FIX_PY = {(3, 13): (3, 13, 17), (3, 14): (3, 14, 9), (3, 15): (3, 15, 1)}
fixed_py = FIX_PY.get(tuple(sys.version_info[:2]))
if fixed_py and tuple(sys.version_info[:3]) < fixed_py:
    emit("WARN", "Python %s: the patched release on this line is %s; upgrade when you can" % (ver, ".".join(map(str, fixed_py))))
if sys.version_info < (3, 10):
    emit("WARN", "Python %s is end of life; the fixed pip needs 3.10+%s. Remove it if unused" % (ver, " and Python 2 cannot run the fixed certifi (the last release for it is 2021.10.8)" if sys.version_info[0] < 3 else ""))
def pip_probe(u):
    # A live test of this interpreter's pip: an SSL verification error means it rejects the host. pip keeps
    # its own certificate list alongside the system store, so only a live test is conclusive.
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
    emit("INFO", "no pip")
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
    import certifi; emit("PASS" if vt(certifi.__version__) >= FIX_CERTIFI else "FAIL", "certifi %s (fixed: 2026.10.19)" % certifi.__version__)
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
            return "rejected" if "CERTIFICATE_VERIFY_FAILED" in repr(e) else "error"
    if probe(control) != "trusted":
        emit("WARN", "Python %s could not reach the control site; urllib not tested" % ver)
        raise SystemExit(0)
    for u in (bad1, bad2):
        r = probe(u)
        if r == "trusted":
            emit("WARN", "urllib TRUSTS %s: Python's standard library on Windows ignores the Untrusted store. Known limitation; the CPython fix (gh-160040) has not shipped yet. pip and requests are covered by the pip/certifi upgrades" % u)
        elif r == "rejected":
            emit("PASS", "urllib rejects %s" % u)
        elif r == "inconclusive":
            emit("WARN", "urllib reached something other than the test site at %s (a proxy may be intercepting TLS)" % u)
'@ | Set-Content -Path $pyTest -Encoding UTF8
$pys = New-Object System.Collections.Generic.List[string]
$launcher = Get-Command py.exe -ErrorAction SilentlyContinue
if ($launcher) {
    & $launcher.Source -0p 2>$null | ForEach-Object { if ($_ -match '([A-Za-z]:\\.+?python[w]?\.exe)') { $pys.Add($Matches[1]) } }
}
Get-Command python.exe -All -ErrorAction SilentlyContinue | Where-Object { $_.Source -notmatch 'WindowsApps\\python\.exe$' } | ForEach-Object { $pys.Add($_.Source) }
# conda, mamba, and micromamba: the base environment, every named one under envs\, and every environment
# conda recorded in ~\.conda\environments.txt (wherever it was created).
$condaEnvs = New-Object System.Collections.Generic.List[string]
foreach ($root in @("$env:USERPROFILE\miniconda3", "$env:USERPROFILE\anaconda3", "$env:USERPROFILE\miniforge3", "$env:USERPROFILE\mambaforge", "$env:USERPROFILE\micromamba", "$env:USERPROFILE\.conda", "$env:LOCALAPPDATA\miniconda3", "$env:LOCALAPPDATA\anaconda3", "$env:ProgramData\miniconda3", "$env:ProgramData\anaconda3")) {
    if (Test-Path $root) { $condaEnvs.Add($root); Get-ChildItem (Join-Path $root 'envs') -Directory -ErrorAction SilentlyContinue | ForEach-Object { $condaEnvs.Add($_.FullName) } }
}
$envList = Join-Path $env:USERPROFILE '.conda\environments.txt'
if (Test-Path $envList) { Get-Content $envList | Where-Object { $_.Trim() } | ForEach-Object { $condaEnvs.Add($_.Trim()) } }
foreach ($e in $condaEnvs) { $c = Join-Path $e 'python.exe'; if (Test-Path $c) { $pys.Add($c) } }
foreach ($py in ($pys | Sort-Object -Unique)) {
    & $py -B $pyTest $py $(if ($net) { '1' } else { '0' }) $RemBadEmsign $RemBadAaa $RemControl 2>$null | ForEach-Object { $lines.Add($_); Write-Output $_ }
}
Remove-Item $pyTest -ErrorAction SilentlyContinue
# Project virtualenvs (Windows layout: <venv>\Lib\site-packages, interpreter <venv>\Scripts\python.exe).
# REMEDIATE_EMUDHRA_PROJECTS (semicolon-separated) replaces the common defaults.
$devList = if ($env:REMEDIATE_EMUDHRA_PROJECTS) { $env:REMEDIATE_EMUDHRA_PROJECTS -split ';' } else {
    @('Development', 'dev', 'src', 'code', 'projects', 'repos', 'git', 'workspace', 'source\repos') | ForEach-Object { Join-Path $env:USERPROFILE $_ }
}
$dev = @($devList | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | ForEach-Object { (Resolve-Path -LiteralPath $_).ProviderPath } | Sort-Object -Unique)
if ($dev.Count -eq 0) { Emit INFO projects none 'no project folder found under your user folder (Development, dev, src, code, projects, repos, git, workspace, source\repos); set REMEDIATE_EMUDHRA_PROJECTS to scan yours for virtualenvs and lock files' }
else {
    $where = $dev -join ', '
    $venvs = @(Get-ChildItem $dev -Filter pyvenv.cfg -Recurse -Depth 3 -File -Force -ErrorAction SilentlyContinue).Count
    if ($venvs -gt 0) { Emit INFO python virtualenvs "$venvs project virtualenvs under $where; each has its own certifi (see fix-recipes)" }
    # A uv.lock pin puts the old certifi back on the next "uv sync". One summary line; the list goes next to the report.
    $locks = @(Get-ChildItem $dev -Filter uv.lock -Recurse -Depth 2 -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\node_modules\\' } | ForEach-Object {
        # Every certifi entry (a forked lock can have more than one); keep the oldest. [string] guards an empty file.
        $vs = @([regex]::Matches([string](Get-Content $_.FullName -Raw), '(?m)^name = "certifi"\r?\nversion = "([^"]+)"') | ForEach-Object {
            try { [version]$_.Groups[1].Value } catch { $null = $_ }  # deliberately ignored
        } | Sort-Object)
        if ($vs.Count -gt 0 -and $vs[0] -lt [version]'2026.10.19') { "$($vs[0]) $($_.DirectoryName)" }
    })
    if ($locks.Count -gt 0) {
        $lockList = $report -replace '\.txt$', '-lockfiles.txt'
        $locks | Set-Content -Path $lockList -Encoding UTF8
        Emit WARN lockfile uv.lock "$($locks.Count) repositories under $where pin certifi older than 2026.10.19, so uv sync reverts their virtualenv fix until the pin is bumped. List: $lockList (fix-recipes: lock files)"
    }
}
# Tools installed with pipx or uv tool live in their own virtualenvs, each with its own certifi. pipx keeps one shared
# pip for all of them. Ask the tools where they keep them, then try the usual defaults.
$toolRoots = New-Object System.Collections.Generic.List[string]
$sharedRoots = New-Object System.Collections.Generic.List[string]
$pipx = Get-Command pipx -ErrorAction SilentlyContinue
if ($pipx) {
    @(Invoke-RemNative $pipx.Source @('environment', '--value', 'PIPX_LOCAL_VENVS')) | Where-Object { $_ } | ForEach-Object { $toolRoots.Add($_.Trim()) }
    @(Invoke-RemNative $pipx.Source @('environment', '--value', 'PIPX_SHARED_LIBS')) | Where-Object { $_ } | ForEach-Object { $sharedRoots.Add($_.Trim()) }
}
$uvCmd = Get-Command uv.exe -ErrorAction SilentlyContinue
if ($uvCmd) { @(Invoke-RemNative $uvCmd.Source @('tool', 'dir')) | Where-Object { $_ } | ForEach-Object { $toolRoots.Add($_.Trim()) } }
foreach ($d in @("$env:LOCALAPPDATA\pipx\pipx\venvs", "$env:USERPROFILE\pipx\venvs", "$env:USERPROFILE\.local\pipx\venvs", "$env:APPDATA\uv\data\tools")) { $toolRoots.Add($d) }
foreach ($d in @("$env:LOCALAPPDATA\pipx\pipx\shared", "$env:USERPROFILE\pipx\shared", "$env:USERPROFILE\.local\pipx\shared")) { $sharedRoots.Add($d) }
foreach ($sh in ($sharedRoots | Sort-Object -Unique)) {
    $spy = Join-Path $sh 'Scripts\python.exe'; if (-not (Test-Path $spy)) { continue }
    foreach ($di in Get-ChildItem (Join-Path $sh 'Lib\site-packages') -Directory -ErrorAction SilentlyContinue) {
        if ($di.Name -notmatch '^pip-([\d.]+)\.dist-info$') { continue }
        $sv = $Matches[1]; $old = $false; try { $old = [version]$sv -lt [version]'26.2.2' } catch { $null = $_ }  # deliberately ignored
        if ($old) { Emit FAIL python $spy "pipx's shared pip $sv, used by every pipx tool (fixed: 26.2.2; fix with fix-python-env.ps1 on this python)" }
    }
}
foreach ($root in ($toolRoots | Sort-Object -Unique)) {
    if (-not (Test-Path $root)) { continue }
    foreach ($tv in Get-ChildItem $root -Directory -ErrorAction SilentlyContinue) {
        $tpy = Join-Path $tv.FullName 'Scripts\python.exe'; if (-not (Test-Path $tpy)) { continue }
        foreach ($di in Get-ChildItem (Join-Path $tv.FullName 'Lib\site-packages') -Directory -ErrorAction SilentlyContinue) {
            if ($di.Name -notmatch '^(certifi|pip)-([\d.]+)\.dist-info$') { continue }
            $pkg = $Matches[1]; $tvv = $Matches[2]; $need = if ($pkg -eq 'certifi') { '2026.10.19' } else { '26.2.2' }
            $old = $false; try { $old = [version]$tvv -lt [version]$need } catch { $null = $_ }  # deliberately ignored
            if ($old) { Emit FAIL python $tpy "tool environment: $pkg $tvv (fixed: $need; fix with fix-python-env.ps1 on this python)" }
        }
    }
}

# ---- Node.js ----
function Get-NodeFixed($v) { switch ($v.Split('.')[0]) { '22' { '22.23.4' } '24' { '24.22.1' } '26' { '26.12.1' } default { $null } } }
$nodes = New-Object System.Collections.Generic.List[string]
Get-Command node.exe -All -ErrorAction SilentlyContinue | ForEach-Object { $nodes.Add($_.Source) }
foreach ($d in @("$env:APPDATA\nvm", "$env:ProgramFiles\nodejs", "$env:LOCALAPPDATA\Volta\tools\image\node")) {
    if (Test-Path $d) { Get-ChildItem $d -Recurse -Filter node.exe -Depth 2 -ErrorAction SilentlyContinue | ForEach-Object { $nodes.Add($_.FullName) } }
}
foreach ($n in ($nodes | Sort-Object -Unique)) {
    $v = (& $n -v 2>$null); if (-not $v) { continue }; $v = $v.TrimStart('v')
    $need = Get-NodeFixed $v
    if (-not $need) { Emit FAIL node $n "Node ${v}: no fixed release on this line; use 22.23.4+, 24.22.1+, or 26.12.1+" }
    elseif ([version]$v -ge [version]$need) { Emit PASS node $n "Node $v" }
    else { Emit FAIL node $n "Node $v (fixed: $need)" }
}

# ---- Java ----
foreach ($j in (Get-RemJdkHome)) {
    if (-not (Get-RemCacertsFile $j)) { continue }
    $verdict = Get-RemJdkVerdict $j $net
    if ($verdict.Pass) { Emit PASS java $j $verdict.Detail } else { Emit FAIL java $j $verdict.Detail }
}

# ---- Other developer tools and browsers ----
$go = Get-Command go.exe -ErrorAction SilentlyContinue
if ($go) {
    $v = ((& $go.Source version) -split ' ')[2].TrimStart('go')
    $need = if ($v -like '1.27.*') { '1.27.3' } elseif ($v -like '1.26.*') { '1.26.10' } else { $null }
    if (-not $need) { Emit FAIL go go "Go ${v}: upgrade to 1.27.3+ or 1.26.10+" }
    elseif ([version]$v -ge [version]$need) { Emit PASS go go "Go $v" } else { Emit FAIL go go "Go $v (fixed: $need)" }
}
$uv = Get-Command uv.exe -ErrorAction SilentlyContinue
if ($uv) {
    $v = ((& $uv.Source --version) -split ' ')[1]
    if ([version]$v -lt [version]'0.13.4') { Emit FAIL uv uv "uv $v (fixed: 0.13.4; 0.13.5 also distrusts the compromised keys)" }
    elseif ([version]$v -lt [version]'0.13.5') { Emit WARN uv uv "uv $v rejects the test hosts, but 0.13.5 also distrusts the compromised keys and ships fixed Pythons; upgrade, then run uv python upgrade" }
    else { Emit PASS uv uv "uv $v" }
}
# Tools with one fixed release each; the agent running this skill may itself be exposed (claude).
function Test-RemTool($area, $name, $exe, [string[]]$versionArgs, $field, $fixed) {
    $cmd = Get-Command $exe -ErrorAction SilentlyContinue
    if (-not $cmd) { return }
    $v = (@(Invoke-RemNative $cmd.Source $versionArgs) | Select-Object -First 1) -split '\s+' | Select-Object -Index $field
    $vv = ($v -replace '^v', '') -replace '[^0-9.].*$', ''
    if ($vv -notmatch '^\d') { Emit WARN $area $name "installed, but its version could not be read (fixed: $fixed)"; return }
    $ok = $false; try { $ok = [version]$vv -ge [version]$fixed } catch { $null = $_ }  # deliberately ignored
    if ($ok) { Emit PASS $area $name "$name $v" } else { Emit FAIL $area $name "$name $v (fixed: $fixed)" }
}
Test-RemTool rust rustup 'rustup.exe' @('--version') 1 '1.29.2'
Test-RemTool deno deno 'deno.exe' @('--version') 1 '2.9.8'
Test-RemTool bun bun 'bun.exe' @('--version') 0 '1.4.4'
Test-RemTool conda conda 'conda.exe' @('--version') 1 '26.9.4'
Test-RemTool mise mise 'mise.exe' @('--version') 0 '2026.10.17'
Test-RemTool pixi pixi 'pixi.exe' @('--version') 1 '0.82.1'
Test-RemTool agent 'Claude Code' 'claude.exe' @('--version') 0 '2.1.303'
Test-RemTool cloudflared cloudflared 'cloudflared.exe' @('--version') 2 '2026.10.2'
if (Get-Command az -ErrorAction SilentlyContinue) { Emit WARN azure-cli az 'Azure CLI bundles an old certifi and has no fixed release yet; avoid it on untrusted networks' }
$ff = Get-ItemProperty 'HKLM:\SOFTWARE\Mozilla\Mozilla Firefox' -ErrorAction SilentlyContinue
if ($ff) {
    # The release channel is fixed in 158.0.1, the ESR channels in 153.5.1 and 115.43.1.
    $fv = ($ff.CurrentVersion -split ' ')[0]; $fvv = $fv -replace '[^0-9.].*$', ''
    $need = if ($fvv -like '153.*') { '153.5.1' } elseif ($fvv -like '115.*') { '115.43.1' } else { '158.0.1' }
    $ok = $false; try { $ok = [version]$fvv -ge [version]$need } catch { $null = $_ }  # deliberately ignored
    # OneCRL protects Firefox without an update, so an older version is a WARN, not a FAIL.
    if ($ok) { Emit PASS browser Firefox "Firefox $fv" } else { Emit WARN browser Firefox "Firefox ${fv}: OneCRL blocks the chains without an update, but $need or later is the fixed release; update it from Help > About Firefox" }
}
Emit INFO browsers manual "Open $RemBadEmsign, $RemBadAaa, $RemBadEmsignNoCt, and $RemBadAaaNoCt in every browser; each must show a certificate error"
Emit INFO apps manual 'Update Electron apps (Slack 4.52.182 or later, Zoom, VS Code, 1Password, Claude Desktop) and Docker Desktop (4.96.3 or later; Docker ships its fix in batches, so install each patch release)'

$lines | Set-Content -Path $report -Encoding UTF8
Write-Output "# Report saved to $report"
Write-RemLog 'vetted-script:check.ps1' 'read-only check' "report $report" 'nothing to undo'
