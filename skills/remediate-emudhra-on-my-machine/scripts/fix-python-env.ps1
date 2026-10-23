# Upgrade pip and certifi inside ONE Python interpreter or virtualenv on Windows, without admin rights.
# Records the versions it replaced so the change can be undone.
# Exit codes: 0 fixed or nothing needed, 3 deliberately skipped (message says why), 4 still vulnerable.
# Usage: powershell.exe -NoProfile -ExecutionPolicy Bypass -File fix-python-env.ps1 -Python C:\path\to\python.exe
param([Parameter(Mandatory = $true)][string]$Python)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib.ps1')
if (-not (Test-Path -LiteralPath $Python)) { Write-Host "Not found: $Python"; exit 2 }
$qpy = ConvertTo-RemQuoted $Python

$probe = @'
import sys, os, glob
def v(m):
    try:
        return __import__(m).__version__
    except Exception:
        return ''
def inst(m):
    # Who installed the copy that is actually imported (conda, pip, or uv), from its dist-info.
    try:
        site = os.path.dirname(os.path.dirname(os.path.abspath(__import__(m).__file__)))
        for f in glob.glob(os.path.join(site, m + '-*.dist-info', 'INSTALLER')):
            return open(f).read().strip()
    except Exception:
        pass
    return ''
print('%d.%d|%s|%s|%s|%s|%s|%s' % (sys.version_info[0], sys.version_info[1], v('pip'), v('certifi'), 'conda' if os.path.isdir(os.path.join(sys.prefix, 'conda-meta')) else '', sys.prefix, inst('pip'), inst('certifi')))
'@
$info = (Invoke-RemNative $Python @('-c', $probe) | Select-Object -Last 1)
$pyver, $oldPip, $oldCertifi, $conda, $prefix, $pipInst, $certifiInst = $info.Trim().Split('|')

$py310 = [version]$pyver -ge [version]'3.10'
function Test-Old($v, $fixed) { try { return [version]$v -lt [version]$fixed } catch { return $true } }

# In a conda environment, upgrade each package with whatever installed the copy Python imports. Its
# dist-info INSTALLER file says "conda" or "pip"; a conda-meta record alone can be stale, because pip
# can replace a conda package and leave the record behind. Without an INSTALLER file, fall back to it.
$condaPkgs = @(); $condaChannel = ''; $skipPip = $false; $skipCertifi = $false
$openMsgs = @()  # what stays vulnerable; printed last, and it makes the exit code 4
if ($conda) {
    $metaDir = Join-Path $prefix 'conda-meta'
    $meta = @(Get-ChildItem $metaDir -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    function Test-CondaOwned($name, $installer) { if ($installer) { return $installer -eq 'conda' } else { return [bool]($meta -match "^$name-\d") } }
    function Test-FromForge($name) {
        $rec = @(Get-ChildItem $metaDir -Filter "$name-*.json" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^$name-\d" })
        return [bool]($rec -and (Select-String -Path $rec[0].FullName -Pattern 'conda-forge' -SimpleMatch -Quiet))
    }
    # conda's OpenSSL, and Python's ssl module in a conda environment, read <prefix>\Library\ssl\cacert.pem, which
    # comes from conda's ca-certificates package, not from certifi. Each environment has its own copy.
    $caRec = @($meta | Where-Object { $_ -match '^ca-certificates-(\d[\d.]*)-' } | Select-Object -First 1)
    if ($caRec -and $caRec[0] -match '^ca-certificates-(\d[\d.]*)-') {
        $cav = $Matches[1]; $caFixed = '2026.10.20'; $caForge = Test-FromForge 'ca-certificates'
        if ($caForge) { $caFixed = '2026.10.19' }
        if (Test-Old $cav $caFixed) {
            # Anaconda's defaults channel has no fixed build for its retired platforms (the record's subdir is the environment's).
            $subdir = ''
            $recFile = Join-Path $metaDir $caRec[0]
            if ((Get-Content $recFile -Raw) -match '"subdir":\s*"([^"]+)"') { $subdir = $Matches[1] }
            if (-not $caForge -and $subdir -in @('osx-64', 'linux-ppc64le', 'linux-s390x')) {
                $openMsgs += "conda's ca-certificates $cav in $prefix is vulnerable, and Anaconda's defaults channel has no fixed build for $subdir. Move this environment to conda-forge, or retire it."
            } else {
                $condaPkgs += "`"ca-certificates>=$caFixed`""
                if ($caForge) { $condaChannel = '-c conda-forge ' }
            }
        }
    }
    if ($oldPip -and (Test-CondaOwned 'pip' $pipInst)) {
        $skipPip = $true
        if ($py310 -and (Test-Old $oldPip '26.2.2')) { $condaPkgs += '"pip>=26.2.2"' }
    }
    if ($oldCertifi -and (Test-CondaOwned 'certifi' $certifiInst)) {
        $skipCertifi = $true
        if (Test-Old $oldCertifi '2026.10.19') {
            # conda's builds of the fixed certifi need Python 3.10+ on the defaults channel and 3.11+ on conda-forge (the PyPI one
            # needs only 3.7). Below that, conda cannot install it: it fails, or it offers to upgrade Python itself.
            $floor = '3.10'
            if (Test-FromForge 'certifi') { $floor = '3.11'; $condaChannel = '-c conda-forge ' }
            if ([version]$pyver -ge [version]$floor) { $condaPkgs += '"certifi>=2026.10.19"' }
            else { $openMsgs += "certifi $oldCertifi in $Python is vulnerable, and conda's build of the fixed certifi for this channel needs Python $floor or later (this is $pyver). Retire this environment, or rebuild it on Python $floor or later." }
        }
    }
}
# Complete-Run CODE: the last step on every path. Prints the conda command for conda-owned packages (exit 3) and then
# whatever stays vulnerable (exit 4); otherwise exits CODE. The conda command uses minimum versions, which fail loudly
# if conda cannot reach them, and pins the Python version so conda never upgrades Python.
function Complete-Run($code) {
    $rc = $code
    if ($condaPkgs.Count -gt 0) {
        Write-Host 'SKIP: conda installed these in this environment, so upgrade them with conda to keep the environment consistent:'
        # micromamba-only machines have no conda command; the same arguments work for mamba and micromamba.
        $cm = 'conda'
        if (-not (Get-Command conda -ErrorAction SilentlyContinue)) {
            if (Get-Command mamba -ErrorAction SilentlyContinue) { $cm = 'mamba' } elseif (Get-Command micromamba -ErrorAction SilentlyContinue) { $cm = 'micromamba' }
        }
        Write-Host "  $cm install $condaChannel-p `"$prefix`" $($condaPkgs -join ' ') `"python=$pyver`""
        $rc = 3
    }
    if ($openMsgs.Count -gt 0) { $openMsgs | ForEach-Object { Write-Host "FAIL: $_" }; $rc = 4 }
    exit $rc
}

if (-not $oldPip) {
    # conda environments can lack pip too; a conda-owned certifi there is conda's to upgrade.
    if ($skipCertifi) {
        if ($condaPkgs.Count -eq 0 -and $openMsgs.Count -eq 0) { Write-Host "certifi $oldCertifi in $Python is fixed, and conda manages it. Nothing to do." }
        Complete-Run 0
    }
    if (-not $oldCertifi) { Write-Host "Nothing for pip or uv to upgrade in $Python (no pip, no certifi)."; Complete-Run 0 }
    if (-not (Test-Old $oldCertifi '2026.10.19')) { Write-Host "certifi $oldCertifi is already fixed."; Complete-Run 0 }
    $uv = Get-Command uv.exe -ErrorAction SilentlyContinue
    if (-not $uv) { $openMsgs += "certifi $oldCertifi in $Python is vulnerable, and this environment has neither pip nor uv to upgrade it."; Complete-Run 4 }
    Write-Host "Upgrading certifi in $Python with uv (this environment has no pip)"
    Invoke-RemNative $uv.Source @('pip', 'install', '--python', $Python, 'certifi>=2026.10.19') | Write-Host
    if ($LASTEXITCODE -ne 0) { $openMsgs += "uv could not install the fixed certifi in $Python; nothing was changed."; Complete-Run 4 }
    $newCertifi = (Invoke-RemNative $Python @('-c', 'import certifi; print(certifi.__version__)') | Select-Object -Last 1).Trim()
    Write-RemLog 'vetted-script:fix-python-env.ps1' "upgraded certifi in $Python (uv)" "certifi $oldCertifi -> $newCertifi" "uv pip install --python $qpy certifi==$oldCertifi"
    Write-Host "Done. certifi $newCertifi. Logged to $RemLog"
    Complete-Run 0
}

$pkgs = @()
# Only what is still old: reinstalling a fixed package would log a no-op change.
if (-not $skipPip -and (Test-Old $oldPip '26.2.2')) {
    if ($py310) { $pkgs += 'pip>=26.2.2' } else { Write-Host "NOTE: Python $pyver cannot run the fixed pip (needs 3.10+). Upgrading certifi only." }
}
if ($oldCertifi -and -not $skipCertifi -and (Test-Old $oldCertifi '2026.10.19')) { $pkgs += 'certifi>=2026.10.19' }
# A pip that is vulnerable and cannot be fixed (the fixed pip needs Python 3.10+) stays open.
if (-not $py310 -and $oldPip -and (Test-Old $oldPip '26.2.2')) {
    $openMsgs += "pip $oldPip in $Python stays vulnerable: the fixed pip needs Python 3.10 or later (this is $pyver). Retire this environment, or rebuild it on Python 3.10 or later."
}
if ($pkgs.Count -eq 0) {
    if ($condaPkgs.Count -eq 0) { Write-Host "Nothing for pip to upgrade in $Python." }
    Complete-Run 0
}

Write-Host "Upgrading in $Python with its own pip: $($pkgs -join ' ')"
Invoke-RemNative $Python (@('-m', 'pip', 'install', '--disable-pip-version-check', '--upgrade') + $pkgs) | Write-Host
if ($LASTEXITCODE -ne 0) {
    $openMsgs += "pip could not install the fixed versions in $Python. Python $pyver may be too old for them: retire this environment, or rebuild it on Python 3.10 or later."
    Complete-Run 4
}

$undo = "& $qpy -m pip install"; $parts = @()
if ($pkgs -contains 'pip>=26.2.2') {
    $newPip = (Invoke-RemNative $Python @('-c', 'import pip; print(pip.__version__)') | Select-Object -Last 1).Trim()
    $undo += " pip==$oldPip"; $parts += "pip $oldPip -> $newPip"
}
if ($pkgs -contains 'certifi>=2026.10.19') {
    $newCertifi = (Invoke-RemNative $Python @('-c', 'import certifi; print(certifi.__version__)') | Select-Object -Last 1).Trim()
    $undo += " certifi==$oldCertifi"; $parts += "certifi $oldCertifi -> $newCertifi"
}
$detail = $parts -join ', '
Write-RemLog 'vetted-script:fix-python-env.ps1' "upgraded pip/certifi in $Python" $detail $undo
Write-Host "Done. $detail. Logged to $RemLog"
Complete-Run 0
