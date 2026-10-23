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
$condaPkgs = @(); $skipPip = $false; $skipCertifi = $false
if ($conda) {
    $meta = @(Get-ChildItem (Join-Path $prefix 'conda-meta') -Filter '*.json' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    function Test-CondaOwned($name, $installer) { if ($installer) { return $installer -eq 'conda' } else { return [bool]($meta -match "^$name-\d") } }
    if ($oldPip -and (Test-CondaOwned 'pip' $pipInst)) {
        $skipPip = $true
        if ($py310 -and (Test-Old $oldPip '26.2.2')) { $condaPkgs += '"pip>=26.2.2"' }
    }
    if ($oldCertifi -and (Test-CondaOwned 'certifi' $certifiInst)) {
        $skipCertifi = $true
        if (Test-Old $oldCertifi '2026.10.19') {
            # conda's build of the fixed certifi needs Python 3.10+ (the PyPI one needs only 3.7), so conda cannot install it here; it would report success and change nothing.
            if (-not $py310) { Write-Host "FAIL: certifi $oldCertifi in $Python is vulnerable, and conda's build of the fixed certifi needs Python 3.10 or later (this is $pyver). Retire this environment, or rebuild it on Python 3.10 or later."; exit 4 }
            $condaPkgs += '"certifi>=2026.10.19"'
        }
    }
}
function Show-CondaAdvice {
    if ($condaPkgs.Count -eq 0) { return }
    Write-Host 'SKIP: conda installed these in this environment, so upgrade them with conda to keep the environment consistent:'
    Write-Host "  conda install -p `"$prefix`" $($condaPkgs -join ' ')"
    exit 3
}

if (-not $oldPip) {
    # conda environments can lack pip too; a conda-owned certifi there is conda's to upgrade.
    if ($skipCertifi) { Show-CondaAdvice; Write-Host "certifi $oldCertifi is already fixed."; exit 0 }
    if (-not $oldCertifi) { Write-Host "Nothing to upgrade in $Python (no pip, no certifi)."; exit 0 }
    if ([version]$oldCertifi -ge [version]'2026.10.19') { Write-Host "certifi $oldCertifi is already fixed."; exit 0 }
    $uv = Get-Command uv.exe -ErrorAction SilentlyContinue
    if (-not $uv) { Write-Host "FAIL: certifi $oldCertifi in $Python is vulnerable, and this environment has neither pip nor uv to upgrade it."; exit 4 }
    Write-Host "Upgrading certifi in $Python with uv (this environment has no pip)"
    Invoke-RemNative $uv.Source @('pip', 'install', '--python', $Python, 'certifi>=2026.10.19') | Write-Host
    if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: uv could not install the fixed certifi in $Python; nothing was changed."; exit 4 }
    $newCertifi = (Invoke-RemNative $Python @('-c', 'import certifi; print(certifi.__version__)') | Select-Object -Last 1).Trim()
    Write-RemLog 'vetted-script:fix-python-env.ps1' "upgraded certifi in $Python (uv)" "certifi $oldCertifi -> $newCertifi" "uv pip install --python $qpy certifi==$oldCertifi"
    Write-Host "Done. certifi $newCertifi. Logged to $RemLog"; exit 0
}

$pkgs = @()
if (-not $skipPip) {
    if ($py310) { $pkgs += 'pip>=26.2.2' } else { Write-Host "NOTE: Python $pyver cannot run the fixed pip (needs 3.10+). Upgrading certifi only." }
}
if ($oldCertifi -and -not $skipCertifi) { $pkgs += 'certifi>=2026.10.19' }
# Exits 4 when this Python's pip is vulnerable and cannot be fixed (the fixed pip needs 3.10+).
function Test-PipStaysOld {
    if (-not $py310 -and -not $skipPip -and $oldPip -and (Test-Old $oldPip '26.2.2')) {
        Write-Host "FAIL: pip $oldPip in $Python stays vulnerable: the fixed pip needs Python 3.10 or later (this is $pyver). Retire this environment, or rebuild it on Python 3.10 or later."
        exit 4
    }
}
if ($pkgs.Count -eq 0) { Show-CondaAdvice; Test-PipStaysOld; Write-Host "Nothing to upgrade in $Python."; exit 0 }

Write-Host "Upgrading in $Python with its own pip: $($pkgs -join ' ')"
Invoke-RemNative $Python (@('-m', 'pip', 'install', '--disable-pip-version-check', '--upgrade') + $pkgs) | Write-Host
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: pip could not install the fixed versions in $Python. Python $pyver may be too old for them: retire this environment, or rebuild it on Python 3.10 or later."
    exit 4
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
Show-CondaAdvice
Test-PipStaysOld
