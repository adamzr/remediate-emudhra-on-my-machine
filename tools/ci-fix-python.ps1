# CI test of scripts/fix-python-env.ps1 against throwaway virtualenvs on Windows (needs Python with venv,
# and network access to PyPI). Never touches an existing environment. Windows PowerShell 5.1 compatible.
#
#   1. a plain venv with an old pip and certifi: both are upgraded and logged
#   2. a venv dressed as a conda environment whose certifi says conda installed it (INSTALLER = conda):
#      the script leaves it alone, prints a conda install command, and exits 3
#
# Usage: powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\ci-fix-python.ps1
$ErrorActionPreference = 'Stop'
$fix = Join-Path $PSScriptRoot '..\skills\remediate-emudhra-on-my-machine\scripts\fix-python-env.ps1'
$t = Join-Path $env:TEMP ("ci-fix-python-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $t | Out-Null
$env:REMEDIATE_EMUDHRA_STATE_DIR = Join-Path $t 'state'
function Get-Ver($py, $mod) { (& $py -c "import $mod; print($mod.__version__)").Trim() }
function Fail($msg) { Write-Output "::error::$msg"; exit 1 }

Write-Output '== 1. plain venv'
& python -m venv (Join-Path $t 'plain')
$py = Join-Path $t 'plain\Scripts\python.exe'
& $py -m pip install -q --disable-pip-version-check 'pip==25.2' 'certifi==2024.8.30'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fix -Python $py
if ($LASTEXITCODE -ne 0) { Fail "fix-python-env.ps1 exited $LASTEXITCODE" }
if ((Get-Ver $py 'certifi') -ne '2026.10.19') { Fail 'certifi was not upgraded' }
if (-not (Select-String -Path (Join-Path $env:REMEDIATE_EMUDHRA_STATE_DIR 'actions.log') -Pattern 'certifi 2024.08.30 -> 2026.10.19' -Quiet)) { Fail 'the upgrade was not logged' }

Write-Output '== 2. conda-owned certifi'
& python -m venv (Join-Path $t 'conda')
$py = Join-Path $t 'conda\Scripts\python.exe'
& $py -m pip install -q --disable-pip-version-check 'certifi==2024.8.30'
New-Item -ItemType Directory -Path (Join-Path $t 'conda\conda-meta') | Out-Null
Get-ChildItem (Join-Path $t 'conda\Lib\site-packages') -Directory -Filter 'certifi-*.dist-info' | ForEach-Object { Set-Content -Path (Join-Path $_.FullName 'INSTALLER') -Value 'conda' }
$out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fix -Python $py
$rc = $LASTEXITCODE
$out | Write-Output
if ($rc -ne 3) { Fail "expected exit 3, got $rc" }
if (-not ($out -match "conda install -p .*certifi>=2026\.10\.19")) { Fail 'no conda install advice' }
if ((Get-Ver $py 'certifi') -ne '2024.08.30') { Fail 'pip touched a conda-owned certifi' }

Remove-Item -Recurse -Force $t
Write-Output 'OK: fix-python-env.ps1 upgrades pip-owned packages, and leaves conda-owned ones to conda'
