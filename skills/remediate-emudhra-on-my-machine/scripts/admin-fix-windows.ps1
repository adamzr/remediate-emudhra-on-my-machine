# Admin-level eMudhra remediation for Windows. Run it yourself from PowerShell opened with "Run as administrator".
# Safe to run more than once. Every change is logged with an undo command in
# %USERPROFILE%\.remediate-emudhra\actions.log, and files are backed up first.
#
#   1. Adds the 16 compromised intermediates to LocalMachine\Disallowed (Untrusted Certificates), the same
#      hash-pinned certificate set as the incident site's Block-EmudhraCompromisedCA.ps1. It does not touch
#      Trusted Root Certification Authorities, so legitimate sites keep working.
#   2. Removes AAA Certificate Services and emSign ECC Root CA - G3 from the cacerts of each JDK found
#      (no fixed JDK exists yet).
#   3. Reports, without changing, a policy that disables automatic root updates.
#
# Usage: powershell.exe -NoProfile -ExecutionPolicy Bypass -File admin-fix-windows.ps1 [-DryRun]
#Requires -Version 5.1
param([switch]$DryRun)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib.ps1')
$src = 'vetted-script:admin-fix-windows.ps1'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $DryRun) {
    Write-Host 'This window is not running as administrator.'
    Write-Host 'Close it, open the Start menu, type PowerShell, right-click Windows PowerShell, choose "Run as administrator", and run the command again.'
    exit 2
}
Initialize-RemState
Write-Host "Action log: $RemLog"

Write-Host '== 1. Block the 16 compromised intermediates (LocalMachine\Disallowed)'
$certs = Get-RemIntermediates
$have = @(Get-ChildItem Cert:\LocalMachine\Disallowed | Select-Object -ExpandProperty Thumbprint)
foreach ($c in $certs) {
    $label = $c.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if ($have -contains $c.Thumbprint) { Write-Host "   already blocked: $label ($($c.Thumbprint))"; continue }
    if ($DryRun) { Write-Host "   would block: $label ($($c.Thumbprint))"; continue }
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Disallowed', 'LocalMachine')
    $store.Open('ReadWrite'); $store.Add($c); $store.Close()
    Write-RemLog $src "blocked $label" "LocalMachine\Disallowed $($c.Thumbprint)" "Remove-Item -Path Cert:\LocalMachine\Disallowed\$($c.Thumbprint)   (in an administrator PowerShell)"
    Write-Host "   blocked: $label"
}

Write-Host '== 2. JDK cacerts (no fixed JDK yet: https://ops.java/emudhra)'
foreach ($j in (Get-RemJdkHomes)) {
    $cac = Get-RemCacerts $j; if (-not $cac) { continue }
    $k = Join-Path $j 'bin\keytool.exe'
    $bad = @(Get-RemBadAliases $k $cac)
    if ($bad.Count -eq 0) { Write-Host "   ${j}: already fixed"; continue }
    if ($DryRun) { Write-Host "   would remove from ${cac}: $($bad -join ', ')"; continue }
    $bak = Backup-RemFile $cac
    $removed = @()
    foreach ($a in $bad) {
        Invoke-RemNative $k @('-delete', '-keystore', $cac, '-storepass', 'changeit', '-alias', $a) | Out-Null
        if ($LASTEXITCODE -eq 0) { $removed += $a } else { Write-Host "   ${j}: keytool could not remove '$a' (exit $LASTEXITCODE)" }
    }
    if ($removed.Count -gt 0) {
        Write-RemLog $src 'removed affected roots from JDK cacerts' "${cac}: $($removed -join ', ')" "Copy-Item -LiteralPath $(ConvertTo-RemQuoted $bak) -Destination $(ConvertTo-RemQuoted $cac) -Force   (in an administrator PowerShell)"
        Write-Host "   ${j}: removed $($removed -join ', ')"
    }
}
Write-Host '   Upgrading a JDK can bring the roots back; run this script again after JDK upgrades.'

Write-Host '== 3. Automatic root certificate updates'
$pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' -ErrorAction SilentlyContinue
if ($pol -and $pol.DisableRootAutoUpdate -eq 1) {
    Write-Host '   Disabled by policy. Step 1 covers this incident; ask whoever manages this computer before changing the policy.'
} else { Write-Host '   Enabled (Microsoft delivers its own block through this channel).' }

Write-Host ''
Write-Host "Done. Go back to your AI agent and say 'done' so it re-runs the check."
