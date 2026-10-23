# Shared helpers for the remediate-emudhra-on-my-machine PowerShell scripts. Dot-source, don't run.
# Windows PowerShell 5.1 compatible.

$RemStateDir = if ($env:REMEDIATE_EMUDHRA_STATE_DIR) { $env:REMEDIATE_EMUDHRA_STATE_DIR } else { Join-Path $env:USERPROFILE '.remediate-emudhra' }
$RemBackupDir = Join-Path $RemStateDir 'backups'
$RemLog = Join-Path $RemStateDir 'actions.log'
$RemIssues = 'https://github.com/adamzr/remediate-emudhra-on-my-machine/issues'

# Test hosts from https://emudhra.we-have-a-problem.com/ that serve compromised chains.
$RemBadEmsign = 'https://dv-g3b-emudhra.we-have-a-problem.com/'
$RemBadAaa = 'https://dv-g3b-aaa-emudhra.we-have-a-problem.com/'
$RemControl = 'https://github.com/'
$RemBadEmsignNoCt = 'https://dv-g3b-noct-emudhra.we-have-a-problem.com/'
$RemBadAaaNoCt = 'https://dv-g3b-aaa-noct-emudhra.we-have-a-problem.com/'

# SHA-256 fingerprints of AAA Certificate Services and emSign ECC Root CA - G3 (roots.json on the incident site).
$RemBadRootFps = @(
    'D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4',
    '86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B'
)

# The 16 compromised intermediates from impacted-intermediates.json, pinned by the SHA-256 of each certificate's
# DER bytes. Pinning the certificates rather than the file keeps the check valid when git converts line endings.
$RemManifest = Join-Path $PSScriptRoot '..\assets\impacted-intermediates.json'
$RemIntermediateSha256 = @(
    '42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493', '45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE',
    '98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B', '5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699',
    'E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838', '579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512',
    '0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19', '62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72',
    'CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F', '7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489',
    '432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3', 'FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F',
    '9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4', 'A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8',
    '4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1', '84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD'
)

$script:RemBackupSeq = 0
function Initialize-RemState { New-Item -ItemType Directory -Force -Path $RemBackupDir | Out-Null; if (-not (Test-Path $RemLog)) { New-Item -ItemType File -Path $RemLog | Out-Null } }

# Write-RemLog SOURCE ACTION DETAIL UNDO. SOURCE is "vetted-script:<name>", "vetted-recipe", or "improvised".
# Undo entries are replayed newest first.
function Write-RemLog($source, $action, $detail, $undo) {
    Initialize-RemState
    $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    Add-Content -Path $RemLog -Value "$ts`t$source`t$action`t$detail`tundo: $undo"
}

# ConvertTo-RemQuoted VALUE -> a single-quoted PowerShell literal, safe to paste into an undo command.
function ConvertTo-RemQuoted($value) { "'" + ($value -replace "'", "''") + "'" }

# Backup-RemFile PATH -> backup path (copies the file; records absence for a missing file).
function Backup-RemFile($path) {
    Initialize-RemState
    $script:RemBackupSeq++
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') + "-$PID-$($script:RemBackupSeq)"
    $dest = Join-Path $RemBackupDir ($stamp + '_' + ($path -replace '[:\\/ ]', '_'))
    if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination $dest -Force; return $dest }
    Set-Content -Path "$dest.absent" -Value "$path did not exist"; return "$dest.absent"
}

# Get-RemIntermediates -> X509Certificate2 objects for the 16 compromised intermediates. Refuses anything unexpected.
function Get-RemIntermediates {
    $items = Get-Content -LiteralPath $RemManifest -Raw -Encoding UTF8 | ConvertFrom-Json
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $certs = @(); $seen = @{}
    foreach ($i in $items) {
        $b64 = $i.pem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', ''
        $der = [Convert]::FromBase64String($b64)
        $h = -join ($sha.ComputeHash($der) | ForEach-Object { $_.ToString('X2') })
        if ($RemIntermediateSha256 -notcontains $h) { throw ('Unexpected certificate in the manifest ({0}). Refusing to continue; report it at {1}' -f $h, $RemIssues) }
        if (-not $seen.ContainsKey($h)) { $seen[$h] = $true; $certs += New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der) }
    }
    if ($seen.Count -ne $RemIntermediateSha256.Count) {
        throw ('Expected all {0} pinned certificates in the manifest, found {1} distinct. Refusing to continue; report it at {2}' -f $RemIntermediateSha256.Count, $seen.Count, $RemIssues)
    }
    return $certs
}

function Get-RemJdkHomes {
    $cands = New-Object System.Collections.Generic.List[string]
    if ($env:JAVA_HOME) { $cands.Add($env:JAVA_HOME) }
    $roots = @("$env:ProgramFiles\Java", "$env:ProgramFiles\Eclipse Adoptium", "$env:ProgramFiles\Microsoft", "$env:ProgramFiles\Zulu",
               "$env:ProgramFiles\Amazon Corretto", "$env:ProgramFiles\BellSoft", "$env:USERPROFILE\.jdks", "${env:ProgramFiles(x86)}\Java")
    foreach ($r in $roots) {
        if ($r -and (Test-Path $r)) { Get-ChildItem $r -Directory -ErrorAction SilentlyContinue | ForEach-Object { $cands.Add($_.FullName) } }
    }
    $cands | Where-Object { Test-Path (Join-Path $_ 'bin\keytool.exe') } | ForEach-Object { (Resolve-Path $_).Path } | Sort-Object -Unique
}

function Get-RemCacerts($jdk) {
    foreach ($c in @((Join-Path $jdk 'lib\security\cacerts'), (Join-Path $jdk 'jre\lib\security\cacerts'))) { if (Test-Path $c) { return $c } }
    return $null
}

# Invoke-RemNative EXE ARGS -> stdout lines. keytool writes warnings to stderr, which Windows PowerShell 5.1 turns
# into terminating errors under $ErrorActionPreference = 'Stop'; this keeps them harmless. Sets $LASTEXITCODE.
function Invoke-RemNative($exe, [string[]]$arguments) {
    $saved = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $exe @arguments 2>$null } finally { $ErrorActionPreference = $saved }
}

# Invoke-RemCapture EXE ARGS -> stdout and stderr together as one string. Sets $LASTEXITCODE.
function Invoke-RemCapture($exe, [string[]]$arguments) {
    $saved = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { ((& $exe @arguments 2>&1) | ForEach-Object { "$_" }) -join "`n" } finally { $ErrorActionPreference = $saved }
}

# Fixed JDK releases, per the incident site. Shown to users; versions are not compared, because the live
# test and blocked.certs decide.
$RemJdkFixed = '27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, or 8u511'

function Get-RemJdkVersion($jdk) {
    $rel = Join-Path $jdk 'release'
    if (Test-Path $rel) { foreach ($l in Get-Content $rel) { if ($l -match '^JAVA_VERSION="(.+)"$') { return $Matches[1] } } }
    return ''
}

# Get-RemJdkBlockedCount JDK -> how many of the 16 compromised intermediates the JDK's blocked.certs
# (blacklisted.certs on JDK 8) lists. A patched JDK blocks them there.
function Get-RemJdkBlockedCount($jdk) {
    foreach ($f in @((Join-Path $jdk 'lib\security\blocked.certs'), (Join-Path $jdk 'jre\lib\security\blacklisted.certs'), (Join-Path $jdk 'lib\security\blacklisted.certs'))) {
        if (-not (Test-Path $f)) { continue }
        $text = ((Get-Content $f -Raw) -replace ':', '').ToUpperInvariant()
        return @($RemIntermediateSha256 | Where-Object { $text.Contains($_) }).Count
    }
    return 0
}

# Invoke-RemJavaProbe JDK URL... -> one result per URL (trusted, rejected, or error) from a live TLS connection
# made by that JDK. Returns nothing when the JDK cannot run a single-file program (JDK 10 and older).
function Invoke-RemJavaProbe($jdk, [string[]]$urls) {
    $v = Get-RemJdkVersion $jdk
    $major = 0; if ($v -match '^1\.(\d+)') { $major = [int]$Matches[1] } elseif ($v -match '^(\d+)') { $major = [int]$Matches[1] }
    $java = Join-Path $jdk 'bin\java.exe'
    if ($major -lt 11 -or -not (Test-Path $java)) { return @() }
    $dir = Join-Path $env:TEMP ('remediate-emudhra-java-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $dir | Out-Null
    $src = Join-Path $dir 'RemProbe.java'
    @'
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
'@ | Set-Content -Path $src -Encoding ASCII
    try { return @(Invoke-RemNative $java (@('-Djava.net.useSystemProxies=true', $src) + $urls)) } finally { Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue }
}

# Get-RemJdkVerdict JDK NET -> @{ Pass = $true/$false; Detail = '...' }. A live test decides when it can run
# (network, JDK 11+); otherwise a JDK is safe when blocked.certs lists all 16 intermediates (a patched JDK,
# or a manual block) or when cacerts no longer has the two affected roots (the admin script's fix).
function Get-RemJdkVerdict($jdk, $net) {
    $v = Get-RemJdkVersion $jdk
    if ($net) {
        $r = (Invoke-RemJavaProbe $jdk @($RemControl, $RemBadEmsign, $RemBadAaa)) -join ' '
        if ($r -eq 'trusted rejected rejected') { return @{ Pass = $true; Detail = "Java $v rejects both test hosts (live test)" } }
        if ($r -match '^trusted .*trusted') { return @{ Pass = $false; Detail = "Java $v TRUSTS a compromised chain (live test). Upgrade to $RemJdkFixed (preferred), or run the admin script" } }
    }
    if ((Get-RemJdkBlockedCount $jdk) -ge 16) { return @{ Pass = $true; Detail = "Java $v blocks all 16 compromised intermediates in blocked.certs" } }
    $c = Get-RemCacerts $jdk
    if (-not $c) { return @{ Pass = $true; Detail = 'no cacerts file' } }
    $bad = @(Get-RemBadAliases (Join-Path $jdk 'bin\keytool.exe') $c)
    if ($bad.Count -eq 0) { return @{ Pass = $true; Detail = "Java ${v}: affected roots absent from cacerts" } }
    return @{ Pass = $false; Detail = "Java ${v}: cacerts still trusts $($bad -join ', '). Upgrade to $RemJdkFixed (preferred), or run the admin script" }
}

# Get-RemBadAliases KEYTOOL CACERTS -> aliases of the two affected roots present in the keystore.
function Get-RemBadAliases($keytool, $cacerts) {
    $alias = $null; $found = @()
    Invoke-RemNative $keytool @('-list', '-v', '-keystore', $cacerts, '-storepass', 'changeit') | ForEach-Object {
        if ($_ -match '^Alias name: (.+)$') { $alias = $Matches[1] }
        elseif ($_ -match '^\s*SHA256:\s*([0-9A-F:]+)\s*$' -and $RemBadRootFps -contains $Matches[1]) { $found += $alias }
    }
    return $found
}
