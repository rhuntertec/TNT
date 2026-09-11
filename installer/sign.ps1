<#
.SYNOPSIS
    Authenticode-signs TNT executables / the setup exe with signtool.

.DESCRIPTION
    Windows PowerShell 5.1 compatible. Signs every file in -Path with

        signtool sign /fd SHA256 /td SHA256 /tr http://timestamp.digicert.com
                      /d "TNT - TEC Network Tool" /du https://totalelectronics.com  <cert selection>  <file>

    and verifies the result with "signtool verify /pa". The certificate comes from
    the environment:

        TNT_SIGN_THUMBPRINT     SHA-1 thumbprint of a code-signing certificate in the Windows
                                certificate store (CurrentUser\My or LocalMachine\My), e.g. one
                                living on a hardware token / smart card.
        TNT_SIGN_PFX            path to a .pfx file, with
        TNT_SIGN_PFX_PASSWORD   its password (may be empty).

    When neither is configured the script prints a clear notice and exits 0 so an
    unsigned development build still completes (-Strict turns that into exit 2).
    Exit code 1 = signing was attempted and failed.

    IMPORTANT: a TLS/SSL certificate for totalelectronics.com CANNOT sign code. You need
    an Authenticode *code-signing* certificate (OV or EV) issued to Total Electronics by a
    public CA (DigiCert, Sectigo, GlobalSign, ...). EV certificates give immediate
    SmartScreen reputation; OV certificates build reputation over time.

.PARAMETER Path
    One or more files to sign (.exe, .dll, .msi).
.PARAMETER SignTool
    Full path to signtool.exe. Auto-detected from the Windows SDK when omitted.
.PARAMETER Strict
    Exit 2 instead of 0 when no certificate is configured.

.EXAMPLE
    $env:TNT_SIGN_THUMBPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
    powershell -ExecutionPolicy Bypass -File installer\sign.ps1 -Path dist\TNT\TNT.exe, dist\TNTService\TNTService.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)][string[]]$Path,
    [string]$SignTool = "",
    [string]$Description = "TNT - TEC Network Tool",
    [string]$DescriptionUrl = "https://totalelectronics.com",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [int]$Retries = 3,
    [switch]$Strict
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

function Find-SignTool {
    $pattern = "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe"
    $candidates = @(Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue)
    if ($candidates.Count -gt 0) {
        $best = $candidates | Sort-Object -Property @{ Expression = {
                $v = $null
                if ([version]::TryParse($_.Directory.Parent.Name, [ref]$v)) { $v } else { [version]"0.0" }
            } } -Descending | Select-Object -First 1
        return $best.FullName
    }
    $cmd = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Write-NoCertNotice {
    Write-Host ""
    Write-Host "NOTICE: no code-signing certificate is configured - the files were NOT signed." -ForegroundColor Yellow
    Write-Host "  Set one of:" -ForegroundColor Yellow
    Write-Host "    TNT_SIGN_THUMBPRINT   = SHA-1 thumbprint of an Authenticode code-signing cert in the Windows store" -ForegroundColor Yellow
    Write-Host "    TNT_SIGN_PFX          = path to a .pfx  (+ TNT_SIGN_PFX_PASSWORD)" -ForegroundColor Yellow
    Write-Host "  A TLS certificate for totalelectronics.com cannot sign code. An Authenticode code-signing" -ForegroundColor Yellow
    Write-Host "  certificate (OV or EV) issued to Total Electronics is required for a trusted release build." -ForegroundColor Yellow
    Write-Host ""
}

# --------------------------------------------------------------------------- inputs
$files = @()
foreach ($p in $Path) {
    if (-not (Test-Path -Path $p -PathType Leaf)) {
        Write-Host "sign.ps1: file not found: $p" -ForegroundColor Red
        exit 1
    }
    $files += (Resolve-Path -Path $p).Path
}

$thumbprint = $env:TNT_SIGN_THUMBPRINT
$pfx = $env:TNT_SIGN_PFX
$pfxPassword = $env:TNT_SIGN_PFX_PASSWORD
if ($thumbprint) { $thumbprint = ($thumbprint -replace "[^0-9A-Fa-f]", "").ToUpperInvariant() }

if ((-not $thumbprint) -and (-not $pfx)) {
    Write-NoCertNotice
    if ($Strict) { exit 2 }
    exit 0
}

if (-not $SignTool) { $SignTool = Find-SignTool }
if ((-not $SignTool) -or (-not (Test-Path $SignTool))) {
    Write-Host "sign.ps1: signtool.exe not found. Install the Windows 10/11 SDK (signing tools) or pass -SignTool <path>." -ForegroundColor Red
    exit 1
}
Write-Host "signtool: $SignTool"

# --------------------------------------------------------------------------- certificate selection
$certArgs = @()
$certLabel = ""
if ($thumbprint) {
    if ($thumbprint.Length -ne 40) {
        Write-Host "sign.ps1: TNT_SIGN_THUMBPRINT must be a 40-hex-digit SHA-1 thumbprint" -ForegroundColor Red
        exit 1
    }
    $inUser = @(Get-ChildItem -Path "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumbprint })
    $inMachine = @(Get-ChildItem -Path "Cert:\LocalMachine\My" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $thumbprint })
    if ($inUser.Count -gt 0) {
        $certArgs = @("/sha1", $thumbprint)
        $certLabel = "store cert " + $inUser[0].Subject + " (CurrentUser\My)"
    } elseif ($inMachine.Count -gt 0) {
        $certArgs = @("/sm", "/sha1", $thumbprint)
        $certLabel = "store cert " + $inMachine[0].Subject + " (LocalMachine\My)"
    } else {
        Write-Host "sign.ps1: no certificate with thumbprint $thumbprint in CurrentUser\My or LocalMachine\My" -ForegroundColor Red
        exit 1
    }
} else {
    if (-not (Test-Path -Path $pfx -PathType Leaf)) {
        Write-Host "sign.ps1: TNT_SIGN_PFX file not found: $pfx" -ForegroundColor Red
        exit 1
    }
    $certArgs = @("/f", (Resolve-Path -Path $pfx).Path)
    if ($pfxPassword) { $certArgs += @("/p", $pfxPassword) }
    $certLabel = "PFX " + $pfx
}
Write-Host "certificate: $certLabel"

# --------------------------------------------------------------------------- sign + verify
$failed = 0
foreach ($file in $files) {
    $signArgs = @("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $TimestampUrl,
                  "/d", $Description, "/du", $DescriptionUrl) + $certArgs + @($file)
    $shown = ($signArgs | ForEach-Object { if ($pfxPassword -and ($_ -eq $pfxPassword)) { "********" } else { $_ } }) -join " "
    Write-Host ">> signtool $shown" -ForegroundColor DarkGray

    $ok = $false
    for ($attempt = 1; $attempt -le [Math]::Max(1, $Retries); $attempt++) {
        $global:LASTEXITCODE = 0
        & $SignTool @signArgs
        if ($LASTEXITCODE -eq 0) {
            $ok = $true
            break
        }
        Write-Warning ("signing attempt {0}/{1} failed (exit {2}) - timestamp servers are flaky, retrying in 5 s" -f $attempt, $Retries, $LASTEXITCODE)
        Start-Sleep -Seconds 5
    }
    if (-not $ok) {
        Write-Host "sign.ps1: could not sign $file" -ForegroundColor Red
        $failed++
        continue
    }

    $global:LASTEXITCODE = 0
    & $SignTool verify /pa /q $file
    if ($LASTEXITCODE -ne 0) {
        Write-Host "sign.ps1: signature verification failed for $file (exit $LASTEXITCODE)" -ForegroundColor Red
        $failed++
        continue
    }
    Write-Host ("signed   {0}" -f $file) -ForegroundColor Green
}

if ($failed -gt 0) {
    Write-Host ("sign.ps1: {0} file(s) failed" -f $failed) -ForegroundColor Red
    exit 1
}
exit 0
