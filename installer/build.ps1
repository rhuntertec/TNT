<#
.SYNOPSIS
    Builds TNT end to end: venv -> dependencies -> tests -> icons -> PyInstaller
    (TNTService.exe + TNT.exe) -> Authenticode signing -> Inno Setup installer -> sign the setup exe.

.DESCRIPTION
    Windows PowerShell 5.1 compatible (no && / || / ternaries). Every step prints a banner
    and the script stops at the first error (non-zero exit code of any tool).

    Outputs:
        dist\TNTService\TNTService.exe   (+ _service\)
        dist\TNT\TNT.exe                 (+ _client\)
        installer\output\TNT-Setup-<version>.exe

    Signing uses installer\sign.ps1, which reads TNT_SIGN_THUMBPRINT or
    TNT_SIGN_PFX + TNT_SIGN_PFX_PASSWORD. When neither is set the build continues
    unsigned with a warning.

.PARAMETER SkipTests
    Do not run pytest.
.PARAMETER SkipSign
    Do not sign the executables / installer (no warning printed).
.PARAMETER SkipInstaller
    Stop after PyInstaller (no ISCC run).
.PARAMETER Python
    Command used to create the venv when .venv does not exist yet (default: "py -3.12", then "python").

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File installer\build.ps1
    powershell -ExecutionPolicy Bypass -File installer\build.ps1 -SkipTests -SkipSign
#>
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipSign,
    [switch]$SkipInstaller,
    [string]$Python = ""
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# --------------------------------------------------------------------------- locations
$Root = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $Root ".venv"
$Py = Join-Path $Venv "Scripts\python.exe"
$Dist = Join-Path $Root "dist"
$BuildDir = Join-Path $Root "build"
$OutputDir = Join-Path $PSScriptRoot "output"
$Iscc = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
$SignScript = Join-Path $PSScriptRoot "sign.ps1"
$ServiceExe = Join-Path $Dist "TNTService\TNTService.exe"
$ClientExe = Join-Path $Dist "TNT\TNT.exe"

$script:StepNo = 0
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

# --------------------------------------------------------------------------- helpers
function Write-Step {
    param([string]$Title)
    $script:StepNo = $script:StepNo + 1
    $line = "=" * 78
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  STEP {0}: {1}   [{2:mm\:ss} elapsed]" -f $script:StepNo, $Title, $Stopwatch.Elapsed) -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Invoke-Native {
    # Runs a native command and throws when its exit code is not zero.
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$What = ""
    )
    if (-not $What) { $What = [System.IO.Path]::GetFileName($Exe) }
    Write-Host (">> " + $Exe + " " + ($Arguments -join " ")) -ForegroundColor DarkGray
    $global:LASTEXITCODE = 0
    & $Exe @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw ("{0} failed with exit code {1}" -f $What, $code)
    }
}

function Find-SignTool {
    # Newest signtool.exe from the Windows 10/11 SDK, else whatever is on PATH.
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

function Get-TntVersion {
    $initPy = Join-Path $Root "tnt\__init__.py"
    $text = Get-Content -Path $initPy -Raw
    $m = [regex]::Match($text, '__version__\s*=\s*"([^"]+)"')
    if (-not $m.Success) { throw "could not read __version__ from $initPy" }
    return $m.Groups[1].Value
}

function Invoke-Sign {
    param([string[]]$Files)
    # Hashtable splat: a [string[]] parameter bound by name must receive the whole array
    # at once (an array splat @("-Path", a, b) leaves the second file unbound).
    $signArgs = @{ Path = @($Files) }
    $tool = Find-SignTool
    if ($tool) {
        Write-Host "signtool: $tool"
        $signArgs.SignTool = $tool
    } else {
        Write-Warning "signtool.exe not found under 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64' or on PATH (install the Windows SDK 'Windows App Certification Kit'/'Signing tools')."
    }
    $global:LASTEXITCODE = 0
    & $SignScript @signArgs
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw ("sign.ps1 failed with exit code {0}" -f $code)
    }
}

# --------------------------------------------------------------------------- pipeline
Push-Location $Root
try {
    $Version = Get-TntVersion
    Write-Host ""
    Write-Host ("TNT build {0}   root={1}" -f $Version, $Root) -ForegroundColor Green
    Write-Host ("options: SkipTests={0} SkipSign={1} SkipInstaller={2}" -f $SkipTests.IsPresent, $SkipSign.IsPresent, $SkipInstaller.IsPresent)

    # ---- 1. venv ---------------------------------------------------------------------
    Write-Step "Python virtual environment (.venv)"
    if (-not (Test-Path $Py)) {
        $launcher = $null
        if ($Python) {
            $launcher = @($Python)
        } elseif (Get-Command py -ErrorAction SilentlyContinue) {
            $launcher = @("py", "-3.12")
        } elseif (Get-Command python -ErrorAction SilentlyContinue) {
            $launcher = @("python")
        } else {
            throw "Python 3.12 was not found (install it from python.org and make sure 'py' or 'python' is on PATH)"
        }
        $exe = $launcher[0]
        $pre = @()
        if ($launcher.Count -gt 1) { $pre = $launcher[1..($launcher.Count - 1)] }
        Invoke-Native -Exe $exe -Arguments ($pre + @("-m", "venv", $Venv)) -What "venv creation"
    }
    if (-not (Test-Path $Py)) { throw "venv python not found at $Py" }
    $pyVersion = (& $Py -c "import sys; print('%d.%d.%d' % sys.version_info[:3])")
    Write-Host "python: $Py ($pyVersion)"
    # A venv derived from a conda interpreter keeps ffi-8.dll / sqlite3.dll / libbz2 / liblzma /
    # libexpat in <base_prefix>\Library\bin. The spec files bundle them explicitly, but putting the
    # folder on PATH as well lets PyInstaller's own dependency walker see them (belt and braces).
    $basePrefix = (& $Py -c "import sys; print(sys.base_prefix)")
    $condaLibBin = Join-Path $basePrefix "Library\bin"
    if ((Test-Path (Join-Path $basePrefix "conda-meta")) -and (Test-Path $condaLibBin)) {
        Write-Host "conda interpreter detected; adding $condaLibBin to PATH for the build"
        $env:PATH = $condaLibBin + ";" + $env:PATH
    }
    $major, $minor = $pyVersion.Split(".")[0, 1]
    if (([int]$major -lt 3) -or (([int]$major -eq 3) -and ([int]$minor -lt 12))) {
        throw "Python 3.12+ is required (found $pyVersion). Delete .venv and re-run with -Python 'py -3.12'."
    }

    # ---- 2. dependencies -------------------------------------------------------------
    Write-Step "pip install -r requirements.txt"
    Invoke-Native -Exe $Py -Arguments @("-m", "pip", "install", "--disable-pip-version-check", "-r", "requirements.txt") -What "pip install"

    # ---- 3. tests --------------------------------------------------------------------
    if ($SkipTests) {
        Write-Step "pytest (skipped: -SkipTests)"
    } else {
        Write-Step "pytest"
        Invoke-Native -Exe $Py -Arguments @("-m", "pytest", "-q") -What "pytest"
    }

    # ---- 4. icons --------------------------------------------------------------------
    Write-Step "Icons (tools\make_icons.py -> assets\tnt.ico, assets\tnt-256.png, ui\assets\logo.png)"
    Invoke-Native -Exe $Py -Arguments @("tools\make_icons.py") -What "make_icons"
    if (-not (Test-Path (Join-Path $Root "assets\tnt.ico"))) { throw "assets\tnt.ico was not generated" }

    # ---- 5. clean --------------------------------------------------------------------
    Write-Step "Clean build\ and dist\ output"
    foreach ($d in @($BuildDir, (Join-Path $Dist "TNTService"), (Join-Path $Dist "TNT"))) {
        if (Test-Path $d) {
            Write-Host "removing $d"
            Remove-Item -Path $d -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # ---- 6. PyInstaller: service -----------------------------------------------------
    Write-Step "PyInstaller: TNTService.exe (installer\tnt_service.spec)"
    Invoke-Native -Exe $Py -Arguments @("-m", "PyInstaller", "--noconfirm", "--clean", "--log-level", "WARN",
        "--distpath", $Dist, "--workpath", $BuildDir, "installer\tnt_service.spec") -What "PyInstaller (service)"
    if (-not (Test-Path $ServiceExe)) { throw "expected $ServiceExe after the PyInstaller run" }
    Write-Host "built $ServiceExe"

    # ---- 7. PyInstaller: client ------------------------------------------------------
    Write-Step "PyInstaller: TNT.exe (installer\tnt_client.spec)"
    Invoke-Native -Exe $Py -Arguments @("-m", "PyInstaller", "--noconfirm", "--clean", "--log-level", "WARN",
        "--distpath", $Dist, "--workpath", $BuildDir, "installer\tnt_client.spec") -What "PyInstaller (client)"
    if (-not (Test-Path $ClientExe)) { throw "expected $ClientExe after the PyInstaller run" }
    Write-Host "built $ClientExe"

    # ---- 7b. self-check the frozen executables ----------------------------------------
    # Runs OUTSIDE the venv / conda PATH so a missing DLL shows up here and not on a customer PC.
    Write-Step "Self-check: TNTService.exe --selfcheck and TNT.exe --selfcheck"
    $savedPath = $env:PATH
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
    try {
        Invoke-Native -Exe $ServiceExe -Arguments @("--selfcheck") -What "TNTService.exe --selfcheck"
        # TNT.exe is windowed: a fatal import error would pop a dialog and hang, so run it with a timeout
        $selfLog = Join-Path $env:LOCALAPPDATA "TNT\selfcheck.log"
        if (Test-Path $selfLog) { Remove-Item $selfLog -Force -ErrorAction SilentlyContinue }
        $proc = Start-Process -FilePath $ClientExe -ArgumentList @("--selfcheck") -PassThru -WindowStyle Hidden
        if (-not $proc.WaitForExit(90000)) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            throw "TNT.exe --selfcheck did not finish within 90 s (a fatal import error dialog is the usual cause)"
        }
        if (Test-Path $selfLog) { Get-Content $selfLog | ForEach-Object { Write-Host ("  " + $_) } }
        if ($proc.ExitCode -ne 0) { throw ("TNT.exe --selfcheck failed with exit code {0} (see {1})" -f $proc.ExitCode, $selfLog) }
    }
    finally {
        $env:PATH = $savedPath
    }

    # ---- 8. sign the executables -----------------------------------------------------
    if ($SkipSign) {
        Write-Step "Code signing (skipped: -SkipSign)"
    } else {
        Write-Step "Code signing: TNTService.exe + TNT.exe (installer\sign.ps1)"
        Invoke-Sign -Files @($ServiceExe, $ClientExe)
    }

    # ---- 9. installer ----------------------------------------------------------------
    $SetupExe = $null
    if ($SkipInstaller) {
        Write-Step "Inno Setup (skipped: -SkipInstaller)"
    } else {
        Write-Step "Inno Setup: installer\tnt.iss"
        if (-not (Test-Path $Iscc)) {
            throw "Inno Setup 6 compiler not found at '$Iscc' (install Inno Setup 6.3 or newer from https://jrsoftware.org/isinfo.php)"
        }
        Invoke-Native -Exe $Iscc -Arguments @("/Qp", ("/DMyAppVersion=" + $Version), "installer\tnt.iss") -What "ISCC"
        $SetupExe = Join-Path $OutputDir ("TNT-Setup-" + $Version + ".exe")
        if (-not (Test-Path $SetupExe)) { throw "expected $SetupExe after the ISCC run" }
        Write-Host "built $SetupExe"

        # ---- 10. sign the installer --------------------------------------------------
        if ($SkipSign) {
            Write-Step "Sign installer (skipped: -SkipSign)"
        } else {
            Write-Step "Code signing: setup exe"
            Invoke-Sign -Files @($SetupExe)
        }

        # ---- 11. SHA-256 checksum (the auto-updater verifies the download against this) ----
        # Hash the FINAL exe (after signing). Publish this .sha256 as a release asset next to the exe;
        # tnt.updater refuses to install a download whose SHA-256 does not match it.
        Write-Step "SHA-256 checksum: setup exe"
        $Sha256File = $SetupExe + ".sha256"
        $Hash = (Get-FileHash -Algorithm SHA256 -Path $SetupExe).Hash.ToLower()
        Set-Content -Path $Sha256File -Value ("{0}  {1}" -f $Hash, (Split-Path -Leaf $SetupExe)) -Encoding ascii -NoNewline
        Write-Host ("wrote {0} ({1})" -f $Sha256File, $Hash)
    }

    # ---- summary ---------------------------------------------------------------------
    Write-Step "Done"
    Write-Host ("TNT {0} built in {1:mm\:ss}" -f $Version, $Stopwatch.Elapsed) -ForegroundColor Green
    Write-Host ("  service : {0}" -f $ServiceExe)
    Write-Host ("  client  : {0}" -f $ClientExe)
    if ($SetupExe) { Write-Host ("  setup   : {0}" -f $SetupExe) }
    if ($SetupExe -and (Test-Path ($SetupExe + ".sha256"))) { Write-Host ("  sha256  : {0}" -f ($SetupExe + ".sha256")) }
    if ($SkipSign) {
        Write-Warning "Unsigned build: Windows SmartScreen will warn when the installer is run. Configure TNT_SIGN_THUMBPRINT or TNT_SIGN_PFX for release builds."
    }
    exit 0
}
catch {
    Write-Host ""
    Write-Host ("BUILD FAILED at step {0}: {1}" -f $script:StepNo, $_.Exception.Message) -ForegroundColor Red
    if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
    exit 1
}
finally {
    Pop-Location
}
