# ============================================================================
# DeepPacketAI Windows Build Script
# Usage:
#   .\build.ps1              -> dev build (with console window)
#   .\build.ps1 -Release     -> release build (no console, for installer)
#   .\build.ps1 -Installer   -> release build + run Inno Setup
#   .\build.ps1 -Clean       -> remove build artifacts
# ============================================================================
param(
    [switch]$Release,
    [switch]$Installer,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot

function Write-Step($msg) {
    Write-Host ""
    Write-Host ">>> $msg" -ForegroundColor Cyan
}

# ---- Clean ----------------------------------------------------------------
if ($Clean) {
    Write-Step "Cleaning build artifacts"
    Remove-Item -Recurse -Force "$Root\bin"                       -ErrorAction SilentlyContinue
    Remove-Item -Force         "$Root\installer\deeppacketai.exe" -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force "$Root\installer\Output"          -ErrorAction SilentlyContinue
    Write-Host "Done." -ForegroundColor Green
    exit 0
}

# ---- Step 1: Build React UI -----------------------------------------------
Write-Step "Building React UI (npm run build)"
Push-Location "$Root\deeppacketai-ui"
try {
    npm install
    if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
} finally {
    Pop-Location
}

# ---- Step 2: Build Go binary -----------------------------------------------
if ($Release -or $Installer) {
    Write-Step "Building Go binary (release - no console window)"
    $OutPath = "$Root\installer\deeppacketai.exe"
    $LdFlags = "-s -w -H windowsgui"
} else {
    Write-Step "Building Go binary (dev - console window)"
    New-Item -ItemType Directory -Force "$Root\bin" | Out-Null
    $OutPath = "$Root\bin\deeppacketai.exe"
    $LdFlags = "-s -w"
}

& go build "-ldflags=$LdFlags" -o $OutPath "$Root\cmd\"
if ($LASTEXITCODE -ne 0) { throw "go build failed" }
Write-Host "Binary: $OutPath" -ForegroundColor Green

# ---- Step 3: Run Inno Setup (only with -Installer) -------------------------
if ($Installer) {
    Write-Step "Building installer with Inno Setup"

    $NpcapPath = "$Root\installer\npcap-installer.exe"
    if (-not (Test-Path $NpcapPath)) {
        Write-Host ""
        Write-Host "ERROR: Npcap installer not found at:" -ForegroundColor Red
        Write-Host "       $NpcapPath" -ForegroundColor Red
        Write-Host ""
        Write-Host "  1. Download Npcap from https://npcap.com/#download" -ForegroundColor Yellow
        Write-Host "  2. Rename it to npcap-installer.exe" -ForegroundColor Yellow
        Write-Host "  3. Place it in the installer\ folder" -ForegroundColor Yellow
        Write-Host "  4. Re-run:  .\build.ps1 -Installer" -ForegroundColor Yellow
        exit 1
    }

    # Try to find ISCC (Inno Setup Compiler) in common locations
    $ISSCPaths = @(
        "ISCC",
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe"
    )
    $ISCC = $null
    foreach ($p in $ISSCPaths) {
        if (Get-Command $p -ErrorAction SilentlyContinue) {
            $ISCC = $p; break
        }
        if (Test-Path $p) {
            $ISCC = $p; break
        }
    }

    if (-not $ISCC) {
        Write-Host ""
        Write-Host "ERROR: Inno Setup not found." -ForegroundColor Red
        Write-Host "  Download from https://jrsoftware.org/isdl.php and install it." -ForegroundColor Yellow
        Write-Host "  Then re-run:  .\build.ps1 -Installer" -ForegroundColor Yellow
        exit 1
    }

    & $ISCC "$Root\installer\deeppacketai.iss"
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed" }

    $SetupExe = "$Root\installer\Output\DeepPacketAI-Setup.exe"
    Write-Host ""
    Write-Host "Installer ready: $SetupExe" -ForegroundColor Green
}

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
