# Daru installer for Windows (PowerShell 5+).
#
# Installs only what Daru needs to run: a Go toolchain (if missing), the Daru
# binary, and ClickHouse via Docker when available. Optional security scanners
# are not installed here.
#
# Go downloads are verified against the official SHA-256 checksums published
# at https://go.dev/dl/ for Go 1.27.3 before anything is extracted. A
# checksum mismatch fails the install.
#
#   powershell -ExecutionPolicy Bypass -File install.ps1
param(
    [switch]$NoClickHouse
)
$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Say($m)  { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

# Official SHA-256 checksums for Go 1.27.3, from https://go.dev/dl/.
$GoHashes = @{
    "windows-amd64" = "f26081f438319757f8a1b46d7d0b2c5ec7583d4038e485e0aa725cfde7885fff"
    "windows-386"   = "fa6fa87202fdd0421bf1f0daab5192d244840f0728398ee35a56f231d54363be"
    "windows-arm64" = "c507872ff21f8a7cd3c1c217b059c6f7271a4a9d8e692810ef9dd3e1f601197c"
}

function Have-Go {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) { return $false }
    $v = (go version) -replace '.*go(\d+)\.(\d+).*', '$1.$2'
    $parts = $v.Split('.')
    return ([int]$parts[0] -gt 1) -or ([int]$parts[0] -eq 1 -and [int]$parts[1] -ge 27)
}

function Install-Go {
    Say "Installing the Go toolchain"
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id GoLang.Go -e --accept-source-agreements --accept-package-agreements
        if (-not (Have-Go)) { Die "winget reported success but 'go version' still fails. Check the winget output above." }
        return
    }
    $ver = "1.27.3"
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $arch = "arm64" }
    $key = "windows-$arch"
    $want = $GoHashes[$key]
    if (-not $want) { Die "No pinned SHA-256 for Go on $key" }
    $url = "https://go.dev/dl/go$ver.windows-$arch.zip"
    $dest = "$env:USERPROFILE\.daru\go"
    Say "Downloading $url"
    $tmp = "$env:TEMP\go-$ver-windows-$arch.zip"
    Invoke-WebRequest -Uri $url -OutFile $tmp
    $got = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash.ToLower()
    if ($got -ne $want) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue; Die "Go download checksum mismatch: got $got, expected $want. Aborting." }
    Say "Go download checksum verified"
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Expand-Archive -Path $tmp -DestinationPath "$env:USERPROFILE\.daru\go-extract" -Force
    Move-Item "$env:USERPROFILE\.daru\go-extract\go" $dest
    Remove-Item $tmp
    $env:Path = "$dest\bin;$env:Path"
    if (-not (Have-Go)) { Die "Go was extracted but 'go version' still fails." }
}

function Rand-Secret {
    # Cryptographic randomness only. Get-Random is not a CSPRNG.
    $bytes = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

function Wait-ClickHouse {
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:8123/ping" -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
            if ($r.StatusCode -eq 200) { Say "ClickHouse is reachable at 127.0.0.1:8123"; return }
        } catch {}
        Start-Sleep -Seconds 1
    }
    Die "ClickHouse did not become reachable at 127.0.0.1:8123. Check 'docker compose -f deploy/docker-compose.yml logs clickhouse'."
}

Say "Platform: Windows $([Environment]::OSVersion.Version)"

if (Have-Go) { Say "Using $(go version)" } else { Install-Go; Say "Using $(go version)" }

Say "Building Daru"
Push-Location $RepoDir
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags "-s -w" -o daru.exe ./cmd/daru
Pop-Location

$BinDir = "$env:USERPROFILE\.daru\bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Copy-Item "$RepoDir\daru.exe" "$BinDir\daru.exe" -Force
Say "Installed daru.exe to $BinDir"
if ($env:Path -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$env:Path;$BinDir", "User")
    $env:Path = "$env:Path;$BinDir"
    Say "Added $BinDir to your user PATH (new terminals will pick it up)"
}

$EnvFile = "$env:USERPROFILE\.daru\daru.env"
if (-not (Test-Path $EnvFile)) {
    $chPass = Rand-Secret; $adminPass = Rand-Secret
    @"
DARU_CLICKHOUSE_URL=http://localhost:8123
DARU_CLICKHOUSE_DB=daru
DARU_CLICKHOUSE_USER=daru
DARU_CLICKHOUSE_PASSWORD=$chPass
DARU_ADMIN_USER=admin
DARU_ADMIN_PASSWORD=$adminPass
DARU_LISTEN=:8088
"@ | Set-Content -Path $EnvFile -Encoding ASCII
    Say "Wrote config and credentials to $EnvFile"
} else {
    Say "Using existing config at $EnvFile"
    $adminPass = (Get-Content $EnvFile | Select-String 'DARU_ADMIN_PASSWORD=(.*)').Matches.Groups[1].Value
    $chPass = (Get-Content $EnvFile | Select-String 'DARU_CLICKHOUSE_PASSWORD=(.*)').Matches.Groups[1].Value
    if (-not $chPass) { Die "Stored ClickHouse password is empty in $EnvFile; delete the file and re-run to generate new credentials" }
    if (-not $adminPass) { Die "Stored admin password is empty in $EnvFile; delete the file and re-run to generate new credentials" }
    if ($chPass -eq "change-me-clickhouse") { Die "Stored ClickHouse password is still the old default in $EnvFile; rotate it before running Daru" }
    if ($adminPass -eq "change-me-admin") { Die "Stored admin password is still the old default in $EnvFile; rotate it before running Daru" }
}

if (-not $NoClickHouse) {
    if ((Get-Command docker -ErrorAction SilentlyContinue) -and (docker info 2>$null)) {
        Say "Starting ClickHouse with Docker"
        Push-Location "$RepoDir\deploy"
        $env:CLICKHOUSE_PASSWORD = $chPass
        docker compose up -d clickhouse
        Pop-Location
        Wait-ClickHouse
    } else {
        Warn "Docker not found. Install Docker Desktop, or set DARU_CLICKHOUSE_URL to an existing ClickHouse."
    }
}

Write-Host ""
Write-Host "Daru is installed." -ForegroundColor Green
Write-Host "  Start it:  daru serve   (after loading $EnvFile into your environment)"
Write-Host "  Open:      http://localhost:8088"
Write-Host "  Sign in:   admin / $adminPass"
Write-Host ""
