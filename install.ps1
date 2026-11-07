# Daru installer for Windows (PowerShell 5+).
#
# Installs only what Daru needs to run: a Go toolchain (if missing), the Daru
# binary, and ClickHouse via Docker when available. Optional security scanners
# are not installed here.
#
#   powershell -ExecutionPolicy Bypass -File install.ps1
param(
    [switch]$NoClickHouse
)
$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Say($m)  { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }

function Have-Go {
    if (-not (Get-Command go -ErrorAction SilentlyContinue)) { return $false }
    $v = (go version) -replace '.*go(\d+)\.(\d+).*', '$1.$2'
    $parts = $v.Split('.')
    return ([int]$parts[0] -gt 1) -or ([int]$parts[0] -eq 1 -and [int]$parts[1] -ge 23)
}

function Install-Go {
    Say "Installing the Go toolchain"
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id GoLang.Go -e --accept-source-agreements --accept-package-agreements
        return
    }
    $ver = "1.25.3"
    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    $url = "https://go.dev/dl/go$ver.windows-$arch.zip"
    $dest = "$env:USERPROFILE\.daru\go"
    Say "Downloading $url"
    $tmp = "$env:TEMP\go.zip"
    Invoke-WebRequest -Uri $url -OutFile $tmp
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Expand-Archive -Path $tmp -DestinationPath "$env:USERPROFILE\.daru\go-extract" -Force
    Move-Item "$env:USERPROFILE\.daru\go-extract\go" $dest
    Remove-Item $tmp
    $env:Path = "$dest\bin;$env:Path"
}

function Rand-Secret {
    -join ((48..57) + (97..102) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
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
if ($env:Path -notlike "*$BinDir*") { Warn "Add $BinDir to your PATH" }

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
}

if (-not $NoClickHouse) {
    if ((Get-Command docker -ErrorAction SilentlyContinue) -and (docker info 2>$null)) {
        Say "Starting ClickHouse with Docker"
        Push-Location "$RepoDir\deploy"
        $env:CLICKHOUSE_PASSWORD = $chPass
        docker compose up -d clickhouse
        Pop-Location
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
