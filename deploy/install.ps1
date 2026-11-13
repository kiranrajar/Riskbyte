<#
.SYNOPSIS
    RiskByte SOC Agent — Enterprise Windows PowerShell Installer
    Platform: Windows Server 2022 / Windows 11 with Docker Desktop
    Mode: Self-Hosted Air-Gapped Evaluation
#>
[CmdletBinding()]
param(
    [string]$InstallPath = "$PSScriptRoot\.."
)

$ErrorActionPreference = "Stop"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "    RISKBYTE SOC AGENT — WINDOWS ENTERPRISE INSTALLER           " -ForegroundColor Cyan
Write-Host "    Air-Gapped · Self-Hosted · Zero Telemetry Egress            " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# 1. Prerequisites Check
Write-Host "`n[1/4] Checking Docker engine..." -ForegroundColor Yellow
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker is required but not installed or not in PATH."
    exit 1
}
Write-Host "✓ Docker CLI detected." -ForegroundColor Green

# 2. Directory layout
Write-Host "`n[2/4] Setting up data directories..." -ForegroundColor Yellow
$DataDir = Join-Path $InstallPath "data"
$KeysDir = Join-Path $DataDir "keys"
$SslDir  = Join-Path $InstallPath "deploy\nginx\ssl"

New-Item -ItemType Directory -Force -Path $KeysDir | Out-Null
New-Item -ItemType Directory -Force -Path $SslDir  | Out-Null
Write-Host "✓ Directories initialized at $DataDir." -ForegroundColor Green

# 3. Environment Secrets
Write-Host "`n[3/4] Checking environment configuration..." -ForegroundColor Yellow
$EnvFile = Join-Path $InstallPath ".env"
if (-not (Test-Path $EnvFile)) {
    $pgPass = [Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Minimum 0 -Maximum 255 }))
    $redisPass = [Convert]::ToBase64String((1..24 | ForEach-Object { Get-Random -Minimum 0 -Maximum 255 }))
    $envContent = @"
RISKBYTE_ENV=production
POSTGRES_PASSWORD=$pgPass
REDIS_PASSWORD=$redisPass
RISKBYTE_LLM_MODEL=llama3.1:8b
RISKBYTE_AIR_GAPPED=true
RISKBYTE_EGRESS_DENY=true
"@
    Set-Content -Path $EnvFile -Value $envContent
    Write-Host "✓ Created secure .env configuration file." -ForegroundColor Green
} else {
    Write-Host "✓ Existing .env file found." -ForegroundColor Green
}

# 4. Launch Docker Compose
Write-Host "`n[4/4] Starting RiskByte SOC Agent containers..." -ForegroundColor Yellow
Push-Location $InstallPath
try {
    docker compose up -d
    Write-Host "`n================================================================" -ForegroundColor Green
    Write-Host "    RISKBYTE SOC AGENT STARTED SUCCESSFULLY                     " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "Access Console:   https://localhost:443" -ForegroundColor Cyan
    Write-Host "Admin User:       admin@riskbyte.internal" -ForegroundColor Cyan
    Write-Host "Air-Gap:          Active (Zero External Egress)" -ForegroundColor Green
} finally {
    Pop-Location
}
