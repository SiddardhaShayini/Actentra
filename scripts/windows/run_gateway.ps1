# Actentra Windows Service / Background Daemon Runner
# Provides automatic restart and health monitoring for Actentra HTTP Gateway.

param(
    [string]$PolicyPath = "policies/examples/starter.yaml",
    [int]$Port = 8080,
    [string]$HostAddress = "127.0.0.1",
    [int]$MaxRestarts = 10,
    [int]$RestartDelaySeconds = 3
)

$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Actentra HTTP Gateway & Operator Console Daemon Runner" -ForegroundColor Cyan
Write-Host " Host: http://${HostAddress}:${Port}" -ForegroundColor Cyan
Write-Host " Policy: $PolicyPath" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$restartCount = 0

while ($restartCount -lt $MaxRestarts) {
    Write-Host "[$(Get-Date -Format 's')] Starting Actentra Gateway..." -ForegroundColor Green
    
    $process = Start-Process -FilePath ".venv\Scripts\actentra.exe" `
        -ArgumentList "serve", "--policy", $PolicyPath, "--host", $HostAddress, "--port", $Port `
        -NoNewWindow -PassThru

    Start-Sleep -Seconds 2

    # Health check probe
    try {
        $healthUri = "http://${HostAddress}:${Port}/health"
        $resp = Invoke-RestMethod -Uri $healthUri -Method Get -TimeoutSec 3
        if ($resp.status -eq "ok") {
            Write-Host "[$(Get-Date -Format 's')] Health probe SUCCESS: Gateway active (policy=$($resp.policy_id))" -ForegroundColor Green
        }
    } catch {
        Write-Warning "[$(Get-Date -Format 's')] Initial health probe failed: $_"
    }

    # Wait for process exit
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    $restartCount++

    Write-Warning "[$(Get-Date -Format 's')] Gateway exited with code $exitCode. (Restart $restartCount/$MaxRestarts)"
    Start-Sleep -Seconds $RestartDelaySeconds
}

Write-Error "Max restart count ($MaxRestarts) reached. Gateway stopped."
