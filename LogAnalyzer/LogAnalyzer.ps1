# LogAnalyzer.ps1 - TraceForge Log Analyzer Launcher

# Absolute path to trusted config
$trustedConfigPath = Join-Path -Path (Join-Path -Path $PSScriptRoot "..\Configs") "trusted_config.json"

# Import the main LogAnalyzer module
Import-Module "$PSScriptRoot\LogAnalyzer.psm1" -Force

function Select-ScanFolder {
    param($OutputRoot)

    if (-not (Test-Path $OutputRoot)) {
        Write-Host "No output directory found at $OutputRoot" -ForegroundColor Red
        return $null
    }

    $folders = Get-ChildItem -Path $OutputRoot -Directory | Sort-Object LastWriteTime -Descending
    if ($folders.Count -eq 0) {
        Write-Host "No scan folders found in $OutputRoot" -ForegroundColor Yellow
        return $null
    }

    Write-Host "`nAvailable scan folders:"
    for ($i = 0; $i -lt $folders.Count; $i++) {
        $idx = $i + 1
        Write-Host "[$idx] $($folders[$i].Name) - $($folders[$i].LastWriteTime)"
    }

    $choice = Read-Host "Enter number of folder to analyze (or press Enter for latest)"
    if ([string]::IsNullOrWhiteSpace($choice)) {
        return $folders[0].FullName
    }
    if ($choice -match '^\d+$' -and [int]$choice -le $folders.Count) {
        return $folders[[int]$choice - 1].FullName
    }

    Write-Host "Invalid choice." -ForegroundColor Red
    return $null
}

function Start-LogAnalysis {
    # default output path
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $outputRoot = Join-Path $repoRoot "\Output" | Resolve-Path -ErrorAction SilentlyContinue
    if (-not $outputRoot) {
        $outputRoot = Join-Path $repoRoot "\Output"
    } else {
        $outputRoot = $outputRoot.Path
    }

    Write-Host "`n=== TraceForge Log Analyzer ===" -ForegroundColor Cyan

    $scanFolder = Select-ScanFolder -OutputRoot $outputRoot
    if (-not $scanFolder) { return }

    Write-Host "`nSelected scan folder: $scanFolder" -ForegroundColor Green

    Write-Host "`nChoose analysis mode:"
    Write-Host "[1] Offline Mode (default, local rule-based analysis)"
    Write-Host "[2] AI Mode (optional; requires API key)"
    Write-Host "[0] Exit"
    $mode = Read-Host "Enter option number"

    switch ($mode) {
        "1" { Invoke-OfflineAnalysis -ScanFolder $scanFolder -TrustedConfigPath $trustedConfigPath }
        "2" { Invoke-AIAnalysis -ScanFolder $scanFolder -TrustedConfigPath $trustedConfigPath }
        "0" { Write-Host "Exiting..." -ForegroundColor Yellow }
        default { Write-Host "Invalid option! Please choose a valid number." -ForegroundColor Red }
    }
}

# Run when script executed directly
if ($MyInvocation.InvocationName -eq ".\LogAnalyzer.ps1" -or $MyInvocation.ExpectingInput -eq $false) {
    Start-LogAnalysis
}
