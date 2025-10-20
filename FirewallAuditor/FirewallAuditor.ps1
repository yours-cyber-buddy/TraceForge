#FirewallAuditor.ps1
<#
.SYNOPSIS
    TraceForge Firewall Auditor - Main launcher
.DESCRIPTION
    Gathers Windows Firewall rules, analyzes them for risky or misconfigured settings,
    and outputs results and remediation suggestions separately.
#>

Clear-Host
Write-Host "=== TraceForge Firewall Auditor ===" -ForegroundColor Cyan

# Base paths
$baseDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$outputDir = Join-Path (Split-Path $baseDir) "Output\Firewall_Scans"
if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }

# Import analyzer module
Import-Module (Join-Path $baseDir "FirewallChecks.psm1") -Force

# Ask user for output name
$outputName = Read-Host "Enter name for this scan output (press Enter for timestamp)"
if ([string]::IsNullOrWhiteSpace($outputName)) {
    $timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
    $outputName = "Scan_$timestamp"
}

$scanFolder = Join-Path $outputDir $outputName
if (-not (Test-Path $scanFolder)) { New-Item -ItemType Directory -Path $scanFolder | Out-Null }

Write-Host "`nCollecting current Windows Firewall rules...
(It will take some time, please wait...)" -ForegroundColor Yellow

try {
    $rules = Get-NetFirewallRule -ErrorAction Stop | ForEach-Object {
        $details = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Name         = $_.Name
            DisplayName  = $_.DisplayName
            Direction    = $_.Direction
            Action       = $_.Action
            Enabled      = $_.Enabled
            Profile      = $_.Profile
            Program      = $_.Program
            LocalPort    = $details.LocalPort
            RemotePort   = $details.RemotePort
            Protocol     = $details.Protocol
            LocalAddress = $details.LocalAddress
            RemoteAddress= $details.RemoteAddress
        }
    }

    $rawFile = Join-Path $scanFolder "FirewallRules.json"
    $rules | ConvertTo-Json -Depth 5 | Out-File $rawFile -Encoding utf8
    Write-Host "[+] Firewall rules collected and saved to $rawFile" -ForegroundColor Green

    # Analyze
    Write-Host "`nStarting rule analysis..." -ForegroundColor Cyan
    $analysisResults = Invoke-FirewallAnalysis -Rules $rules -OutputFolder $scanFolder

    $outputJson = Join-Path $scanFolder "$($outputName)_Analyzed.json"
    $analysisResults | ConvertTo-Json -Depth 5 | Out-File $outputJson -Encoding utf8

    Write-Host "[+] Analysis complete. Results saved to: $outputJson" -ForegroundColor Green
    Write-Host "[i] For remediation guidance, please refer to: $($outputName)_Remediation.ps1" -ForegroundColor Cyan
    Write-Host "`n[Scan Complete] All results saved in: $scanFolder" -ForegroundColor Green

} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}
