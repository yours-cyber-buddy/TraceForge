#LogCollector.ps1

Import-Module "$PSScriptRoot\LogCollector.psm1" -Force
Write-Host "`n=== TraceForge Log Collector ===" -ForegroundColor Cyan

# --- Output Folder Setup ---
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$defaultFolderName = "scan_$timestamp"
Write-Host "`n[+] Default scan folder name: $defaultFolderName" -ForegroundColor Yellow

$customName = Read-Host "[?] Press Enter to use default name or enter custom folder name"
$customName = $customName.Trim()

if ([string]::IsNullOrWhiteSpace($customName)) {
    $scanFolder = Join-Path "$PSScriptRoot\..\Output" $defaultFolderName
} else {
    $scanFolder = Join-Path "$PSScriptRoot\..\Output" $customName
}

# Create the folder if it doesn't exist
if (-not (Test-Path $scanFolder)) {
    New-Item -ItemType Directory -Path $scanFolder | Out-Null
}

Write-Host "[+] Output folder created at: $scanFolder" -ForegroundColor Green

Write-Host "`nSelect a module to run:"
Write-Host "[1] Process Scanner"
Write-Host "[2] Service Scanner"
Write-Host "[3] Autorun Scanner"
Write-Host "[4] TCP Connection Scanner"
Write-Host "[5] Run Full System Scan"
Write-Host "[0] Exit"

$choice = Read-Host "Enter option number"

switch ($choice) {
    1 { Get-SuspiciousProcesses -OutputFolder $scanFolder }
    2 { Get-SuspiciousServices -OutputFolder $scanFolder }
    3 { Get-SuspiciousAutoruns -OutputFolder $scanFolder }
    4 { Get-SuspiciousConnections -OutputFolder $scanFolder }
    5 {
        Get-SuspiciousProcesses -OutputFolder $scanFolder
        Get-SuspiciousServices -OutputFolder $scanFolder
        Get-SuspiciousAutoruns -OutputFolder $scanFolder
        Get-SuspiciousConnections -OutputFolder $scanFolder
    }
    0 { Write-Host "Exiting..." }
    default { Write-Host "Invalid option!" }
}

Write-Host ("`n[Scan Complete] All results saved in: " + $scanFolder) -ForegroundColor Cyan
