# SecureFileStorage.ps1 — interactive CLI for SecureFileStorage module
# Usage: run this script from the SecureFileStorage folder
# It will import SecureFileStorage.psm1 which orchestrates the operations.


$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $scriptDir 'SecureFileStorage.psm1') -Force


Write-Host "========================================="
Write-Host " TraceForge - SecureFileStorage Module"
Write-Host "========================================="


function Read-Choice {
param($prompt, $valid)
while ($true) {
$c = Read-Host $prompt
if ($valid -contains $c) { return $c }
Write-Host "Invalid choice. Try again." -ForegroundColor Yellow
}
}


# Step 1: action selection
Write-Host "Choose action:`n 1) Encrypt`n 2) Decrypt"
$action = Read-Choice -prompt 'Enter choice (1/2):' -valid @('1','2')


# Step 2: path input
$pathOK = $false
while (-not $pathOK) {
$targetPath = Read-Host "Enter full path to file or folder"
if (Test-Path $targetPath) { $pathOK = $true } else { Write-Host "Path not found. Try again." -ForegroundColor Yellow }
}


# Step 3: password input (secure)
function Read-Password($prompt) {
$sec = Read-Host $prompt -AsSecureString
if (-not $sec) { Write-Host "Password empty. Try again." -ForegroundColor Yellow; return Read-Password $prompt }
return $sec
}


$pass = Read-Password "Enter password (will not be displayed):"
$passConfirm = Read-Password "Confirm password (re-enter):"


# Compare secure strings
if ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)) -ne [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($passConfirm))) {
Write-Host "Passwords do not match. Aborting." -ForegroundColor Red
exit 1
}


# Step 4: confirmation
$actionName = if ($action -eq '1') { 'Encrypt' } else { 'Decrypt' }
Write-Host "\nSummary:`n Action: $actionName`n Target: $targetPath"
$ok = Read-Host "Proceed? (Y/N)"
if ($ok.ToUpper() -ne 'Y') { Write-Host "Aborted by user."; exit 0 }


# Call orchestration functions in the module
if ($action -eq '1') {
Start-Encryption -Path $targetPath -Password $pass
} else {
Start-Decryption -Path $targetPath -Password $pass 
}

