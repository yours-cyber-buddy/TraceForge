<#
StegaTool.ps1 - TraceForge Steganography Stimulator & Detector launcher
Save as: TraceForge\StegaTool\StegaTool.ps1
#>

# Resolve script root and module path
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ModulePath = Join-Path $ScriptRoot "Modules\StegaCore.psm1"

if (-not (Test-Path $ModulePath)) {
    Write-Host "Missing module: $ModulePath" -ForegroundColor Red
    return
}

# Import module (force reload safe)
Import-Module $ModulePath -Force

Write-Host ""
Write-Host "=== TraceForge :: StegaTool ===" -ForegroundColor Cyan

# Use central Output folder at repo root
$repoRoot = Split-Path -Parent $ScriptRoot
$outputRoot = Join-Path $repoRoot "Output\StegaScans"
if (-not (Test-Path $outputRoot)) { New-Item -ItemType Directory -Path $outputRoot | Out-Null }

function Ask-ScanName {
    $timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
    $default = "StegaScan_$timestamp"
    Write-Host ""
    Write-Host "[+] Default scan name: $default" -ForegroundColor Yellow
    $custom = Read-Host "[?] Press Enter to use default or enter custom scan name"
    if ([string]::IsNullOrWhiteSpace($custom)) { return $default }
    return $custom.Trim()
}

function NormalizePath([string]$p) {
    if (-not $p) { return $p }
    $s = $p.Trim()
    if ($s.StartsWith('"') -and $s.EndsWith('"')) { $s = $s.Trim('"') }
    if ($s.StartsWith("'") -and $s.EndsWith("'")) { $s = $s.Trim("'") }
    return $s
}

# Check if we can actually read from stdin (interactive session)
$isInteractive = $true
try {
    # Try to read from stdin without blocking
    $null = [Console]::KeyAvailable
    $isInteractive = $true
} catch {
    $isInteractive = $false
}

# Additional check - if we're in a non-console environment
if ($Host.Name -ne "ConsoleHost") {
    $isInteractive = $false
}

if ($isInteractive) {
    while ($true) {
        Write-Host ""
        Write-Host "Choose Stega mode:"
        Write-Host "[1] Stimulator (Embed payload into image - PNG recommended)"
        Write-Host "[2] Detector (Detect / Extract payload from image)"
        Write-Host "[0] Exit"
        $choice = Read-Host "Enter option number"

    switch ($choice.Trim()) {
        "1" {
            # EMBED
            $cover = NormalizePath (Read-Host "Enter path to cover image (PNG recommended). Example: D:\images\cover.png")
            if ([string]::IsNullOrWhiteSpace($cover) -or -not (Test-Path $cover)) {
                Write-Host "Cover image not found." -ForegroundColor Red
                continue
            }

            $payloadInput = NormalizePath (Read-Host "Enter path to payload file (leave blank to enter text manually)")
            $payloadBytes = $null
            $payloadName = $null

            if ([string]::IsNullOrWhiteSpace($payloadInput)) {
                $text = Read-Host "Enter short text to embed (single-line)"
                $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($text)
                $payloadName = "embedded_text.txt"
            } else {
                if (-not (Test-Path $payloadInput)) {
                    Write-Host "Payload file not found." -ForegroundColor Red
                    continue
                }
                $payloadBytes = [System.IO.File]::ReadAllBytes($payloadInput)
                $payloadName = Split-Path $payloadInput -Leaf
            }

            $useAes = Read-Host "Encrypt payload before embed with AES? (Y/N)"
            $password = $null
            if ($useAes -match '^[Yy]') {
                $pwdSecure = Read-Host "Enter encryption password (will not be saved)" -AsSecureString
                $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwdSecure))
            }

            $scanName = Ask-ScanName
            $scanFolder = Join-Path $outputRoot $scanName
            if (-not (Test-Path $scanFolder)) { New-Item -ItemType Directory -Path $scanFolder | Out-Null }

            $origLeaf = Split-Path $cover -Leaf
            $outLeaf = "stego_$origLeaf"
            $stegoOut = Join-Path $scanFolder $outLeaf

            try {
                $res = Invoke-StegaEmbed -CoverImagePath $cover -PayloadBytes $payloadBytes -PayloadName $payloadName -Password $password -OutputImagePath $stegoOut -ScanFolder $scanFolder
                if ($res.Success) {
                    Write-Host "[+] Embed succeeded. Stego image: $($res.OutputImage)" -ForegroundColor Green
                    Write-Host "[+] Report saved: $($res.ReportFile)" -ForegroundColor Green
                } else {
                    Write-Host "[!] Embed failed: $($res.Error)" -ForegroundColor Red
                }
            } catch {
                Write-Host "Error during embed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        "2" {
            # DETECT / EXTRACT
            $image = NormalizePath (Read-Host "Enter path to image to analyze (PNG/JPG). Example: D:\images\stego.png")
            if ([string]::IsNullOrWhiteSpace($image) -or -not (Test-Path $image)) {
                Write-Host "Image not found." -ForegroundColor Red
                continue
            }

            $scanName = Ask-ScanName
            $scanFolder = Join-Path $outputRoot $scanName
            if (-not (Test-Path $scanFolder)) { New-Item -ItemType Directory -Path $scanFolder | Out-Null }

            $mode = Read-Host "Choose mode: [1] Quick (LSB+signature) [2] Deep (Chi-like + heuristics) [3] Extract (attempt extract)"
            switch ($mode.Trim()) {
                "1" { $deep = $false; $extract = $false }
                "2" { $deep = $true; $extract = $false }
                "3" { $deep = $true; $extract = $true }
                default { $deep = $false; $extract = $false }
            }

            $password = $null
            $pw = Read-Host "If payload may be encrypted, enter password now (or press Enter to skip)"
            if (-not [string]::IsNullOrWhiteSpace($pw)) { $password = $pw }

            try {
                $res = Invoke-StegaDetect -ImagePath $image -DeepChecks:$deep -AttemptExtract:$extract -Password $password -ScanFolder $scanFolder
                if ($res.Success) {
                    Write-Host "[+] Analysis completed. Report: $($res.ReportFile)" -ForegroundColor Green
                    if ($res.ExtractedFile) {
                        Write-Host "[+] Extracted payload saved: $($res.ExtractedFile)" -ForegroundColor Green
                    }
                } else {
                    Write-Host "[!] Analysis finished with warnings: $($res.Error)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error during analysis: $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        "0" { Write-Host "Exiting..." }
        default {
            Write-Host "Invalid choice." -ForegroundColor Yellow
        }
    } # switch
    } # while
} else {
    Write-Host "StegaTool requires an interactive PowerShell session to run." -ForegroundColor Yellow
    Write-Host "Please run this script directly in PowerShell: .\StegaTool.ps1" -ForegroundColor Yellow
}
