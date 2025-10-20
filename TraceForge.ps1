<#
TraceForge.ps1
Main launcher for the TraceForge project.
Style: "hacker-like" CLI with a modern, clean layout
Usage: place this file in the TraceForge/ root (next to module folders) and run it.
#>

# -------------------------
# Banner function
# -------------------------
function Show-Banner {
    Clear-Host
    $cyan = "Cyan"
    $mag = "Magenta"
    $yellow = "Yellow"
    $darkGray = "DarkGray"

    Write-Host "=================================================================" -ForegroundColor $darkGray
    Write-Host ""
    Write-Host " _________ _______  _______  _______  _______    _______  _______  _______  _______  _______   " -ForegroundColor $cyan
    Write-Host " \__   __/(  ____ )(  ___  )(  ____ \(  ____ \  (  ____ \(  ___  )(  ____ )(  ____ \(  ____ \  " -ForegroundColor $cyan
    Write-Host "    ) (   | (    )|| (   ) || (    \/| (    \/  | (    \/| (   ) || (    )|| (    \/| (    \/  " -ForegroundColor $mag
    Write-Host "    | |   | (____)|| (___) || |      | (__      | (__    | |   | || (____)|| |      | (__      " -ForegroundColor $mag
    Write-Host "    | |   |     __)|  ___  || |      |  __)     |  __)   | |   | ||     __)| | ____ |  __)     " -ForegroundColor $cyan
    Write-Host "    | |   | (\ (   | (   ) || |      | (        | (      | |   | || (\ (   | | \_  )| (        " -ForegroundColor $cyan
    Write-Host "    | |   | ) \ \__| )   ( || (____/\| (____/\  | )      | (___) || ) \ \__| (___) || (____/\  " -ForegroundColor $darkGray
    Write-Host "    )_(   |/   \__/|/     \|(_______/(_______/  |/       (_______)|/   \__/(_______)(_______/" -ForegroundColor $darkGray
    Write-Host ""
    Write-Host "                               TraceForge - v1.0" -ForegroundColor $darkGray
    Write-Host ""
    Write-Host "Welcome - choose a module to run (type number and Enter)." -ForegroundColor $yellow
    Write-Host "=================================================================" -ForegroundColor $darkGray
    Write-Host ""
}

# -------------------------
# Helper: find a main script/module file for a module folder
# -------------------------
function Find-ModuleEntry {
    param(
        [string]$Root,
        [string]$ModuleName
    )

    if (-not $Root) { Write-Host "[!] Root path is null" -ForegroundColor Red; return $null }

    $modFolder = Join-Path $Root $ModuleName
    $candidates = @()

    # 1. ModuleName.ps1
    $candidates += Join-Path $modFolder ("$ModuleName.ps1")

    # 2. ModuleName.psm1
    $candidates += Join-Path $modFolder ("$ModuleName.psm1")

    # 3. Modules subfolder
    $modulesSub = Join-Path $modFolder "Modules"
    if (Test-Path $modulesSub) {
        $psm1s = Get-ChildItem -Path $modulesSub -Filter "*.psm1" -File -ErrorAction SilentlyContinue
        foreach ($f in $psm1s) { $candidates += $f.FullName }
        $ps1s = Get-ChildItem -Path $modulesSub -Filter "*.ps1" -File -ErrorAction SilentlyContinue
        foreach ($f in $ps1s) { $candidates += $f.FullName }
    }

    # 4. fallback: any ps1/psm1 in module folder root
    if (Test-Path $modFolder) {
        $others = Get-ChildItem -Path $modFolder -Include *.ps1, *.psm1 -File -ErrorAction SilentlyContinue
        foreach ($o in $others) { if (-not ($candidates -contains $o.FullName)) { $candidates += $o.FullName } }
    }

    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) { return $c }
    }

    return $null
}

# -------------------------
# Helper: launch module
# -------------------------
function Launch-Module {
    param(
        [string]$Root,
        [string]$ModuleName
    )

    $entry = Find-ModuleEntry -Root $Root -ModuleName $ModuleName
    if (-not $entry) {
        Write-Host "[!] Module '$ModuleName' not found under $Root. Skipping." -ForegroundColor Red
        return
    }

    $ext = [System.IO.Path]::GetExtension($entry).ToLowerInvariant()
    Write-Host "[*] Found: $entry" -ForegroundColor DarkGray

    try {
        if ($ext -eq ".ps1") {
            Write-Host "[>] Executing script: $ModuleName (ps1)" -ForegroundColor Cyan
            & $entry
            Write-Host "`n[<] Returned from $ModuleName." -ForegroundColor Green
            return
        }

        if ($ext -eq ".psm1") {
            Write-Host "[>] Importing module file: $entry" -ForegroundColor Cyan
            Import-Module $entry -Force -ErrorAction Stop

            $entryCandidates = @(
                "Start-$ModuleName",
                "Start-${ModuleName}Module",
                "Invoke-$ModuleName",
                "Invoke-${ModuleName}Analysis",
                "Invoke-OfflineAnalysis",
                "Start-Encryption",
                "Start-Decryption",
                "Invoke-StegaDetect",
                "Invoke-StegaEmbed",
                "Start-FirewallAudit",
                "Start-LogCollector",
                "Start-LogAnalyzer"
            )

            $called = $false
            foreach ($fn in $entryCandidates) {
                $cmd = Get-Command -Name $fn -ErrorAction SilentlyContinue
                if ($cmd) {
                    Write-Host "[>] Calling entry function: $fn" -ForegroundColor Cyan
                    & $fn
                    $called = $true
                    break
                }
            }

            if (-not $called) {
                $mod = Get-Module | Where-Object { $_.Path -eq (Get-Item $entry).FullName }
                if ($mod) {
                    $exports = $mod.ExportedCommands.Keys
                    Write-Host "[i] Module imported but no standard entry function found." -ForegroundColor Yellow
                    Write-Host "    Exported commands:" -ForegroundColor DarkGray
                    foreach ($e in $exports) { Write-Host "      - $e" -ForegroundColor DarkGray }
                    Write-Host "    Press Enter to continue..." -ForegroundColor Yellow
                    Read-Host | Out-Null
                }
            } else {
                Write-Host "`n[<] Returned from $ModuleName." -ForegroundColor Green
            }
            return
        }

        Write-Host "[!] Unsupported file type: $entry" -ForegroundColor Red
    } catch {
        Write-Host "[!] Error launching module $ModuleName`: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# -------------------------
# Main loop
# -------------------------
function Start-TraceForge {
    Write-Host "[*] TraceForge starting..." -ForegroundColor Green

    $root = Split-Path -Parent $MyInvocation.MyCommand.Path
    if (-not $root) { $root = Get-Location }

    $modules = @(
        @{ id = 1; name = "LogCollector"; label = "Log Collector" },
        @{ id = 2; name = "LogAnalyzer"; label = "Log Analyzer" },
        @{ id = 3; name = "FirewallAuditor"; label = "Firewall Auditor" },
        @{ id = 4; name = "StegaTool"; label = "Stega Tool" },
        @{ id = 5; name = "SecureFileStorage"; label = "Secure File Storage" },
        @{ id = 0; name = "Exit"; label = "Exit / Quit" }
    )

    while ($true) {
        Show-Banner

        foreach ($m in $modules) {
            $id = $m.id
            $label = $m.label
            if ($id -eq 0) {
                Write-Host "  [0] $label" -ForegroundColor DarkYellow
            } else {
                $exists = $null
                if ($root) {
                    $exists = Test-Path (Join-Path $root $m.name)
                }
                $mark = if ($exists) { "*" } else { " " }
                Write-Host ("  [{0}] {1} {2}" -f $id, $label, $mark) -ForegroundColor White
            }
        }

        Write-Host ""
        Write-Host "[*] Modules marked with '*' are present on disk." -ForegroundColor DarkGray
        $choice = Read-Host "Enter option number (or press Enter to refresh menu)"

        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        if (-not ([int]::TryParse($choice, [ref]$null))) {
            Write-Host "Please enter a numeric selection." -ForegroundColor Red
            Start-Sleep -Seconds 1
            continue
        }

        $num = [int]$choice
        if ($num -eq 0) {
            Write-Host "Exiting TraceForge — goodbye." -ForegroundColor Yellow
            break
        }

        $selected = $modules | Where-Object { $_.id -eq $num }
        if (-not $selected) {
            Write-Host "Invalid selection. Try again." -ForegroundColor Red
            Start-Sleep -Seconds 1
            continue
        }

        $modName = $selected.name
        Write-Host "`nLaunching module: $($selected.label) ..." -ForegroundColor Cyan
        Launch-Module -Root $root -ModuleName $modName

        Write-Host "`nPress Enter to return to main menu..." -ForegroundColor DarkGray
        Read-Host | Out-Null
    }
}

# -------------------------
# Start launcher
# -------------------------
Start-TraceForge
