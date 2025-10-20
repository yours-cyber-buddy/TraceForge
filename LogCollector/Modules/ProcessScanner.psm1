#ProcessScanner.psm1

function Get-SuspiciousProcesses {
    param($OutputFolder)

    Write-Host "`n[+] Scanning Processes..." -ForegroundColor Yellow

    $allProcesses = Get-CimInstance Win32_Process
    $results = @()

    foreach ($proc in $allProcesses) {
        $path = $proc.ExecutablePath
        $suspicious = $false
        $reason = ""

        # Flag processes with missing paths or from unusual locations
        if (-not $path -or -not (Test-Path $path)) {
            $suspicious = $true
            $reason = "Missing or invalid path"
        } elseif ($path -notmatch "Windows|Program Files") {
            $suspicious = $true
            $reason = "Unusual execution path"
        }

        $results += [PSCustomObject]@{
            ProcessName = $proc.Name
            PID         = $proc.ProcessId
            Path        = $path
            Suspicious  = $suspicious
            Reason      = $reason
        }
    }

    $results | ConvertTo-Json -Depth 4 | Out-File "$OutputFolder\Processes.json" -Encoding utf8
    Write-Host "[+] Processes saved to $OutputFolder\Processes.json" -ForegroundColor Green
}

Export-ModuleMember -Function Get-SuspiciousProcesses
