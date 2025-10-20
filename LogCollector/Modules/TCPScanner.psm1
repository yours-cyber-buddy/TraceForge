#TCPScanner.psm1

function Get-SuspiciousConnections {
    param($OutputFolder)

    Write-Host "`n[+] Scanning TCP Connections..." -ForegroundColor Yellow
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" }
    $results = @()

    foreach ($conn in $connections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $procName = if ($proc) { $proc.ProcessName } else { "Unknown" }

        $remote = $conn.RemoteAddress
        $local = $conn.LocalAddress
        $reasons = @()

        if ($remote -notmatch '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1]))' -and $remote -ne "::1") {
            $reasons += "External IP"
        }
        if ($procName -eq "Unknown") {
            $reasons += "Unknown process"
        }

        $suspicious = $reasons.Count -gt 0

        $results += [PSCustomObject]@{
            Process        = $procName
            PID            = $conn.OwningProcess
            LocalAddress   = "$($conn.LocalAddress):$($conn.LocalPort)"
            RemoteAddress  = "$($conn.RemoteAddress):$($conn.RemotePort)"
            Suspicious     = $suspicious
            Reasons        = ($reasons -join ", ")
        }
    }

    $results | ConvertTo-Json -Depth 4 | Out-File "$OutputFolder\Network.json" -Encoding utf8
    Write-Host "[+] Network connections saved to $OutputFolder\Network.json" -ForegroundColor Green
}

Export-ModuleMember -Function Get-SuspiciousConnections
