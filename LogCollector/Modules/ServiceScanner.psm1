#ServiceScanner.psm1

function Get-SuspiciousServices {
    param($OutputFolder)

    Write-Host "`n[*] Scanning Services..." -ForegroundColor Cyan
    $services = Get-WmiObject -Class Win32_Service
    $results = @()

    foreach ($service in $services) {
        $path = $service.PathName
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        if ($path -match '^"([^"]+)"') {
            $path = $matches[1]
        } elseif ($path -match '^(\S+\.exe)') {
            $path = $matches[1]
        }

        $exists = Test-Path $path
        $signature = "Unknown"

        try {
            $sig = Get-AuthenticodeSignature -FilePath $path
            if ($sig.Status -eq 'Valid') {
                $signature = $sig.SignerCertificate.Subject
            } else {
                $signature = "Unsigned"
            }
        } catch {
            $signature = "Unsigned"
        }

        $suspicious = $false
        $reason = ""

        if (-not $exists) {
            $suspicious = $true
            $reason = "Service file missing"
        } elseif ($signature -eq "Unsigned") {
            $suspicious = $true
            $reason = "Unsigned service binary"
        } elseif ($signature -notmatch "Microsoft") {
            $suspicious = $true
            $reason = "Signed by non-Microsoft vendor"
        }

        $results += [PSCustomObject]@{
            ServiceName = $service.Name
            DisplayName = $service.DisplayName
            State       = $service.State
            Path        = $path
            Signer      = $signature
            Suspicious  = $suspicious
            Reason      = $reason
        }
    }

    $results | ConvertTo-Json -Depth 4 | Out-File "$OutputFolder\Services.json" -Encoding utf8
    Write-Host "[+] Services saved to $OutputFolder\Services.json" -ForegroundColor Green
}

Export-ModuleMember -Function Get-SuspiciousServices
