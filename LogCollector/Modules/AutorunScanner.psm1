#AutorunScanner.psm1

function Get-SuspiciousAutoruns {
    param($OutputFolder)

    Write-Host "`n[+] Scanning Autoruns..." -ForegroundColor Yellow
    $autorunKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    $results = @()

    foreach ($key in $autorunKeys) {
        if (Test-Path $key) {
            Get-ItemProperty $key | ForEach-Object {
                foreach ($prop in $_.PSObject.Properties) {
                    if ($prop.Name -like "PS*") { continue }

                    $val = $prop.Value
                    if (-not $val) { continue }

                    $path = if ($val -match '"([^"]+)"') {
                        $matches[1]
                    } else {
                        $val.Split(" ")[0]
                    }

                    $exists = Test-Path $path
                    $suspicious = -not $exists
                    $reason = if (-not $exists) { "Missing file" } else { "" }

                    $results += [PSCustomObject]@{
                        EntryName  = $prop.Name
                        Path       = $path
                        Exists     = $exists
                        Suspicious = $suspicious
                        Reason     = $reason
                    }
                }
            }
        }
    }

    $results | ConvertTo-Json -Depth 4 | Out-File "$OutputFolder\Autoruns.json" -Encoding utf8
    Write-Host "[+] Autoruns saved to $OutputFolder\Autoruns.json" -ForegroundColor Green
}

Export-ModuleMember -Function Get-SuspiciousAutoruns
