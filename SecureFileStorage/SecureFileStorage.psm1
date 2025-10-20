# SecureFileStorage.psm1 — orchestration / glue module
# Fully corrected for in-place decryption and folder support

# Import SecureCore (crypto) module from Modules folder
$moduleRoot = $PSScriptRoot
$corePath = Join-Path $moduleRoot 'Modules\SecureCore.psm1'
if (Test-Path $corePath) {
    Import-Module $corePath -Force
} else {
    throw "SecureCore.psm1 not found in Modules folder ($corePath)"
}

function Write-OperationLog {
    param($outputDir, $entry)
    if (-not (Test-Path $outputDir)) { New-Item -ItemType Directory -Path $outputDir | Out-Null }
    $logFile = Join-Path $outputDir 'operation_log.json'
    $entries = @()
    if (Test-Path $logFile) {
        $raw = Get-Content $logFile -Raw
        if ($raw.Trim().Length -gt 0) { $entries = $raw | ConvertFrom-Json }
    }
    # Ensure entries is always an array
    if (-not ($entries -is [System.Collections.IList])) { $entries = @($entries) }
    $entries += $entry
    $entries | ConvertTo-Json -Depth 6 | Out-File $logFile -Encoding utf8
}

function Start-Encryption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][System.Security.SecureString]$Password
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $outputRoot = Join-Path (Join-Path $moduleRoot '..\Output\SecureFileScans') ""
    $outputDir = Join-Path $outputRoot "scan_$timestamp"
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

    if ((Get-Item $Path).PSIsContainer) {
        $files = Get-ChildItem -Path $Path -Recurse -File
        foreach ($f in $files) {
            try {
                $res = Encrypt-File -FilePath $f.FullName -Password $Password
                $entry = @{
                    File = $f.FullName
                    Status = 'Encrypted'
                    Output = $res.EncryptedPath
                    Meta = $res.MetaPath
                    Time = (Get-Date).ToString('s')
                }
                Write-OperationLog -outputDir $outputDir -entry $entry
                Write-Host "Encrypted: $($f.FullName) -> $($res.EncryptedPath)"
            } catch {
                $entry = @{
                    File = $f.FullName
                    Status = 'Error'
                    Error = $_.Exception.Message
                    Time = (Get-Date).ToString('s')
                }
                Write-OperationLog -outputDir $outputDir -entry $entry
                Write-Host ("Error encrypting {0}: {1}" -f $f.FullName, $_.Exception.Message) -ForegroundColor Red
            }
        }
    } else {
        try {
            $res = Encrypt-File -FilePath $Path -Password $Password
            $entry = @{
                File = $Path
                Status = 'Encrypted'
                Output = $res.EncryptedPath
                Meta = $res.MetaPath
                Time = (Get-Date).ToString('s')
            }
            Write-OperationLog -outputDir $outputDir -entry $entry
            Write-Host "Encrypted: $Path -> $($res.EncryptedPath)"
        } catch {
            $entry = @{
                File = $Path
                Status = 'Error'
                Error = $_.Exception.Message
                Time = (Get-Date).ToString('s')
            }
            Write-OperationLog -outputDir $outputDir -entry $entry
            Write-Host ("Error encrypting {0}: {1}" -f $Path, $_.Exception.Message) -ForegroundColor Red
        }
    }
    Write-Host "Encryption run complete. Logs saved to: $outputDir"
}

function Start-Decryption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][System.Security.SecureString]$Password
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $outputRoot = Join-Path (Join-Path $moduleRoot '..\Output\SecureFileScans') ""
    $outputDir = Join-Path $outputRoot "scan_$timestamp"
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

    if ((Get-Item $Path).PSIsContainer) {
        # Get all files in folder, then check if a corresponding meta file exists
        $files = Get-ChildItem -Path $Path -Recurse -File
        foreach ($f in $files) {
            $metaPathCandidate = "$($f.FullName).meta.json"
            if (-not (Test-Path $metaPathCandidate)) { continue }

            try {
                $res = Decrypt-File -EncryptedPath $f.FullName -Password $Password
                $entry = @{
                    File = $f.FullName
                    Status = 'Decrypted'
                    Output = $res.OutputPath
                    Time = (Get-Date).ToString('s')
                }
                Write-OperationLog -outputDir $outputDir -entry $entry
                Write-Host "Decrypted: $($f.FullName) -> $($res.OutputPath)"
            } catch {
                $entry = @{
                    File = $f.FullName
                    Status = 'Error'
                    Error = $_.Exception.Message
                    Time = (Get-Date).ToString('s')
                }
                Write-OperationLog -outputDir $outputDir -entry $entry
                Write-Host ("Error decrypting {0}: {1}" -f $f.FullName, $_.Exception.Message) -ForegroundColor Red
            }
        }
    } else {
        try {
            $res = Decrypt-File -EncryptedPath $Path -Password $Password
            $entry = @{
                File = $Path
                Status = 'Decrypted'
                Output = $res.OutputPath
                Time = (Get-Date).ToString('s')
            }
            Write-OperationLog -outputDir $outputDir -entry $entry
            Write-Host "Decrypted: $Path -> $($res.OutputPath)"
        } catch {
            $entry = @{
                File = $Path
                Status = 'Error'
                Error = $_.Exception.Message
                Time = (Get-Date).ToString('s')
            }
            Write-OperationLog -outputDir $outputDir -entry $entry
            Write-Host ("Error decrypting {0}: {1}" -f $Path, $_.Exception.Message) -ForegroundColor Red
        }
    }
    Write-Host "Decryption run complete. Logs saved to: $outputDir"
    Write-Host "Decrypted files are restored in-place, replacing encrypted files."
}

Export-ModuleMember -Function Start-Encryption, Start-Decryption, Write-OperationLog
