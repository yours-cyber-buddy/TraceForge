# StegaCore.psm1 – Core LSB steganography functions for TraceForge StegaTool (modified, reporting enhanced)
# Exports:
#  - Invoke-StegaEmbed
#  - Invoke-StegaDetect
#  - Get-ImageCapacity

# Load System.Drawing for image access (Windows/PowerShell 7+)
try {
    Add-Type -AssemblyName System.Drawing
} catch {
    # For PowerShell 7+ on Windows, try loading from .NET Core
    try {
        Add-Type -AssemblyName System.Drawing.Common
    } catch {
        throw "System.Drawing assembly not available. This module requires Windows or .NET Core with System.Drawing.Common."
    }
}

function Get-ImageCapacity {
    param([Parameter(Mandatory = $true)][string]$ImagePath)

    if (-not (Test-Path $ImagePath)) { throw "Image not found: $ImagePath" }

    $bmp = New-Object System.Drawing.Bitmap $ImagePath
    try {
        $pixels = $bmp.Width * $bmp.Height
        $capacityBits = $pixels * 3
        $capacityBytes = [math]::Floor($capacityBits / 8)
        return [PSCustomObject]@{
            Pixels        = $pixels
            CapacityBytes = $capacityBytes
            Width         = $bmp.Width
            Height        = $bmp.Height
        }
    }
    finally {
        $bmp.Dispose()
    }
}

function Build-Header {
    param(
        [Parameter(Mandatory = $true)][string]$PayloadName,
        [Parameter(Mandatory = $true)][bool]$Encrypted,
        [byte[]]$Salt,
        [byte[]]$InitializationVector,
        [Parameter(Mandatory = $true)][uint32]$PayloadLength
    )

    $magic = [System.Text.Encoding]::ASCII.GetBytes("TRGFSTEG")
    if ($magic.Length -lt 8) {
        $tmp = New-Object byte[] 8
        [Array]::Copy($magic, 0, $tmp, 0, $magic.Length)
        $magic = $tmp
    }

    $version = [byte]1
    $flags = [byte]0
    if ($Encrypted) { $flags = [byte]($flags -bor 1) }

    $payloadLenBytes = [BitConverter]::GetBytes([uint32]$PayloadLength)
    $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($PayloadName)
    $nameLenBytes = [BitConverter]::GetBytes([uint16]$nameBytes.Length)

    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter $ms
    try {
        $bw.Write($magic)
        $bw.Write($version)
        $bw.Write($flags)
        $bw.Write($payloadLenBytes)
        $bw.Write($nameLenBytes)
        $bw.Write($nameBytes)

        if ($Encrypted) {
            $saltLenBytes = [BitConverter]::GetBytes([uint16]$Salt.Length)
            $ivLenBytes = [BitConverter]::GetBytes([uint16]$InitializationVector.Length)
            $bw.Write($saltLenBytes)
            $bw.Write($Salt)
            $bw.Write($ivLenBytes)
            $bw.Write($InitializationVector)
        }

        $bw.Flush()
        return $ms.ToArray()
    }
    finally {
        $bw.Close()
        $ms.Close()
    }
}

function Parse-Header {
    param([Parameter(Mandatory = $true)][byte[]]$Data)

    $ms = New-Object System.IO.MemoryStream -ArgumentList ($Data)
    $br = New-Object System.IO.BinaryReader $ms
    try {
        $magic = $br.ReadBytes(8)
        $magicStr = [System.Text.Encoding]::ASCII.GetString($magic).Trim([char]0)
        if ($magicStr -ne "TRGFSTEG") { throw "Header magic not found." }

        $version = $br.ReadByte()
        $flags = $br.ReadByte()
        $payloadLen = $br.ReadUInt32()
        $nameLen = $br.ReadUInt16()
        $nameBytes = $br.ReadBytes($nameLen)
        $name = [System.Text.Encoding]::UTF8.GetString($nameBytes)

        $encrypted = (($flags -band 1) -ne 0)
        $salt = $null; $iv = $null
        if ($encrypted) {
            $saltLen = $br.ReadUInt16()
            $salt = $br.ReadBytes($saltLen)
            $ivLen = $br.ReadUInt16()
            $iv = $br.ReadBytes($ivLen)
        }

        return [PSCustomObject]@{
            Magic         = $magicStr
            Version       = $version
            Encrypted     = $encrypted
            PayloadLength = $payloadLen
            PayloadName   = $name
            Salt          = $salt
            InitializationVector = $iv
            HeaderSize    = [int]$ms.Position
        }
    }
    finally {
        $br.Close()
        $ms.Close()
    }
}

function Encrypt-Bytes {
    param([Parameter(Mandatory = $true)][byte[]]$Data,
          [Parameter(Mandatory = $true)][string]$Password)

    $salt = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 10000)
    $key = $derive.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.GenerateIV()
    $iv = $aes.IV

    $encryptor = $aes.CreateEncryptor()
    $ms = New-Object System.IO.MemoryStream
    $mode = [System.Security.Cryptography.CryptoStreamMode]::Write
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $encryptor, $mode)

    try {
        $cs.Write($Data, 0, $Data.Length)
        $cs.FlushFinalBlock()
        $enc = $ms.ToArray()
    }
    finally {
        $cs.Close()
        $ms.Close()
        $aes.Dispose()
    }

    return [PSCustomObject]@{ Encrypted = $enc; Salt = $salt; IV = $iv }
}

function Decrypt-Bytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$EncryptedData,
        [Parameter(Mandatory = $true)][byte[]]$Salt,
        [Parameter(Mandatory = $true)][byte[]]$InitializationVector,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, 10000)
    $key = $derive.GetBytes(32)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key
    $aes.IV = $InitializationVector

    $decryptor = $aes.CreateDecryptor()
    $ms = New-Object System.IO.MemoryStream
    $mode = [System.Security.Cryptography.CryptoStreamMode]::Write
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, $mode)

    try {
        $cs.Write($EncryptedData, 0, $EncryptedData.Length)
        $cs.FlushFinalBlock()
        $plain = $ms.ToArray()
    }
    catch {
        throw "Decryption failed: $($_.Exception.Message)"
    }
    finally {
        $cs.Close()
        $ms.Close()
        $aes.Dispose()
    }
    return $plain
}

function BytesToBits {
    param([Parameter(Mandatory = $true)][byte[]]$data)
    $bitsList = New-Object System.Collections.Generic.List[byte]
    foreach ($b in $data) {
        for ($i = 7; $i -ge 0; $i--) {
            $bitsList.Add([byte](($b -shr $i) -band 1))
        }
    }
    return $bitsList.ToArray()
}

function BitsToBytes {
    param([Parameter(Mandatory = $true)][byte[]]$bits)
    $outList = New-Object System.Collections.Generic.List[byte]
    for ($i = 0; $i -lt $bits.Length; $i += 8) {
        $val = 0
        for ($j = 0; $j -lt 8; $j++) {
            if ($i + $j -lt $bits.Length) {
                $val = ($val -shl 1) -bor $bits[$i + $j]
            } else {
                $val = ($val -shl 1)
            }
        }
        $outList.Add([byte]$val)
    }
    return $outList.ToArray()
}

function Invoke-StegaEmbed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$CoverImagePath,
        [Parameter(Mandatory = $true)][byte[]]$PayloadBytes,
        [Parameter(Mandatory = $true)][string]$PayloadName,
        [string]$Password,
        [Parameter(Mandatory = $true)][string]$OutputImagePath,
        [Parameter(Mandatory = $true)][string]$ScanFolder
    )

    if (-not (Test-Path $CoverImagePath)) {
        return [PSCustomObject]@{ Success = $false; Error = "Cover image not found: $CoverImagePath" }
    }

    $CoverImagePath = (Resolve-Path $CoverImagePath).Path
    if (-not (Test-Path $ScanFolder)) { New-Item -ItemType Directory -Path $ScanFolder | Out-Null }

    $cap = Get-ImageCapacity -ImagePath $CoverImagePath
    $encrypted = $false; $salt = $null; $iv = $null; $payloadToEmbed = $PayloadBytes

    if ($Password) {
        $enc = Encrypt-Bytes -Data $PayloadBytes -Password $Password
        $payloadToEmbed = $enc.Encrypted
        $salt = $enc.Salt
        $iv = $enc.IV
        $encrypted = $true
    }

    $header = Build-Header -PayloadName $PayloadName -Encrypted:$encrypted -Salt $salt -InitializationVector $iv -PayloadLength ([uint32]$payloadToEmbed.Length)
    $totalBytes = $header.Length + $payloadToEmbed.Length

    if ($totalBytes -gt $cap.CapacityBytes) {
        return [PSCustomObject]@{ Success = $false; Error = "Payload + header too large for image capacity ($($cap.CapacityBytes) bytes). Required: $totalBytes bytes." }
    }

    $bmp = New-Object System.Drawing.Bitmap $CoverImagePath
    try {
        $bits = BytesToBits -data ($header + $payloadToEmbed)
        $bitIndex = 0

        for ($y = 0; $y -lt $bmp.Height; $y++) {
            for ($x = 0; $x -lt $bmp.Width; $x++) {
                $color = $bmp.GetPixel($x, $y)
                $r = $color.R; $g = $color.G; $b = $color.B
                if ($bitIndex -lt $bits.Length) { $r = ($r -band 0xFE) -bor $bits[$bitIndex]; $bitIndex++ }
                if ($bitIndex -lt $bits.Length) { $g = ($g -band 0xFE) -bor $bits[$bitIndex]; $bitIndex++ }
                if ($bitIndex -lt $bits.Length) { $b = ($b -band 0xFE) -bor $bits[$bitIndex]; $bitIndex++ }
                $bmp.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($r, $g, $b))
                if ($bitIndex -ge $bits.Length) { break }
            }
            if ($bitIndex -ge $bits.Length) { break }
        }

        $ext = ([System.IO.Path]::GetExtension($OutputImagePath)).ToLowerInvariant()
        switch ($ext) {
            ".png" { $format = [System.Drawing.Imaging.ImageFormat]::Png }
            ".jpg" { $format = [System.Drawing.Imaging.ImageFormat]::Jpeg }
            ".jpeg" { $format = [System.Drawing.Imaging.ImageFormat]::Jpeg }
            default { $format = [System.Drawing.Imaging.ImageFormat]::Png }
        }

        if ($format -eq [System.Drawing.Imaging.ImageFormat]::Jpeg) {
            Write-Host "[!] Warning: JPEG is lossy. Prefer PNG for reliable extraction." -ForegroundColor Yellow
        }

        $bmp.Save($OutputImagePath, $format)

        $report = [PSCustomObject]@{
            Mode                = "embed"
            CoverImage          = $CoverImagePath
            OutputImage         = $OutputImagePath
            PayloadName         = $PayloadName
            Encrypted           = $encrypted
            PayloadOriginalBytes = $PayloadBytes.Length
            PayloadEmbeddedBytes = $payloadToEmbed.Length
            CapacityBytes       = $cap.CapacityBytes
            UsedBytes           = $totalBytes
            ScanTime            = (Get-Date).ToString("s")
        }

        $reportFile = Join-Path $ScanFolder "report.json"
        $report | ConvertTo-Json -Depth 6 | Out-File $reportFile -Encoding utf8

        return [PSCustomObject]@{ Success = $true; OutputImage = $OutputImagePath; ReportFile = $reportFile }
    }
    finally {
        $bmp.Dispose()
    }
}

function Invoke-StegaDetect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ImagePath,
        [string]$Password,
        [Parameter(Mandatory = $true)][string]$ScanFolder,
        [switch]$DeepChecks,
        [switch]$AttemptExtract
    )

    if (-not (Test-Path $ImagePath)) {
        return [PSCustomObject]@{ Success = $false; Error = "Image not found: $ImagePath" }
    }

    if (-not (Test-Path $ScanFolder)) { New-Item -ItemType Directory -Path $ScanFolder | Out-Null }

    $bmp = New-Object System.Drawing.Bitmap $ImagePath
    try {
        # Extract LSBs for all pixels (same order as embedding: R,G,B)
        $bitList = New-Object System.Collections.Generic.List[byte]
        for ($y = 0; $y -lt $bmp.Height; $y++) {
            for ($x = 0; $x -lt $bmp.Width; $x++) {
                $color = $bmp.GetPixel($x, $y)
                $bitList.Add([byte]($color.R -band 1))
                $bitList.Add([byte]($color.G -band 1))
                $bitList.Add([byte]($color.B -band 1))
            }
        }

        $Bytes = BitsToBytes -bits $bitList.ToArray()
        $parsedHeader = $null; $foundHeader = $false
        try { $parsedHeader = Parse-Header -Data $Bytes; $foundHeader = $true } catch { }

        $extractedFile = $null; $issues = @(); $detectionBasis = @()

        # Determine operational mode for reporting clarity
        $mode = if ($AttemptExtract.IsPresent) { "Extract" } elseif ($DeepChecks.IsPresent) { "Deep" } else { "Quick" }

        # Attempt extraction only if requested or if header found
        if ($AttemptExtract -or $foundHeader) {
            if ($foundHeader -and $parsedHeader) {
                $payloadStart = $parsedHeader.HeaderSize
                $payloadLen = [int]$parsedHeader.PayloadLength
                if ($payloadStart + $payloadLen -le $Bytes.Length) {
                    $payloadBytes = $Bytes[$payloadStart..($payloadStart + $payloadLen - 1)]
                    if ($parsedHeader.Encrypted -and $Password) {
                        try {
                            $plain = Decrypt-Bytes -EncryptedData $payloadBytes -Salt $parsedHeader.Salt -InitializationVector $parsedHeader.InitializationVector -Password $Password
                            $outName = Join-Path $ScanFolder $parsedHeader.PayloadName
                            [System.IO.File]::WriteAllBytes($outName, $plain)
                            $extractedFile = $outName
                            $detectionBasis += "Header-based extraction: payload saved"
                        } catch {
                            $issues += "Decryption failed: $($_.Exception.Message)"
                            $detectionBasis += "Header-based extraction attempted: decryption failed"
                        }
                    } elseif ($parsedHeader.Encrypted -and -not $Password) {
                        $issues += "Payload is encrypted but no password provided."
                        $detectionBasis += "Header-based extraction: encrypted payload, no password"
                    } else {
                        $outName = Join-Path $ScanFolder $parsedHeader.PayloadName
                        [System.IO.File]::WriteAllBytes($outName, $payloadBytes)
                        $extractedFile = $outName
                        $detectionBasis += "Header-based extraction: payload saved"
                    }
                } else {
                    $issues += "Payload length exceeds available data."
                    $detectionBasis += "Header parse succeeded but payload length invalid"
                }
            } elseif ($AttemptExtract -and -not $foundHeader) {
                $issues += "No valid header found for extraction."
                $detectionBasis += "Extraction attempted but no header present"
            }
        }

        # -- LSB statistics (always run) --
        $totalBits = $bitList.Count
        $ones = 0
        foreach ($b in $bitList) { if ($b -eq 1) { $ones++ } }
        $lsbRatio = if ($totalBits -gt 0) { $ones / $totalBits } else { 0 }

        # Block analysis: split into blocks of 8x8 pixels
        $blockWidth = 8; $blockHeight = 8
        $blocks = @()
        for ($by = 0; $by -lt $bmp.Height; $by += $blockHeight) {
            for ($bx = 0; $bx -lt $bmp.Width; $bx += $blockWidth) {
                $blockOnes = 0; $blockBits = 0
                for ($y = $by; ($y -lt $bmp.Height) -and ($y -lt $by + $blockHeight); $y++) {
                    for ($x = $bx; ($x -lt $bmp.Width) -and ($x -lt $bx + $blockWidth); $x++) {
                        $color = $bmp.GetPixel($x, $y)
                        $blockOnes += ($color.R -band 1) + ($color.G -band 1) + ($color.B -band 1)
                        $blockBits += 3
                    }
                }
                if ($blockBits -gt 0) { $blocks += @{ Ones = $blockOnes; Bits = $blockBits } }
            }
        }

        $anomalousBlockCount = 0; $blockRatios = @()
        foreach ($binfo in $blocks) {
            $r = $binfo.Ones / $binfo.Bits
            $blockRatios += $r
            if (($r -ge 0.47 -and $r -le 0.53) -or ($r -le 0.05) -or ($r -ge 0.95)) { $anomalousBlockCount++ }
        }

        # Build detection signals depending on mode
        $suspiciousWithoutHeader = $false
        $suspicionReasons = @()

        # Quick mode: lightweight checks (global + simple local)
        if ($mode -eq "Quick") {
            $detectionBasis += "Quick: global LSB ratio and block anomaly checks"
            if ($lsbRatio -ge 0.47 -and $lsbRatio -le 0.53) {
                $suspiciousWithoutHeader = $true
                $suspicionReasons += "Global LSB ratio near 0.5 (ratio: $([math]::Round($lsbRatio,3))) -> possible LSB embedding."
            }
            $totalBlocks = $blockRatios.Count
            if ($totalBlocks -gt 0) {
                $anomalousFraction = $anomalousBlockCount / $totalBlocks
                if ($anomalousFraction -ge 0.15) { # quick mode uses slightly stricter fraction
                    $suspiciousWithoutHeader = $true
                    $suspicionReasons += "Anomalous blocks detected ($anomalousBlockCount/$totalBlocks, fraction: $([math]::Round($anomalousFraction,3))) -> localized stego possible."
                }
            }
        }
        # Deep mode: add sampled chi-like statistics and more sensitive thresholds
        elseif ($mode -eq "Deep") {
            $detectionBasis += "Deep: block analysis, sampled chi-like deviation & heuristics"
            # Sampled ratio with step to speed large images
            $step = 10
            $lsbSum = 0; $sampleCount = 0
            for ($y = 0; $y -lt $bmp.Height; $y += $step) {
                for ($x = 0; $x -lt $bmp.Width; $x += $step) {
                    $color = $bmp.GetPixel($x, $y)
                    $lsbSum += ($color.R -band 1) + ($color.G -band 1) + ($color.B -band 1)
                    $sampleCount++
                }
            }
            $sampleBits = $sampleCount * 3
            $sampleRatio = if ($sampleBits -gt 0) { $lsbSum / $sampleBits } else { 0 }

            # Chi-like deviation (two-category deviation from expected 50/50)
            $deviation = [math]::Abs($sampleRatio - 0.5)
            $detectionBasis += "Sampled LSB ratio: $([math]::Round($sampleRatio,4))"
            if ($deviation -ge 0.04) {
                $suspiciousWithoutHeader = $true
                $suspicionReasons += "Significant sampled LSB deviation detected (sample ratio: $([math]::Round($sampleRatio,4)), deviation: $([math]::Round($deviation,4)))."
            }

            # Local block anomaly check (more sensitive in deep mode)
            $totalBlocks = $blockRatios.Count
            if ($totalBlocks -gt 0) {
                $anomalousFraction = $anomalousBlockCount / $totalBlocks
                if ($anomalousFraction -ge 0.08) { # deep mode is more sensitive
                    $suspiciousWithoutHeader = $true
                    $suspicionReasons += "Anomalous blocks detected ($anomalousBlockCount/$totalBlocks, fraction: $([math]::Round($anomalousFraction,3))) -> localized stego likely."
                }
            }

            # Extreme bias check
            if ($lsbRatio -le 0.02 -or $lsbRatio -ge 0.98) {
                $suspiciousWithoutHeader = $true
                $suspicionReasons += "Extreme global LSB bias detected (ratio: $([math]::Round($lsbRatio,3)))."
            }
        }

        # If header missing but flagged suspicious, add reasons and basis
        if (-not $foundHeader -and $suspiciousWithoutHeader) {
            $issues += $suspicionReasons
        }

        # Compute a simple confidence level based on signals
        $confidence = "Low"
        if ($suspiciousWithoutHeader) {
            # stronger signals -> higher confidence
            $score = 0
            $score += ([math]::Round([math]::Abs($lsbRatio - 0.5) * 100,0))
            $score += $anomalousBlockCount * 2
            if ($score -ge 15) { $confidence = "High" } elseif ($score -ge 6) { $confidence = "Medium" } else { $confidence = "Low" }
        } elseif ($foundHeader) {
            $confidence = "High"
            $detectionBasis += "Header parse: positive"
        }

        # Compose final report with clear differences by mode
        $report = [PSCustomObject]@{
            Mode                = $mode
            Image               = $ImagePath
            FoundHeader         = $foundHeader
            SuspiciousWithoutHeader = $suspiciousWithoutHeader
            DetectionBasis      = $detectionBasis
            SuspicionReasons    = if ($suspiciousWithoutHeader) { $suspicionReasons } else { @() }
            Confidence          = $confidence
            LsbRatio            = [math]::Round($lsbRatio, 4)
            PayloadName         = if ($parsedHeader) { $parsedHeader.PayloadName } else { $null }
            Encrypted           = if ($parsedHeader) { $parsedHeader.Encrypted } else { $false }
            ExtractedFile       = $extractedFile
            Issues              = $issues
            DeepChecks          = $DeepChecks.IsPresent
            AttemptExtract      = $AttemptExtract.IsPresent
            ScanTime            = (Get-Date).ToString("s")
        }

        $reportFile = Join-Path $ScanFolder "report.json"
        $report | ConvertTo-Json -Depth 10 | Out-File $reportFile -Encoding utf8
        return [PSCustomObject]@{ Success = $true; ReportFile = $reportFile; ExtractedFile = $extractedFile }
    }
    finally {
        $bmp.Dispose()
    }
}

Export-ModuleMember -Function Invoke-StegaEmbed, Invoke-StegaDetect, Get-ImageCapacity
