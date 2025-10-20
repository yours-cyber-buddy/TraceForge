# SecureCore.psm1 — core crypto functions for SecureFileStorage
# Exports: Encrypt-File, Decrypt-File, Secure-Delete, Derive-Key, Get-SHA256HashBytes

function Convert-SecureStringToBytes {
    param([System.Security.SecureString]$s)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
    try { return [System.Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)) }
    finally { if ($bstr) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) } }
}

function Derive-Key {
    param([byte[]]$salt, [System.Security.SecureString]$password)
    $passwordBytes = Convert-SecureStringToBytes -s $password
    $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($passwordBytes, $salt, 10000)
    $key = $derive.GetBytes(32)
    return $key
}

function Get-SHA256HashBytes {
    param([byte[]]$data)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return $sha.ComputeHash($data) } finally { $sha.Dispose() }
}

function Bytes-ToHex {
    param([byte[]]$bytes)
    return ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLower()
}

function Encrypt-File {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][System.Security.SecureString]$Password
    )

    if (-not (Test-Path $FilePath)) { throw "File not found: $FilePath" }
    $origBytes = [System.IO.File]::ReadAllBytes($FilePath)

    # generate salt and iv
    $salt = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    $iv = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)

    # derive key
    $key = Derive-Key -salt $salt -password $Password

    # encrypt to temp .enc file in same folder
    $encPathTmp = "$FilePath.enc.tmp"
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $key; $aes.IV = $iv

    try {
        $encryptor = $aes.CreateEncryptor()
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($origBytes, 0, $origBytes.Length)
        $cs.FlushFinalBlock()
        $encBytes = $ms.ToArray()
    } finally {
        if ($cs) { $cs.Close() }
        if ($ms) { $ms.Close() }
        $aes.Dispose()
    }

    [System.IO.File]::WriteAllBytes($encPathTmp, $encBytes)

    # basic checks
    if (-not (Test-Path $encPathTmp)) { throw "Encryption failed: temporary file not created." }
    if ((Get-Item $encPathTmp).Length -le 0) { Remove-Item $encPathTmp -ErrorAction SilentlyContinue; throw "Encryption failed: empty output." }

    # internal verification: decrypt in-memory and compare
    try {
        $decBytes = Decrypt-Bytes -EncryptedBytes $encBytes -Key $key -IV $iv

        # Compare byte arrays safely without using SequenceEqual (PowerShell-native comparison)
        $isEqual = $true
        if ($decBytes.Length -ne $origBytes.Length) {
            $isEqual = $false
        } else {
            for ($i = 0; $i -lt $origBytes.Length; $i++) {
                if ($origBytes[$i] -ne $decBytes[$i]) {
                    $isEqual = $false
                    break
                }
            }
        }

        if (-not $isEqual) {
            Remove-Item $encPathTmp -ErrorAction SilentlyContinue
            throw "Verification failed: decrypted content mismatch."
        }
    } catch {
        Remove-Item $encPathTmp -ErrorAction SilentlyContinue
        throw "Verification failed: $_"
    }

    # write meta file
    $meta = @{
        original_name = [System.IO.Path]::GetFileName($FilePath)
        algorithm     = 'AES-256-CBC'
        salt          = [System.Convert]::ToBase64String($salt)
        iv            = [System.Convert]::ToBase64String($iv)
        hash          = (Bytes-ToHex (Get-SHA256HashBytes -data $origBytes))
        timestamp     = (Get-Date).ToString('s')
    }
    $metaPath = "$FilePath.meta.json"
    $meta | ConvertTo-Json -Depth 6 | Out-File $metaPath -Encoding utf8

    # secure delete original and rename tmp to original path (so encrypted file keeps original name)
    Secure-Delete -Path $FilePath
    $finalEncPath = $FilePath
    Move-Item -Path $encPathTmp -Destination $finalEncPath -Force

    return @{ EncryptedPath = $finalEncPath; MetaPath = $metaPath }
}

function Decrypt-Bytes {
    param([byte[]]$EncryptedBytes, [byte[]]$Key, [byte[]]$IV)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256; $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key = $Key; $aes.IV = $IV
    try {
        $decryptor = $aes.CreateDecryptor()
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $cs.Write($EncryptedBytes, 0, $EncryptedBytes.Length)
        $cs.FlushFinalBlock()
        return $ms.ToArray()
    } finally {
        if ($cs) { $cs.Close() }
        if ($ms) { $ms.Close() }
        $aes.Dispose()
    }
}

function Decrypt-File {
    param(
        [Parameter(Mandatory=$true)][string]$EncryptedPath,
        [Parameter(Mandatory=$true)][System.Security.SecureString]$Password
    )

    if (-not (Test-Path $EncryptedPath)) { throw "Encrypted file not found: $EncryptedPath" }

    # auto-locate meta
    $metaPathCandidate1 = "$EncryptedPath.meta.json"
    $metaPathCandidate2 = (Join-Path (Split-Path $EncryptedPath -Parent) ([System.IO.Path]::GetFileNameWithoutExtension($EncryptedPath) + '.meta.json'))
    $metaPath = $null
    if (Test-Path $metaPathCandidate1) { $metaPath = $metaPathCandidate1 }
    elseif (Test-Path $metaPathCandidate2) { $metaPath = $metaPathCandidate2 }
    else {
        $provided = Read-Host "Meta file not found automatically. Enter full path to meta JSON (or press Enter to skip)"
        if ($provided -and (Test-Path $provided)) { $metaPath = $provided } else { throw "Meta file not provided or found." }
    }

    $meta = Get-Content $metaPath -Raw | ConvertFrom-Json
    $salt = [System.Convert]::FromBase64String($meta.salt)
    $iv = [System.Convert]::FromBase64String($meta.iv)
    $storedHash = $meta.hash

    $key = Derive-Key -salt $salt -password $Password

    $encBytes = [System.IO.File]::ReadAllBytes($EncryptedPath)

    # attempt decrypt in memory
    try {
        $decBytes = Decrypt-Bytes -EncryptedBytes $encBytes -Key $key -IV $iv
    } catch {
        throw "Decryption failed: wrong password or corrupted file. $_"
    }

    # verify hash
    $decHash = Bytes-ToHex (Get-SHA256HashBytes -data $decBytes)
    if ($decHash -ne $storedHash) { throw "Integrity check failed: decrypted hash does not match stored hash." }

    # Prepare safe temporary decrypted file path (don't overwrite encrypted file yet)
    $tempDecPath = "$EncryptedPath.decrypted.tmp"
    [System.IO.File]::WriteAllBytes($tempDecPath, $decBytes)

    # Final output path (original filename from meta)
    $origName = $meta.original_name
    $outPath = Join-Path (Split-Path $EncryptedPath -Parent) $origName

    # Now securely delete the encrypted file
    Secure-Delete -Path $EncryptedPath

    # Move temporary decrypted file to final output path
    if (Test-Path $tempDecPath) {
        Move-Item -Path $tempDecPath -Destination $outPath -Force
    } else {
        throw "Temporary decrypted file missing; cannot complete restore."
    }

    # Remove meta file
    Remove-Item $metaPath -ErrorAction SilentlyContinue

    return @{ OutputPath = $outPath }
}

function Secure-Delete {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        $fi = Get-Item $Path
        # If file is zero-length, just remove it
        $length = $fi.Length
        if ($length -le 0) { Remove-Item $Path -Force -ErrorAction SilentlyContinue; return }
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write)
        try {
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            for ($pass = 0; $pass -lt 3; $pass++) {
                $buf = New-Object byte[] $length
                $rng.GetBytes($buf)
                $stream.Seek(0, [System.IO.SeekOrigin]::Begin)
                $stream.Write($buf, 0, $buf.Length)
                $stream.Flush()
            }
        } finally { $stream.Close() }
        Remove-Item $Path -Force -ErrorAction SilentlyContinue
    } catch {
        # best-effort: if secure overwrite fails, just remove file
        Remove-Item $Path -Force -ErrorAction SilentlyContinue
    }
}

Export-ModuleMember -Function Encrypt-File, Decrypt-File, Secure-Delete, Derive-Key, Get-SHA256HashBytes
