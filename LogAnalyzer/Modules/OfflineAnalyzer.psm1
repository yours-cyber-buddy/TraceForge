# OfflineAnalyzer.psm1 - TraceForge Local Analysis Logic (upgraded, syntax-fixed)
# - Respects existing trusted_config.json keys:
#   trusted_processes (array), trusted_vendors (array), trusted_ip_prefixes (array)
# - Adds Category and improved Reason fields for Process, Service, Autorun, Network entries
# - Backward compatible: does not change invocation signature

function Load-TrustedConfig {
    param(
        [string]$TrustedConfigPath
    )

    if (-not (Test-Path $TrustedConfigPath)) {
        Write-Host "Trusted config not found at $TrustedConfigPath" -ForegroundColor Red
        return $null
    }

    try {
        $json = Get-Content $TrustedConfigPath -Raw | ConvertFrom-Json
        return $json
    } catch {
        Write-Host "Error reading trusted config JSON: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Helper: is localhost or loopback
function Is-Localhost {
    param([string]$ip)
    if (-not $ip) { return $false }
    return ($ip -match '^(127\.0\.0\.1|::1)')
}

# Helper: is private IPv4 range (strips port if present)
function Is-PrivateIP {
    param([string]$ip)
    if (-not $ip) { return $false }
    $addr = ($ip -split ':')[0]
    return (
        $addr -match '^10\.' -or
        $addr -match '^192\.168\.' -or
        $addr -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.'
    )
}

# Case-insensitive contains helper for collections (safe)
function Contains-Insensitive {
    param($collection, $value)
    if (-not $collection -or -not $value) { return $false }
    foreach ($item in $collection) {
        if ($null -eq $item) { continue }
        try {
            if ($value -imatch [regex]::Escape($item.ToString())) { return $true }
        } catch {
            if ($item.ToString().ToLower() -eq $value.ToString().ToLower()) { return $true }
        }
    }
    return $false
}

# Default trusted vendor fallbacks (used if trusted config lacks entries)
$Script:DefaultTrustedVendors = @(
    'Microsoft', 'Google', 'VMware', 'ASUSTeK', 'Riot', 'OpenVPN', 'Gen Digital',
    'Oracle', 'NVIDIA', 'Intel', 'KRAFTON', 'BattlEye', 'Brave', 'OneDrive'
)

# System process names (commonly safe)
$Script:SystemProcessNames = @('svchost','services','wininit','lsass','csrss','System','smss','winlogon')

# Analyze a process entry: adds Category, Reason, adjusts Suspicious
function Analyze-ProcessEntry {
    param(
        [Parameter(Mandatory=$true)] $p,
        [Parameter(Mandatory=$false)] $trusted
    )

    if (-not $p) { return }

    if (-not ($p.PSObject.Properties.Name -contains 'Category')) { $p | Add-Member -NotePropertyName Category -NotePropertyValue $null -Force }
    if (-not ($p.PSObject.Properties.Name -contains 'Reason')) { $p | Add-Member -NotePropertyName Reason -NotePropertyValue $null -Force }

    $name = $p.Name
    $path = $p.Path
    $origSusp = $false
    if ($p.PSObject.Properties.Name -contains 'Suspicious') { $origSusp = [bool]$p.Suspicious }

    # Default
    $p.Suspicious = $origSusp
    $p.Reason = $p.Reason

    # Trusted processes from config (explicit allowlist)
    if ($trusted -and $trusted.trusted_processes -and (Contains-Insensitive $trusted.trusted_processes $name)) {
        $p.Suspicious = $false
        $p.Category = 'Trusted Process'
        $p.Reason = 'Listed in trusted_processes'
        return
    }

    # Missing path -> suspicious
    if (-not $path -or $path -in @($null,'')) {
        $p.Suspicious = $true
        $p.Category = 'Unknown'
        $p.Reason = 'Missing or invalid path'
        return
    }

    $pathLower = $path.ToLower()

    # System binaries
    if ($pathLower -match '\\windows\\' -or $pathLower -match '\\system32\\' -or ($name -and (Contains-Insensitive $Script:SystemProcessNames $name))) {
        $p.Suspicious = $false
        $p.Category = 'System Process'
        $p.Reason = 'System path or known system process'
        return
    }

    # Program Files -> normal user app
    if ($pathLower -match '\\program files( \(x86\))?\\') {
        $p.Suspicious = $false
        $p.Category = 'User Application'
        $p.Reason = 'Standard Program Files install'
        return
    }

    # VS Code and developer tools: explicit allowlist heuristics
    if ($pathLower -match '\\appdata\\local\\programs\\microsoft vs code\\' -or $pathLower -match '\\.vscode\\extensions\\' -or ($name -and $name -match '^(Code|code|python|pip|node|npm|git)$')) {
        $p.Suspicious = $false
        $p.Category = 'Developer Tool'
        $p.Reason = 'Developer tool or VS Code component (allow-listed)'
        return
    }

    # AppData local programs (user-installed apps)
    if ($pathLower -match '\\appdata\\local\\') {
        $p.Suspicious = $false
        $p.Category = 'User Installed Application'
        $p.Reason = 'Installed under user AppData (user apps)'
        return
    }

    # If originally flagged suspicious, keep and provide reason
    if ($origSusp) {
        $p.Suspicious = $true
        $p.Category = 'Unknown'
        if (-not $p.Reason -or $p.Reason -eq '') { $p.Reason = 'Unusual execution path or flagged by collector' }
        return
    }

    # Default: consider non-suspicious but unknown category
    $p.Suspicious = $false
    $p.Category = 'Unknown'
    if (-not $p.Reason -or $p.Reason -eq '') { $p.Reason = 'No indicators matched (inspect manually if needed)' }
}

# Analyze a service entry: Category, Reason, Suspicious
function Analyze-ServiceEntry {
    param(
        [Parameter(Mandatory=$true)] $s,
        [Parameter(Mandatory=$false)] $trusted
    )

    if (-not $s) { return }

    if (-not ($s.PSObject.Properties.Name -contains 'Category')) { $s | Add-Member -NotePropertyName Category -NotePropertyValue $null -Force }
    if (-not ($s.PSObject.Properties.Name -contains 'Reason')) { $s | Add-Member -NotePropertyName Reason -NotePropertyValue $null -Force }

    $name    = $s.ServiceName
    $path    = $s.Path
    $vendor  = $s.Vendor
    $signer  = $s.Signer
    $origSusp = $false
    if ($s.PSObject.Properties.Name -contains 'Suspicious') { $origSusp = [bool]$s.Suspicious }

    $s.Suspicious = $origSusp
    $s.Reason = $s.Reason

    # Config trusted vendors first
    if ($trusted -and $trusted.trusted_vendors -and (Contains-Insensitive $trusted.trusted_vendors $vendor -or Contains-Insensitive $trusted.trusted_vendors $signer)) {
        $s.Suspicious = $false
        $s.Category = 'User Application Service'
        $s.Reason = 'Vendor listed in trusted_vendors'
        return
    }

    # fallback trusted vendor matching with defaults
    foreach ($v in $Script:DefaultTrustedVendors) {
        if (($vendor -and ($vendor -imatch $v)) -or ($signer -and ($signer -imatch $v))) {
            $s.Suspicious = $false
            if ($v -match 'Microsoft') {
                $s.Category = 'System Service'
                $s.Reason = 'Signed by Microsoft (trusted)'
            } else {
                $s.Category = 'User Application Service'
                $s.Reason = "Signed by known vendor ($v)"
            }
            return
        }
    }

    # unsigned / missing signer
    if (-not $vendor -and -not $signer) {
        $s.Suspicious = $true
        $s.Category = 'Untrusted'
        $s.Reason = 'Unsigned or missing signer information'
        return
    }

    # path checks: running from Temp or roaming -> suspicious
    if ($path -and ($path -imatch 'temp' -or ($path -imatch '\\appdata\\roaming\\' -and -not ($path -imatch '\\appdata\\local\\programs')))) {
        $s.Suspicious = $true
        $s.Category = 'Untrusted'
        $s.Reason = 'Service running from unusual directory (temp or roaming)'
        return
    }

    # default: non-suspicious but user service
    $s.Suspicious = $false
    $s.Category = 'User Application Service'
    if (-not $s.Reason -or $s.Reason -eq '') { $s.Reason = 'Signed by non-Microsoft vendor or unknown; path appears legitimate' }
}

# Analyze autorun entry: Category, Reason, Suspicious
function Analyze-AutorunEntry {
    param(
        [Parameter(Mandatory=$true)] $a,
        [Parameter(Mandatory=$false)] $trusted
    )

    if (-not $a) { return }

    if (-not ($a.PSObject.Properties.Name -contains 'Category')) { $a | Add-Member -NotePropertyName Category -NotePropertyValue $null -Force }
    if (-not ($a.PSObject.Properties.Name -contains 'Reason')) { $a | Add-Member -NotePropertyName Reason -NotePropertyValue $null -Force }

    $name = $a.Name
    $path = $a.Path
    $exists = $a.Exists
    $origSusp = $false
    if ($a.PSObject.Properties.Name -contains 'Suspicious') { $origSusp = [bool]$a.Suspicious }

    $a.Suspicious = $origSusp
    $a.Reason = $a.Reason

    # Trusted by name
    if ($trusted -and $trusted.trusted_processes -and (Contains-Insensitive $trusted.trusted_processes $name)) {
        $a.Suspicious = $false
        $a.Category = 'Startup Entry'
        $a.Reason = 'Listed in trusted_processes'
        return
    }

    # Modern protocols (UWP / ms-protocol) or shell links
    if ($path -and ($path -match '^ms-protocol:' -or $path -match '^shell:')) {
        $a.Suspicious = $false
        $a.Category = 'Startup Entry (protocol/UWP)'
        $a.Reason = 'Modern autorun protocol / AppContract (not a regular file)'
        return
    }

    # If file exists on disk -> not suspicious
    if ($exists -eq $true -or ($path -and (Test-Path $path))) {
        $a.Suspicious = $false
        $a.Category = 'Startup Entry'
        $a.Reason = 'Target executable exists'
        return
    }

    # If file missing but in WindowsApps or UWP-style path, treat as non-suspicious
    if ($path -and ($path -match 'WindowsApps' -or $path -match 'AppX')) {
        $a.Suspicious = $false
        $a.Category = 'Startup Entry (UWP/AppX)'
        $a.Reason = 'UWP/WindowsApps entry (file missing from standard path)'
        return
    }

    # If Exists false and not previously handled -> orphaned/disabled autorun
    if ($exists -eq $false) {
        $a.Suspicious = $true
        $a.Category = 'Orphaned/Disabled Autorun'
        if (-not $a.Reason -or $a.Reason -eq '') {
            $a.Reason = 'File missing or autorun entry orphaned (inspect / remove if unwanted)'
        }
        return
    }

    # default fallback
    $a.Suspicious = $false
    $a.Category = 'Startup Entry'
    if (-not $a.Reason -or $a.Reason -eq '') { $a.Reason = 'No specific issues detected' }
}

# Analyze network entry with context
function Analyze-NetworkEntry {
    param(
        [Parameter(Mandatory=$true)] $n,
        [Parameter(Mandatory=$false)] $trusted
    )

    if (-not $n) { return }

    if (-not ($n.PSObject.Properties.Name -contains 'Category')) { $n | Add-Member -NotePropertyName Category -NotePropertyValue $null -Force }
    if (-not ($n.PSObject.Properties.Name -contains 'Reason')) { $n | Add-Member -NotePropertyName Reason -NotePropertyValue $null -Force }

    $dest = $n.DestinationIP
    $proc = $n.Process
    $origSusp = $false
    if ($n.PSObject.Properties.Name -contains 'Suspicious') { $origSusp = [bool]$n.Suspicious }

    # default: keep previous suspicious flag if present; otherwise default to $false
    $n.Suspicious = $origSusp

    # Localhost/loopback
    if ($dest -and (Is-Localhost $dest -or $dest -match '^127\.|::1')) {
        $n.Suspicious = $false
        $n.Category = 'Localhost Communication'
        $n.Reason = 'Loopback communication between local components'
        return
    }

    # Private LAN
    if ($dest -and (Is-PrivateIP $dest)) {
        $n.Suspicious = $false
        $n.Category = 'Private LAN Communication'
        $n.Reason = 'Local network communication (private IP)'
        return
    }

    # System process making external connections: mark informational
    if ($proc -and (Contains-Insensitive $Script:SystemProcessNames $proc)) {
        $n.Suspicious = $false
        $n.Category = 'System Process External Communication'
        $n.Reason = 'System service making external connection (inspect IP if unknown)'
        return
    }

    # Trusted prefixes from config
    if ($dest -and $trusted -and $trusted.trusted_ip_prefixes) {
        foreach ($prefix in $trusted.trusted_ip_prefixes) {
            if ($dest.StartsWith($prefix)) {
                $n.Suspicious = $false
                $n.Category = 'Trusted External'
                $n.Reason = "Destination matches trusted prefix $prefix"
                return
            }
        }
    }

    # fallback: mark suspicious (unclassified external IP)
    $n.Suspicious = $true
    $n.Category = 'External Connection'
    $n.Reason = 'Unclassified external IP (requires review)'
}

function Invoke-OfflineAnalysis {
    param(
        [Parameter(Mandatory=$true)][string]$ScanFolder,
        [Parameter(Mandatory=$true)][string]$TrustedConfigPath
    )

    Write-Host "`nStarting Offline Analysis..." -ForegroundColor Cyan

    $trusted = Load-TrustedConfig -TrustedConfigPath $TrustedConfigPath
    if (-not $trusted) {
        Write-Host 'No trusted configuration loaded — continuing with defaults.' -ForegroundColor Yellow
    }

    # --- Process Analysis ---
    $processFile = Join-Path $ScanFolder 'Processes.json'
    if (Test-Path $processFile) {
        $processes = Get-Content $processFile -Raw | ConvertFrom-Json

        foreach ($p in $processes) {
            try {
                Analyze-ProcessEntry -p $p -trusted $trusted
            } catch {
                Write-Host "Error analyzing process entry $($p.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        $processes | ConvertTo-Json -Depth 6 | Out-File (Join-Path $ScanFolder 'Processes_Analyzed.json') -Encoding utf8
        Write-Host "[+] Processes analysis saved to $ScanFolder\Processes_Analyzed.json"
    }

    # --- Service Analysis ---
    $serviceFile = Join-Path $ScanFolder 'Services.json'
    if (Test-Path $serviceFile) {
        $services = Get-Content $serviceFile -Raw | ConvertFrom-Json

        foreach ($s in $services) {
            try {
                Analyze-ServiceEntry -s $s -trusted $trusted
            } catch {
                Write-Host "Error analyzing service entry $($s.ServiceName): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        $services | ConvertTo-Json -Depth 6 | Out-File (Join-Path $ScanFolder 'Services_Analyzed.json') -Encoding utf8
        Write-Host "[+] Services analysis saved to $ScanFolder\Services_Analyzed.json"
    }

    # --- Autorun Analysis ---
    $autorunFile = Join-Path $ScanFolder 'Autoruns.json'
    if (Test-Path $autorunFile) {
        $autoruns = Get-Content $autorunFile -Raw | ConvertFrom-Json

        foreach ($a in $autoruns) {
            try {
                Analyze-AutorunEntry -a $a -trusted $trusted
            } catch {
                Write-Host "Error analyzing autorun entry $($a.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        $autoruns | ConvertTo-Json -Depth 6 | Out-File (Join-Path $ScanFolder 'Autoruns_Analyzed.json') -Encoding utf8
        Write-Host "[+] Autoruns analysis saved to $ScanFolder\Autoruns_Analyzed.json"
    }

    # --- Network Analysis ---
    $networkFile = Join-Path $ScanFolder 'Network.json'
    if (Test-Path $networkFile) {
        $networks = Get-Content $networkFile -Raw | ConvertFrom-Json

        foreach ($n in $networks) {
            try {
                Analyze-NetworkEntry -n $n -trusted $trusted
            } catch {
                Write-Host "Error analyzing network entry $($n.Process): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        $networks | ConvertTo-Json -Depth 6 | Out-File (Join-Path $ScanFolder 'Network_Analyzed.json') -Encoding utf8
        Write-Host "[+] Network analysis saved to $ScanFolder\Network_Analyzed.json"
    }

    Write-Host "`n[Scan Complete] All results analyzed in: $ScanFolder" -ForegroundColor Green
}

Export-ModuleMember -Function Invoke-OfflineAnalysis
