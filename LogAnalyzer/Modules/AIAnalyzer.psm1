<#
AIAnalyzer.psm1 - Universal AI connector for TraceForge Log Analyzer
#>

function Get-ProviderFromKey {
    param([string]$ApiKey)
    if (-not $ApiKey) { return "mock" }
    $k = $ApiKey.Trim()
    if ($k -match "^sk-" -or $k -match "^openai") { return "openai" }
    if ($k -match "^AIza" -or ($k.Length -gt 40 -and $k -notmatch "^sk-")) { return "gemini" }
    if ($k -match "^anthropic" -or $k -match "^claude" -or $k -match "claude") { return "anthropic" }
    if ($k -match "^deepseek" -or $k -match "deepseek") { return "deepseek" }
    return "unknown"
}

function Build-PromptFromScan {
    param(
        [Parameter(Mandatory = $true)][string]$ScanFolder,
        [int]$MaxLines = 30
    )

    $parts = New-Object System.Collections.Generic.List[string]
    $filesToCheck = @(
        "Processes_Analyzed.json",
        "Services_Analyzed.json",
        "Autoruns_Analyzed.json",
        "Network_Analyzed.json"
    )

    foreach ($f in $filesToCheck) {
        $path = Join-Path $ScanFolder $f
        if (-not (Test-Path $path)) { continue }

        $content = Get-Content -Path $path -Raw -ErrorAction SilentlyContinue
        $parts.Add("=== $f ===`n" + ($content.Substring(0, [Math]::Min(5000, $content.Length))))
    }

    if ($parts.Count -eq 0) { return "No analyzed JSON files found in $ScanFolder." }

    $combined = ($parts -join "`n") -replace "`r", ""
    if ($combined.Length -gt 15000) { $combined = $combined.Substring(0,15000) + "`n[TRUNCATED]" }
    return $combined
}

function Invoke-OpenAIRequest {
    param(
        [string]$ApiKey,
        [string]$Prompt,
        [string]$Model = "gpt-4o-mini"
    )

    $uri = "https://api.openai.com/v1/chat/completions"
    $payload = @{
        model = $Model
        messages = @(
            @{ role = "system"; content = "You are a cybersecurity forensic assistant." }
            @{ role = "user"; content = $Prompt }
        )
        max_tokens = 800
        temperature = 0
    } | ConvertTo-Json -Depth 10

    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers @{ Authorization = "Bearer $ApiKey" } -ContentType "application/json" -Body $payload -TimeoutSec 120
    $text = $response.choices[0].message.content
    return @{ raw = $response; text = $text }
}

function Invoke-GeminiRequest {
    param(
        [string]$ApiKey,
        [string]$Prompt,
        [string]$Model = "text-bison-001"
    )

    $uri = "https://generativelanguage.googleapis.com/v1/models/$Model:generateText?key=$ApiKey"
    $payload = @{ prompt = @{ text = $Prompt }; maxOutputTokens = 800; temperature = 0 } | ConvertTo-Json -Depth 10
    $response = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $payload -TimeoutSec 120
    $text = $response.candidates[0].output
    return @{ raw = $response; text = $text }
}

function Invoke-AIAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ScanFolder,
        [Parameter(Mandatory=$true)][string]$TrustedConfigPath
    )

    Write-Host "`nAI Mode selected." -ForegroundColor Cyan

    if (-not (Test-Path $ScanFolder)) {
        Write-Host "Scan folder not found: $ScanFolder" -ForegroundColor Red
        return
    }

    $envKey = $env:TRACEFORGE_AI_KEY
    if ($envKey) {
        Write-Host "[i] Using TRACEFORGE_AI_KEY from environment." -ForegroundColor Yellow
        $apiKey = $envKey
    } else {
        $apiKey = Read-Host "Enter your AI API key (press Enter for MOCK mode)"
    }

    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        Write-Host "Running in MOCK mode." -ForegroundColor Yellow
        $prompt = Build-PromptFromScan -ScanFolder $ScanFolder
        $mock = @{
            provider = "mock"
            timestamp = (Get-Date).ToString("s")
            summary = "Mock output: no API key used."
            findings = @(@{ id = 1; title = "Demo finding"; severity = "Low"; recommendation = "Provide API key." })
        }
        $outFile = Join-Path $ScanFolder "AI_Analysis.json"
        $mock | ConvertTo-Json -Depth 6 | Out-File $outFile -Encoding utf8
        Write-Host "[MOCK] Saved to $outFile" -ForegroundColor Green
        return
    }

    $provider = Get-ProviderFromKey -ApiKey $apiKey
    if ($provider -eq "unknown") {
        $provider = Read-Host "Provider not detected. Enter manually (openai/gemini)"
    }

    Write-Host "Using provider: $provider" -ForegroundColor Cyan
    $prompt = Build-PromptFromScan -ScanFolder $ScanFolder

@'
You are an expert Windows forensic and incident response assistant.
Analyze the following summarized forensic outputs and produce a JSON object with these keys:
- summary: brief (1-2 sentences)
- findings: array of objects {id, title, evidence, severity (Low/Medium/High/Critical), next_steps}
- recommendations: array of short remediation actions
Return ONLY valid JSON. The data follows:

--- BEGIN DATA ---
'@ | Out-Null

    $instruction = "You are an expert forensic assistant. Analyze this data and output JSON only.`n---DATA---`n$prompt"

    try {
        if ($provider -eq "openai") {
            $resp = Invoke-OpenAIRequest -ApiKey $apiKey -Prompt $instruction
        } elseif ($provider -eq "gemini") {
            $resp = Invoke-GeminiRequest -ApiKey $apiKey -Prompt $instruction
        } else {
            Write-Host "Unsupported provider in this build." -ForegroundColor Red
            return
        }
    } catch {
        Write-Host "API request failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $outFile = Join-Path $ScanFolder "AI_Analysis.json"
    $meta = @{
        provider = $provider
        timestamp = (Get-Date).ToString("s")
        text = $resp.text
    }

    try {
        $parsed = $null
        if ($resp.text.Trim().StartsWith("{")) {
            $parsed = $resp.text | ConvertFrom-Json -ErrorAction Stop
        }
        if ($parsed) { $meta.parsed = $parsed }
    } catch {
        $meta.parse_error = $_.Exception.Message
    }

    $meta | ConvertTo-Json -Depth 10 | Out-File $outFile -Encoding utf8
    Write-Host "[+] AI analysis saved to: $outFile" -ForegroundColor Green
}

Export-ModuleMember -Function Invoke-AIAnalysis
