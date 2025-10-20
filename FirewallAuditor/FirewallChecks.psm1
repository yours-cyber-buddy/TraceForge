#FirewallChecks.psm1
<#
.SYNOPSIS
    Core analysis logic for TraceForge Firewall Auditor
#>

function Invoke-FirewallAnalysis {
    param(
        [Parameter(Mandatory=$true)][array]$Rules,
        [Parameter(Mandatory=$true)][string]$OutputFolder
    )

    $results = @()
    $remediationFile = Join-Path $OutputFolder ((Split-Path $OutputFolder -Leaf) + "_Remediation.ps1")

    # Start remediation file
    @"
# ============================================================
# TraceForge Firewall Remediation Script
# Generated: $(Get-Date)
# Each section below corresponds to a risky rule identified.
# ============================================================

"@ | Out-File $remediationFile -Encoding utf8

    foreach ($rule in $Rules) {
        $riskLevel = "Low"
        $issueDesc = @()
        $fixCmds   = @()

        # --- Risk Detection Rules ---
        if ($rule.Action -eq "Allow" -and $rule.Enabled -eq "True") {
            if ($rule.RemoteAddress -eq "Any" -or $rule.RemoteAddress -match "0\.0\.0\.0") {
                $riskLevel = "High"
                $issueDesc += "Allows inbound connections from ANY remote address."
                $fixCmds += "Set-NetFirewallRule -Name '$($rule.Name)' -Enabled False  # Disable risky rule"
            }
            if ($rule.LocalPort -eq "Any" -or $rule.LocalPort -eq "0") {
                $riskLevel = "High"
                $issueDesc += "Allows all local ports (wildcard)."
                $fixCmds += "Set-NetFirewallRule -Name '$($rule.Name)' -LocalPort <specific_port>"
            }
            if ($rule.Protocol -eq "Any" -or $rule.Protocol -eq "0") {
                $riskLevel = "Medium"
                $issueDesc += "Applies to all protocols."
            }
            if ($rule.Profile -eq "Any") {
                $riskLevel = "Medium"
                $issueDesc += "Applies to all profiles (Domain, Private, Public)."
            }
        }

        # If no issues found, skip
        if ($issueDesc.Count -eq 0) {
            continue
        }

        # Save result
        $result = [PSCustomObject]@{
            Name         = $rule.Name
            DisplayName  = $rule.DisplayName
            Direction    = $rule.Direction
            Action       = $rule.Action
            Enabled      = $rule.Enabled
            RiskLevel    = $riskLevel
            IssuesFound  = $issueDesc
            RecommendationFile = (Split-Path $remediationFile -Leaf)
        }

        $results += $result

        # Write fixes into remediation file
        Add-Content $remediationFile ("# --- Remediation for Rule: {0}`n" -f $rule.DisplayName)
        $fixCmds | ForEach-Object { Add-Content $remediationFile ("$_`n") }
        Add-Content $remediationFile "`n"
    }

    if ($results.Count -eq 0) {
        Add-Content $remediationFile "# No high-risk rules detected. System configuration appears safe.`n"
    }

    return $results
}
Export-ModuleMember -Function Invoke-FirewallAnalysis
