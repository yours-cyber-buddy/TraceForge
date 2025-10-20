#LogCollector.psm1

# Import all functional submodules
Import-Module "$PSScriptRoot\Modules\ProcessScanner.psm1" -Force
Import-Module "$PSScriptRoot\Modules\ServiceScanner.psm1" -Force
Import-Module "$PSScriptRoot\Modules\AutorunScanner.psm1" -Force
Import-Module "$PSScriptRoot\Modules\TCPScanner.psm1" -Force

# Export public functions (clean and explicit)
Export-ModuleMember -Function `
    Get-SuspiciousProcesses,
    Get-SuspiciousServices,
    Get-SuspiciousAutoruns,
    Get-SuspiciousConnections
