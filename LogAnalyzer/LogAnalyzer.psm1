# LogAnalyzer.psm1 - Imports analyzer modules

$ModuleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Import OfflineAnalyzer module
Import-Module "$ModuleRoot\Modules\OfflineAnalyzer.psm1" -Force

# Import AIAnalyzer module
Import-Module "$ModuleRoot\Modules\AIAnalyzer.psm1" -Force
