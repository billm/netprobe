@{
  # Syntax must run on Windows PowerShell 5.1, the only PowerShell on the hosts this targets.
  Rules        = @{
    PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1') }
  }
  ExcludeRules = @(
    # An interactive console tool: Write-Host is its UI; results go to CSV/text files.
    'PSAvoidUsingWriteHost',
    # Internal helpers that create an output folder or an options object; no -WhatIf need.
    'PSUseShouldProcessForStateChangingFunctions'
  )
}
