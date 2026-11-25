# PSScriptAnalyzer with the repo settings (Windows PowerShell 5.1 syntax). Exits non-zero on
# any finding.
$findings = @(
  foreach ($f in '/work/netprobe.ps1', '/work/test/run-tests.ps1', '/work/test/lint.ps1') {
    Invoke-ScriptAnalyzer -Path $f -Settings /work/PSScriptAnalyzerSettings.psd1
  }
)
$findings | Format-Table ScriptName, Line, RuleName, Message -AutoSize -Wrap | Out-String -Width 160
if ($findings.Count -gt 0) { exit 1 }
Write-Output 'PSScriptAnalyzer: no findings'
