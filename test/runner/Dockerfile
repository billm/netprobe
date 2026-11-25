# PowerShell images are amd64-only; this runs under emulation on Apple silicon.
FROM --platform=linux/amd64 mcr.microsoft.com/powershell:7.5-ubuntu-24.04@sha256:042240d57ec9e47e511033b92625a8d95875ee5860af3015992c248b58a8be81
RUN pwsh -NoProfile -Command \
  "Install-Module PSScriptAnalyzer -RequiredVersion 1.24.0 -Scope AllUsers -Force"
