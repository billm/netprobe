# PowerShell images are amd64-only; this runs under emulation on Apple silicon.
FROM --platform=linux/amd64 mcr.microsoft.com/powershell:7.5-ubuntu-24.04@sha256:042240d57ec9e47e511033b92625a8d95875ee5860af3015992c248b58a8be81
RUN pwsh -NoProfile -Command \
  "Install-Module PSScriptAnalyzer -RequiredVersion 1.24.0 -Scope AllUsers -Force"
# System.DirectoryServices.Protocols on Linux loads libldap-2.5.so.0; Ubuntu 24.04 ships
# OpenLDAP 2.6 as libldap.so.2. Test runner only: Windows uses wldap32.dll.
RUN apt-get update && apt-get install -y --no-install-recommends libldap2 && apt-get clean \
 && ln -s /usr/lib/x86_64-linux-gnu/libldap.so.2 /usr/lib/x86_64-linux-gnu/libldap-2.5.so.0
