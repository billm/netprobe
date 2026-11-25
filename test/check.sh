#!/usr/bin/env bash
# Every check for netprobe.ps1:
#   1. its C# compiles as C# 5 against .NET Framework 4.5 (what Add-Type does on PS 5.1)
#   2. PSScriptAnalyzer, including Windows PowerShell 5.1 syntax compatibility
#   3. ruff on the lab's Python
#   4. the scans against the Docker lab (test/compose.yaml)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose() { docker compose -f "$here/compose.yaml" "$@"; }

dotnet build "$here/csharp5/csharp5.csproj" --no-incremental -nologo -v q
ruff check "$here/lab" && ruff format --check "$here/lab"

trap 'compose down --remove-orphans >/dev/null 2>&1' EXIT
compose build --quiet
compose run --rm --no-deps runner pwsh -NoProfile -File /work/test/lint.ps1
compose up -d services empty
compose run --rm runner
