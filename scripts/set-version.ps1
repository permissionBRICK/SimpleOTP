<#
.SYNOPSIS
  Set the MAJOR.MINOR release line in version.json.

.DESCRIPTION
  The PATCH number is NOT stored here — CI computes it automatically on each push to master by
  counting existing v<major>.<minor>.* tags, so bumping major or minor here makes the next release
  restart at patch 0 (e.g. 1.4 -> 2.0 makes the next release v2.0.0).

.EXAMPLE
  scripts/set-version.ps1 1.2
  scripts/set-version.ps1 1.2 -Commit
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Version,
    [switch]$Commit
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

if ($Version -notmatch '^(\d+)\.(\d+)$') {
    Write-Error "version must be MAJOR.MINOR (e.g. 1.2), got '$Version'"
    exit 2
}
$major = [int]$Matches[1]
$minor = [int]$Matches[2]

"{`n  `"major`": $major,`n  `"minor`": $minor`n}`n" | Set-Content -NoNewline -Path version.json
Write-Host "version.json set to $major.$minor (next release: v$major.$minor.0)"

if ($Commit) {
    git add version.json
    git commit -m "Set version line to $major.$minor"
    Write-Host "Committed. Push to master to cut v$major.$minor.0."
} else {
    Write-Host "Review, commit, and push version.json to master to cut v$major.$minor.0."
}
