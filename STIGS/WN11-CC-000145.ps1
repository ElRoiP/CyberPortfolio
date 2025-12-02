<#
.SYNOPSIS
    Ensures that the registry value 'DCSettingIndex' at 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' is set to '1'.
.NOTES
    Author          : El Roi Pablo
    LinkedIn        : linkedin.com/in/Elroipablo/
    GitHub          : github.com/ElRoiP
    Date Created    : 2025-11-30
    Last Modified   : 2025-11-30
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000145

.USAGE
    PS C:\> .\WN11-CC-000145.ps1
#>

$RegPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$ValueName = "DCSettingIndex"
$Value     = 1

# Ensure the registry key exists
if (-not (Test-Path $RegPath))
{
    New-Item -Path $RegPath -Force | Out-Null
}

# Set (or overwrite) the registry value
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $Value -Force

Write-Host "STIG Enforcement Complete." -ForegroundColor Green
