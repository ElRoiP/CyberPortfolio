<#
.SYNOPSIS
    Ensures that the registry value 'AutoConnectAllowedOEM' at 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' is set to '0'.
.NOTES
    Author          : El Roi Pablo
    LinkedIn        : linkedin.com/in/Elroipablo/
    GitHub          : github.com/ElRoiP
    Date Created    : 2025-11-30
    Last Modified   : 2025-11-30
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000065

.USAGE
    PS C:\> .\WN11-CC-000065.ps1
#>

$RegPath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
$ValueName = "AutoConnectAllowedOEM"
$Value = 0

# Ensure the registry key exists
if (-not (Test-Path $RegPath))
{
    New-Item -Path $RegPath -Force | Out-Null
}

# Set (or overwrite) the registry value
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $Value -Force

Write-Host "STIG Enforcement Complete." -ForegroundColor Green
