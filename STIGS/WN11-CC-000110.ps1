<#
.SYNOPSIS
    Ensures that the registry value 'DisableHTTPPrinting' at 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' is set to '1'.
.NOTES
    Author          : El Roi Pablo
    LinkedIn        : linkedin.com/in/Elroipablo/
    GitHub          : github.com/ElRoiP
    Date Created    : 2025-11-30
    Last Modified   : 2025-11-30
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000110

.USAGE
    PS C:\> .\WN11-CC-000110.ps1
#>

$RegPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$ValueName = "DisableHTTPPrinting"
$Value     = 1

# Ensure the registry key exists
if (-not (Test-Path $RegPath))
{
    New-Item -Path $RegPath -Force | Out-Null
}

# Set (or overwrite) the registry value
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $Value -Force

Write-Host "STIG Enforcement Complete." -ForegroundColor Green
