<#
.SYNOPSIS
    Ensures that the registry value 'DeviceEnumerationPolicy' at 'HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection' is set to '0'.
.NOTES
    Author          : El Roi Pablo
    LinkedIn        : linkedin.com/in/Elroipablo/
    GitHub          : github.com/ElRoiP
    Date Created    : 2025-11-30
    Last Modified   : 2025-11-30
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-EP-000310

.USAGE
    PS C:\> .\WN11-EP-000310.ps1
#>

$RegPath   = "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection"
$ValueName = "DeviceEnumerationPolicy"
$Value     = 0

if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $Value -Force
Write-Host "✔ STIG Enforcement Complete." -ForegroundColor Green
