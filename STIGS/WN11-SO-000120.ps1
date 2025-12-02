<#
.SYNOPSIS
    Ensures that the registry value 'RequireSecuritySignature' at 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' is set to '1'.
.NOTES
    Author          : El Roi Pablo
    LinkedIn        : linkedin.com/in/Elroipablo/
    GitHub          : github.com/ElRoiP
    Date Created    : 2025-11-30
    Last Modified   : 2025-11-30
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000120

.USAGE
    PS C:\> .\WN11-SO-000120.ps1
#>

$RegPath   = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$ValueName = "RequireSecuritySignature"
$Value     = 1

if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $Value -Force
Write-Host "STIG Enforcement Complete." -ForegroundColor Green
