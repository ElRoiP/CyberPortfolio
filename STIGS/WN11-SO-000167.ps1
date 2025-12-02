<#
.SYNOPSIS
    Ensures that the registry value 'RestrictRemoteSAM' at 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' is set to 'O:BAG:BAD:(A;;RC;;;BA)'.
.NOTES
    Author          : El Roi Pablo
    LinkedIn        : linkedin.com/in/Elroipablo/
    GitHub          : github.com/ElRoiP
    Date Created    : 2025-11-30
    Last Modified   : 2025-11-30
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-SO-000167

.USAGE
    PS C:\> .\WN11-SO-000167.ps1
#>

$RegPath   = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$ValueName = "RestrictRemoteSAM"
$Value     = "O:BAG:BAD:(A;;RC;;;BA)"

if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $Value -Force
Write-Host "STIG Enforcement Complete." -ForegroundColor Green
