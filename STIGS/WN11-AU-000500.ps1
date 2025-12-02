<#
.SYNOPSIS
    Ensures that the registry value 'MaxSize' at 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' is set to '0x00008000'.
.NOTES
    Author          : El Roi Pablo
    LinkedIn        : linkedin.com/in/Elroipablo/
    GitHub          : github.com/ElRoiP
    Date Created    : 2025-11-30
    Last Modified   : 2025-11-30
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-AU-000500

.USAGE
    Run this script in PowerShell to enforce the STIG.
    Example:
    PS C:\> .\WN11-AU-000500.ps1
#>

# -------- CONFIGURABLE VALUES --------
$RegPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$ValueName = "MaxSize"
$Value     = 0x00008000   # 32768 KB
# -------------------------------------

# Ensure the registry key exists
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set (or overwrite) the registry value
Set-ItemProperty -Path $RegPath -Name $ValueName -Value $Value -Force

Write-Host "STIG Enforcement Complete." -ForegroundColor Green
