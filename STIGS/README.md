# Windows 11 STIG Remediation with PowerShell

## Overview

This repository contains **PowerShell scripts designed to remediate Windows 11 Security Technical Implementation Guides (STIGs)** published by the Defense Information Systems Agency (DISA).

Each script enforces a specific STIG requirement by configuring Windows registry settings to meet the required security posture. These scripts are intended for **system administrators, security engineers, and compliance teams** managing Windows 11 systems in enterprise or regulated environments.

---

## What Are STIGs?

**Security Technical Implementation Guides (STIGs)** are configuration standards developed by **DISA** to secure information systems used by the U.S. Department of Defense (DoD).

STIGs:
- Define **secure configuration requirements**
- Reduce system attack surface
- Ensure compliance with DoD cybersecurity policies
- Are commonly used outside DoD in regulated environments (finance, healthcare, critical infrastructure)

Each STIG is identified by a unique **STIG ID** (for example: `WN11-CC-000110`) and typically specifies:
- Registry keys and values
- Required settings (enabled/disabled)
- Acceptable value ranges

---

## Why PowerShell?

PowerShell is used for remediation because it:
- Is **native to Windows**
- Can **programmatically enforce registry settings**
- Supports **automation, scripting, and deployment**
- Integrates well with:
  - Group Policy
  - Configuration Management tools (SCCM, Intune, Ansible, etc.)
  - CI/CD pipelines

Using PowerShell ensures **consistent, repeatable, and auditable remediation** across systems.

---

## How These Scripts Work

Each STIG is implemented as an **independent PowerShell script** that:

1. Ensures the required **registry key exists**
2. Sets (or overwrites) the required **registry value**
3. Enforces the STIG regardless of the system’s prior configuration

### Design Principles

- **One STIG per script**  
- **Minimal logic** for reliability
- **Idempotent behavior** (safe to run multiple times)
- **Comment-based help** for documentation and auditing
- **STIG ID stored in script metadata**, not runtime logic

---

## Script Structure

Each script follows this pattern:

```powershell
<#
.SYNOPSIS
    Describes exactly what the script enforces.

.NOTES
    Author, versioning, and STIG ID metadata.

.USAGE
    Example execution syntax.
#>

# Configurable registry values
$RegPath
$ValueName
$Value

# Ensure registry key exists
# Set required value
