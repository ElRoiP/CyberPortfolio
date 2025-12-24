### SOC Investigation Report – AZUKI Logistics Remote Compromise

**Incident ID:** AZUKI-2025-11-19-01

**Prepared by:** [El Roi Pablo](https://www.linkedin.com/in/elroipablo/)

**Date of report:** December 22, 2025

---

### 1. Executive Summary

On 19 November 2025, suspicious remote interactive logons were observed on endpoint `azuki-logistics` from an external IP address `88.97.178.12`. Subsequent investigation revealed a full intrusion chain involving account compromise, internal reconnaissance, malware staging and execution from `C:\\ProgramData\\WindowsCache`, defense evasion through AV exclusions and event log clearing, credential theft using `mm.exe`, data staging and compression into [`export-data.zip`](http://export-data.zip), command‑and‑control (C2) communication with `78.141.196.6:443`, data exfiltration using [`discord.com`](http://discord.com), and lateral movement to a remote host at `10.1.0.188` via `mstsc.exe`.

The activity is consistent with a targeted intrusion leveraging living‑off‑the‑land binaries (LOLBins) and custom tooling, achieving credential theft, persistence, data theft, and lateral movement.

---

### 2. Findings

### Flag 1 - **INITIAL ACCESS - Remote Access Source**

`2025-11-19T00:57:18.3409813Z`
Answer:`88.97.178.12`

Queried the `DeviceLogonEvents` table for any external sources that has successfully logged on and found RemoteIP:`88.97.178.12` has successfully logged on to `azuki-logistics` device.

```kql
DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| where DeviceName contains "azuki"
| project TimeGenerated, DeviceName, ActionType, RemoteIP, RemoteIPType, LogonType
| sort by TimeGenerated desc
```
<img width="428" height="197" alt="image" src="https://github.com/user-attachments/assets/e3aa7b2a-2ed2-4c81-9787-8a54000579bf" />

### Flag 2 - **INITIAL ACCESS - Compromised User Account**

`2025-11-19T01:04:05.73442Z`

Answer: `kenji.sato`

Queried the `DeviceLogonEvents` table to find which account was compromised and found that the account `kenji.sato` was used by `88.97.178.12` to login to the `azuki-logistics` device.

```kql
DeviceLogonEvents
| where DeviceName == "azuki-logistics"
| where RemoteIP  == "88.97.178.12"
| where TimeGenerated == todatetime('2025-11-19T00:57:18.3409813Z')
| project TimeGenerated, AccountName, RemoteIP, DeviceName
```
<img width="427" height="190" alt="image" src="https://github.com/user-attachments/assets/a49e652a-9f06-488c-b3ab-d73003b72fbf" />

### Flag 3 - **DISCOVERY - Network Reconnaissance**

`2025-11-19T01:04:05.73442Z`

Answer: `ARP -a`

Queried the `DeviceProcessEvents` table to find what commands were used to enumerate the network by searching the `ProcessCommandLine` with common commands that is usually used to enumerate the network. The command used was `ARP -a`.

```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| sort by TimeGenerated desc
| where ProcessCommandLine has_any ("net view", "net use","net group","net localgroup","arp","nbtstat","ipconfig","route print") //potential commands to enumerate the network
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```
<img width="411" height="168" alt="image" src="https://github.com/user-attachments/assets/f9dd29de-47f0-4f5c-8cd5-4a49b8a9f0b1" />

### Flag 4 - **DEFENCE EVASION - Malware Staging Directory**

`2025-11-19T12:59:39.3271415Z`

Answer: `C:\\ProgramData\\WindowsCache`

Queried the `DeviceProcessEvents` table for any newly folders that were hidden from normal view. Searched the `ProcessCommandLine` and found that a `WindowsCache` folder was created with the attributes `+h` to hide the folder and `+s` to make it into a system file.

```kql
DeviceProcessEvents
| where AccountName == "kenji.sato"
| sort by TimeGenerated desc
| where ProcessCommandLine contains "attrib"
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
```
<img width="501" height="145" alt="image" src="https://github.com/user-attachments/assets/4ee7f66c-be6b-4a46-a36e-3c8e3102cdbd" />

### Flag 5 - **DEFENCE EVASION - File Extension Exclusions**

`2025-11-19T18:49:27.7301011Z`

Answer: `3`
Queried the `DeviceRegistryEvents` table to see if any extensions were exluded from the Windows Defender registry and found  `.bat`, `.ps1`, `.exe` was added to the `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Extensions`.

```kql
DeviceRegistryEvents
| order by TimeGenerated desc
| where DeviceName contains "azuki"
| where RegistryKey contains @"exclusions\extensions"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName
```
<img width="1055" height="148" alt="image" src="https://github.com/user-attachments/assets/d15e971a-c300-4cda-9426-8c811b9d8cba" />

### Flag 6 - **DEFENCE EVASION - Temporary Folder Exclusion**

`2025-11-19T18:49:27.6830204Z`

Answer: `C:\\Users\\KENJI\\\~1.SAT\\AppData\\Local\\Temp`

Queried the `DeviceRegistryEvents` table to see if any paths were excluded from the Windows Defender registry and found `C:\\Users\\KENJI\\\~1.SAT\\AppData\\Local\\Temp` was added to the `HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths` .

```kql
 DeviceRegistryEvents
| order by TimeGenerated desc
| where DeviceName contains "azuki"
| where RegistryKey contains @"exclusions\paths"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName 
```
<img width="620" height="113" alt="image" src="https://github.com/user-attachments/assets/871b2c3a-63d0-4f11-88c2-1e739e762472" />

### Flag 7 - **DEFENCE EVASION - Download Utility Abuse**

`2025-11-19T13:09:45.7113015Z`

Answer: `certutil.exe`

Queried the `DeviceProcessEvents` table to find any tools used to download into the the `C:\\ProgramData\\WindowsCache\\` folder. Found that the `certutil.exe` was used to download a `svchost.exe` and `mm.exe` by searching the `ProcessCommandLine` that has any of the potential commands used to download.

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where AccountName == "kenji.sato"
| where ProcessCommandLine has_any ("url", "http", "https") and ProcessCommandLine contains @"C:\ProgramData\WindowsCache\"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```
<img width="1202" height="117" alt="image" src="https://github.com/user-attachments/assets/e33e85af-a26c-4fbf-bbe4-6aec2fe79fe4" />

### Flag 8 & 9 - **PERSISTENCE - Scheduled Task Name & Target**

`2025-11-19T13:10:09.5749653Z`

Flag 8 Answer: `Windows Update Check`

Flag 9 Answer: `C:\\ProgramData\\WindowsCache\\svchost.exe`

Queried the `DeviceProcessEvents` table to check if any scheduled tasks were created by serching the `FileName`  that used `schtasks.exe` and found that a task called `Windows Update Check` and the target was set to `C:\\ProgramData\\WindowsCache\\svchost.exe`.

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where AccountName == "kenji.sato"
| where FileName == "schtasks.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```
<img width="841" height="151" alt="image" src="https://github.com/user-attachments/assets/e03dec09-34d2-4e3f-970c-aba7ad091483" />

### Flag 10 & 11 - **COMMAND & CONTROL - C2 Server Address & Port**

`2025-11-19T13:11:56.7217784Z`

Flag 10 Answer: `78.141.196.6`
Flag 11 Answer: `443`

Queried the `DeviceNetworkEvents` table to look for any successful connection using `c:\\programdata\\windowscache\\svchost.exe` and fouind that a remote IP `78.141.196.6` connected back through port `443`.

```kql
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFolderPath contains @"C:\ProgramData\WindowsCache\"
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFolderPath, RemoteIP, RemotePort
```
<img width="904" height="119" alt="image" src="https://github.com/user-attachments/assets/0aa7c113-172a-4afe-9973-08bfdeb36af3" />

### Flag 12 - **CREDENTIAL ACCESS - Credential Theft Tool**

`2025-11-19T13:15:50.5597227Z`

Answer `mm.exe`

Queried the `DeviceFileEvents` table to look for any other tools in the `WindowsCache` staging folder and found `mm.exe`.

```kql
DeviceFileEvents
| where FolderPath contains "WindowsCache"
| where FileName endswith ".exe"
| order by TimeGenerated desc
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
```
<img width="803" height="261" alt="image" src="https://github.com/user-attachments/assets/3fb35d96-bff8-4dcc-9f26-39dec959f285" />

### Flag 13 - **CREDENTIAL ACCESS - Memory Extraction Module**

`2025-11-19T19:08:26.2804285Z`

Answer: `sekurlsa::logonpasswords`

Queried the `DeviceProcessEvents` table to see what commands were used to run `mm.exe` and saw that it used `sekurlsa::logonpasswords` which is a module in mimikatz.

```kql
DeviceProcessEvents
| where FileName == "mm.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
```
<img width="891" height="85" alt="image" src="https://github.com/user-attachments/assets/1201c624-b2c5-4627-9928-f532cbd00140" />

### Flag 14 - **COLLECTION - Data Staging Archive**

`2025-11-19T17:19:19.2066001Z`

Answer: [`export-data.zip`](http://export-data.zip)

Queried the `DeviceFileEvents` table to see if any zip files created to to exfiltrate data back to the attacker and found [`export-data.zip`](http://export-data.zip) by filtering down any files that ends with `.zip` in the `WindowsCache` folder.

```kql
DeviceFileEvents
| where DeviceName contains "azuki"
| where FileName endswith ".zip" and FolderPath contains "WindowsCache"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
```
<img width="919" height="103" alt="image" src="https://github.com/user-attachments/assets/ea22630b-1cc1-401f-b8b5-ff8a38330a9a" />

### Flag 15 - **EXFILTRATION - Exfiltration Channel**

`2025-11-19T19:09:21.4234133Z`
Answer: [`discord.com`](http://discord.com)

Queried the `DeviceNetworkEvents` table to see if the attacker was able to exfiltrate the data and  found [`discord.com`](http://discord.com) was used to extract the data back to the attacker.

```kql
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where InitiatingProcessCommandLine contains "WindowsCache"
| project TimeGenerated, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated desc
```
<img width="959" height="113" alt="image" src="https://github.com/user-attachments/assets/ef483cd2-23e2-4f49-a13e-65916a741f6a" />

### Flag 16 - **ANTI-FORENSICS - Log Tampering**

`2025-11-19T17:21:25.9061368Z`

Answer: `Security`

Queried the `DeviceProcessEvents` table to find if the attacker tried to hide their tracks by searching for any `cl` commands ran by `wevutil.exe` and saw that it was used to clear `Security` ,`System` ,`Application` logs.

```kql
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName == "wevtutil.exe"
| where ProcessCommandLine contains "cl"
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
```
<img width="819" height="320" alt="image" src="https://github.com/user-attachments/assets/0210c436-bb15-4092-ae93-b79e63228aaf" />

### Flag 17 - **IMPACT - Persistence Account**

`2025-11-19T19:09:48.8977132Z`

Answer: `support`

Queried the `DeviceProcessEvents` table to check if any newly `Administrator` accounts created and saw that a `support` account was created and added to the `Administrator` group.

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any (@"/add", "Administrator")
| project TimeGenerated,DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated desc 
```
<img width="935" height="148" alt="image" src="https://github.com/user-attachments/assets/1518e5aa-c409-4561-9607-c1ec6739175a" />

### Flag 18 - **EXECUTION - Malicious Script**

`2025-11-19T18:49:48.7079818Z`
Answer: [`wupdate.ps`](http://wupdate.ps)`1`
Queried the `DeviceFileEvents` table to find if there were any downloaded scripts and found [`wupdate.ps](http://wupdate.ps)1` by filtering `FileName` that has any `.ps1` or `.bat` that has the command `invoke-webrequest`to download.

```kql
DeviceFileEvents
| where DeviceName contains "azuki"
| where FileName has_any (".ps1", ".bat")
| where InitiatingProcessCommandLine contains "invoke-webrequest"
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, ActionType, FileName, InitiatingProcessCommandLine
```
<img width="1275" height="140" alt="image" src="https://github.com/user-attachments/assets/3f27174b-77fd-49bd-932b-81eab83563c8" />

### Flag 19 - 20 - **LATERAL MOVEMENT - Secondary Target & Remote Access Tool**

`2025-11-19T19:10:41.372526Z`
Flag 19 Answer: `10.1.0.188`

Flag 20 Answer: `mstsc.exe`

Queried the `DeviceProcessEvents` table for `ProcessCommandLines`that has any of the built-in tools to remote on to another device on the network and found the attcker used `mstsc.exe` to remotely connect to `10.1.0.188` .

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("mstsc","cmdkey")
| order by TimeGenerated desc 
| project TimeGenerated, DeviceName, ProcessCommandLine
```
<img width="796" height="115" alt="image" src="https://github.com/user-attachments/assets/fd5bbc57-8f9b-44c1-8607-eb757ac3e82e" />

---

### 3. Timeline of Events (UTC)

- **2025-11-19 00:57:18Z** – Remote interactive logon to `azuki-logistics` from external IP `88.97.178.12`. (Flag 1)
- **2025-11-19 01:04:05Z** – Compromise of domain account `kenji.sato` confirmed on `azuki-logistics`. (Flag 2)
- **2025-11-19 ~01:00–12:59Z** – Attacker performs internal reconnaissance using `ARP -a` and other discovery commands from the compromised account. (Flag 3)
- **2025-11-19 12:59:39Z** – Malware staging in `C:\\ProgramData\\WindowsCache` via `attrib` command, indicating file attribute manipulation (likely to hide payloads). (Flag 4)
- **2025-11-19 18:49:27Z** – AV/EDR exclusions configured for extensions `.bat`, `.ps1`, `.exe`, reducing detection for script and executable files. (Flag 5)
- **2025-11-19 18:49:27Z** – AV/EDR path exclusion added for `C:\\Users\\KENJI\~1.SAT\\AppData\\Local\\Temp`. (Flag 6)
- **2025-11-19 13:09:45Z** – `certutil.exe` used to download or manipulate content in `C:\\ProgramData\\WindowsCache\\`, indicating use of built‑in Windows tool for payload retrieval. (Flag 7)
- **2025-11-19 13:10:09Z** – Scheduled task `Windows Update Check` created to execute `C:\\ProgramData\\WindowsCache\\svchost.exe` for persistence. (Flags 8–9)
- **2025-11-19 13:11:56Z** – Network connection from staged malware in `WindowsCache` to C2 IP `78.141.196.6` over port `443`. (Flags 10–11)
- **2025-11-19 13:15:50Z** – Credential theft executable `mm.exe` observed in `WindowsCache`. (Flag 12)
- **2025-11-19 19:08:26Z** – `mm.exe` executes `sekurlsa::logonpasswords`, indicating LSASS memory scraping for credentials. (Flag 13)
- **2025-11-19 17:19:19Z** – Creation of [`export-data.zip`](http://export-data.zip) within `WindowsCache`, indicating data staging and compression. (Flag 14)
- **2025-11-19 19:09:21Z** – Outbound connection associated with `WindowsCache` processes to [`discord.com`](http://discord.com), used as a data exfiltration channel. (Flag 15)
- **2025-11-19 17:21:25Z** – Execution of `wevtutil.exe` with clear (`cl`) arguments to wipe Windows event logs, starting with the Security log. (Flag 16)
- **2025-11-19 19:09:48Z** – Local user account `support` created, likely for persistence and fallback access. (Flag 17)
- **2025-11-19 18:49:48Z** – Malicious script [`wupdate.ps`](http://wupdate.ps)`1` observed being downloaded or executed via `invoke-webrequest`. (Flag 18)
- **2025-11-19 19:10:41Z** – Lateral movement activity towards `10.1.0.188` using `mstsc.exe` and related credential‑handling commands (`cmdkey`). (Flags 19–20)

---

### 4. Root Cause Analysis

- **Initial Access:**
    - Initial access originated from remote interactive logons from IP `88.97.178.12` to `azuki-logistics` (Flag 1).
    - Account `kenji.sato` was successfully used for access, indicating credential compromise through unknown upstream vector (possible phishing, password reuse, or prior credential theft). (Flag 2)
- **Privilege / Credential Access:**
    - Adversary deployed `mm.exe` within `C:\\ProgramData\\WindowsCache` and executed `sekurlsa::logonpasswords` to dump credentials from memory (Flags 12–13).
- **Defense Evasion:**
    - AV exclusions were created for key file extensions `.bat`, `.ps1`, `.exe`, and for the Temp path of the compromised user, reducing detection of scripts and executables (Flags 5–6).
    - Windows event logs, including Security, were cleared using `wevtutil.exe cl`, hampering forensic visibility (Flag 16).
- **Persistence:**
    - Scheduled task **Windows Update Check** configured to run `svchost.exe` from `C:\\ProgramData\\WindowsCache\\`, providing scheduled execution of malicious payloads (Flags 8–9).
    - Local account `support` was created, providing a persistent local access method (Flag 17).
- **Command and Control & Exfiltration:**
    - Malware executed from `WindowsCache` established outbound C2 to `78.141.196.6:443`. (Flags 10–11)
    - Data staged as [`export-data.zip`](http://export-data.zip) and exfiltrated via connections to [`discord.com`](http://discord.com). (Flags 14–15)
- **Lateral Movement:**
    - `mstsc.exe` and related commands targeted `10.1.0.188`, indicating attempted or successful lateral movement within the environment (Flags 19–20).

---

### 5. Scope and Impact Assessment

- **Impacted assets:**
    - Primary: `azuki-logistics` endpoint.
    - Secondary (suspected): Host at IP `10.1.0.188` pending validation.
- **Compromised identities:**
    - Domain account: `kenji.sato`.
    - New local account: `support` (purpose unknown, assumed malicious).
- **Data exposure:**
    - Data archived into [`export-data.zip`](http://export-data.zip) in `C:\\ProgramData\\WindowsCache`.
    - Exfiltration via [`discord.com`](http://discord.com); exact content and volume require network and proxy log review.
- **Security controls affected:**
    - Endpoint protection efficacy reduced due to extension and path exclusions.
    - Logging integrity reduced due to Security and possibly other event logs being cleared.

Impact is assessed as **High**, given credential theft, potential lateral movement, defense evasion, and confirmed exfiltration channel.

---

### 6. Indicators of Compromise (IOCs)

- **IPs and Domains**
    - External source IP: `88.97.178.12` (initial remote logon).
    - C2 server IP: `78.141.196.6`.
    - C2 port: `443`.
    - Exfiltration service: [`discord.com`](http://discord.com).
- **Host Artifacts**
    - Endpoint: `azuki-logistics` (and any other hosts containing `WindowsCache` artifacts and similar logs).
    - Staging directory: `C:\\ProgramData\\WindowsCache`.
    - Suspicious Temp path excluded from AV: `C:\\Users\\KENJI\~1.SAT\\AppData\\Local\\Temp`.
- **Files and Binaries**
    - `svchost.exe` (non‑standard location: `C:\\ProgramData\\WindowsCache\\svchost.exe`).
    - `mm.exe` (credential theft tool).
    - [`export-data.zip`](http://export-data.zip) (staged archive for exfiltration).
    - [`wupdate.ps`](http://wupdate.ps)`1` (malicious PowerShell script).
    - `certutil.exe` used for downloading or encoding payloads from remote sources.
- **Processes and Commands**
    - Discovery: `ARP -a`, plus other discovery commands (`net view`, `net use`, etc.).
    - `schtasks.exe` creating **Windows Update Check** task.
    - `wevtutil.exe cl` (clearing event logs, including Security).
    - `mstsc.exe` and `cmdkey` toward `10.1.0.188`.

---

### 7. Recommended Containment Actions

- Immediately disable or reset credentials for account `kenji.sato` and any accounts discovered by `mm.exe`.
- Disable or remove the `support` local account from affected hosts.
- Isolate `azuki-logistics` and host `10.1.0.188` from the network for forensic acquisition and eradication.
- Terminate malicious processes associated with `C:\\ProgramData\\WindowsCache\\` and remove the scheduled task **Windows Update Check**.
- Remove all malicious files in `C:\\ProgramData\\WindowsCache\\` and related directories, including `mm.exe`, `svchost.exe`, [`wupdate.ps`](http://wupdate.ps)`1`, and [`export-data.zip`](http://export-data.zip) (after acquisition for evidence).
- Remove AV exclusions for extensions `.bat`, `.ps1`, `.exe` and the path `C:\\Users\\KENJI\~1.SAT\\AppData\\Local\\Temp`.
- Block outbound connections to C2 IP `78.141.196.6`, and restrict or inspect use of [`discord.com`](http://discord.com) at the network boundary.
- Collect and preserve forensic artifacts (memory, disk images, remaining logs) before full cleanup.

---

### 8. Eradication and Recovery Plan

- Rebuild or reimage affected hosts (`azuki-logistics` and any confirmed compromised systems) from a known‑good baseline.
- Reset passwords and rotate credentials for:
    - `kenji.sato`.
    - Any accounts found in credential dumps.
    - Service accounts that may have been present on impacted systems.
- Re‑enable and verify logging on all impacted systems:
    - Security, System, Application, and relevant custom logs.
- Validate that no unauthorized scheduled tasks, local users, or AV exclusions remain.
- Monitor for recurrence of IOCs and suspicious behavior for a defined period (for example, 30 days).

---

### 9. Lessons Learned and Recommendations

- Strengthen authentication:
    - Enforce multi‑factor authentication (MFA) for remote interactive logons.
    - Implement stricter controls on RDP exposure, including VPN requirements and conditional access.
- Harden endpoints:
    - Restrict local administrative rights and prevent unauthorized creation of local users.
    - Block creation of arbitrary AV/EDR exclusions by non‑admin users; review and alert on exclusion changes.
- Improve monitoring and detection:
    - Add detections for:
        - Non‑standard `svchost.exe` paths.
        - Scheduled tasks executing from user or ProgramData directories.
        - Use of `certutil.exe` with remote URLs.
        - `wevtutil.exe cl` execution.
        - Network connections to file‑sharing and chat platforms (such as [`discord.com`](http://discord.com)) from servers or sensitive endpoints.
- Enhance logging and retention:
    - Increase log retention and forward critical logs to a central SIEM for integrity.
- User awareness:
    - Conduct targeted awareness and training for users with elevated access, including secure handling of credentials.

---

### 10. Open Questions / Follow‑ups

- Was lateral movement to `10.1.0.188` successful and what is the role of that host?
- What specific data was included in [`export-data.zip`](http://export-data.zip)?
- Are there additional accounts or hosts impacted as a result of credential theft via `mm.exe`?
- Are there any related incidents with the same C2 IP `78.141.196.6` or similar TTPs in the environment?

---
