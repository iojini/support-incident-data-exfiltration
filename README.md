# Threat Hunt Report: Fabricated Support Incident and Data Exfiltration

<img width="1024" height="965" alt="Data Exfiltration Image v5" src="https://github.com/user-attachments/assets/103db624-3abf-44be-88ac-8772cb1b101b" />

##  Scenario

Subsequent analysis of a routine support request reveals behavior inconsistent with typical remote assistance. Multiple artifacts were left behind, including unusual process executions and system modifications. Notably, a post-session narrative was introduced to explain away anomalies, though forensic traces suggest a premeditated sequence of access and manipulation. This investigation seeks to reconstruct the timeline of activity and determine whether the actions taken were aligned with support protocols or if they were intentionally staged under the guise of assistance.

## Background
**Incident Date:** 09 October 2025  
**Compromised Host:** gab-intern-vm  

---

## Steps Taken

### 1. Initial Execution Detection

Searched for files created in the user's Downloads folder during the investigation timeframe and discovered SupportTool.ps1 created on 10/9/2025 at 12:22 PM by powershell.exe in the user's Downloads folder at C:\Users\g4bri3lintern\Downloads\. Next, searched for the execution of SupportTool.ps1 to identify command-line parameters. The first execution revealed the attacker used -ExecutionPolicy Bypass to circumvent PowerShell security controls by bypassing PowerShell's execution policy. 

**Queries used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == "gab-intern-vm"
| where FileName contains "desk" or FileName contains "help" or FileName contains "support" or FileName contains "tool"
| where FolderPath contains "Downloads"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessFileName
| sort by TimeGenerated asc

```
<img width="2685" height="459" alt="Query1A Results" src="https://github.com/user-attachments/assets/e539c268-b75e-4aa1-9985-ca00d6f96a0d" />

---

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "SupportTool.ps1"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| sort by TimeGenerated asc

```
<img width="2868" height="657" alt="Query1B Results" src="https://github.com/user-attachments/assets/c2c3abe4-f2fe-446f-b99c-36f6eea3cc2c" />

---

### 2. Defense Disabling

Searched for evidence of staged artifacts and discovered that DefenderTamperArtifact.lnk was created on 10/09/2025 at 12:34 PM. This shortcut file in the Recent folder indicates that the attacker may have manually accessed a file designed to simulate Windows Defender tampering.

**Query used to locate events:**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where FolderPath contains "Recent"
| where ActionType == "FileCreated"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName
| sort by TimeGenerated asc

```
<img width="1954" height="876" alt="Query2 Results" src="https://github.com/user-attachments/assets/4808772a-3c7e-4b05-a7dc-8523b7ff72cf" />

---

### 3. Data Probe

Searched for clipboard access attempts and discovered the attacker executed the following clipboard data probe: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }" on 10/09/2025 at 12:50 PM. This PowerShell command attempts to quietly query the clipboard, possibly in an attempt to capture any sensitive or copied data present (e.g., passwords or credit card numbers), essentially leveraging Get-Clipboard for a low-effort win.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "clip" 
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc

```
<img width="2539" height="721" alt="Query3 Results" src="https://github.com/user-attachments/assets/35926e7e-bc2c-4b88-ad02-d602ffd1d054" />

---

### 4. Searched the `DeviceLogonEvents` Table for successful network logons

The only successful remote network logons in the last 30 days was for the labuser account (53 total).

**Query used to locate events:**

```kql
//Successful logons
DeviceLogonEvents
| where DeviceName == "irene-test-vm-m"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"

//Number of successful logons by account owner
DeviceLogonEvents
| where DeviceName == "irene-test-vm-m"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```
---

### 5. Searched the `DeviceLogonEvents` Table for failed network logon attempts by account owner

There were zero (0) failed logons for the ‘labuser’ account, indicating that a brute force attempt for this account didn’t take place, and a 1-time password guess is unlikely (i.e., this likely represents legitimate activity by the actual user; however, can't rule out that an attacker may already know the username and password obtained through other means including phishing, credential dumps, password reuse, etc).

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "irene-test-vm-m"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()

```
---

### 6. Searched the `DeviceLogonEvents` table to identify successful network logons by the account owner and the source of the logon activity 

Searched for remote IP addresses that successfully logged in as 'labuser' to assess whether the activity originated from unusual or unexpected locations. Based on the results, the IP address was consistent with expected/legitimate sources.


**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "irene-test-vm-m"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```
<img width="2848" height="453" alt="IF_3" src="https://github.com/user-attachments/assets/516575b1-d820-4c1a-9389-9d4a00543a5a" />

---

## Summary

The analysis revealed that the target device was internet-facing for several days, with the most recent occurrence on October 16, 2025. During this exposure period, multiple threat actors attempted to gain unauthorized access to the device. Analysis of failed logon attempts identified numerous external IP addresses conducting brute-force attacks, with some IPs attempting to log in over 90 times (e.g., 185.39.19.56 with 100 failed attempts, 45.227.254.130 with 93 failed attempts).

Critically, none of the identified threat actor IP addresses successfully gained access to the system. Further investigation revealed that the only successful network logons during the last 30 days were associated with the 'labuser' account (53 total). Notably, there were zero failed logon attempts for this account, and the successful logons originated from an IP address consistent with expected and legitimate sources. In summary, no indicators of compromise (IOC) were found.

---

## Relevant MITRE ATT&CK TTPs

| TTP ID | TTP Name | Description | Detection Relevance |
|--------|----------|-------------|---------------------|
| T1133 | External Remote Services | Internet-facing VM inadvertently exposed to the public internet, allowing external access attempts. | Identifies misconfigured devices exposed to the internet through DeviceInfo table queries. |
| T1046 | Network Service Discovery | External threat actors discovered and identified the exposed service before attempting access. | Indicates potential reconnaissance and scanning by external actors prior to brute-force attempts. |
| T1110 | Brute Force | Multiple failed login attempts from external IP addresses attempting to gain unauthorized access (e.g., 185.39.19.56 with 100 attempts). | Identifies brute-force login attempts and suspicious login behavior from multiple remote IPs. |
| T1075 | Pass the Hash | Failed login attempts could suggest credential-based attacks including pass-the-hash techniques. | Identifies failed login attempts from external sources, indicative of credential attacks. |
| T1021 | Remote Services | Remote network logons via legitimate services showing external interaction attempts with the exposed device. | Identifies legitimate and malicious remote service logons to the exposed device. |
| T1070 | Indicator Removal on Host | No indicators of successful brute-force attacks, demonstrating that defensive measures prevented unauthorized access. | Confirms the lack of successful attacks due to effective monitoring and legitimate account usage. |
| T1078 | Valid Accounts | Successful logons from the legitimate account 'labuser' were normal and monitored, representing valid credential usage. | Monitors legitimate access and excludes unauthorized access attempts by confirming expected IP sources. |

---

This table organizes the MITRE ATT&CK techniques (TTPs) observed during the investigation. The detection methods identified both the attack attempts (brute force from external IPs) and confirmed that no unauthorized access occurred, with all successful logons representing legitimate user activity.

---

## Response Taken

| MITRE Mitigation ID | Name | Action Taken | Description | Relevance |
|---------------------|------|--------------|-------------|-----------|
| M1030 | Network Segmentation | Network Security Group Hardening | Reconfigured the NSG attached to 'irene-test-vm-m' to restrict RDP access to authorized IP addresses only, eliminating public internet exposure. | Prevents unauthorized external access by limiting remote access to trusted sources only. |
| M1036 | Account Use Policies | Account Lockout Policy Implementation | Implemented account lockout thresholds to automatically lock accounts after a specified number of failed login attempts. | Mitigates brute-force attack risks by preventing unlimited password guessing attempts. |
| M1032 | Multi-factor Authentication | Multi-Factor Authentication Deployment | Deployed MFA for all network logon types, requiring additional authentication factors beyond passwords. | Adds an additional security layer to prevent unauthorized access even if credentials are compromised. |
| M1047 | Audit | Continuous Monitoring Configuration | Established ongoing monitoring of DeviceInfo and DeviceLogonEvents tables for configuration changes and suspicious login activity. | Enables early detection of future misconfigurations or unauthorized access attempts. |

---

The following response actions were taken: reconfigured the NSG attached to the target machine to restrict RDP access to authorized endpoints only, removing public internet exposure; implemented account lockout thresholds to prevent brute-force attacks by automatically locking accounts after excessive failed login attempts; deployed MFA for network authentication to provide additional security beyond password-based access; established ongoing monitoring for configuration changes and suspicious login activity.

---
