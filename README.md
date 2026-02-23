# Threat-Hunt-The-Broker

<p align="center">
  <img
    src="images/Screenshot 2026-02-23 173753.png"
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

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔥 Executive MITRE ATT&CK Heatmap](#-executive-mitre-attck-heatmap)
- [📊 Executive Takeaway](#-executive-takeaway)
- [⏱️ Attack Timeline](#️-attack-timeline)
- [🔍 Flag Analysis](#-flag-analysis)
  - Phase 1: Initial Access & Execution (Flags 1–5)
  - Phase 2: Command & Control Infrastructure (Flags 6–8)
  - Phase 3: Credential Access & Local Staging (Flags 9–11)
  - Phase 4: Reconnaissance & Privilege Discovery (Flags 12–14)
  - Phase 5: Persistence Establishment (Flags 15–20)
  - Phase 6: Lateral Movement & Identity Abuse (Flags 21–27)
  - Phase 7: Advanced Persistence & Backdoors (Flags 28–31)
  - Phase 8: Data Collection & Staging (Flags 32–36)
  - Phase 9: Defense Evasion & Fileless Execution (Flags 37–40)
- [🚨 Detection Opportunities](#-detection-opportunities)
- [🛡️ Defensive Takeaways](#️-defensive-takeaways)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

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

## ⏱️ Attack Timeline

### January 15, 2026 — Initial Compromise
**~05:08 UTC** — Phishing payload executed on as-pc1 (daniel_richardson_cv.pdf.exe)  
**~05:10 UTC** — Windows logs cleared via wevtutil (anti-forensics)  
**Early post-execution** — Outbound connections to attacker infrastructure established

### Post-Exploitation
**Credential harvesting** — SAM and SYSTEM registry hives dumped and staged locally  
**Reconnaissance** — whoami, net view, and privilege discovery commands executed

### Persistence Establishment
**Remote access deployed** — AnyDesk installed with unattended access  
**Persistence layering** — Scheduled tasks, masqueraded binaries, account manipulation observed

### Lateral Movement
**Failed attempts** — PsExec and WMIC used during early pivots  
**Successful pivot** — Interactive RDP (mstsc.exe) enabled multi-host access  
**Expansion** — Persistence observed across as-pc1, as-pc2, and as-srv

### Data Collection
**Server access** — Internal file server compromised  
**Sensitive interaction** — Financial documents accessed and edited  
**Attribution** — SMB telemetry ties access to as-pc2

### Staging Phase
**Archive creation** — Shares.7z created on file server  
**Artifact hashing** — Unique SHA256 identified for staged data

### Advanced Tradecraft
**Reflective loading detected** — ClrUnbackedModuleLoaded telemetry observed  
**Fileless credential theft** — GhostPack SharpChrome executed in memory  
**Process injection** — SharpChrome injected into notepad.exe

**Investigation Window:** January 15, 2026 – February 23, 2026


