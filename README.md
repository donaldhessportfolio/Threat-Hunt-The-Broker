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
Execution of a double-extension payload (daniel_richardson_cv.pdf.exe) establishing the first foothold on as-pc1.

**Immediate post-exploitation activity**  
Rapid log clearing and outbound communications to attacker-controlled infrastructure, confirming active operator presence shortly after execution.

**Credential harvesting and staging**  
Registry hive dumping (SAM and SYSTEM) followed by local staging of credential artifacts in publicly writable directories.

**Reconnaissance and privilege discovery**  
Systematic enumeration of user context, network shares, and privileged group membership using native administrative utilities.

**Persistence hardening phase**  
Deployment of AnyDesk remote access tooling, unattended access configuration, scheduled task persistence, and creation of a service-style backdoor account.

**Lateral movement across the environment**  
Multi-method lateral movement attempts including PsExec, WMIC, and eventual interactive RDP pivots, enabling expansion from workstation foothold to additional endpoints and internal infrastructure.

**Server access and data collection**  
Compromise of an internal file server followed by access to sensitive financial documents and staged data collection activity.

**Pre-exfiltration staging**  
Creation of compressed archives containing collected data, indicating preparation for outbound data transfer.

**Advanced defense evasion and fileless execution**  
Reflective loading of in-memory GhostPack tooling (SharpChrome) injected into legitimate processes, enabling credential theft without leaving disk artifacts.

---

This hunt demonstrates how a single successful phishing execution can rapidly escalate into a multi-host intrusion involving layered persistence, credential abuse, and advanced defense evasion techniques.

The investigation highlights the importance of correlating endpoint, identity, and in-memory telemetry to detect modern adversaries who rely heavily on legitimate tooling and fileless execution to evade traditional security controls.
