# Threat-Hunt-The-Broker

<p align="center">
  <img
    src="PASTE_YOUR_ALERT_IMAGE_LINK_HERE"
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
