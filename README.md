# Threat Hunting Scenarios

**A practical collection of 50 hypothesis-driven threat hunting and SOC investigation scenarios.**

This repository documents investigation scenarios designed to develop structured reasoning for SOC Tier 2 and Threat Hunter workflows. The focus is on behavior-based hunting, telemetry selection, query logic, event correlation, hypothesis validation, scoping, and evidence-driven response—not just searching for known Indicators of Compromise (IOCs).

> **Language:** Scenario content is primarily written in Persian (Farsi). Scenario titles below are provided in English for easier navigation.

## Repository at a Glance

- **50** documented scenarios
- Hypothesis-driven and behavior-based investigation
- Windows security events, Sysmon, SIEM/EDR, Active Directory, and network telemetry
- Query examples and investigative pivots where applicable
- Detection engineering, false-positive analysis, incident scoping, and response workflows

## Threat Hunting Workflow

The scenarios encourage a repeatable investigation process:

1. **Define the objective** — Clarify the suspicious behavior and investigation window.
2. **Form a hypothesis** — State what may be happening and identify plausible benign alternatives.
3. **Select telemetry** — Identify the endpoint, identity, network, and security logs needed to test the hypothesis.
4. **Build and run queries** — Search for relevant behavior, establish a baseline, and refine results.
5. **Correlate evidence** — Pivot across users, hosts, processes, logon sessions, timestamps, and network connections.
6. **Validate findings** — Evaluate supporting and contradicting evidence, false positives, and data limitations.
7. **Scope the activity** — Determine affected accounts, endpoints, time ranges, and related behaviors.
8. **Recommend action** — Document confidence, preserve evidence, and recommend detection, containment, or further investigation as appropriate.

A match is a lead, not automatically proof of compromise. Conclusions should be proportionate to the quality and completeness of the evidence.

## Scenarios

### Process Execution & Windows Tradecraft

- [Scenario 01: PowerShell Launched by Microsoft Word](Scenarios/Scenario%2001.md)
- [Scenario 02: Unknown Process Launching cmd.exe (Security Event 4688)](Scenarios/Scenario%2002.md)
- [Scenario 03: Suspicious rundll32.exe Execution (Sysmon Event ID 1)](Scenarios/Scenario%2003.md)
- [Scenario 04: Process Creation Followed by an External Network Connection](Scenarios/Scenario%2004.md)
- [Scenario 05: PowerShell Execution with -EncodedCommand](Scenarios/Scenario%2005.md)
- [Scenario 14: svchost.exe Executed from an Unusual Path (Masquerading)](Scenarios/Scenario%2014.md)
- [Scenario 15: Suspicious rundll32.exe Arguments Followed by Network Activity](Scenarios/Scenario%2015.md)
- [Scenario 17: Behavior-Based PowerShell Hunting Without Known IOCs](Scenarios/Scenario%2017.md)

### Authentication & Credential Access

- [Scenario 06: Multiple Failed Logons Followed by a Successful Logon](Scenarios/Scenario%2006.md)
- [Scenario 07: One Account Logging In to Multiple Servers at 03:00](Scenarios/Scenario%2007.md)
- [Scenario 08: Service Account Interactive Login on a Workstation](Scenarios/Scenario%2008.md)
- [Scenario 09: Administrator Account Login on an Unusual Host](Scenarios/Scenario%2009.md)
- [Scenario 10: Investigating Potential Credential Theft](Scenarios/Scenario%2010.md)
- [Scenario 11: Suspicious Kerberos Authentication](Scenarios/Scenario%2011.md)
- [Scenario 12: Potential Pass-the-Hash Activity](Scenarios/Scenario%2012.md)
- [Scenario 13: Potential Kerberoasting Activity](Scenarios/Scenario%2013.md)
- [Scenario 18: Brute Force Followed by Successful Authentication](Scenarios/Scenario%2018.md)
- [Scenario 19: Domain Admin Login to an Unusual Workstation Outside Business Hours](Scenarios/Scenario%2019.md)
- [Scenario 26: Credential Access Hunting Without Known IOCs](Scenarios/Scenario%2026.md)

### Active Directory & Lateral Movement

- [Scenario 20: Unusual LDAP Queries Against a Domain Controller](Scenarios/Scenario%2020.md)
- [Scenario 21: SMB Connections from One Workstation to Multiple Internal Hosts](Scenarios/Scenario%2021.md)
- [Scenario 22: PsExec, Service Creation, and Potential Lateral Movement](Scenarios/Scenario%2022.md)
- [Scenario 23: Potential Lateral Movement Through RDP](Scenarios/Scenario%2023.md)
- [Scenario 24: Remote Execution Through WinRM or WMI](Scenarios/Scenario%2024.md)
- [Scenario 25: Reconstructing Lateral Movement from a Compromised Host](Scenarios/Scenario%2025.md)
- [Scenario 46: Reconstructing an Attack Chain from Phishing to Lateral Movement](Scenarios/Scenario%2046.md)
- [Scenario 47: Assessing and Responding to Potential Domain Admin Compromise](Scenarios/Scenario%2047.md)

### Persistence, C2 & Data Exfiltration

- [Scenario 27: Persistence Hunting Without Known IOCs](Scenarios/Scenario%2027.md)
- [Scenario 28: Periodic Outbound Connections and C2 Beaconing](Scenarios/Scenario%2028.md)
- [Scenario 29: Potential Data Exfiltration Without Known IOCs](Scenarios/Scenario%2029.md)
- [Scenario 30: Threat-Intelligence-Led Hunting Without Usable IOCs](Scenarios/Scenario%2030.md)
- [Scenario 39: Identifying Patient Zero Using Forensic Timelines](Scenarios/Scenario%2039.md)
- [Scenario 40: Systematic Pivoting Across Hash, Domain, and IP Indicators](Scenarios/Scenario%2040.md)
- [Scenario 41: Detecting Potential DNS Tunneling](Scenarios/Scenario%2041.md)
- [Scenario 42: Distinguishing HTTPS C2 Beaconing from Legitimate Traffic](Scenarios/Scenario%2042.md)
- [Scenario 43: Distinguishing Malicious Reconnaissance from Authorized Scanning](Scenarios/Scenario%2043.md)
- [Scenario 44: Correlating Large Outbound Transfers with Endpoint Processes](Scenarios/Scenario%2044.md)

### Detection Engineering & SIEM Operations

- [Scenario 31: Reducing False Positives in a Noisy PowerShell Detection](Scenarios/Scenario%2031.md)
- [Scenario 32: Designing a PowerShell Detection Use Case](Scenarios/Scenario%2032.md)
- [Scenario 33: Correlating Logon, Process Creation, and Network Events](Scenarios/Scenario%2033.md)
- [Scenario 34: Hunting When Required SIEM Logs Are Missing](Scenarios/Scenario%2034.md)
- [Scenario 35: Clustering and Prioritizing a High Volume of Alerts](Scenarios/Scenario%2035.md)

### Incident Investigation & Response

- [Scenario 36: Investigating a Suspicious Email Click Without Confirmed Malware Execution](Scenarios/Scenario%2036.md)
- [Scenario 37: Determining Whether a Suspicious File Was Executed](Scenarios/Scenario%2037.md)
- [Scenario 38: Ransomware Investigation, Scoping, and Containment](Scenarios/Scenario%2038.md)
- [Scenario 48: Resolving Conflicting EDR and IT Evidence](Scenarios/Scenario%2048.md)
- [Scenario 49: Reconstructing an Incident with Incomplete Logs](Scenarios/Scenario%2049.md)
- [Scenario 50: End-to-End Incident Handling: Alert to Closure](Scenarios/Scenario%2050.md)
- [Scenario 45: Correlating Zeek, Suricata, and Endpoint Telemetry](Scenarios/Scenario%2045.md)

## Common Data Sources and Technologies

Depending on the scenario, investigations may use:

- **Windows Security Logs** — including logon and process-creation events.
- **Sysmon** — process creation, network connections, DNS queries, and process access.
- **Microsoft Defender XDR / Sentinel** — endpoint, identity, and security-event hunting.
- **SIEM and EDR telemetry** — alert context, process ancestry, file activity, and host timelines.
- **Active Directory** — Kerberos, NTLM, LDAP, privileged accounts, and service accounts.
- **Network telemetry** — Zeek, Suricata, DNS, proxy, firewall, and flow records.
- **Forensic artifacts** — Prefetch, Amcache, MFT, and USN Journal, where relevant.

Tooling and field names vary by environment. Validate queries against the schema and telemetry available in your own platform.

## MITRE ATT&CK

Where relevant, scenarios reference techniques from [MITRE ATT&CK](https://attack.mitre.org/) to help classify adversary behavior and guide follow-up hunting. Treat mappings as investigative context; validate them against the observed behavior and evidence.

## How to Use This Repository

1. Choose a scenario relevant to your environment or learning objective.
2. Read the hypothesis and identify the telemetry needed to test it.
3. Review the query examples and understand what each filter or join contributes.
4. Consider benign explanations and the limits of the available logs.
5. Record findings, confidence, affected assets, and follow-up actions.
6. Adapt queries to your own data schema before using them operationally.

## Intended Audience

- SOC Analysts (especially Tier 2)
- Threat Hunters
- Detection Engineers
- Incident Responders
- Blue Team practitioners preparing for technical interviews

## Disclaimer

This repository is intended for educational purposes, defensive security research, and authorized investigations. Queries and thresholds are examples and may require tuning for the target environment. Do not use the content to access or investigate systems without appropriate authorization. Never commit credentials, sensitive organizational logs, or personally identifiable information.

## Author

**Archmmd**  
Cybersecurity | Security Operations | Threat Hunting

- GitHub: [@archmmd](https://github.com/archmmd)

---

*Proactive hunting. Evidence-driven analysis. Continuous improvement.*
