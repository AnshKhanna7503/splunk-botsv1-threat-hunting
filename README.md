# splunk-botsv1-threat-hunting
End-to-End SOC L1 Threat Hunting &amp; Incident Response Investigation on the Splunk BOTS v1 Dataset (Joomla Web Compromise &amp; Cerber Ransomware Forensics)
# 🛡️ Splunk BOTS v1: End-to-End Threat Hunting & Incident Response Investigation

## 📌 Executive Summary
This repository documents a comprehensive digital forensics and incident response (DFIR) investigation conducted on the **Splunk Boss of the SOC (BOTS v1)** dataset for **Wayne Enterprises**. Using **Splunk Enterprise (SPL)**, network stream telemetry (`stream:http`), Windows Security Event Logs (`WinEventLog:Security`), and Sysmon endpoint logs (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`), this investigation uncovers and reconstructs two distinct, multi-stage cyberattacks:

1. **Incident 1 (Phases 1–7): Joomla Web Server Compromise & C2 Establishment**  
   An external adversary (`40.80.148.42`) conducted automated vulnerability reconnaissance against the corporate Joomla CMS, compromised the administrator portal (`admin:batman`), deployed a malicious web payload (`3791.exe`), and established outbound Command-and-Control (C2) communication to `23.22.63.114:1337`.
2. **Incident 2 (Phases 8–13): Cerber Ransomware Outbreak & Endpoint Forensics**  
   After ruling out lateral movement from the DMZ web server, global threat hunting identified a separate **Cerber Ransomware** outbreak impacting corporate file server `we9041srv` (`EventCode 5145`). Endpoint forensics isolated Patient Zero (`WAYNECORPINC\bob.smith` on workstation `we8105desk` / `192.168.250.100`) and reconstructed the full execution chain: a malicious macro-enabled Word template (`D:\Miranda_Tate_unveiled.dotm`) $\rightarrow$ obfuscated `cmd.exe` stager $\rightarrow$ VBScript dropper (`20429.vbs`) with a 5-minute sandbox evasion delay $\rightarrow$ HTTP payload download (`http://solidaritedeproximite.org/mhtr.jpg` from `37.187.37.150`) $\rightarrow$ execution of the disguised Cerber ransomware binary (`121214.tmp`)[cite: 4, 6, 7, 8, 9].

---

## 🛠️ Environment & Telemetry Sources
* **SIEM Platform:** Splunk Enterprise
* **Network Telemetry:** `stream:http` (HTTP packet capture & form data inspection)
* **Windows Security Auditing:** `WinEventLog:Security` (`EventCode 4624` Logon Activity, `EventCode 5145` Detailed File Share Access)
* **Endpoint Detection (EDR/Sysmon):** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (`EventID 1` Process Creation, `EventID 3` Network Connection)
* **Core SPL Techniques:** Statistical aggregation (`stats`, `sort`, `head`, `table`), on-the-fly XML regular expression field extraction (`rex`), and multi-source timeline correlation[cite: 1, 6, 7, 8, 9].

---

## 🌐 Part 1 & 2: Web Server Compromise & C2 Investigation

### Phase 1: Initial Reconnaissance
* **Objective:** Identify the attacker's IP address and scanning methodology.
* **SPL Query:**
```spl
index="botsv1" sourcetype="stream:http"
| stats count by src_ip, http_user_agent
| sort - count
