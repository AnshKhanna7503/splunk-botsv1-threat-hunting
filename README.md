# splunk-botsv1-threat-hunting
End-to-End SOC L1 Threat Hunting &amp; Incident Response Investigation on the Splunk BOTS v1 Dataset (Joomla Web Compromise &amp; Cerber Ransomware Forensics)
# 🛡️ Splunk BOTS v1: End-to-End Threat Hunting & Incident Response Investigation

## 📌 Executive Summary
This repository documents a comprehensive digital forensics and incident response (DFIR) investigation conducted on the **Splunk Boss of the SOC (BOTS v1) dataset for **Wayne Enterprises. Using Splunk Enterprise (SPL), network stream telemetry (`stream:http`), Windows Security Event Logs (`WinEventLog:Security`), and Sysmon endpoint logs (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`), this investigation uncovers and reconstructs two distinct, multi-stage cyberattacks:

1. Incident 1 (Phases 1–7): Joomla Web Server Compromise & C2 Establishment  
   An external adversary (`40.80.148.42`) conducted automated vulnerability reconnaissance against the corporate Joomla CMS, compromised the administrator portal (`admin:batman`), deployed a malicious web payload (`3791.exe`), and established outbound Command-and-Control (C2) communication to `23.22.63.114:1337`.
2. After ruling out lateral movement from the DMZ web server, global threat hunting identified a separate Cerber Ransomware outbreak impacting corporate file server `we9041srv` (`EventCode 5145`). Endpoint forensics isolated Patient Zero (`WAYNECORPINC\bob.smith` on workstation `we8105desk` / `192.168.250.100`) and reconstructed the full execution chain: a malicious macro-enabled Word template (`D:\Miranda_Tate_unveiled.dotm`) $\rightarrow$ obfuscated `cmd.exe` stager $\rightarrow$ VBScript dropper (`20429.vbs`) with a 5-minute sandbox evasion delay $\rightarrow$ HTTP payload download (`http://solidaritedeproximite.org/mhtr.jpg` from `37.187.37.150`) $\rightarrow$ execution of the disguised Cerber ransomware binary (`121214.tmp`)[cite: 4, 6, 7, 8, 9].

---

## 🛠️ Environment & Telemetry Sources
SIEM Platform: Splunk Enterprise
Network Telemetry: `stream:http` (HTTP packet capture & form data inspection)
Windows Security Auditing: `WinEventLog:Security` (`EventCode 4624` Logon Activity, `EventCode 5145` Detailed File Share Access)
Endpoint Detection (EDR/Sysmon): `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (`EventID 1` Process Creation, `EventID 3` Network Connection)
Core SPL Techniques: Statistical aggregation (`stats`, `sort`, `head`, `table`), on-the-fly XML regular expression field extraction (`rex`), and multi-source timeline correlation[cite: 1, 6, 7, 8, 9].

---

## 🌐 Part 1 & 2: Web Server Compromise & C2 Investigation

### Phase 1: Initial Reconnaissance
Objective: Identify the attacker's IP address and scanning methodology.
SPL Query:
```spl
index="botsv1" sourcetype="stream:http"
| stats count by src_ip, http_user_agent
| sort - count
```
Evidence:(Drag and drop Phase 1 screenshot here)

Analyst Conclusion: A single external IP address (40.80.148.42) generated 17,420 HTTP requests in a very short window. Although the user-agent strings attempt to spoof a legitimate Chrome browser, the sheer volume of requests confirms the use of an automated vulnerability scanner or brute-force tool.

Phase 2: Target Identification
Objective: Determine the targeted web platform and specific attack vectors.

SPL Query:
```spl
index="botsv1" sourcetype="stream:http" src_ip="40.80.148.42"
| stats count by uri
| sort - count
| head 10
```

Evidence:(Drag and drop Phase 2 screenshot here)

Triage & Analysis: The attacker targeted a Joomla CMS installation. The high volume of traffic directed at the Joomla search component indicates automated vulnerability fuzzing, while requests to /windows/win.ini show attempted Local File Inclusion (LFI). The attacker also discovered the administrative login portal at /joomla/administrator/index.php.

Phase 3: Admin Portal Targeting
Objective: Quantify the login attempts directed at the Joomla administrator portal.

SPL Query:
```spl
index="botsv1" sourcetype="stream:http" src_ip="40.80.148.42" uri="/joomla/administrator/index.php" http_method="POST"
| stats count
```
Evidence:(Drag and drop Phase 3 screenshot here)

Analyst Conclusion: The attacker executed exactly 13 HTTP POST requests against the admin login page. This low volume indicates a highly targeted password guessing attempt rather than a massive, noisy brute-force attack.

Phase 4: Credential Compromise
Objective: Identify the compromised credentials used to breach the administrative portal.

SPL Query:
```spl
index="botsv1" sourcetype="stream:http" src_ip="40.80.148.42" uri="/joomla/administrator/index.php" http_method="POST"
| table _time, form_data
Evidence:(Drag and drop Phase 4 screenshot here)
```

Analyst Conclusion: Packet capture inspection of form_data reveals the attacker submitted the credentials username=admin and passwd=batman via an HTTP POST request. This indicates the administrative password was compromised via a targeted dictionary attack or prior credential leak.

Phase 5: Breach Confirmation
Objective: Verify if the credential submission resulted in a successful authentication.

SPL Query:
```spl
index="botsv1" sourcetype="stream:http" src_ip="40.80.148.42" uri="/joomla/administrator/index.php" http_method="POST"
| table _time, status
Evidence:(Drag and drop Phase 5 screenshot here)
```

Analyst Conclusion: The web server returned an HTTP 303 Redirect at the exact timestamp of the admin:batman POST request, confirming the credentials were valid and the adversary bypassed perimeter authentication controls to gain administrative access.

Phase 6: Payload Delivery
Objective: Identify the malicious executable uploaded to the web server post-breach.

SPL Query:
```spl
index="botsv1" "C:\\inetpub\\wwwroot\\joomla\\" ".exe"
Evidence:(Drag and drop Phase 6 screenshot here)
```

Analyst Conclusion: Endpoint telemetry confirms that shortly after gaining administrative access, the attacker uploaded and executed a malicious portable executable named 3791.exe within the C:\inetpub\wwwroot\joomla\ directory.

Phase 7: Command and Control (C2) Connection
Objective: Identify the external infrastructure the uploaded malware communicates with.

SPL Query:
```spl
index="botsv1" "3791.exe" "DestinationIp"
```
Evidence:(Drag and drop Phase 7 screenshot here)

Analyst Conclusion: Endpoint Sysmon logs (EventID 3) reveal that immediately upon execution, 3791.exe initiated an outbound TCP connection to an external C2 IP address (23.22.63.114) over port 1337, establishing a reverse shell / secondary staging channel. Subsequent analysis of Windows Security EventCode 4624 network logons confirmed the attacker did not laterally pivot from this web server to internal desktops, proving the subsequent ransomware alert stemmed from a separate attack vector.
