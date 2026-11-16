# 🛡️ Splunk BOTS v1: End-to-End Threat Hunting & Incident Response Investigation

## 📌 Executive Summary
This repository documents a comprehensive digital forensics and incident response (DFIR) investigation conducted on the **Splunk Boss of the SOC (BOTS v1)** dataset for **Wayne Enterprises**. Using **Splunk Enterprise (SPL)**, network stream telemetry (`stream:http`), Windows Security Event Logs (`WinEventLog:Security`), and Sysmon endpoint logs (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`), this investigation uncovers and reconstructs two distinct, multi-stage cyberattacks:

1. **Incident 1 (Phases 1–7): Joomla Web Server Compromise & C2 Establishment**  
   An external adversary (`40.80.148.42`) conducted automated vulnerability reconnaissance against the corporate Joomla CMS, compromised the administrator portal (`admin:batman`), deployed a malicious web payload (`3791.exe`), and established outbound Command-and-Control (C2) communication to `23.22.63.114:1337`.
2. **Incident 2 (Phases 8–13): Cerber Ransomware Outbreak & Endpoint Forensics**  
   After ruling out lateral movement from the DMZ web server, global threat hunting identified a separate **Cerber Ransomware** outbreak impacting corporate file server `we9041srv` (`EventCode 5145`). Endpoint forensics isolated Patient Zero (`WAYNECORPINC\bob.smith` on workstation `we8105desk` / `192.168.250.100`) and reconstructed the full execution chain: a malicious macro-enabled Word template (`D:\Miranda_Tate_unveiled.dotm`) $\rightarrow$ obfuscated `cmd.exe` stager $\rightarrow$ VBScript dropper (`20429.vbs`) with a 5-minute sandbox evasion delay $\rightarrow$ HTTP payload download (`http://solidaritedeproximite.org/mhtr.jpg` from `37.187.37.150`) $\rightarrow$ execution of the disguised Cerber ransomware binary (`121214.tmp`).

---

## 🛠️ Environment & Telemetry Sources
* **SIEM Platform:** Splunk Enterprise
* **Network Telemetry:** `stream:http` (HTTP packet capture & form data inspection)
* **Windows Security Auditing:** `WinEventLog:Security` (`EventCode 4624` Logon Activity, `EventCode 5145` Detailed File Share Access)
* **Endpoint Detection (EDR/Sysmon):** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (`EventID 1` Process Creation, `EventID 3` Network Connection)
* **Core SPL Techniques:** Statistical aggregation (`stats`, `sort`, `head`, `table`), on-the-fly XML regular expression field extraction (`rex`), and multi-source timeline correlation.

---

## 🌐 Part 1 & 2: Web Server Compromise & C2 Investigation

### Phase 1: Initial Reconnaissance
* **Objective:** Identify the attacker's IP address and scanning methodology.
* **SPL Query:**
```spl
index="botsv1" sourcetype="stream:http"
| stats count by src_ip, http_user_agent
| sort - count
```
Evidence: https://github.com/AnshKhanna7503/splunk-botsv1-threat-hunting/blob/main/screenshots/phase01_initial_recon.png

Analyst Conclusion: A single external IP address (40.80.148.42) generated 17,420 HTTP requests in a very short window. Although the user-agent strings attempt to spoof a legitimate Chrome browser, the sheer volume of requests confirms the use of an automated vulnerability scanner or brute-force tool.

### Phase 2: Target Identification
* **Objective:** Determine the targeted web platform and specific attack vectors.
* **SPL Query:**
```spl
index="botsv1" sourcetype="stream:http" src_ip="40.80.148.42"
| stats count by uri
| sort - count
| head 10
```
Evidence:(Drag and drop Phase 2 screenshot here)

Triage & Analysis: The attacker targeted a Joomla CMS installation. The high volume of traffic directed at the Joomla search component indicates automated vulnerability fuzzing, while requests to /windows/win.ini show attempted Local File Inclusion (LFI). The attacker also discovered the administrative login portal at /joomla/administrator/index.php.

### Phase 3: Admin Portal Targeting
* **Objective:** Quantify the login attempts directed at the Joomla administrator portal.
* **SPL Query:**
```spl
index="botsv1" sourcetype="stream:http" src_ip="40.80.148.42" uri="/joomla/administrator/index.php" http_method="POST"
| stats count
```
Evidence:(Drag and drop Phase 3 screenshot here)

Analyst Conclusion: The attacker executed exactly 13 HTTP POST requests against the admin login page. This low volume indicates a highly targeted password guessing attempt rather than a massive, noisy brute-force attack.

### Phase 4: Credential Compromise
* **Objective:** Identify the compromised credentials used to breach the administrative portal.
* **SPL Query:**
```spl
index="botsv1" sourcetype="stream:http" src_ip="40.80.148.42" uri="/joomla/administrator/index.php" http_method="POST"
| table _time, form_data
Evidence:(Drag and drop Phase 4 screenshot here)
```
Analyst Conclusion: Packet capture inspection of form_data reveals the attacker submitted the credentials username=admin and passwd=batman via an HTTP POST request. This indicates the administrative password was compromised via a targeted dictionary attack or prior credential leak.

### Phase 5: Breach Confirmation
* **Objective:** Verify if the credential submission resulted in a successful authentication.
* **SPL Query:**
```spl
index="botsv1" sourcetype="stream:http" src_ip="40.80.148.42" uri="/joomla/administrator/index.php" http_method="POST"
| table _time, status
```
Evidence:(Drag and drop Phase 5 screenshot here)

Analyst Conclusion: The web server returned an HTTP 303 Redirect at the exact timestamp of the admin:batman POST request, confirming the credentials were valid and the adversary bypassed perimeter authentication controls to gain administrative access.

### Phase 6: Payload Delivery
* **Objective:** Identify the malicious executable uploaded to the web server post-breach.
* **SPL Query:**
```spl
index="botsv1" "C:\\inetpub\\wwwroot\\joomla\\" ".exe"
Evidence:(Drag and drop Phase 6 screenshot here)
```
Analyst Conclusion: Endpoint telemetry confirms that shortly after gaining administrative access, the attacker uploaded and executed a malicious portable executable named 3791.exe within the C:\inetpub\wwwroot\joomla\ directory.

### Phase 7: Command and Control (C2) Connection
* **Objective:** Identify the external infrastructure the uploaded malware communicates with.
* **SPL Query:**
```spl
index="botsv1" "3791.exe" "DestinationIp"
Evidence:(Drag and drop Phase 7 screenshot here)
```
Analyst Conclusion: Endpoint Sysmon logs (EventID 3) reveal that immediately upon execution, 3791.exe initiated an outbound TCP connection to an external C2 IP address (23.22.63.114) over port 1337, establishing a reverse shell / secondary staging channel. Subsequent analysis of Windows Security EventCode 4624 network logons confirmed the attacker did not laterally pivot from this web server to internal desktops, proving the subsequent ransomware alert stemmed from a separate attack vector.

## 🔒 Part 3: Cerber Ransomware Outbreak & Endpoint Forensics

### Phase 8: Ransomware Target Identification
* **Objective:** Identify the specific internal endpoint impacted by the Cerber ransomware.
* **SPL Query:**
```spl
index="botsv1" "cerber"
| stats count by host
```
Evidence:(Drag and drop Screenshot (238).png here)

Analyst Conclusion: A global search for Cerber indicators across the botsv1 index revealed 986 ransomware-related events on internal host we9041srv. Inspection of the underlying sourcetype (wineventlog:security) and active system processes (dfssvc.exe, NT AUTHORITY\SYSTEM) confirmed that we9041srv is the corporate File Server, where shared files were encrypted over the network.

### Phase 9: Compromised User & Patient Zero Identification
* **Objective:** Identify the user account and source workstation IP responsible for encrypting files on the corporate file server (`we9041srv`).
* **SPL Query:**
```spl
index="botsv1" host="we9041srv" "cerber"
| head 1
```
Evidence:(Drag and drop Screenshot (241).png here)

Analyst Conclusion: Analysis of Windows Security EventCode 5145 (Detailed File Share) logs on we9041srv reveals that domain user account WAYNECORPINC\bob.smith (bob.smith), operating from internal workstation IP 192.168.250.100, actively wrote encrypted .cerber files (such as 838\nvdSp0qz63.cerber) to the \\*\fileshare (\??\C:\fileshare) network share. This confirms Bob Smith (192.168.250.100) is Patient Zero for the ransomware outbreak.

### Phase 10: Victim Workstation Identification
* **Objective:** Correlate the compromised user account (`bob.smith`) and source IP (`192.168.250.100`) to a specific corporate desktop hostname.
* **SPL Query:**
```spl
index="botsv1" "192.168.250.100" "bob.smith" host="*desk*"
| stats count by host
| sort - count
```
Evidence:(Drag and drop Screenshot (245).png here)

Analyst Conclusion: By correlating source IP 192.168.250.100 and user bob.smith across desktop endpoints (host="*desk*"), all 48,285 workstation events resolved to a single machine: we8105desk. This confirms we8105desk is the origin endpoint where the Cerber ransomware detonated.

### Phase 11: Initial Access & Malicious Macro Execution Chain
* **Objective:** Reconstruct the process execution timeline on `we8105desk` using on-the-fly XML field extraction (`rex`) to determine how the ransomware entered the environment and executed.
* **SPL Query:**
```spl
index="botsv1" host="we8105desk" "<EventID>1</EventID>" "bob.smith"
| rex field=_raw "Name='ParentImage'>(?<ParentProcess>[^<]+)<"
| rex field=_raw "Name='Image'>(?<Process>[^<]+)<"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)<"
| table _time, ParentProcess, Process, CommandLine
| sort _time
```
Evidence:(Drag and drop Screenshot (246).jpg here)

Analyst Conclusion: Sysmon EventID 1 (Process Creation) logs on we8105desk reveal that at 22:13:12, user bob.smith opened a malicious macro-enabled Word template located on an external/mounted volume: "C:\Program Files (x86)\Microsoft Office\Office14\WINWORD.EXE" /n /dde "D:\Miranda_Tate_unveiled.dotm". Nine seconds later (22:13:21), WINWORD.EXE spawned C:\Windows\SysWOW64\cmd.exe with a heavily obfuscated command line that dynamically wrote a VBScript dropper to C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\20429.vbs and immediately executed it via wscript.exe.

### Phase 12: Ransomware Payload Detonation (`121214.tmp`)
* **Objective:** Identify the final ransomware binary dropped and executed by the VBScript stager (`20429.vbs`).
* **SPL Query:**
```spl
index="botsv1" host="we8105desk" "<EventID>1</EventID>" "bob.smith"
| rex field=_raw "Name='ParentImage'>(?<ParentProcess>[^<]+)<"
| rex field=_raw "Name='Image'>(?<Process>[^<]+)<"
| rex field=_raw "Name='CommandLine'>(?<CommandLine>[^<]+)<"
| table _time, ParentProcess, Process, CommandLine
| sort _time
```
Evidence:(Drag and drop Phase 12 / Page 7 screenshot here)

Analyst Conclusion: Following a 5-minute sleep cycle inside 20429.vbs designed to evade automated sandbox analysis (22:13:21 to 22:18:21), wscript.exe spawned cmd.exe ("C:\Windows\System32\cmd.exe" /C START "" "C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp") to launch a disguised portable executable. Eight seconds later (22:18:29), 121214.tmp spawned a child instance of itself and began encrypting files across we8105desk and the \\*\fileshare network share on we9041srv.

### Phase 13: Payload Hash Extraction & C2 / Staging Infrastructure Identification
* **Objective:** Extract the cryptographic hashes of `121214.tmp` and identify the external staging server from which the ransomware payload was downloaded.
* **SPL Queries:**
```spl
index="botsv1" host="we8105desk" "<EventID>1</EventID>" "121214.tmp"
| rex field=_raw "Name='Hashes'>(?<Hashes>[^<]+)<"
| table _time, Process, Hashes
```
```spl
index="botsv1" sourcetype="stream:http" src_ip="192.168.250.100"
| table _time, dest_ip, site, uri, http_user_agent
| sort _time
```
Evidence:(Drag and drop Screenshot (249).png and Screenshot (250).png here)

### Incident 1: Joomla Web Server Compromise

| Kill Chain Stage | MITRE ATT&CK | Indicator of Compromise (IOC) / Artifact | Context |
| :--- | :--- | :--- | :--- |
| **Reconnaissance** | `T1595.002` – Vulnerability Scanning | `40.80.148.42` | Generated 17,420 HTTP requests scanning Joomla CMS & testing LFI (`/windows/win.ini`). |
| **Initial Access** | `T1110.001` – Password Guessing | `/joomla/administrator/index.php` (`admin:batman`) | Compromised Joomla admin panel across 13 targeted HTTP POST requests (HTTP 303 Redirect). |
| **Execution** | `T1505.003` / `T1204` – Web Shell / Server Execution | `C:\inetpub\wwwroot\joomla\3791.exe` | Malicious binary uploaded and executed on the web server post-compromise. |
| **Command & Control** | `T1071` / `T1571` – Non-Standard Port | `23.22.63.114:1337` | Outbound TCP C2 connection initiated by `3791.exe`. |

### Incident 2: Cerber Ransomware Outbreak

| Kill Chain Stage | Timestamp (Log) | MITRE ATT&CK | Artifact / Indicator of Compromise (IOC) | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Patient Zero / Host** | `2016-08-24` | — | User: `WAYNECORPINC\bob.smith` \| Host: `we8105desk` (`192.168.250.100`) | Compromised domain user and desktop workstation. |
| **Initial Access** | `22:13:12` | `T1091` / `T1566.001` | `D:\Miranda_Tate_unveiled.dotm` | Malicious macro-enabled Word template opened from mounted drive `D:\` via `WINWORD.EXE`. |
| **Execution (Stager)** | `22:13:21` | `T1059.005` / `T1027` | `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\20429.vbs` | Obfuscated `cmd.exe` macro command writes and launches VBScript dropper via `wscript.exe`. |
| **Defense Evasion** | `22:13:21`–`22:18:21` | `T1497.003` – Time-Based Evasion | 5-minute `WScript.Sleep` loop | Delays payload download/execution for 300 seconds to bypass automated sandboxes. |
| **Payload Delivery** | `22:18:13` | `T1105` / `T1036.008` | `http://solidaritedeproximite.org/mhtr.jpg` (`37.187.37.150`) | `20429.vbs` downloads the Cerber executable masquerading as a `.jpg` image. |
| **Payload Detonation** | `22:18:21`–`22:18:29` | `T1204.002` / `T1055` | `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\121214.tmp` | Disguised binary executed via `cmd.exe /C START` and self-injected (`MD5: EE0828A4E4C195D97313BFC7D4B531F1` \| `SHA256: 37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B`). |
| **Discovery** | `22:19:24` | `T1016` | `http://ipinfo.io/json` (`54.148.194.58`) | Automated victim public IP and geolocation check post-detonation. |
| **Impact** | `2016-08-24` | `T1486` – Data Encrypted for Impact | Target: `we9041srv` (`\\*\fileshare` $\rightarrow$ `*.cerber`) | Network file share encrypted over SMB (`EventCode 5145`, 986 security audit events). |

---

## 🛡️ Remediation & Defensive Recommendations
1. **Immediate Containment:**
   * Isolate host **`we8105desk` (`192.168.250.100`)** and the DMZ Joomla web server from the corporate network.
   * Disable compromised domain account **`WAYNECORPINC\bob.smith`** and rotate credentials for the Joomla **`admin`** account.
   * Block external attacker and C2 IPs/domains at the perimeter firewall: `40.80.148.42`, `23.22.63.114`, `37.187.37.150`, and `solidaritedeproximite.org`.
2. **Endpoint & Access Hardening:**
   * Enforce Group Policy Objects (GPO) to **disable Microsoft Office macros** from executing in files originating from the internet or removable drives (`D:\`), and implement Attack Surface Reduction (ASR) rules blocking Office applications (`WINWORD.EXE`) from spawning child command interpreters (`cmd.exe`, `wscript.exe`, `powershell.exe`).
   * Apply Software Restriction Policies / AppLocker rules blocking executables and scripts from running out of `%APPDATA%` (`AppData\Roaming`) and `%TEMP%`.
3. **Recovery:**
   * Restore encrypted files on **`we9041srv` (`C:\fileshare`)** from verified offline/immutable backups and re-image `we8105desk`.
