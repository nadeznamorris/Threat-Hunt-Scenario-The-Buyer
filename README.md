# Threat-Hunt-Scenario-The-Buyer

## RDP Compromise Incident

**Report ID:** INC-2026-1403

**Analyst:** Nadezna Morris

**Date:** 14-March-2026

**Incident Date:** 27-January-2026

---

## 1. Findings

### **Key Indicators of Compromise (IOCs):**

- **Attack Source IP:** 
- **Compromised Account:** 
- **Malicious File:** 
- **Persistence Mechanism:** 
- **C2 Server:** 
- **Exfiltration Destination:**

---

### **KQL Queries Used:**

***SECTION 1: RANSOM NOTE ANALYSIS***

<img width="536" height="557" alt="Ransomware note" src="https://github.com/user-attachments/assets/25e0905f-d491-4cb5-9307-e0c103e572ad" /> <br>

**Objective:** Identify the ransomware group from the ransom note.  
**Flag:** `Akira`

**Objective:** The ransom note provides a contact method.  
**Flag:** `akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`

**Objective:** Each victim receives a unique identifier for negotiations.  
**Flag:** `813R-QWJM-XKIJ`

**Objective:** Each victim receives a unique identifier for negotiations.  
**Flag:** `.akira`

---

***SECTION 2: INFRASTRUCTURE***

**Objective:** Each victim receives a unique identifier for negotiations. 

**Flag:** `sync.cloud-endpoint.net`

```
DeviceNetworkEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where ActionType == "ConnectionSuccess"
| where RemoteUrl != ""
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated asc
```
<img width="1257" height="91" alt="image" src="https://github.com/user-attachments/assets/f77288a5-4897-4177-95b9-3602078db329" /> <br>

**Objective:** The payload established outbound connections.

**Flag:** `cdn.cloud-endpoint.net`

```
DeviceNetworkEvents
| where DeviceName == ("as-srv")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where RemoteUrl != ""
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by TimeGenerated asc
```
<img width="1213" height="116" alt="image" src="https://github.com/user-attachments/assets/81dbfb62-204b-40dc-90e2-e94453a2c527" /> <br>

**Objective:** The C2 infrastructure resolved to multiple IPs.

**Flag:** `104.21.30.237, 172.67.174.46`

```
DeviceNetworkEvents
| where DeviceName =="as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where RemoteUrl has_any ("sync.cloud-endpoint.net", "cdn.cloud-endpoint.net")
| distinct DeviceName, RemoteIP
```
<img width="275" height="107" alt="image" src="https://github.com/user-attachments/assets/6416fbab-80ba-4e5f-a584-0321ffa849b8" /> <br>

**Objective:** A Remote Tool route through relay servers.

**Flag:** `relay-0b975d23.net.anydesk.com`

```
DeviceNetworkEvents
| where DeviceName == "as-srv"
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where RemoteUrl has_any ("relay", "tunnel", "proxy", "gateway", "remote", "connect", "access")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| sort by TimeGenerated desc
```
<img width="955" height="78" alt="image" src="https://github.com/user-attachments/assets/02f86e8e-8868-4c33-a6d7-75a4411a42b2" />

---

***SECTION 3: DEFENSE EVASION***

**Objective:** A script was used to disable security controls.

**Flag:** `kill.bat`

```
DeviceFileEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any (".ps1", ".bat", ".cmd")
| where FileName !startswith "__PSScriptPolicyTest_"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated desc
```
<img width="1130" height="87" alt="image" src="https://github.com/user-attachments/assets/03790339-3bf5-4025-89ae-128191b3fe44" /> <br>

**Objective:** Identify the hash of the evasion script.

**Flag:** `0e7da57d92eaa6bda9d0bbc24b5f0827250aa42f295fd056ded50c6e3c3fb96c`

```
DeviceFileEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any (".ps1", ".bat", ".cmd")
| where FileName !startswith "__PSScriptPolicyTest_"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated desc
```
<img width="1299" height="85" alt="image" src="https://github.com/user-attachments/assets/cd6f24f1-c9c8-4f93-ae2e-127a2a6d3008" /> <br>

**Objective:** Windows Defender was disabled via registry modification.

**Flag:** `DisableAntiSpyware`

```
DeviceRegistryEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where RegistryKey has "Windows Defender"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
| sort by TimeGenerated desc 
```
<img width="1142" height="82" alt="image" src="https://github.com/user-attachments/assets/c98eae49-1688-4d90-9768-b0d506d54dfc" /> <br>

**Objective:** Determine when the registry was modified.

**Flag:** `21:03:42`

```
DeviceRegistryEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where RegistryKey has "Windows Defender"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
| sort by TimeGenerated desc 
```
<img width="1142" height="82" alt="image" src="https://github.com/user-attachments/assets/c98eae49-1688-4d90-9768-b0d506d54dfc" />

---

***SECTION 4: CREDENTIAL ACCESS***

**Objective:** The attacker enumerated running processes to locate a target for credential theft.

**Flag:** `tasklist | findstr lsass`

```
DeviceProcessEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where ProcessCommandLine has_any ("tasklist","Get-Process","wmic process","ps")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="768" height="83" alt="image" src="https://github.com/user-attachments/assets/d0fd6213-23d4-42b2-aa37-e9cc0697d149" /> <br>

**Objective:** A named pipe was accessed during credential theft activity.

**Flag:** `\Device\NamedPipe\lsass`

```
DeviceEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where ActionType == "NamedPipeEvent"
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| project TimeGenerated, DeviceName, InitiatingProcessFileName, PipeName
| sort by TimeGenerated asc
```
<img width="643" height="116" alt="image" src="https://github.com/user-attachments/assets/b913959f-104d-4e25-9143-d10d8b3e4d74" /> <br>

---

***SECTION 5: INITIAL ACCESS***

**Objective:** A remote access tool was pre-staged from the previous attack.

**Flag:** `Anydesk.exe`

```
DeviceProcessEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any ("anydesk.exe", "teamviewer.exe", "ngrok.exe", "cloudflared.exe", "rutserv.exe", "radmin.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FolderPath
| sort by TimeGenerated asc
```
<img width="827" height="82" alt="image" src="https://github.com/user-attachments/assets/9557eaf7-33a8-4f21-b223-ba5dbecb817f" /> <br>

**Objective:** The remote access tool was running from an unusual location on AS-PC2.

**Flag:** `C:\Users\Public\`

```
DeviceProcessEvents
| where DeviceName has_any ("as-")
| where TimeGenerated between (datetime(2026-01-27) .. datetime(2026-02-28))
| where FileName has_any ("anydesk.exe", "teamviewer.exe", "ngrok.exe", "cloudflared.exe", "rutserv.exe", "radmin.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, FolderPath
| sort by TimeGenerated asc
```
<img width="828" height="113" alt="image" src="https://github.com/user-attachments/assets/3004dacb-ea7d-4834-ad6b-8ba4ea9d15af" /> <br>

**Objective:** Identify the attacker's external IP address.

**Flag:** `88.97.164.155`

```



