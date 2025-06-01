
# 🔍 Threat Hunt: Sudden Network Slowdown 

## 1. Executive Summary

* **Case ID / Title:** TH-2025-05-31-001 / Sudden Network Slowdown & Port Scan Detection
* **Date Range Investigated:** 2025-05-31 (Initial detection to resolution)
* **Analyst:** Danielle Morris
* **Environment:** Cyber Range / Production / Lab
* **Goal:** Investigate unusual network latency and connection issues to determine if activity was benign, misconfigured, or malicious.
* **Compromised Host:** `danielletargetm` (Local IP: `10.0.0.99`)
* **Targeted Account(s):** `SYSTEM account` (for script execution)
* **Summary:** A threat hunt was initiated following network monitoring alerts for unusual latency and repeated failed connection attempts originating from `danielletargetm`. Investigation revealed a PowerShell script, `portscan.ps1`, executed by the `SYSTEM account` from `C:\programdata`, performing internal network reconnaissance via port scanning. The device was isolated, scanned for malware (no detections), and an incident ticket was submitted for reimaging. The activity was confirmed as malicious reconnaissance.


  ![image](https://github.com/user-attachments/assets/ddcc4258-34c6-40fd-836a-77541052a918)
  

---

## 2. Scenario Overview

During routine performance monitoring, an internal host, `danielletargetm`, was flagged for unusual network latency and consistent connection failures. This anomaly prompted a deeper threat hunting investigation to ascertain the nature of the activity. The primary concern was to identify if the behavior was benign or a more malicious intent.

---

## 3. Mission & Hypothesis

* **Mission:** To thoroughly investigate the anomalous network activity originating from `danielletargetm`, identify the root cause, and determine the scope and impact of any detected threats.
* **Hypothesis:**
    * **Hypothesis 1 (Validated): Unauthorized Reconnaissance Script** - A malicious actor or compromised system is conducting internal reconnaissance via port scanning. Evidence suggests a PowerShell script was intentionally executed for this purpose.
    * **Hypothesis 2 (Invalidated): Misconfigured or Broken Script** - A legitimate internal tool or scheduled task is misconfigured, generating repeated failed connections. This was disproven by the nature of the script and its execution context.
    * **Hypothesis 3 (Potential): Lateral Movement Attempt** - An attacker is probing the network for accessible services to pivot deeper into the environment. The port scanning activity supports this as a potential next step.
    * **Hypothesis 4 (Invalidated): Exfiltration Attempt Blocked** - An external communication script failed due to egress filtering or proxy restrictions. No evidence of attempted external communication was found; activity was internal.

* **Expected Techniques:** PowerShell execution, network scanning, potential persistence mechanisms (e.g., scheduled tasks, registry modifications).

---

## 4. Methodology

* **Frameworks:** PEAK (Prepare, Enrich, Analyze, Act, Confirm, Know), MITRE ATT&CK
* **Tools Used:** Microsoft Defender for Endpoint (MDE), Microsoft Sentinel
* **Query Language:** Kusto Query Language (KQL)
* **Steps Followed:**
    1.  **Prepare:** Defined hypotheses based on initial alerts.
    2.  **Enrich:** Collected initial connection failure logs from `DeviceNetworkEvents`.
    3.  **Analyze:** Pivoted to `DeviceProcessEvents` to identify initiating processes and command lines. Examined script content and execution context.
    4.  **Act:** Isolated the compromised device via MDE and initiated a malware scan.
    5.  **Confirm:** Reviewed scan results and confirmed malicious activity based on script behavior and execution.
    6.  **Know:** Documented findings, mapped to MITRE ATT&CK, identified lessons learned, and recommended defensive actions.

---

## 5. Phase-by-Phase Breakdown

### Phase 1 - Initial Detection & Reconnaissance Confirmation

* **PEAK Step:** Enrich, Analyze
* **MITRE Tactics:** Discovery
* **Techniques Expected / Validated:** Network Service Scanning (T1046)
* **What We Investigated:** Initial network monitoring alerts indicating unusual latency and repeated failed connection attempts from `danielletargetm`. We focused on `DeviceNetworkEvents` to understand the volume and nature of these failures and identify target IPs/ports.
* **Query Input 🔽**

    ```kql
    DeviceNetworkEvents
    | where DeviceName contains "danielletargetm"
    | where ActionType == "ConnectionFailed"
    | summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP,  RemoteIP
    | order by ConnectionCount desc
    ```kql
    DeviceNetworkEvents
    | where DeviceName == "danielletargetm"
    | where ActionType == "ConnectionFailed"
    | project Timestamp, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine
    | order by Timestamp desc
    ```

  * **KQL Output** ⏬

      ![image](https://github.com/user-attachments/assets/ee0f86d7-a902-4d49-8337-94135d59dcce)

       ---

      ![KQL 4](https://github.com/user-attachments/assets/b2e446d6-154e-48c6-a5af-a7d78d911fb3)
      

      ---
      ![image](https://github.com/user-attachments/assets/1e8ece07-d075-4e67-b86f-da492d40fd23)


* **What We Found:**
    * `danielletargetm` (Local IP: `10.0.0.99`) showed 46 failed connection attempts.
    * Analysis of `RemoteIP` and `RemotePort` revealed a sequential port scan targeting `10.0.0.5` across common TCP ports (e.g., 21, 22, 80, 443, 3389).
    * The initiating process for these connections was identified as `powershell.exe` executing `C:\programdata\portscan.ps1` with an `-ExecutionPolicy Bypass` flag.
    * Bursts of activity were observed at 12:38 PM and 1:45 PM, the earliest port scan activity logged at `2025-05-31T16:38:07Z` UTC.

* **Interpretation:** The high volume of failed connections and the sequential nature of the targeted ports strongly indicated an intentional port scan. The use of PowerShell with `ExecutionPolicy Bypass` and the suspicious `C:\programdata` path for `portscan.ps1` immediately raised red flags, pointing towards malicious or unauthorized reconnaissance rather than a benign misconfiguration. This behavior is typical of an attacker attempting to enumerate services on internal hosts.

* **Mapped MITRE Techniques:**
    | Tactic    | Technique ID | Description             |
    | :-------- | :----------- | :---------------------- |
    | Discovery | T1046        | Network Service Scanning |

### Phase 2 - Execution & Privilege Analysis

* **PEAK Step:** Analyze, Act
* **MITRE Tactics:** Execution, Persistence, Defense Evasion
* **Techniques Expected / Validated:** PowerShell (T1059.001), Valid Accounts (T1078), Obfuscated Files/Scripts (T1027)
* **What We Investigated:** We focused on the process execution details related to `portscan.ps1` to understand its launch time, initiating account, and command-line arguments. This helped confirm the nature of the execution and potential privilege escalation. Upon gaining access to the compromised device, the `portscan.ps1` PowerShell script was directly examined.

* **Query Input 🔽**
    ```kql
    let VMName = "danielletargetm";
    let specificTime = datetime(2025-05-31T16:38:07.6642589Z);
    DeviceProcessEvents
    | where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
    | where DeviceName == VMName
    | order by Timestamp desc
    | project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
    ```

    * **KQL Output** ⏬

       ![inspect record](https://github.com/user-attachments/assets/04cfd7a6-2697-4c9e-9ec9-0eae4f16122d)

        
* **What We Found:**
    * The `portscan.ps1` script was launched at `2025-05-31T16:37:35Z`.
    * Crucially, the script was executed by the `SYSTEM account`.
    * The full command line was `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1`.
    * Screenshot of `portscan.ps1`:
        ![powershell](https://github.com/user-attachments/assets/a82ea14d-f12c-4886-9157-45205c83fe06)


* **Interpretation:** Execution by the `SYSTEM account` is highly unusual for a legitimate user-initiated script and suggests either a compromised SYSTEM process, a malicious scheduled task, or privilege escalation. The `-ExecutionPolicy Bypass` flag is a common tactic for attackers to circumvent security controls. This confirmed the malicious nature of the activity and indicated a potential compromise of the `SYSTEM account` for persistence or broader impact.

* **Mapped MITRE Techniques:**
    | Tactic          | Technique ID | Description                                     |
    | :-------------- | :----------- | :---------------------------------------------- |
    | Execution       | T1059.001    | PowerShell                                      |
    | Persistence     | T1078        | Valid Accounts (likely SYSTEM abuse)            |
    | Defense Evasion | T1027        | Obfuscated Files/Scripts (via policy bypass)    |

---

## 6. Timeline of Attacker Activity

| Timestamp (UTC)         | Event                                                                                         |
| :---------------------- | :-------------------------------------------------------------------------------------------- |
| 2025-05-31 16:37:35     | `portscan.ps1` launched from `C:\programdata` by `SYSTEM` account.                             |
| 2025-05-31 16:38:07     | Initial `portscan.ps1` execution attempt observed, initiating first burst of failed connections.  |
| 2025-05-31 17:44:50    | Second burst of port scanning activity detected.                                               |
| Post-scan               | `danielletargetm` isolated via MDE; full malware scan initiated.                              |

---

## 7. MITRE ATT&CK Summary Table

| Tactic          | Technique ID | Technique Name             | Evidence                                                                  |
| :-------------- | :----------- | :------------------------- | :------------------------------------------------------------------------ |
| Discovery       | T1046        | Network Service Scanning   | Repeated failed connections to sequential ports on `10.0.0.5`             |
| Execution       | T1059.001    | PowerShell                 | `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1` |
| Persistence     | T1078        | Valid Accounts             | Script executed by `SYSTEM account`                                       |
| Defense Evasion | T1027        | Obfuscated Files/Scripts   | Use of `-ExecutionPolicy Bypass` and suspicious `C:\programdata` path     |

---

## 8. Indicators of Compromise (IOCs)

| Type     | Value                                    | Description                                     |
| :------- | :--------------------------------------- | :---------------------------------------------- |
| File Path| `C:\programdata\portscan.ps1`            | Location of the suspicious PowerShell script    |
| File Name| `portscan.ps1`                           | Name of the reconnaissance script               |
| IP Address| `10.0.0.5`                               | Internal IP targeted by the port scan           |
| Command Line| `powershell.exe -ExecutionPolicy Bypass -File C:\programdata\portscan.ps1` | Full command executed for port scanning         |

---

## 9. Defensive Recommendations

| Area                 | Recommendation                                                                      |
| :------------------- | :---------------------------------------------------------------------------------- |
| **Endpoint Security**| Implement stricter endpoint detection rules for PowerShell execution, especially with `-ExecutionPolicy Bypass` and from unusual directories like `C:\programdata`. |
| **Detection Engineering**| Create alerts for `DeviceProcessEvents` where `FileName` is `powershell.exe` and `InitiatingProcessCommandLine` contains `-ExecutionPolicy Bypass` and unusual file paths. |
| **Privilege Management**| Regularly audit processes running with SYSTEM privileges to identify unauthorized or suspicious activity. Implement least privilege principles. |
| **Network Monitoring**| Enhance network monitoring to detect sequential port scanning patterns and unusual connection failures, particularly from internal hosts. |
| **Application Whitelisting**| Consider implementing application whitelisting to prevent unauthorized executables and scripts from running. |
| **User Education** | Educate users on the risks of executing unknown scripts and the importance of reporting suspicious activity. |
| **Incident Response**| Review and refine incident response playbooks for rapid containment and eradication of reconnaissance activities. |
| **Vulnerability Management**| Ensure all internal systems are regularly patched to minimize the attack surface for reconnaissance and lateral movement. |

---

## 10. Conclusion

This threat hunt successfully identified and contained a malicious port scanning activity originating from `danielletargetm`. The investigation confirmed that a PowerShell script, executed by the `SYSTEM account`, was performing internal reconnaissance, validating our primary hypothesis. While no malware was detected post-isolation, the nature of the activity necessitated a full reimaging of the device to ensure complete eradication of any potential hidden threats or persistence mechanisms. The incident provided valuable lessons, particularly regarding the need for closer examination of PowerShell execution, SYSTEM-level processes, and the importance of context in distinguishing benign IT automation from malicious reconnaissance. 

---

## 📅 Revision History

| Version | Changes                      | Date       | Author            |
| :------ | :--------------------------- | :--------- | :---------------- |
| 1.0     | Initial Investigation Log    | May 2025  | Danielle Morris   |
| 1.1     | Expanded Report with PEAK/MITRE Mapping, IOCs, and Detailed Recommendations | June 2025   | Danielle Morris   |

---

## 🚀 Project Status

![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Focus](https://img.shields.io/badge/Focus-Threat%20Hunting-blue)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Defender-blueviolet)
![Language](https://img.shields.io/badge/Scripting-KQL-yellow)

---

> ⚠ *"Automation can serve you or surveil you—it's up to how well it's secured."*
