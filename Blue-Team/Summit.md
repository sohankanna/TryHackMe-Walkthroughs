# TryHackMe: Summit

**Category:** Blue Team / SOC Analysis
**Topic:** Pyramid of Pain, Threat Simulation, Malware Analysis, Sigma Rules

## Introduction

After participating in incident response activities, PicoSecure has decided to conduct a threat simulation and detection engineering engagement. We have been assigned to work with an external penetration tester (Sphinx) in an iterative purple-team scenario.

**Objective:**
The goal is to configure PicoSecure's security tools to detect and prevent malware execution. following the **Pyramid of Pain**. As we move up the pyramid, the indicators become harder to detect for us, but blocking them causes significantly more pain to the adversary.
<img width="1744" height="661" alt="image" src="https://github.com/user-attachments/assets/9122d03d-835b-4e76-ab60-d51638cd5909" />


---

## Challenge 1: Hash Values (sample1.exe)

### Scenario
We receive an email from Sphinx initiating the engagement. The first payload, `sample1.exe`, has been dropped. The first level of the Pyramid of Pain is **Hash Values**—trivial for attackers to change, but the easiest for us to block.
<img width="1892" height="773" alt="Screenshot 2025-11-28 140642" src="https://github.com/user-attachments/assets/496d4f6e-f3ab-4e4e-a1bd-c0a7d408600d" />

### Analysis
1. Navigate to the **Malware Sandbox**.
2. Select `sample1.exe` and click **Submit for Analysis**.
3. Once analyzed, review the **General Info** section.

<img width="1897" height="720" alt="Screenshot 2025-11-28 140801" src="https://github.com/user-attachments/assets/ade1239c-b414-46e3-9da9-51cb50fd68c7" />


We identify the unique SHA256 signature of the malware:
*   **File:** `sample1.exe`
*   **SHA256:** `9c550591a25c6228cb7d74d970d133d75c961ffed2ef7180144859cc09efca8c`

### Remediation
1. Go to **Manage Hashes**.
2. Select Algorithm: **SHA256**.
3. Paste the hash found in the analysis.
4. Click **Submit Hash**.

<img width="1899" height="720" alt="Screenshot 2025-11-28 140947" src="https://github.com/user-attachments/assets/7184b503-df55-4980-b9c1-6b0550298170" />


**Flag 1:** `THM{REDACTED}`

---

## Challenge 2: IP Addresses (sample2.exe)

### Scenario
Sphinx bypasses the hash block by simply changing the file (likely by flipping a bit), resulting in a new hash. We proceed to `sample2.exe`. To escalate the defense, we look for **IP Addresses**.

### Analysis
1. Upload `sample2.exe` to the **Malware Sandbox**.
2. Scroll down to the **Network Activity** tab.

<img width="1264" height="647" alt="Screenshot 2025-11-28 141208" src="https://github.com/user-attachments/assets/1c5bc4d9-d85e-45bb-964a-e59cf8f514d3" />

We observe the malware attempting to connect to an external Command & Control (C2) server:
*   **Destination IP:** `154.35.10.113`
*   **Port:** `4444`

### Remediation
We need to block this connection at the firewall level.

1. Go to the **Firewall Rule Manager**.
2. Create a new rule:
    *   **Type:** `Egress` (Outbound traffic).
    *   **Source IP:** `Any` (We want to stop any machine from reaching this IP).
    *   **Destination IP:** `154.35.10.113`.
    *   **Action:** `Deny`.
<img width="1898" height="734" alt="Screenshot 2025-11-28 141310" src="https://github.com/user-attachments/assets/35f32c92-7c53-4309-ac15-4bae4153f2c6" />
<br>


> **Note:** Egress filtering is critical here. Once malware is inside the network, it attempts to "phone home." Blocking the outbound connection severs the attacker's control.

**Flag 2:** `THM{REDACTED}`

---

## Challenge 3: Domain Names (sample3.exe)

### Scenario
Blocking IPs is effective, but attackers can easily change their IP address using cloud providers. Sphinx updates the malware (`sample3.exe`) to connect to a **Domain Name** instead. We must block the domain.

### Analysis
1. Upload `sample3.exe` to the **Malware Sandbox**.
2. Review the **DNS Requests** section under Network Activity.

<img width="1158" height="261" alt="Screenshot 2025-11-28 141544" src="https://github.com/user-attachments/assets/55aa2f2e-ba64-4f3b-8844-bf88d840a3f3" />


We see a request to a suspicious domain that does not look like standard traffic:
*   **Domain:** `emudyn.bresonicz.info`

### Remediation
1. Go to the **DNS Rule Manager**.
2. Create a new rule:
    *   **Rule Name:** `Suspicious C2`
    *   **Category:** `Malware`
    *   **Domain Name:** `emudyn.bresonicz.info`
    *   **Action:** `Deny`

<img width="1902" height="706" alt="Screenshot 2025-11-28 141639" src="https://github.com/user-attachments/assets/c47cbac9-99be-45ab-954a-ca8c4b12043e" />


**Flag 3:** `THM{REDACTED}`

---

## Challenge 4: Host Artifacts (sample4.exe)

### Scenario
Sphinx has stopped trying to reach out to the network immediately. `sample4.exe` is now modifying the host system to evade detection. We are now dealing with **Host Artifacts** (Annoying level).

### Analysis
1. Upload `sample4.exe` to the **Malware Sandbox**.
2. Inspect the **Registry Activity** tab.



We spot a malicious modification:
*   **Key:** `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`
*   **Name:** `DisableRealtimeMonitoring`
*   **Value:** `1`

The malware is attempting to turn off Windows Defender.

### Remediation
We need to create a **Sigma** rule to detect this specific registry change.

1. Go to the **Sigma Rule Builder**.
2. **Step 1:** Select **Sysmon Event Logs**.
3. **Step 2:** Select **Registry Modifications**.
4. **Step 3:** Configure the rule:
    *   **Registry Key:** `...Windows Defender\Real-Time Protection`
    *   **Registry Name:** `DisableRealtimeMonitoring`
    *   **Value:** `1`
    *   **ATT&CK ID:** `Defense Evasion (TA0005)`
<img width="1250" height="424" alt="Screenshot 2025-11-28 142031" src="https://github.com/user-attachments/assets/a7898040-a096-45da-9b0d-5fbad01d8992" />


**Flag 4:** `THM{REDACTED}`

---

## Challenge 5: Tools (Network Logs)

### Scenario
We have moved past simple file analysis. Sphinx is now using an automated tool to maintain persistence. We are provided with a network log file (`outgoing_connections.log`) to analyze **Tool** behavior.

### Analysis
We review the log file and look for patterns in the traffic (Beaconing).

<img width="1098" height="723" alt="Screenshot 2025-11-28 142150" src="https://github.com/user-attachments/assets/3f1c1aef-ea36-4976-801c-88cd60c35691" />


*   **Destination:** `51.102.10.19` (High frequency).
*   **Time:** Connections occur exactly every **30 minutes** (1800 seconds).
*   **Size:** The packet size is consistently **97 bytes**.

This regularity indicates an automated C2 beacon.

### Remediation
We create a Sigma rule to detect this traffic pattern, regardless of the IP it connects to.

1. Go to **Sigma Rule Builder**.
2. **Step 1:** Select **Sysmon Event Logs**.
3. **Step 2:** Select **Network Connections**.
4. **Step 3:** Configure the rule:
    *   **Remote IP:** `Any`
    *   **Remote Port:** `Any`
    *   **Size:** `97`
    *   **Frequency:** `1800`
    *   **ATT&CK ID:** `Command and Control (TA0011)`

<img width="1117" height="548" alt="Screenshot 2025-11-28 142453" src="https://github.com/user-attachments/assets/7af3cce1-cb5d-46fa-bc8d-2cf5654a171a" />


**Flag 5:** `THM{REDACTED}`

---

## Challenge 6: TTPs (commands.log)

### Scenario
We have reached the top of the Pyramid: **Tactics, Techniques, and Procedures (TTPs)**. This implies detecting the *behavior* of the attacker, not just their tools or hashes. Sphinx is using "Living off the Land" binaries to steal data.

### Analysis
We analyze the provided `commands.log`.

<img width="1168" height="479" alt="Screenshot 2025-11-28 142649" src="https://github.com/user-attachments/assets/a63590bd-7fab-4771-9406-9983f9026421" />


We see standard Windows commands (`dir`, `ipconfig`, `netstat`), but they all share a malicious procedure:
`>> %temp%\exfiltr8.log`

The attacker is staging data into a temporary file for exfiltration.

### Remediation
We need to detect the creation of this staging file.

1. Go to **Sigma Rule Builder**.
2. **Step 1:** Select **Sysmon Event Logs**.
3. **Step 2:** Select **File Creation and Modification**.
4. **Step 3:** Configure the rule:
    *   **File Path:** `%temp%`
    *   **File Name:** `exfiltr8.log`
    *   **ATT&CK ID:** `Exfiltration (TA0010)`

<img width="923" height="396" alt="Screenshot 2025-11-28 142823" src="https://github.com/user-attachments/assets/4598301b-0b72-4e36-a608-64eec5019ea3" />


**Flag 6:** `THM{REDACTED}`

---

## Conclusion
This room demonstrates the practical application of the **Pyramid of Pain**.
1.  **Hash:** Easy to block, easy for attackers to bypass.
2.  **IP/Domain:** Slightly harder, but attackers can use proxies/cloud.
3.  **Artifacts:** Requires specific knowledge of the malware's changes.
4.  **Tools/TTPs:** The most effective defense. By detecting the *behavior* (beaconing patterns or data staging), we force the attacker to fundamentally change how they operate.

***
