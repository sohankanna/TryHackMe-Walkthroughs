# TryHackMe: Eviction

**Room Link:** [Eviction](https://tryhackme.com/room/eviction)
<br>

**Category:** Blue Team / Threat Intelligence
<br>

**Topic:** MITRE ATT&CK, APT28, Threat Hunting
<br>

## Introduction
<img width="1692" height="394" alt="image" src="https://github.com/user-attachments/assets/be217625-cc5d-4034-9e6d-69ef0b7b242c" />

Sunny is a SOC analyst at E-corp. A classified intelligence report indicates that **APT28** (also known as Fancy Bear) is targeting organizations similar to E-corp.

**Objective:**
We need to use the **MITRE ATT&CK Navigator** to analyze the Tactics, Techniques, and Procedures (TTPs) associated with APT28. By mapping their behavior, we can determine if they have already intruded into the network and how to stop them.

**Room Resource:**
We are provided with a pre-loaded MITRE Navigator layer for APT28:
[Link to Layer provided in Room]
<img width="1902" height="891" alt="image" src="https://github.com/user-attachments/assets/634ccbf2-c624-48aa-aa6d-edf4e2672bf7" />


---

## Analysis & Solutions

### 1. Reconnaissance & Initial Access
**Question:** What is a technique used by the APT to both perform recon and gain initial access?

We need to look at the first two columns: **Reconnaissance** and **Initial Access**. We are looking for a technique that is highlighted in *both* columns.

<img width="371" height="143" alt="image" src="https://github.com/user-attachments/assets/b2c66351-ae39-4002-b427-6a421d62bf4b" />


*   **Analysis:** Under "Initial Access", we see "Phishing" techniques highlighted. Specifically, the technique involving links is a common overlap.
*   **Answer:** `Spearphishing Link`

### 2. Resource Development
**Question:** Which accounts might the APT compromise while developing resources?

Move to the **Resource Development** column (the stage where attackers set up their infrastructure).
<img width="295" height="180" alt="image" src="https://github.com/user-attachments/assets/79e03520-5952-4dfe-9449-2bfd5055c221" />


*   **Analysis:** We look for the "Compromise Accounts" section. The blue highlight indicates the specific type of account they target.
*   **Answer:** `Email Accounts`

### 3. Execution (Social Engineering)
**Question:** What two techniques of user execution should Sunny look out for?

We are now in the **Execution** tactic. The scenario mentions "Social Engineering" to make the user execute code.

<img width="326" height="176" alt="image" src="https://github.com/user-attachments/assets/ddb7241c-c930-4f33-a76b-7c7b5db45d53" />


*   **Analysis:** We look for techniques that require user interaction. The two standard methods involving social engineering are sending files or links.
*   **Answer:** `Malicious File and Malicious Link`

### 4. Execution (Scripting)
**Question:** Which scripting interpreters should Sunny search for to identify successful execution?

Still in the **Execution** column. If the social engineering works, the payload usually runs a script.

<img width="317" height="265" alt="image" src="https://github.com/user-attachments/assets/208a0b9a-f453-4e6f-99cb-8e56de433940" />


*   **Analysis:** Under "Command and Scripting Interpreter", we see two very common Windows tools highlighted in blue.
*   **Answer:** `Powershell and Windows Command Shell`

### 5. Persistence (Registry)
**Question:** Which registry keys should Sunny observe to track these changes?

The attacker wants to maintain access (Persistence). We look at the **Persistence** column.
<img width="508" height="154" alt="image" src="https://github.com/user-attachments/assets/c18662ef-25a7-4ad1-9f5e-77a32406886c" />


*   **Analysis:** The question specifically asks about **Registry** changes. We look for techniques involving "Boot or Logon Autostart Execution".
*   **Answer:** `Registry Run Keys / Startup Folder`

### 6. Defense Evasion (Binaries)
**Question:** Which system binary's execution should Sunny scrutinize for proxy execution?

The attacker is trying to hide (Defense Evasion). The question mentions "System Binary Proxy Execution".

<img width="568" height="361" alt="image" src="https://github.com/user-attachments/assets/ea7790c1-e8f3-44f3-91d8-83091a270ffe" />


*   **Analysis:** We scan the **Defense Evasion** column. Towards the bottom, under "System Binary Proxy Execution", we find a specific binary often abused to run DLLs.
*   **Answer:** `Rundll32`

### 7. Discovery (Sniffing)
**Question:** Which technique might the APT be using here for discovery? (Hint: tcpdump)

**tcpdump** is a packet analyzer. We need to find the technique in the **Discovery** column that relates to analyzing network packets.
<img width="313" height="234" alt="image" src="https://github.com/user-attachments/assets/f0899cfe-b52e-4255-b7c1-602e053651e2" />


*   **Analysis:** Analyzing packets on the wire is defined as "Network Sniffing".
*   **Answer:** `Network Sniffing`

### 8. Lateral Movement
**Question:** Which remote services should Sunny observe to identify APT activity traces?

The attacker is moving to other machines (**Lateral Movement**). The question asks about "Remote Services".
<img width="329" height="195" alt="image" src="https://github.com/user-attachments/assets/a3cc3b99-d9f4-4f61-8258-58c34f65c642" />

*   **Analysis:** We look under the "Remote Services" technique. APT28 is known for abusing standard Windows sharing protocols.
*   **Answer:** `SMB/Windows Admin Shares`

### 9. Collection
**Question:** Which information repository can be the likely target of the APT?

The goal is to steal IP (Intellectual Property). Look at the **Collection** column.

<img width="293" height="96" alt="image" src="https://github.com/user-attachments/assets/665594bb-22d7-4261-82f3-bffdf78b2e1e" />


*   **Analysis:** Under "Data from Information Repositories", we check which specific repository service is highlighted. APT28 frequently targets this Microsoft service.
*   **Answer:** `Sharepoint`

### 10. Command and Control (Proxy)
**Question:** What types of proxy might the APT use?

Finally, the attacker tries to exfiltrate data via C2. We look at the **Command and Control** column for "Proxy" usage.
<img width="394" height="119" alt="image" src="https://github.com/user-attachments/assets/47a26b75-2875-43a4-81f7-2a67471cf5e0" />


*   **Analysis:** Under "Proxy", there are two highlighted techniques that allow the attacker to bounce their traffic to hide its origin.
*   **Answer:** `External Proxy and Multi-hop Proxy`

---

## Conclusion
By mapping the intelligence report to the MITRE ATT&CK framework, we have built a complete profile of the attacker's expected behavior. We now know exactly what to look for in our SIEM (e.g., Rundll32 usage, SMB traffic, PowerShell scripts) to detect APT28.

