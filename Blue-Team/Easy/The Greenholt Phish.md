# TryHackMe: The Greenholt Phish

**Room Link:** [The Greenholt Phish](https://tryhackme.com/room/phishingemails5fgjlzxc)
<br>

**Category:** Blue Team / Security Operations
<br>

**Topic:** Phishing Analysis, Email Header Analysis, OSINT, SPF/DMARC
<br>

## Introduction
<img width="1698" height="442" alt="image" src="https://github.com/user-attachments/assets/d9319371-eb2b-418a-87c0-24b92248ccda" />

We are presented with a suspicious email scenario. An employee has received an email concerning a "Payment Update."

**Objective:**
Our goal is to analyze the provided email headers and attachment to determine if it is a phishing attempt. We will use tools like Thunderbird to view the email, inspect the source code for IP addresses, and perform OSINT lookups (Whois, MxToolbox, VirusTotal) to verify the sender's reputation and the attachment's integrity.

**Room Resource:**
We begin by opening the suspicious email using the Thunderbird client on the provided VM.
<img width="1917" height="817" alt="image" src="https://github.com/user-attachments/assets/8a0b6b17-7e5e-4614-b96d-d23d598e767c" />


---

## Analysis & Solutions

### 1. Header Analysis: Subject Line
**Question:** What is the Transfer Reference Number listed in the email's Subject?

We start by examining the visible headers in the email client to understand the context of the message.

<img width="1320" height="529" alt="image" src="https://github.com/user-attachments/assets/ebf163f2-2269-44c9-97aa-142317ff5d66" />


*   **Analysis:** Looking at the "Subject" line in Thunderbird, we see a specific numeric reference number following the text "Payment Update".
*   **Answer:** `09813627`

### 2. Header Analysis: Sender Information
**Question:** Who is the email from?

We need to identify the display name and the sending email address.

*   **Analysis:** In the "From" field of the email header, we can see the sender's display name and the spoofed address.
*   **Answer:** `Mr. James Jackson`

### 3. Header Analysis: Reply Path
**Question:** What email address will receive a reply to this email?

Phishers often use a different "Reply-To" address than the one they send from to divert responses to an account they control.

<img width="854" height="160" alt="image" src="https://github.com/user-attachments/assets/a3b518a8-9de1-4de2-b8c0-0becdfc23446" />


*   **Analysis:** Checking the "Reply-To" field in the headers (as shown in the source view above), we see it directs to a `info.mutawamarine@mail.com` address.
*   **Answer:** `info@mutawamarine.com`

### 4. Technical Headers: Originating IP
**Question:** What is the Originating IP?

To see the true origin, we need to view the raw source code of the email (Press `Ctrl + U` in Thunderbird).

<img width="1014" height="225" alt="image" src="https://github.com/user-attachments/assets/4f3a899c-2caf-48a7-9a82-049707494b64" />


*   **Analysis:** We scan the raw headers for `X-Originating-IP` or the last `Received` header. The source code reveals the IP explicitly.
*   **Answer:** `192.119.71.157`

### 5. OSINT: IP Ownership
**Question:** Who is the owner of the Originating IP? (Do not include the "." in your answer.)

Now that we have the IP, we perform a Whois lookup to check the ISP or hosting provider.

<img width="1277" height="897" alt="image" src="https://github.com/user-attachments/assets/d656a8b3-d156-4ce4-bbf0-cde43c358ded" />


*   **Analysis:** Using a standard `whois` command or an online lookup tool, the "Organization" or "OrgName" field identifies the owner.
*   **Answer:** `Hostwinds LLC`

### 6. Domain Security: SPF Record
**Question:** What is the SPF record for the Return-Path domain?

We need to check the security configuration of the attacker's domain (`galvanized-steel.net`) using **MxToolbox**.

<img width="692" height="360" alt="image" src="https://github.com/user-attachments/assets/31d0093a-abf1-44d6-8ea6-094930282cd8" />


*   **Analysis:** By querying the TXT records for the domain, we find the SPF configuration string.
*   **Answer:** `v=spf1 include:spf.protection.outlook.com -all`

### 7. Domain Security: DMARC Record
**Question:** What is the DMARC record for the Return-Path domain?

Similarly, we check for DMARC implementation to see how the domain handles unauthenticated emails. We can use **dmarcian** or a DNS text record lookup.

<img width="1544" height="702" alt="image" src="https://github.com/user-attachments/assets/8589b012-5a7d-46c7-8048-629de430f3c3" />


*   **Analysis:** The DMARC record is visible in the DNS query results, showing the policy (`p`) and forensic options (`fo`).
*   **Answer:** `v=DMARC1; p=quarantine; fo=1`

### 8. Attachment Analysis: Filename
**Question:** What is the name of the attachment?

Back in the email source code, we look for the `Content-Disposition` section.

<img width="744" height="114" alt="image" src="https://github.com/user-attachments/assets/312c24fc-290d-483f-a1a5-e8fba42ca439" />


*   **Analysis:** The `filename` parameter within the header indicates what the file is called.
*   **Answer:** `SWT_#09674321____PDF__.CAB`

### 9. Attachment Analysis: Hashing
**Question:** What is the SHA256 hash of the file attachment?

We save the attachment to the machine and calculate its hash to identify it uniquely.

<img width="941" height="458" alt="image" src="https://github.com/user-attachments/assets/7ca77aa3-a87f-43a0-82b2-e1c3b82b8e8e" />


*   **Analysis:** Running `sha256sum [filename]` in the terminal generates the hash.
*   **Answer:** `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f`

### 10. Malware Analysis: File Size
**Question:** What is the attachment's file size? (Don't forget to add "KB" to your answer, NUM KB)

We query **VirusTotal** using the hash obtained in the previous step.

<img width="1682" height="804" alt="image" src="https://github.com/user-attachments/assets/91861a5a-7bf6-4dbf-9a6f-40ca62112839" />


*   **Analysis:** By navigating to the "Relations" or "Details" tab in the VirusTotal report, we can find the exact size of the bundled file.
*   **Answer:** `400.26 KB`

### 11. Malware Analysis: File Extension
**Question:** What is the actual file extension of the attachment?

Although the file is named `.pdf`, the headers or magic bytes often reveal the true file type.

<img width="1199" height="426" alt="image" src="https://github.com/user-attachments/assets/4bafdc9c-c1dd-406f-8131-536769bccd71" />


*   **Analysis:** Under the VirusTotal "Relations" or "Details" tab, the file type identification reveals it is actually an archive format, not a PDF document.
*   **Answer:** `rar`

---

## Conclusion
By dissecting the email headers, we successfully identified the spoofed sender, the true originating IP, and the lack of proper domain security (SPF/DMARC) which allowed the phish to land. Furthermore, analyzing the attachment hash revealed it to be a malicious RAR archive disguised as a PDF, confirming this was a malicious phishing attempt.
