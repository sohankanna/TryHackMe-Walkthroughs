# TryHackMe: Snapped Phish-ing Line

**Room Link:** [Snapped Phish-ing Line](https://tryhackme.com/room/snappedphishingline)
<br>

**Category:** Blue Team / Security Operations
<br>

**Topic:** Phishing Analysis, Threat Intelligence, Email Forensics, Source Code Analysis
<br>

## Introduction
<img width="1647" height="792" alt="image" src="https://github.com/user-attachments/assets/2f772782-b9be-4643-aa24-2f9ddde79ca3" />

We are tasked with investigating a spear-phishing campaign targeting our organization. The attackers have sent various emails to employees, some containing malicious attachments and others linking to credential harvesting sites.

**Objective:**
We need to use Thunderbird to inspect the emails, identify the victims and the attacker's sending address, and analyze the malicious payloads (both PDF and HTML). We will further investigate the attacker's infrastructure by analyzing the phishing kit source code to find exfiltration addresses and hidden flags.

**Room Resource:**
We start by opening the Thunderbird client on the provided VM to view the inbox containing the suspicious emails.
<img width="846" height="331" alt="image" src="https://github.com/user-attachments/assets/8893b132-404a-4c9d-ac00-5585d19e2a59" />


---

## Analysis & Solutions

### 1. Identifying the PDF Target
**Question:** Who is the individual who received an email attachment containing a PDF?

We look through the emails to find one specifically containing a PDF attachment.
<img width="1419" height="142" alt="image" src="https://github.com/user-attachments/assets/d90dcbbf-0c3a-4d82-a313-7962e5d61cac" />

We open this specific email in Thunderbird to inspect the headers.
<img width="1825" height="789" alt="image" src="https://github.com/user-attachments/assets/8435732b-70bc-46b6-acf3-b16010837c8b" />

*   **Analysis:** Looking at the "To" field in the email header, we identify the recipient.
*   **Answer:** `William McClean`

### 2. Identifying the Attacker
**Question:** What email address was used by the adversary to send the phishing emails?

Staying on the same email (or checking the others in the campaign), we look at the "From" field.

<img width="974" height="181" alt="image" src="https://github.com/user-attachments/assets/e1c43788-45b9-48fe-9d2a-fc7f9af67171" />


*   **Analysis:** The sender's address is clearly visible in the header information.
*   **Answer:** `Accounts.Payable@groupmarketingonline.icu`

### 3. Phishing URL Analysis
**Question:** What is the redirection URL to the phishing page for the individual Zoe Duncan? (defanged format)

We switch to the email sent to **Zoe Duncan**. This email contains an HTML attachment named `Payment-Update-id.html` rather than a PDF.

<img width="485" height="404" alt="image" src="https://github.com/user-attachments/assets/9ef21bbb-d05f-478a-bd16-48344f743da3" />


We save the attachment and open the source code (or view it in a browser to see the URL bar).
<img width="1521" height="735" alt="image" src="https://github.com/user-attachments/assets/b5cb3ee5-dc63-4a19-b85b-19d1cb4433eb" />

*   **Analysis:** By inspecting the HTML source or the browser address bar, we extract the full URL. We use CyberChef to "Defang" the URL (replacing dots and colons) as requested.
<img width="1182" height="487" alt="image" src="https://github.com/user-attachments/assets/ff542e1c-c764-412b-a383-3c655b438ac0" />

*   **Answer:** `hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error`

### 4. Locating the Phishing Kit
**Question:** What is the URL to the .zip archive of the phishing kit? (defanged format)

Attackers often leave their directories open (Directory Listing). We navigate up the directory tree of the malicious URL to see if we can find the source code.
First, we check `http[:]//kennaroads.buzz/data/Update365/`.
<img width="1241" height="514" alt="image" src="https://github.com/user-attachments/assets/aa754028-af67-4c87-9a83-4602d80d4392" />

Then we go up one more level to `http[:]//kennaroads.buzz/data/`.
<img width="866" height="437" alt="image" src="https://github.com/user-attachments/assets/b7673781-20b8-4169-945b-d9faafb395cb" />

*   **Analysis:** In the `/data/` directory, we see a zip file named `Update365.zip`. This is likely the phishing kit source code.
*   **Answer:** `hxxp[://]kennaroads[.]buzz/data/Update365[.]zip`

### 5. Hashing the Kit
**Question:** What is the SHA256 hash of the phishing kit archive?

We download the `Update365.zip` file to our analysis machine and calculate its hash.

<img width="968" height="244" alt="image" src="https://github.com/user-attachments/assets/75cec624-0b2e-4df0-9b5b-155f742dfe90" />


*   **Analysis:** Using the command `sha256sum Update365.zip` provides the unique fingerprint of the file.
*   **Answer:** `ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686`

### 6. Threat Intelligence (VirusTotal)
**Question:** When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM:SS UTC)

We take the SHA256 hash calculated in the previous step and search for it on **VirusTotal**.

<img width="1783" height="796" alt="image" src="https://github.com/user-attachments/assets/c3cb425e-715e-4dac-872f-a8801d997908" />


*   **Analysis:** navigating to the **Details** or **History** tab, we look for the "First Submission" timestamp.
<img width="935" height="210" alt="image" src="https://github.com/user-attachments/assets/c05b6c72-451e-425f-9a5d-f1ca9f6180f5" />

*   **Answer:** `2020-04-08 21:55:50 UTC`

### 7. Infrastructure Analysis (SSL)
**Question:** When was the SSL certificate the phishing domain used to host the phishing kit archive first logged? (format: YYYY-MM-DD)

Since the site might be down or the certificate changed, we rely on Threat Intelligence history (or the room hint).

<img width="617" height="136" alt="image" src="https://github.com/user-attachments/assets/bc52f6bb-92ef-4844-aecc-e100edd1b9d3" />


*   **Answer:** `2020-06-25`

### 8. Analyzing Victim Logs
**Question:** What was the email address of the user who submitted their password twice?

In the directory listing we found earlier (`/data/Update365/`), there was a log text file. We examine this file to see captured credentials.

<img width="1314" height="545" alt="image" src="https://github.com/user-attachments/assets/618862a6-f88e-400d-8524-1393656a4c4e" />


*   **Analysis:** Scanning the log file, we see entries for `michael.ascot` appear multiple times, indicating he tried to log in twice.
*   **Answer:** `michael.ascot@swiftspend.finance`

### 9. Analyzing Source Code (Exfiltration)
**Question:** What was the email address used by the adversary to collect compromised credentials?

We unzip the `Update365.zip` file and examine the PHP scripts. The most interesting file for handling form submissions is usually `submit.php`. We check `Update365/office365/Validation/submit.php`.

<img width="987" height="600" alt="image" src="https://github.com/user-attachments/assets/2abe28e2-dac5-4b27-a932-e54a83a82abf" />


*   **Analysis:** In the PHP code, the `$send` variable contains the email address where the harvested credentials are sent.
*   **Answer:** `m3npat@yandex.com`

### 10. Analyzing Source Code (Other Actors)
**Question:** The adversary used other email addresses in the obtained phishing kit. What is the email address that ends in "@gmail.com"?

Attackers often reuse code or leave comments. We use `grep` to search recursively through the unzipped kit for any other email addresses.

<img width="928" height="183" alt="image" src="https://github.com/user-attachments/assets/8e27eeb0-e1c3-44fa-990e-a58cbaee62d9" />


*   **Analysis:** Running `grep -r "@gmail.com" .` reveals a hardcoded email address in one of the files.
*   **Answer:** `jamestanner2299@gmail.com`

### 11. Finding the Flag
**Question:** What is the hidden flag?

We found a reference to a flag file in the directory structure or simply try accessing common filenames. The file is located at `.../Update365/office365/flag.txt`.

<img width="1140" height="356" alt="image" src="https://github.com/user-attachments/assets/6249b04b-70eb-455f-9ab8-e7854b7bafd4" />


The text appears to be encoded (Base64) and reversed. We use **CyberChef** to decode it.
1.  **From Base64**
2.  **Reverse**

<img width="1331" height="634" alt="image" src="https://github.com/user-attachments/assets/04687931-7fd5-41fb-bb89-ef21ff86ade2" />


*   **Answer:** `THM{pL4y_w1Th_tH3_URL}`

---

## Conclusion
By combining email header analysis with open-source intelligence (OSINT) and direct examination of the phishing kit's source code, we were able to map out the entire attack chain. We identified the victims, the attacker's exfiltration methods, and the specific infrastructure used to host the malicious campaign.
