# The Greenholt Phish

## Objectives 

<img width="1698" height="442" alt="image" src="https://github.com/user-attachments/assets/d9319371-eb2b-418a-87c0-24b92248ccda" />

open the mail using thunderbird as shown 
<img width="1917" height="817" alt="image" src="https://github.com/user-attachments/assets/8a0b6b17-7e5e-4614-b96d-d23d598e767c" />


#### What is the Transfer Reference Number listed in the email's Subject?
this can be found in the email subject

<img width="1320" height="529" alt="image" src="https://github.com/user-attachments/assets/ebf163f2-2269-44c9-97aa-142317ff5d66" />

#### Who is the email from?

again can be found in the email header from part 

#### What email address will receive a reply to this email? 

again can be found in the email header from part 

#### What email address will receive a reply to this email? 

foumnd in the same place as all the previous questions 


<img width="854" height="160" alt="image" src="https://github.com/user-attachments/assets/a3b518a8-9de1-4de2-b8c0-0becdfc23446" />

#### What is the Originating IP?

to view this press ctrl+u to view the plain source code 
and u can find the ip as shown in the image 
<img width="1014" height="225" alt="image" src="https://github.com/user-attachments/assets/4f3a899c-2caf-48a7-9a82-049707494b64" />

#### Who is the owner of the Originating IP? (Do not include the "." in your answer.)


just use the whois lookup to find the ownser of the above ip address 
<img width="1277" height="897" alt="image" src="https://github.com/user-attachments/assets/d656a8b3-d156-4ce4-bbf0-cde43c358ded" />

#### What is the SPF record for the Return-Path domain?

use mxtoolbox an online tool to find this as shown 
<img width="692" height="360" alt="image" src="https://github.com/user-attachments/assets/31d0093a-abf1-44d6-8ea6-094930282cd8" />



#### What is the DMARC record for the Return-Path domain?

use dmarcian to get the dmarc record as shown below 
<img width="1544" height="702" alt="image" src="https://github.com/user-attachments/assets/8589b012-5a7d-46c7-8048-629de430f3c3" />

#### What is the name of the attachment?

this can be found with the filename variable 
<img width="744" height="114" alt="image" src="https://github.com/user-attachments/assets/312c24fc-290d-483f-a1a5-e8fba42ca439" />

#### What is the SHA256 hash of the file attachment?
download the file and use the command sha256sum filename to get the hash of the file as shown below 

<img width="941" height="458" alt="image" src="https://github.com/user-attachments/assets/7ca77aa3-a87f-43a0-82b2-e1c3b82b8e8e" />

### What is the attachments file size? (Don't forget to add "KB" to your answer, NUM KB)

to solve this go to virustotal and enter the hash as shown below 
<img width="1682" height="804" alt="image" src="https://github.com/user-attachments/assets/91861a5a-7bf6-4dbf-9a6f-40ca62112839" />
the answer is located under the relations tab as shown 
<img width="1199" height="426" alt="image" src="https://github.com/user-attachments/assets/4bafdc9c-c1dd-406f-8131-536769bccd71" />

#### What is the actual file extension of the attachment?

located under the relations tab same as in the previous question 


