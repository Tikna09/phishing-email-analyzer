# phishing-email-analyzer
Phishing Email Analysis project using email headers, SPF, DKIM, DMARC, and SOC investigation tools.
# Phishing Email Analyzer

## Project Overview
This project focuses on the technical analysis of a phishing email to identify malicious indicators using real-world Security Operations Center (SOC) investigation techniques. The analysis includes email header inspection, sender authentication validation, IP reputation checks, and malicious URL analysis using industry-standard tools.

The goal of this project is to simulate how a SOC analyst investigates phishing incidents and classifies emails based on technical evidence rather than user perception.

---

## What is Phishing?
Phishing is a cyberattack technique in which attackers send fraudulent emails that appear to come from trusted organizations such as banks or well-known companies. These emails attempt to trick victims into revealing sensitive information or clicking malicious links.

### Common Objectives of Phishing Attacks
- Credential theft  
- Financial fraud  
- Malware delivery  
- Identity theft  

---

## Types of Phishing
- **Email Phishing** – Mass-sent phishing emails (most common)
- **Spear Phishing** – Targeted attacks on specific individuals
- **Whaling** – Targeting senior executives
- **Smishing** – Phishing via SMS
- **Vishing** – Voice-based phishing
- **Clone Phishing** – Legitimate emails copied and modified with malicious content

---

## Attack Scenario
A suspicious email claimed to be from **Bradesco Bank**, informing the recipient about expiring reward points and urging immediate action via a provided link. Due to urgency-based messaging and brand impersonation, the email was analyzed for phishing indicators.

---

## Email Authentication Protocols
### SPF (Sender Policy Framework)
Verifies whether the sending IP address is authorized to send emails on behalf of a domain.

### DKIM (DomainKeys Identified Mail)
Uses cryptographic signatures to ensure the email content has not been modified during transit.

### DMARC (Domain-based Message Authentication, Reporting & Conformance)
Combines SPF and DKIM and defines how receiving mail servers should handle authentication failures.

---

## Tools Used
- **EML / Email Header Analyzer** – Email routing and authentication analysis  
- **VirusTotal** – IP and URL reputation analysis  
- **AbuseIPDB** – Historical IP abuse records  
- **urlscan.io** – URL behavior and infrastructure analysis  
- **Browserling** – Safe browser-based URL testing  
- **MXToolbox** – SPF, DKIM, and DMARC validation  
- **nslookup** – DNS record verification  

---

## Step-by-Step Analysis

### Step 1: Email Header Analysis
- Sender email impersonated Bradesco Bank
- Sender IP address identified
- Authentication failures observed

### Step 2: Authentication Results
- SPF: **Fail (temperror)**
- DKIM: **None**
- DMARC: **Fail / Not compliant**

These results indicate sender spoofing and lack of proper email authentication.

### Step 3: Sender IP Reputation Analysis
- **IP Address:** 137.184.34.4
- Hosting Provider: DigitalOcean
- AbuseIPDB shows historical abuse reports (scanning and probing activity)

Despite not being currently blacklisted, the IP is considered suspicious.

### Step 4: URL Analysis
- **Suspicious URL:**  
  https://blog1seguimentmydomaine2bra.me/

**Observations:**
- Domain unrelated to Bradesco Bank
- Random and deceptive domain naming
- urlscan.io revealed multiple historical scans and phishing lander behavior

### Step 5: Safe Browsing Test
- Website failed to load during testing
- Common behavior observed in expired or takedown phishing campaigns

### Step 6: MXToolbox Results
- SPF Authentication: ❌
- DKIM Authentication: ❌
- DMARC Record: ❌ (Not found)

---

## Investigation Q&A

**Q1. What is the full sender email address?**  
banco.bradesco@atendimento.com.br  

**Q2. What domain was used to send the email?**  
atendimento.com.br  

**Q3. What is the sender IP address?**  
137.184.34.4  

**Q4. Is the sender IP blacklisted?**  
No (only historical abuse reports, no active blacklist)

**Q5. What was the SPF authentication result?**  
Fail (SPF = temperror)

**Q6. Name one suspicious URL found in the email body.**  
https://blog1seguimentmydomaine2bra.me/

---

## Project Outcome
- Successfully identified a phishing email
- Detected SPF, DKIM, and DMARC failures
- Identified a malicious phishing URL
- Correlated multiple threat intelligence sources
- Classified the email as phishing with technical justification

---

## Learning Outcomes
- Practical phishing detection techniques
- Deep understanding of email authentication protocols
- Hands-on SOC investigation experience
- Threat intelligence correlation
- Incident analysis and reporting skills

---

## Author
**Ankit Kirtane**

---

## License
This project is licensed under the MIT License.
