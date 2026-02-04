# phishing-email-analyzer
Phishing Email Analysis project using email headers, SPF, DKIM, DMARC, and SOC investigation tools.
# Phishing Email Analyzer

## Overview
This project demonstrates a real-world phishing email investigation using email header analysis, authentication checks, IP reputation analysis, and URL inspection. The workflow simulates how a Security Operations Center (SOC) analyst identifies phishing attempts.

## Attack Scenario
A suspicious email claiming to be from **Bradesco Bank** was received, warning about expiring reward points and urging the user to click a link.

## Tools Used
- EML / Email Header Analyzer
- VirusTotal
- AbuseIPDB
- urlscan.io
- Browserling
- MXToolbox
- nslookup

## Key Findings
- Sender impersonation detected
- SPF, DKIM, and DMARC authentication failures
- Suspicious cloud-hosted sender IP
- Malicious external phishing URL identified

## Outcome
The email was confirmed as **Phishing** based on multiple technical indicators and threat intelligence correlation.

## Learning Outcomes
- Phishing detection techniques
- Email authentication protocols (SPF, DKIM, DMARC)
- SOC investigation methodology
- Threat intelligence analysis

## Author
**Ankit Kirtane**
