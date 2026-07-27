# AWS Cloud Honeypot: Attack Surface Analysis Lab

---

## Goal

I wanted real hands-on experience with cloud security and log analysis. I built a deliberately misconfigured AWS EC2 instance running a fake company intranet, left it exposed to the internet for 8 hours, collected every layer of logs I could, and analyzed what hit it. This repo has everything: the infrastructure code, the web app, and the analysis pipeline. 

The instance ran Apache, PHP, and SQLite and hosted a fictional "Meridian Corp" employee portal complete with a login page, admin section, document downloads, and a search function. The security group was intentionally wrong: SSH, HTTP, and HTTPS all open to 0.0.0.0/0. That misconfiguration is the whole point.

---

## Repo Structure

```
aws-cloud-security-lab/
├── terraform/                  # Full IaC for the lab environment
│   ├── main.tf
│   ├── vpc.tf
│   ├── security_group.tf       # The intentional misconfiguration
│   ├── ec2.tf                  # Auto-terminates after 8 hours
│   ├── iam.tf                  # Least-privilege instance role
│   ├── s3.tf                   # Hardened log bucket
│   ├── cloudtrail.tf
│   ├── flow_logs.tf
│   ├── guardduty.tf            # Optional, disabled during this run
│   ├── user_data.sh.tpl        # First-boot deployment script
│   └── terraform.tfvars.example
│
├── webapp/                     # The fake Meridian Corp employee portal
│   ├── public/                 # What Apache serves to the internet
│   │   ├── index.php
│   │   ├── login.php
│   │   ├── admin.php
│   │   ├── search.php
│   │   ├── docs.php
│   │   ├── contact.php
│   │   └── policy_documents/
│   ├── db/                     # SQLite schema, outside the web root
│   └── scripts/                # Setup and log sync helpers
│
├── analyze_logs.py             # Five-phase log analysis pipeline
└── README.md
```

---

## What the analysis pipeline does

`analyze_logs.py` takes the raw logs from S3 and runs them through five phases:

1. **Sanitize** -- redacts own IP addresses before anything else touches the data
2. **Parse** -- normalizes all seven log sources into one common SQLite table
3. **Correlate** -- groups by source IP across log sources to find multi-source actors
4. **Map** -- tags observed behavior with MITRE ATT&CK technique IDs
5. **Report** -- writes a markdown findings report

Log sources it handles: Apache access log, Apache error log, Linux auth.log, the custom PHP app log, the SQLite login-attempts snapshot, VPC Flow Logs, and CloudTrail.

---

## Findings mapped to MITRE ATT&CK

Over the 8-hour window the instance saw 14,711 events from 5,405 distinct source IPs. Most of it was background internet noise. The findings worth calling out:

| Technique | What actually happened |
|---|---|
| T1595.002 Active Scanning: Vulnerability Scanning | Two IPs ran an identical multi-CVE exploit checklist in synchronized waves, 5 hours apart, same-second timestamps. One scanning operation, two source addresses. Probed for CVE-2021-41773, CVE-2017-9841, CVE-2018-20062, pearcmd RCE, and the Docker API. None succeeded. |
| T1595.001 Active Scanning: Scanning IP Blocks | Censys and Palo Alto Xpanse both self-identified and indexed the instance within the first hour. |
| T1190 Exploit Public-Facing Application | The CVE-specific payloads from the synchronized scanner above. |
| T1046 Network Service Discovery | Two IPs ran systematic port sweeps: one across VNC range (5900-5999, 62 ports TCP), one across UDP ports 4051-4099. Both rejected at the security group. |
| T1083 File and Directory Discovery | One IP with a real iPhone Safari user agent browsed the site and downloaded a document. Likely a real person who found an exposed IP. |

Two things that didn't happen are also worth noting: nobody submitted the login form once, and there was no classic SSH brute-forcing. The SSH activity that did happen was reconnaissance, banner grabbing and pre-authentication disconnects from four IPs, with one aborted root login attempt.

---

## The three-part writeup

This project is documented in three posts on Medium:

- **Part 1: Building a Cloud Honeypot** -- the why, the infrastructure design, the web app, the bugs, and how I got it working
- **Part 2: Designing a Log Sanitization and Normalization Pipeline** -- how the analysis pipeline works and why it's structured the way it is
- **Part 3: Technical Findings Report** -- full breakdown of what hit the instance, correlated across all log sources and mapped to ATT&CK

[Read on Medium](#) *(link to be added after publishing)*
