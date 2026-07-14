# Cloud Attack Surface Analysis of an Internet-Exposed AWS Workload

**Status: in progress.** Network foundation (VPC, subnet, IGW, route table, IAM) and the simulated web application are built and tested locally. Currently setting up log storage (S3) and AWS-native monitoring (CloudTrail, VPC Flow Logs, GuardDuty) ahead of deployment and the live observation window.

## What is the project?

This project deploys a minimal, realistic web application on an internet-facing AWS EC2 instance and studies how automated internet traffic — scanners, bots, and brute-force tools — discovers, enumerates, and attacks it. The instance is deliberately configured with a common cloud security misconfiguration (SSH exposed to the public internet alongside HTTP/HTTPS), left publicly accessible for a fixed observation window, and instrumented to capture traffic across the network, OS, web server, application, and AWS control-plane layers. The collected data is then analyzed to reconstruct attacker behavior, build an attack timeline, and map observed techniques to the MITRE ATT&CK framework.

The web application itself is not the deliverable — it exists purely as a stimulus to generate authentic attack telemetry. The deliverable is the investigation: the architecture, the data, and the findings.

## Why am I building it?

To gain hands-on, practical experience with cloud security engineering rather than studying it theoretically — specifically AWS networking and IAM, security group configuration, Linux system administration, log collection and analysis, and mapping real-world attacker behavior to a recognized threat framework (MITRE ATT&CK). Exposing a deliberately misconfigured instance and observing what actually happens to it will produce a more concrete, evidence-based understanding of cloud attack surface risk than reading about best practices alone, and result in a portfolio-quality artifact demonstrating that skill set end to end.

## What technologies does it use?

**AWS:** VPC, subnets, Internet Gateway, route tables, security groups, EC2, IAM (least-privilege instance role), S3 (durable log storage), CloudTrail (API activity audit), VPC Flow Logs (network-level traffic visibility), and optionally GuardDuty for managed threat detection comparison.

**Application stack:** Ubuntu, Apache, PHP, and SQLite, hosting a simple simulated internal web portal (login page, dashboard, admin page, search, downloadable documents, contact form) designed to attract common categories of automated probing.

**Analysis:** Python-based log parsing and sanitization scripts (planned), used to process Apache access/error logs, Linux authentication logs, custom application logs, and AWS-native telemetry into a timeline and MITRE ATT&CK mapping.

## What will the repository contain?

- Infrastructure-as-code for the network, security groups, IAM roles, and S3 bucket used in the project
- Source code for the simulated web application
- Log-shipping and sanitization scripts
- Sanitized log samples referenced in the analysis
- Log parsing and analysis scripts
- The final written report: architecture, attack timeline, MITRE ATT&CK mapping, findings, and remediation recommendations

All account-specific identifiers, IP addresses, and credentials have been removed or replaced with generic placeholders (e.g. `<AWS_ACCOUNT_ID>`, `<ADMIN_IAM_USER>`, `<VPC_NAME>`) throughout every published artifact.
