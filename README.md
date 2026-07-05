# AWS Cloud Security Lab

## Overview

This project documents the design and implementation of a production-inspired AWS cloud security lab built entirely with native AWS services.

The objective is to gain hands-on experience with AWS networking, identity and access management (IAM), infrastructure security, monitoring, threat detection, and incident response while documenting the engineering process from start to finish.

The lab will begin with a securely configured AWS environment and later introduce intentionally weakened configurations to compare attack surface, telemetry, and AWS-native security findings.

---

## Project Goals

- Build a production-inspired AWS environment from the ground up.
- Learn AWS networking, IAM, and infrastructure design.
- Configure AWS-native logging, monitoring, and threat detection.
- Investigate and analyze security events.
- Compare secure and intentionally weakened cloud configurations.
- Document architecture, implementation decisions, and lessons learned.

---

## Planned AWS Services

### Identity & Access Management
- IAM
- IAM Roles

### Networking
- VPC
- Subnets
- Internet Gateway
- Route Tables
- Security Groups

### Compute
- EC2
- Amazon Linux / Ubuntu
- Systems Manager (later)

### Monitoring & Detection
- CloudTrail
- CloudWatch
- VPC Flow Logs
- GuardDuty
- Security Hub
- Amazon Inspector

---

## Project Roadmap

### Phase 0 – Project Setup ✅

- [x] AWS Account
- [x] Root MFA
- [x] IAM Administrator User
- [x] AWS CLI
- [x] GitHub Repository

### Phase 1 – Networking Foundation 🚧

- [x] Custom VPC
- [x] Public Subnet
- [x] Internet Gateway
- [x] Public Route Table
- [x] Route Table Association
- [ ] Security Group

### Phase 2 – Secure Infrastructure

- [ ] Launch secure EC2 instance
- [ ] Install Nginx
- [ ] Configure least-privilege Security Group
- [ ] Configure IAM Role

### Phase 3 – Cloud Security Monitoring

- [ ] CloudTrail
- [ ] CloudWatch
- [ ] VPC Flow Logs
- [ ] GuardDuty
- [ ] Security Hub
- [ ] Amazon Inspector

### Phase 4 – Security Experiments

- [ ] Deploy second EC2 instance
- [ ] Introduce controlled security misconfigurations
- [ ] Compare secure vs. weakened configurations
- [ ] Analyze AWS security findings

### Phase 5 – Incident Investigation

- [ ] Investigate alerts
- [ ] Analyze logs
- [ ] Document findings
- [ ] Produce incident reports

---

## Repository Structure

```text
docs/
diagrams/
screenshots/
scripts/
notes/
```

---

## Current Status

🚧 Currently building the networking and infrastructure layer of the lab before introducing AWS-native monitoring and detection services.