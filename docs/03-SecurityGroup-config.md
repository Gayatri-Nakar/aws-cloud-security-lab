# Security Group

## Objective

Create a Security Group to act as a stateful virtual firewall for the EC2 web server, allowing only the network traffic required for administration and hosting a public website.

---

## Why a Security Group?

A Security Group controls inbound and outbound network traffic at the instance level.

Unlike a Route Table, which determines **where** traffic is sent, a Security Group determines **whether** traffic is allowed to reach the EC2 instance.

Security Groups are **stateful**, meaning that if inbound traffic is allowed, the return traffic is automatically permitted.

---

## Configuration

Name

web-server-sg

Description

Security Group for the cloud security lab web server

VPC

cloud-security-lab-vpc

### Inbound Rules

| Protocol | Port | Source | Purpose |
|----------|------|--------|---------|
| SSH | 22 | My Public IP (/32) | Secure remote administration |
| HTTP | 80 | 0.0.0.0/0 | Allow public web traffic |
| HTTPS | 443 | 0.0.0.0/0 | Allow secure web traffic |

### Outbound Rules

| Protocol | Destination | Purpose |
|----------|-------------|---------|
| All Traffic | 0.0.0.0/0 | Allow the instance to reach the Internet for updates and package installation |

---

## Validation

Verified using:

```bash
aws ec2 describe-security-groups --filters "Name=group-name,Values=web-server-sg"
```

Validation confirmed:

- Security Group successfully created
- Associated with cloud-security-lab-vpc
- SSH restricted to my public IP
- HTTP and HTTPS open to the Internet
- Default outbound traffic enabled

---

## What I Learned

A Security Group functions as a stateful firewall attached to AWS resources such as EC2 instances.

It does **not** determine how traffic is routed through the network. Instead, it evaluates whether incoming or outgoing traffic should be permitted after routing decisions have already been made.

Applying the Principle of Least Privilege, SSH access was restricted to my public IP address while only the web service ports (80 and 443) were exposed publicly.

---

## Security Considerations

Opening SSH (22) to the Internet (0.0.0.0/0) would expose the instance to automated brute-force attacks.

Restricting SSH access to a single trusted IP significantly reduces the attack surface while still allowing administrative access.

## Relationship to Previous Components

The networking foundation built in previous steps allows packets to reach the public subnet.

The Security Group is the first component that evaluates whether those packets are permitted to reach the EC2 instance.

Traffic Flow

Internet
    ↓
Internet Gateway
    ↓
Route Table
    ↓
Public Subnet
    ↓
Security Group
    ↓
EC2