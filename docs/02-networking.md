# Networking Foundation

## Objective

Build the networking foundation for the AWS Cloud Security Lab by creating a custom VPC, public subnet, Internet Gateway, and route table.

---

# 1. Virtual Private Cloud (VPC)

## Objective

Create an isolated virtual network to host all cloud resources.

### Configuration

| Setting | Value |
|---------|-------|
| Name | cloud-security-lab-vpc |
| CIDR | 10.0.0.0/16 |
| IPv6 | Disabled |
| Tenancy | Default |

### Validation

```bash
aws ec2 describe-vpcs \
    --filters "Name=tag:Name,Values=cloud-security-lab-vpc"
```

### Key Takeaways

- A VPC is an isolated network within AWS.
- It defines the IP address space for cloud resources.
- It does not provide internet connectivity by itself.

---

# 2. Public Subnet

## Objective

Create a subnet to host internet-facing resources.

### Configuration

| Setting | Value |
|---------|-------|
| Name | public-subnet-1 |
| CIDR | 10.0.1.0/24 |
| Availability Zone | us-east-1a |

### Validation

```bash
aws ec2 describe-subnets \
    --filters "Name=tag:Name,Values=public-subnet-1"
```

### Key Takeaways

- Subnets partition a VPC into smaller networks.
- EC2 instances are launched inside subnets.
- A subnet is **not** public simply because it exists.

---

# 3. Internet Gateway

## Objective

Allow the VPC to communicate with the public internet.

### Configuration

| Setting | Value |
|---------|-------|
| Name | cloud-security-lab-igw |
| Attached To | cloud-security-lab-vpc |

### Validation

```bash
aws ec2 describe-internet-gateways \
    --filters "Name=attachment.vpc-id,Values=vpc-0537fc0d028017885"
```

### Key Takeaways

- An Internet Gateway connects a VPC to the internet.
- Attaching an Internet Gateway alone does not make resources publicly accessible.

---

# 4. Public Route Table

## Objective

Control how traffic leaves the public subnet.

### Configuration

| Route | Target |
|------|--------|
| 10.0.0.0/16 | local |
| 0.0.0.0/0 | Internet Gateway |

Associated Subnet:

- public-subnet-1

### Key Takeaways

- Route tables determine where network traffic is forwarded.
- A subnet becomes public only when:
  - An Internet Gateway is attached to the VPC.
  - The subnet is associated with a route table.
  - The route table contains a default route (`0.0.0.0/0`) to the Internet Gateway.

---

# Networking Flow

A packet from the internet reaches an EC2 instance by traversing the following components:

```
Internet
    │
    ▼
Internet Gateway
    │
    ▼
Public Route Table
    │
    ▼
Public Subnet
    │
    ▼
Security Group
    │
    ▼
EC2 Instance
```

## Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| VPC | Defines the network boundary |
| Public Subnet | Hosts internet-facing resources |
| Internet Gateway | Connects the VPC to the internet |
| Route Table | Determines where packets are sent |
| Security Group | Determines whether packets are allowed |

---

# Next Steps

The networking layer is complete.

The next phase is to deploy an EC2 instance protected by a Security Group that permits only the required inbound traffic.