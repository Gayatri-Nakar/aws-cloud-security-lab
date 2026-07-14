# AWS CLI Setup

## Objective

Configure the AWS CLI to securely manage AWS resources from my local machine.

## Completed

- Installed Git
- Installed AWS CLI v2
- Created IAM administrator user
- Created CLI access key
- Configured AWS CLI (`aws configure`)
- Default region: `us-east-1`
- Output format: `json`

## Verification

```bash
aws sts get-caller-identity
```

Successfully authenticated as the IAM administrator user.