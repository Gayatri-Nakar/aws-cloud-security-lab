# Terraform: Cloud Attack Surface Analysis infrastructure

This deploys the entire AWS environment for the project as code: VPC,
subnet, Internet Gateway, route table, the intentionally-misconfigured
security group, a least-privilege IAM role, an S3 log bucket, CloudTrail,
VPC Flow Logs, GuardDuty, and the EC2 instance itself (which auto-deploys
the web app on first boot via user-data).

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5 installed locally
- [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) installed and configured (`aws configure`) with your IAM administrator credentials
- The `webapp/` folder from this repo, placed one level up from this `terraform/` folder (or pass its path explicitly)
- `zip` and `unzip` available locally (used by the packaging script)

**If you previously created the VPC/subnet/IGW/route table by hand in the
console**, delete those before running this, so Terraform isn't fighting
with resources it doesn't know about. Terraform should own every resource
in this project going forward.

## One-time setup

1. Copy the example variables file and fill in a globally unique bucket name:

   ```
   cp terraform.tfvars.example terraform.tfvars
   ```

   Edit `terraform.tfvars` and set `log_bucket_name` to something unique
   (S3 bucket names are unique across *all* of AWS, not just your
   account — e.g. `yourname-cloud-security-lab-logs-2026`).

2. Package the web application:

   ```
   bash package_webapp.sh ../webapp
   ```

   This produces `webapp.zip` in this folder, which Terraform will upload
   to S3 for the instance to pull down and deploy on first boot.

3. Initialize Terraform (downloads the AWS/TLS/local provider plugins):

   ```
   terraform init
   ```

## Deploy

```
terraform plan    # review exactly what will be created
terraform apply   # type "yes" to confirm
```

This will take a few minutes. When it finishes, Terraform prints:

- `instance_public_ip` — the IP to browse the site or SSH into
- `ssh_command` — a ready-to-use SSH command
- `log_bucket` — where all your logs are landing
- `cloudtrail_name` / `guardduty_detector_id`

**The instance is not "ready" the instant `apply` finishes** — user-data
takes a couple of minutes to install Apache/PHP, pull the app down from
S3, and start it. Give it 2–3 minutes, then check:

```
curl http://<instance_public_ip>/
```

If you want to watch the deployment happen in real time, SSH in and tail
the setup log:

```
ssh -i cloud-security-lab-key.pem ubuntu@<instance_public_ip>
sudo tail -f /var/log/user-data.log
```

## What gets created

| Resource | Purpose |
|---|---|
| VPC, subnet, IGW, route table | Network foundation |
| Security group (misconfigured) | SSH/HTTP/HTTPS open inbound; outbound restricted to 80/443/DNS |
| IAM role + instance profile | Scoped to S3 read (webapp package) and S3 write (own log prefix) only |
| S3 bucket | Destination for app/Apache/auth logs, CloudTrail, and VPC Flow Logs |
| CloudTrail | Account-level API activity audit trail |
| VPC Flow Logs | Network-level traffic visibility, delivered to S3 |
| GuardDuty detector | Managed threat detection (toggle with `enable_guardduty`) |
| EC2 instance | Runs the web app; auto-deployed via user-data on first boot |
| Generated SSH key pair | Private key saved locally as `<project_name>-key.pem` |

## During the observation window

Nothing further to do — logs are shipped to S3 automatically every 5
minutes via a cron job set up in user-data. Just let the instance sit
publicly exposed for your planned 24–48 hour window.

## Tearing down

When the observation window ends:

```
terraform destroy
```

This terminates the EC2 instance and removes the network/security group/
IAM role. **The S3 bucket and its contents are not deleted** by default
(no `force_destroy` is set on the bucket, and logs should already be
safely there from the continuous sync) — pull your logs down locally for
analysis and sanitization, and delete the bucket manually once you've
confirmed you have everything.

## Cost awareness

This uses a `t3.micro` instance (Free Tier eligible in most accounts) and
short-lived resources, so total cost for a 24–48 hour run should be
small — but GuardDuty and Security Hub-adjacent services are usage-based,
not flat-rate. Consider setting a billing alarm before you begin if
you're cost-conscious, and always confirm `terraform destroy` completed
successfully afterward.

## A note on secrets

`terraform.tfvars` and the generated `*.pem` private key file should never
be committed to git. Both are already listed in the project's
`.gitignore` — double check they stay out of anything you publish.
