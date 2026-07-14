variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short name used to prefix/tag all resources in this project."
  type        = string
  default     = "cloud-security-lab"
}

variable "vpc_cidr" {
  description = "CIDR block for the project VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet."
  type        = string
  default     = "10.0.1.0/24"
}

variable "instance_type" {
  description = "EC2 instance type. t3.micro is Free Tier eligible in most accounts."
  type        = string
  default     = "t3.micro"
}

variable "log_bucket_name" {
  description = "Globally unique S3 bucket name for all project logs (app logs, Apache logs, auth.log, CloudTrail, VPC Flow Logs). Must be globally unique across all of AWS."
  type        = string
}

variable "instance_label" {
  description = "Label used as an S3 key prefix to distinguish this instance's logs from any other instance you might launch later."
  type        = string
  default     = "misconfigured-01"
}

variable "enable_guardduty" {
  description = "Whether to enable GuardDuty threat detection for this account/region."
  type        = bool
  default     = true
}

variable "webapp_local_path" {
  description = "Local path to the zipped webapp package (produced by scripts/package_webapp.sh) that will be uploaded to S3 and deployed to the instance."
  type        = string
  default     = "./webapp.zip"
}
