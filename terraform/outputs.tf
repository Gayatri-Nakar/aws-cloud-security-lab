output "instance_public_ip" {
  description = "Public IP of the EC2 instance -- use this to browse the site or SSH in."
  value       = aws_instance.web.public_ip
}

output "ssh_command" {
  description = "Ready-to-use SSH command using the generated key."
  value       = "ssh -i ${var.project_name}-key.pem ubuntu@${aws_instance.web.public_ip}"
}

output "log_bucket" {
  description = "S3 bucket receiving all project telemetry."
  value       = aws_s3_bucket.logs.id
}

output "cloudtrail_name" {
  value = aws_cloudtrail.lab.name
}

output "guardduty_detector_id" {
  value = var.enable_guardduty ? aws_guardduty_detector.lab[0].id : "GuardDuty not enabled"
}
