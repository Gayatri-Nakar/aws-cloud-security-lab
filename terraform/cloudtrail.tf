########################################
# CloudTrail: account-level API activity audit trail
#
# Records every AWS API call made in this account/region -- including the
# resources this very Terraform run creates, and anything the instance's
# scoped-down role does (or would attempt to do) afterward.
########################################

resource "aws_cloudtrail" "lab" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  tags = {
    Project = var.project_name
  }

  depends_on = [aws_s3_bucket_policy.logs]
}
