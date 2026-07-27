########################################
# S3: durable log storage
#
# Single bucket for everything -- app/Apache/auth logs shipped by the
# instance itself, plus CloudTrail and VPC Flow Logs delivered natively
# by AWS. Public access is fully blocked; only the instance role,
# CloudTrail, and the VPC Flow Logs service can write to it.
########################################

resource "aws_s3_bucket" "logs" {
  bucket        = var.log_bucket_name
  force_destroy = var.bucket_force_destroy

  tags = {
    Name    = "${var.project_name}-logs"
    Project = var.project_name
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls       = true
  restrict_public_buckets = true
}

# Disables ACLs entirely in favor of bucket-policy-only access control.
# This is the current AWS-recommended default and removes an entire
# class of misconfiguration (accidentally-permissive object/bucket ACLs)
# from being possible at all. CloudTrail and VPC Flow Logs delivery both
# use the newer policy-based delivery method below, not ACLs, so this
# doesn't conflict with either.
resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "logs_bucket_policy" {
  # Allow CloudTrail to check the bucket ACL before delivering logs
  statement {
    sid     = "AWSCloudTrailAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  # Allow CloudTrail to write its log files
  statement {
    sid     = "AWSCloudTrailWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.logs.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  # Allow the VPC Flow Logs delivery service to check the bucket ACL
  statement {
    sid     = "AWSFlowLogsAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
  }

  # Allow the VPC Flow Logs delivery service to write log files
  statement {
    sid     = "AWSFlowLogsWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.logs.arn}/vpc-flow-logs/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Reject any request to this bucket that isn't over HTTPS. Without this,
  # a request made over plain HTTP would still be permitted by default;
  # this closes that off entirely regardless of who the caller is.
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [
      aws_s3_bucket.logs.arn,
      "${aws_s3_bucket.logs.arn}/*"
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Only added when GuardDuty is enabled. Scoped to this specific
  # detector via aws:SourceArn, and to a dedicated prefix so exported
  # findings sit alongside, but don't mix with, the other log sources.
  dynamic "statement" {
    for_each = var.enable_guardduty ? [1] : []
    content {
      sid       = "AWSGuardDutyBucketLocation"
      effect    = "Allow"
      actions   = ["s3:GetBucketLocation"]
      resources = [aws_s3_bucket.logs.arn]

      principals {
        type        = "Service"
        identifiers = ["guardduty.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [data.aws_caller_identity.current.account_id]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_guardduty ? [1] : []
    content {
      sid       = "AWSGuardDutyWriteFindings"
      effect    = "Allow"
      actions   = ["s3:PutObject"]
      resources = ["${aws_s3_bucket.logs.arn}/guardduty-findings/*"]

      principals {
        type        = "Service"
        identifiers = ["guardduty.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [data.aws_caller_identity.current.account_id]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs_bucket_policy.json

  depends_on = [
    aws_s3_bucket_public_access_block.logs,
    aws_s3_bucket_ownership_controls.logs
  ]
}

# Uploads the packaged webapp so the instance can pull it down on first
# boot via its instance role (see iam.tf / ec2.tf).
resource "aws_s3_object" "webapp_package" {
  bucket = aws_s3_bucket.logs.id
  key    = "deploy/webapp.zip"
  source = var.webapp_local_path
  etag   = filemd5(var.webapp_local_path)
}
