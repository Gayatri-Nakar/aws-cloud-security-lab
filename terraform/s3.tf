########################################
# S3: durable log storage
#
# Single bucket for everything -- app/Apache/auth logs shipped by the
# instance itself, plus CloudTrail and VPC Flow Logs delivered natively
# by AWS. Public access is fully blocked; only the instance role,
# CloudTrail, and the VPC Flow Logs service can write to it.
########################################

resource "aws_s3_bucket" "logs" {
  bucket = var.log_bucket_name

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
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs_bucket_policy.json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# Uploads the packaged webapp so the instance can pull it down on first
# boot via its instance role (see iam.tf / ec2.tf).
resource "aws_s3_object" "webapp_package" {
  bucket = aws_s3_bucket.logs.id
  key    = "deploy/webapp.zip"
  source = var.webapp_local_path
  etag   = filemd5(var.webapp_local_path)
}
