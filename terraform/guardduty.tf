########################################
# GuardDuty: managed threat detection (optional)
#
# Analyzes VPC Flow Logs, DNS logs, and CloudTrail events automatically
# and surfaces findings (e.g. "SSH brute force detected"). Used as an
# independent comparison point against the manual log analysis in the
# final report. Set enable_guardduty = false to skip all of this.
#
# By default, GuardDuty findings only live in the GuardDuty console/API --
# they are NOT automatically shipped anywhere. The publishing destination
# below is what actually exports findings into the same S3 bucket as
# everything else, so they survive `terraform destroy` and are available
# offline during analysis, just like the Apache/auth/app/Flow logs.
# AWS requires findings to be encrypted with a customer-managed KMS key
# (not S3's default encryption) to do this, hence the KMS resources here.
########################################

resource "aws_guardduty_detector" "lab" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  tags = {
    Project = var.project_name
  }
}

data "aws_iam_policy_document" "guardduty_kms" {
  count = var.enable_guardduty ? 1 : 0

  # Keeps full admin control of the key with your own account -- without
  # this statement, a KMS key policy that only grants GuardDuty access
  # can accidentally lock even the account root out of managing the key.
  statement {
    sid       = "EnableAccountKeyAdmin"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  # Scoped narrowly to this specific detector only, via aws:SourceArn --
  # GuardDuty can't use this key on behalf of any other detector, in this
  # or any other account.
  statement {
    sid       = "AllowGuardDutyToEncryptFindings"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [aws_guardduty_detector.lab[0].arn]
    }
  }
}

resource "aws_kms_key" "guardduty" {
  count                   = var.enable_guardduty ? 1 : 0
  description              = "CMK for encrypting GuardDuty findings exported to S3"
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.guardduty_kms[0].json

  tags = {
    Project = var.project_name
  }
}

resource "aws_guardduty_publishing_destination" "lab" {
  count             = var.enable_guardduty ? 1 : 0
  detector_id        = aws_guardduty_detector.lab[0].id
  destination_arn    = "${aws_s3_bucket.logs.arn}/guardduty-findings"
  kms_key_arn        = aws_kms_key.guardduty[0].arn
  destination_type  = "S3"

  depends_on = [aws_s3_bucket_policy.logs]
}
