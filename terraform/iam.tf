########################################
# IAM: least-privilege instance role
#
# This is the ONLY AWS credential the instance carries. It can write logs
# to the project's log prefix in S3, and read the webapp package used to
# deploy itself on first boot. Nothing else -- no broader S3 access, no
# access to other AWS services, so even a full compromise of the instance
# cannot be used to pivot into the wider AWS account.
########################################

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance_role" {
  name               = "${var.project_name}-instance-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json

  tags = {
    Project = var.project_name
  }
}

data "aws_iam_policy_document" "instance_permissions" {
  statement {
    sid     = "WriteLogsToOwnPrefix"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "arn:aws:s3:::${var.log_bucket_name}/${var.instance_label}/*"
    ]
  }

  statement {
    sid       = "ReadWebappPackage"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${var.log_bucket_name}/deploy/webapp.zip"]
  }
}

resource "aws_iam_role_policy" "instance_permissions" {
  name   = "${var.project_name}-instance-permissions"
  role   = aws_iam_role.instance_role.id
  policy = data.aws_iam_policy_document.instance_permissions.json
}

resource "aws_iam_instance_profile" "instance_profile" {
  name = "${var.project_name}-instance-profile"
  role = aws_iam_role.instance_role.name
}
