########################################
# GuardDuty: managed threat detection (optional)
#
# Analyzes VPC Flow Logs, DNS logs, and CloudTrail events automatically
# and surfaces findings (e.g. "SSH brute force detected"). Used as an
# independent comparison point against the manual log analysis in the
# final report. Set enable_guardduty = false to skip.
########################################

resource "aws_guardduty_detector" "lab" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  tags = {
    Project = var.project_name
  }
}
