########################################
# VPC Flow Logs: network-level traffic visibility
#
# Captures metadata (source/dest IP, port, protocol, accept/reject) for
# all traffic in and out of the VPC -- including scans and probes that
# never complete a full connection, which Apache/auth.log never see.
########################################

resource "aws_flow_log" "lab" {
  vpc_id               = aws_vpc.lab.id
  traffic_type          = "ALL"
  log_destination_type  = "s3"
  log_destination       = "${aws_s3_bucket.logs.arn}/vpc-flow-logs"

  tags = {
    Project = var.project_name
  }

  depends_on = [aws_s3_bucket_policy.logs]
}
