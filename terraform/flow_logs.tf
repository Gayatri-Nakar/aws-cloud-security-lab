########################################
# VPC Flow Logs: network-level traffic visibility
#
# Captures metadata (source/dest IP, port, protocol, accept/reject) for
# all traffic in and out of the VPC -- including scans and probes that
# never complete a full connection, which Apache/auth.log never see.
########################################

resource "aws_flow_log" "lab" {
  vpc_id                    = aws_vpc.lab.id
  traffic_type               = "ALL"
  log_destination_type       = "s3"
  log_destination            = "${aws_s3_bucket.logs.arn}/vpc-flow-logs"

  # 60 seconds is the shortest aggregation window AWS offers (the
  # alternative is 600s/10min). Note this controls how much traffic gets
  # batched into each flow log *record*, not literally how fast AWS
  # delivers files to S3 -- actual delivery to S3 is still handled by AWS
  # on its own internal schedule (observed in practice as roughly every
  # 5-15 minutes), which this setting doesn't change. If you need tighter
  # delivery latency than that, the alternative is streaming Flow Logs to
  # CloudWatch Logs instead of S3, which is a larger architecture change.
  max_aggregation_interval = 60

  tags = {
    Project = var.project_name
  }

  depends_on = [aws_s3_bucket_policy.logs]
}
