########################################
# Security group
#
# This is the deliberate misconfiguration under study: SSH (22) is open
# to the entire internet alongside HTTP/HTTPS, instead of being restricted
# to a single administrator IP. Outbound traffic is intentionally
# restricted so that even in a worst-case compromise, the instance cannot
# be used to pivot outward, exfiltrate data broadly, or attack third
# parties -- it can only reach the ports needed for OS updates and
# talking to AWS APIs (S3, etc.), both of which use 443.
########################################

resource "aws_security_group" "web_misconfigured" {
  name        = "${var.project_name}-web-sg-misconfigured"
  description = "Intentionally misconfigured: SSH/HTTP/HTTPS all open to the internet"
  vpc_id      = aws_vpc.lab.id

  tags = {
    Name    = "${var.project_name}-web-sg-misconfigured"
    Project = var.project_name
  }
}

resource "aws_vpc_security_group_ingress_rule" "ssh_from_internet" {
  security_group_id = aws_security_group.web_misconfigured.id
  description        = "INTENTIONAL MISCONFIGURATION: SSH open to the entire internet"
  cidr_ipv4           = "0.0.0.0/0"
  from_port           = 22
  to_port              = 22
  ip_protocol          = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "http_from_internet" {
  security_group_id = aws_security_group.web_misconfigured.id
  description        = "HTTP, expected to be public"
  cidr_ipv4           = "0.0.0.0/0"
  from_port           = 80
  to_port              = 80
  ip_protocol          = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "https_from_internet" {
  security_group_id = aws_security_group.web_misconfigured.id
  description        = "HTTPS, expected to be public"
  cidr_ipv4           = "0.0.0.0/0"
  from_port           = 443
  to_port              = 443
  ip_protocol          = "tcp"
}

# Outbound restricted to 80/443 only -- enough for apt package updates and
# AWS API calls (S3 log shipping uses HTTPS), nothing broader.
resource "aws_vpc_security_group_egress_rule" "outbound_http" {
  security_group_id = aws_security_group.web_misconfigured.id
  description        = "Outbound HTTP for package updates"
  cidr_ipv4           = "0.0.0.0/0"
  from_port           = 80
  to_port              = 80
  ip_protocol          = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "outbound_https" {
  security_group_id = aws_security_group.web_misconfigured.id
  description        = "Outbound HTTPS for package updates and AWS API calls"
  cidr_ipv4           = "0.0.0.0/0"
  from_port           = 443
  to_port              = 443
  ip_protocol          = "tcp"
}

# DNS resolution is required for apt/AWS endpoints to resolve at all.
resource "aws_vpc_security_group_egress_rule" "outbound_dns_udp" {
  security_group_id = aws_security_group.web_misconfigured.id
  description        = "Outbound DNS"
  cidr_ipv4           = "0.0.0.0/0"
  from_port           = 53
  to_port              = 53
  ip_protocol          = "udp"
}
