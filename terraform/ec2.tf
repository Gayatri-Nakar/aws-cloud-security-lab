########################################
# SSH key pair (key-based auth only -- no password auth, see user-data /
# sshd_config note below). Terraform generates the key pair so you don't
# need to create one by hand; the private key is saved locally and never
# uploaded anywhere.
########################################

resource "tls_private_key" "instance_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "instance_key" {
  key_name   = "${var.project_name}-key"
  public_key = tls_private_key.instance_key.public_key_openssh
}

resource "local_file" "private_key" {
  content         = tls_private_key.instance_key.private_key_pem
  filename        = "${path.module}/${var.project_name}-key.pem"
  file_permission = "0400"
}

########################################
# EC2 instance
########################################

resource "aws_instance" "web" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.web_misconfigured.id]
  key_name                    = aws_key_pair.instance_key.key_name
  iam_instance_profile        = aws_iam_instance_profile.instance_profile.name
  associate_public_ip_address = true

  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    bucket_name    = var.log_bucket_name
    instance_label = var.instance_label
  })

  tags = {
    Name    = "${var.project_name}-${var.instance_label}"
    Project = var.project_name
  }

  depends_on = [aws_s3_object.webapp_package]
}
