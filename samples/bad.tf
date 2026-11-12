# deliberately insecure sample
resource "aws_security_group" "ssh_open" {
  name = "ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "demo-logs-{not-a-brace}"
  acl    = "public-read"
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
