resource "aws_security_group" "web" {
  /* only HTTPS from the world */
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # public web, fine
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "demo-data"
  server_side_encryption_configuration {
    rule { apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" } }
  }
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  storage_encrypted   = true
  publicly_accessible = false
}
