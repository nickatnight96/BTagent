# ── Security Group ────────────────────────────────────────────
resource "aws_security_group" "rds" {
  name_prefix = "btagent-${var.environment}-rds-"
  description = "Security group for RDS PostgreSQL"
  vpc_id      = var.vpc_id

  tags = {
    Name = "btagent-${var.environment}-rds-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group_rule" "rds_ingress_eks" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = var.eks_security_group_id
  security_group_id        = aws_security_group.rds.id
  description              = "Allow PostgreSQL access from EKS nodes"
}

resource "aws_security_group_rule" "rds_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.rds.id
  description       = "Allow all outbound traffic"
}

# ── DB Subnet Group ──────────────────────────────────────────
resource "aws_db_subnet_group" "main" {
  name       = "btagent-${var.environment}-db-subnet"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "btagent-${var.environment}-db-subnet-group"
  }
}

# ── KMS Key for RDS Encryption ──────────────────────────────
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption - btagent ${var.environment}"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name = "btagent-${var.environment}-rds-kms"
  }
}

resource "aws_kms_alias" "rds" {
  name          = "alias/btagent-${var.environment}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# ── Parameter Group (with pgvector) ─────────────────────────
resource "aws_db_parameter_group" "main" {
  name_prefix = "btagent-${var.environment}-pg16-"
  family      = "postgres16"
  description = "Custom parameter group for BTagent PostgreSQL with pgvector"

  parameter {
    name         = "shared_preload_libraries"
    value        = "pg_stat_statements,pgaudit"
    apply_method = "pending-reboot"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  parameter {
    name  = "max_connections"
    value = "200"
  }

  parameter {
    name  = "work_mem"
    value = "16384"
  }

  parameter {
    name  = "maintenance_work_mem"
    value = "524288"
  }

  tags = {
    Name = "btagent-${var.environment}-pg-params"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ── RDS Instance ─────────────────────────────────────────────
resource "aws_db_instance" "main" {
  identifier = "btagent-${var.environment}"

  engine               = "postgres"
  engine_version       = "16.3"
  instance_class       = var.db_instance_class
  allocated_storage    = 100
  max_allocated_storage = 500
  storage_type         = "gp3"
  storage_encrypted    = true
  kms_key_id           = aws_kms_key.rds.arn

  db_name  = var.db_name
  username = var.db_username
  manage_master_user_password = true

  multi_az               = var.db_multi_az
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.main.name
  publicly_accessible    = false

  backup_retention_period = 14
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"
  copy_tags_to_snapshot   = true
  skip_final_snapshot     = false
  final_snapshot_identifier = "btagent-${var.environment}-final-snapshot"
  deletion_protection     = true

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = aws_kms_key.rds.arn

  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  auto_minor_version_upgrade = true

  tags = {
    Name = "btagent-${var.environment}-postgres"
  }
}

# ── Enhanced Monitoring IAM Role ─────────────────────────────
resource "aws_iam_role" "rds_monitoring" {
  name = "btagent-${var.environment}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
  role       = aws_iam_role.rds_monitoring.name
}

# ── CloudWatch Alarms ────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "rds_cpu" {
  alarm_name          = "btagent-${var.environment}-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS CPU utilization is above 80% for 15 minutes"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }

  tags = {
    Name = "btagent-${var.environment}-rds-cpu-alarm"
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_storage" {
  alarm_name          = "btagent-${var.environment}-rds-low-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 10737418240 # 10 GB in bytes
  alarm_description   = "RDS free storage space is below 10 GB"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }

  tags = {
    Name = "btagent-${var.environment}-rds-storage-alarm"
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_connections" {
  alarm_name          = "btagent-${var.environment}-rds-high-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 150
  alarm_description   = "RDS connection count is above 150"

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.identifier
  }

  tags = {
    Name = "btagent-${var.environment}-rds-connections-alarm"
  }
}
