# BTagent Infrastructure

Guide for deploying and managing BTagent infrastructure.

---

## Table of Contents

- [Docker Compose Modes](#docker-compose-modes)
- [Service Descriptions](#service-descriptions)
- [Helm Chart](#helm-chart)
- [Terraform Modules](#terraform-modules)
- [Monitoring Setup](#monitoring-setup)
- [Backup Procedures](#backup-procedures)

---

## Docker Compose Modes

BTagent provides multiple Docker Compose configurations for different use cases. All compose files are located in the `infra/` directory.

### Default Mode

The primary stack with all application and infrastructure services.

```bash
# Start all services
docker compose -f infra/docker-compose.yml up -d

# Or from the project root
make up
```

Services started: PostgreSQL, Redis, MinIO, Ollama, Backend, Frontend, Nginx.

### Dev Mode

Hot-reload configuration for local development. Backend source directories are mounted as volumes, and the frontend/nginx Docker containers are excluded (run locally instead).

```bash
# Start infrastructure + backend with hot reload
docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up -d

# Or from the project root (starts infra, prints instructions for local backend/frontend)
make dev
```

Dev mode overrides:
- Backend runs with `uvicorn --reload` and mounts `backend/`, `shared/`, `agents/` as volumes
- Frontend and Nginx are excluded (use `npm run dev` locally on port 5173)
- `BTAGENT_ENV=dev`, `BTAGENT_DEBUG=true`, `BTAGENT_LOG_LEVEL=debug`

### Observability Mode

Adds monitoring and tracing services alongside the default stack.

```bash
# Start with full observability
docker compose -f infra/docker-compose.yml -f infra/docker-compose.observability.yml up -d

# Or from the project root
make up-observability
```

Additional services: OpenTelemetry Collector, Jaeger, Prometheus, Grafana.

### Combining Modes

Compose files can be layered. For example, dev mode with observability:

```bash
docker compose \
  -f infra/docker-compose.yml \
  -f infra/docker-compose.dev.yml \
  -f infra/docker-compose.observability.yml \
  up -d
```

---

## Service Descriptions

### PostgreSQL (pgvector)

| Property | Value |
|----------|-------|
| Image | `pgvector/pgvector:pg16` |
| Port | 5432 |
| Purpose | Primary database with vector search support |

Stores all application data: investigations, IOCs, events, audit logs, users, knowledge base embeddings (via pgvector), playbooks, and MITRE ATT&CK data. Uses async SQLAlchemy with Alembic for migrations.

**Configuration:**

```bash
POSTGRES_USER=btagent          # Database user
POSTGRES_PASSWORD=<secret>     # Database password (change from default in production)
POSTGRES_DB=btagent            # Database name
```

### Redis

| Property | Value |
|----------|-------|
| Image | `redis:7-alpine` |
| Port | 6379 |
| Purpose | Pub/sub event bus, rate limiter backend, caching |

Handles real-time event routing from agent hooks to WebSocket clients via pub/sub channels (`btagent:events:{investigation_id}`). Also backs the sliding-window rate limiter.

### MinIO

| Property | Value |
|----------|-------|
| Image | `minio/minio:latest` |
| Ports | 9000 (API), 9001 (Console) |
| Purpose | S3-compatible object storage for evidence files |

Stores forensic evidence artifacts (files, screenshots, memory dumps) with SHA-256 integrity hashes. Compatible with any S3-compatible storage in production.

**Console:** Access the MinIO web console at `http://localhost:9001` (default credentials: `minioadmin`/`minioadmin`).

### Ollama

| Property | Value |
|----------|-------|
| Image | `ollama/ollama:latest` |
| Port | 11434 |
| Purpose | Local LLM inference for TLP:RED classified data |

Required for processing TLP:RED investigations where data cannot leave the local environment. Pull a model before use:

```bash
docker compose -f infra/docker-compose.yml exec ollama ollama pull llama3.3
```

### Nginx

| Property | Value |
|----------|-------|
| Image | `nginx:alpine` |
| Ports | 8080 (HTTP), 8443 (HTTPS) |
| Purpose | Reverse proxy, TLS termination, static file serving |

Routes traffic to the frontend and backend services. Configuration at `infra/nginx/nginx.conf`. TLS certificates (for HTTPS) are mounted from `infra/nginx/ssl/`.

### Observability Services

These are only started in observability mode (`docker-compose.observability.yml`).

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| **OpenTelemetry Collector** | `otel/opentelemetry-collector-contrib` | 4317 (gRPC), 4318 (HTTP) | Receives OTLP traces and forwards to Jaeger |
| **Jaeger** | `jaegertracing/all-in-one` | 16686 (UI) | Distributed tracing UI |
| **Prometheus** | `prom/prometheus` | 9090 | Metrics collection and querying |
| **Grafana** | `grafana/grafana` | 3001 | Dashboards and alerting |

---

## Helm Chart

The Helm chart is located at `infra/helm/btagent/` and provides Kubernetes deployment for production environments.

### Chart Structure

```
helm/btagent/
  Chart.yaml                  Chart metadata
  values.yaml                 Default configuration values
  values-staging.yaml         Staging environment overrides
  values-production.yaml      Production environment overrides
  templates/
    deployment.yaml           Backend + frontend deployments
    service.yaml              ClusterIP services
    ingress.yaml              Ingress with TLS termination
    configmap.yaml            Application configuration
    secret.yaml               Sensitive configuration (JWT secret, DB password)
    hpa.yaml                  Horizontal Pod Autoscaler
    pdb.yaml                  Pod Disruption Budget
    networkpolicy.yaml        Pod-to-pod traffic restrictions
    serviceaccount.yaml       Minimal-permission service account
    _helpers.tpl              Template helper functions
```

### Key Values

```yaml
# Backend
replicaCount: 1                  # Number of backend replicas
image:
  repository: ghcr.io/nickatnight96/btagent-backend
  tag: latest

# Frontend
frontendReplicaCount: 1
frontendImage:
  repository: ghcr.io/nickatnight96/btagent-frontend
  tag: latest

# Security
podSecurityContext:
  fsGroup: 1000
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]

# Services
service:
  type: ClusterIP
  port: 8000
frontendService:
  type: ClusterIP
  port: 80
```

### Installing

```bash
# Install with default values
helm install btagent infra/helm/btagent/

# Install with staging values
helm install btagent infra/helm/btagent/ -f infra/helm/btagent/values-staging.yaml

# Install with production values
helm install btagent infra/helm/btagent/ -f infra/helm/btagent/values-production.yaml

# Upgrade an existing release
helm upgrade btagent infra/helm/btagent/ -f infra/helm/btagent/values-production.yaml
```

### Template Features

- **HPA**: Auto-scales backend pods based on CPU/memory utilization
- **PDB**: Ensures minimum availability during node maintenance or upgrades
- **NetworkPolicy**: Restricts pod-to-pod traffic (e.g., only backend can reach PostgreSQL)
- **Ingress**: TLS termination with configurable host and certificate
- **ServiceAccount**: Minimal RBAC permissions for the application pods

---

## Terraform Modules

Terraform configurations for cloud infrastructure are in `infra/terraform/`. These provision the underlying cloud resources that the Helm chart deploys onto.

### Module Overview

```
terraform/
  main.tf                      Root module, composes all sub-modules
  variables.tf                 Input variables (region, instance sizes, etc.)
  outputs.tf                   Output values (endpoints, ARNs, etc.)
  modules/
    vpc/                       VPC, subnets, NAT gateways, security groups
    eks/                       EKS cluster, node groups, OIDC provider
    rds/                       RDS PostgreSQL with pgvector, parameter groups
    observability/             CloudWatch, managed Prometheus/Grafana
```

### VPC Module (`modules/vpc/`)

Provisions the network foundation:
- VPC with configurable CIDR block
- Public and private subnets across availability zones
- NAT gateways for private subnet internet access
- Security groups for EKS nodes, RDS, and ElastiCache

### EKS Module (`modules/eks/`)

Provisions the Kubernetes cluster:
- EKS cluster with managed node groups
- OIDC provider for IAM Roles for Service Accounts (IRSA)
- Node group with configurable instance types and scaling
- Cluster add-ons (CoreDNS, kube-proxy, VPC CNI)

### RDS Module (`modules/rds/`)

Provisions the managed PostgreSQL database:
- RDS instance with pgvector extension support
- Custom parameter group for PostgreSQL tuning
- Automated backups with configurable retention
- Multi-AZ option for production
- Security group restricting access to EKS nodes only

### Observability Module (`modules/observability/`)

Provisions cloud-native monitoring:
- Amazon Managed Service for Prometheus
- Amazon Managed Grafana
- CloudWatch log groups for application and infrastructure logs

### Usage

```bash
cd infra/terraform

# Initialize
terraform init

# Plan changes
terraform plan -var-file=production.tfvars

# Apply changes
terraform apply -var-file=production.tfvars
```

---

## Monitoring Setup

### Prometheus

Prometheus scrapes the backend's `/metrics` endpoint, which exposes:
- HTTP request counts and latency histograms
- WebSocket connection gauges
- Agent task counts and durations
- LLM token usage and cost counters
- Database connection pool statistics

Configuration: `infra/prometheus.yml`

Access Prometheus UI: `http://localhost:9090` (observability mode)

### Grafana

Grafana is pre-configured with:
- **Datasources**: Prometheus (metrics), Jaeger (traces)
- **Dashboards**: Provisioned automatically from `infra/grafana/provisioning/`

Access Grafana: `http://localhost:3001` (default: `admin`/`btagent`)

Key dashboards:
- **BTagent Overview**: Request rate, error rate, latency percentiles
- **Agent Performance**: Task durations, LLM token usage, cost tracking
- **Infrastructure**: Database connections, Redis operations, MinIO storage

### Jaeger

Jaeger provides distributed tracing for request flows across the backend and agent engine.

Access Jaeger UI: `http://localhost:16686` (observability mode)

Traces are collected via:
1. OpenTelemetry SDK in the backend emits OTLP spans
2. OTEL Collector receives and forwards to Jaeger
3. Jaeger stores and visualizes trace data

Configuration: `infra/otel-collector-config.yaml`

### Alerting

Grafana alerting can be configured to notify on:
- High error rates (>5% of requests returning 5xx)
- Elevated latency (p99 > 5s)
- Agent task failures
- Token budget exhaustion
- Database connection pool saturation

---

## Backup Procedures

### PostgreSQL Backups

#### Manual Backup

```bash
# Dump the full database
docker compose -f infra/docker-compose.yml exec postgres \
  pg_dump -U btagent -Fc btagent > backup_$(date +%Y%m%d_%H%M%S).dump

# Dump specific tables (e.g., audit logs only)
docker compose -f infra/docker-compose.yml exec postgres \
  pg_dump -U btagent -Fc -t audit_logs btagent > audit_backup.dump
```

#### Restore from Backup

```bash
# Restore a full backup
docker compose -f infra/docker-compose.yml exec -T postgres \
  pg_restore -U btagent -d btagent --clean < backup_20260326_120000.dump
```

#### Automated Backups (Production)

In production (Terraform-managed RDS):
- Automated daily snapshots with configurable retention (default: 7 days)
- Point-in-time recovery within the retention window
- Cross-region snapshot replication (optional)

### Redis Backups

Redis is used as a transient event bus and cache. Data loss on Redis restart is acceptable -- events are replayed from the database on reconnection. No backup is typically needed.

If you need to persist Redis data:

```bash
# Trigger an RDB snapshot
docker compose -f infra/docker-compose.yml exec redis redis-cli BGSAVE
```

### MinIO (Evidence) Backups

Evidence files stored in MinIO should be backed up regularly:

```bash
# Using the MinIO client (mc)
mc alias set local http://localhost:9000 minioadmin minioadmin
mc mirror local/btagent-evidence ./evidence_backup/
```

In production, use S3 versioning and cross-region replication for evidence storage.

### Backup Verification

Regularly verify backups by restoring to a test environment:

```bash
# Start a fresh PostgreSQL instance
docker run -d --name pg-test -e POSTGRES_PASSWORD=test pgvector/pgvector:pg16

# Restore the backup
cat backup.dump | docker exec -i pg-test pg_restore -U postgres -d postgres --clean

# Run a quick validation
docker exec pg-test psql -U postgres -c "SELECT count(*) FROM investigations;"

# Clean up
docker rm -f pg-test
```

---

## Further Reading

- [Architecture Overview](../docs/ARCHITECTURE.md)
- [Contributing Guide](../docs/CONTRIBUTING.md)
- [Security Policy](../SECURITY.md)
