# Deployment Guide

This guide covers deploying BTagent to production using Docker Compose, Kubernetes (Helm), or AWS (Terraform).

## Docker Compose Production

### 1. Production Environment File

Create a production environment file with strong credentials:

```bash
cp infra/.env.example infra/.env.production
```

```bash
# infra/.env.production

# Environment
BTAGENT_ENV=prod
BTAGENT_LOG_LEVEL=warning
BTAGENT_DEBUG=false

# Database (use strong password)
POSTGRES_USER=btagent
POSTGRES_PASSWORD=$(openssl rand -hex 24)
POSTGRES_DB=btagent
BTAGENT_DATABASE_URL=postgresql+asyncpg://btagent:${POSTGRES_PASSWORD}@postgres:5432/btagent

# Redis (enable authentication)
# Both lines are required and they must agree: the compose `redis` service
# starts with `--requirepass $REDIS_PASSWORD` when the variable is non-empty
# (and starts open when it is), while BTAGENT_REDIS_URL is what the backend
# and the arq scheduler dial. Setting only one of the two is an auth error.
REDIS_PASSWORD=$(openssl rand -hex 24)
BTAGENT_REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379

# Auth (generate a strong secret)
BTAGENT_JWT_SECRET=$(openssl rand -hex 32)

# S3 / MinIO (change from defaults)
BTAGENT_S3_ENDPOINT=http://minio:9000
BTAGENT_S3_ACCESS_KEY=$(openssl rand -hex 16)
BTAGENT_S3_SECRET_KEY=$(openssl rand -hex 32)
MINIO_ROOT_USER=${BTAGENT_S3_ACCESS_KEY}
MINIO_ROOT_PASSWORD=${BTAGENT_S3_SECRET_KEY}

# LLM providers (add your keys)
ANTHROPIC_API_KEY=sk-ant-...
BTAGENT_OPENAI_API_KEY=sk-...

# CORS — REQUIRED in prod. The backend refuses to start (B7) if this is
# unset, a wildcard ("*"), or still pointing at a localhost origin.
BTAGENT_CORS_ORIGINS=["https://btagent.example.com"]

# Observability
BTAGENT_OTEL_ENABLED=true
BTAGENT_OTEL_ENDPOINT=http://otel-collector:4317

# Connectors
BTAGENT_MOCK_CONNECTORS=false
```

> **Warning:** Never commit `.env.production` to version control. The `.gitignore` already excludes `.env` files.

### 2. SSL/TLS Configuration

> **The compose `nginx` service is HTTP-only out of the box.**
> `infra/nginx/nginx.conf` ships a single `listen 80` server block, so the
> compose file publishes `8080:80` and **no** 443 mapping — a published 8443
> that nothing listens on is worse than no port at all. Everything in this
> section is the opt-in work to change that; do all three steps or none.

#### Enabling TLS on the compose nginx

1. **Get a certificate** into `infra/nginx/ssl/` (already mounted read-only at
   `/etc/nginx/ssl`). Option A or B below, or for a local-production smoke test
   a self-signed pair:

   ```bash
   mkdir -p infra/nginx/ssl
   openssl req -x509 -newkey rsa:4096 -nodes -days 365 \
     -keyout infra/nginx/ssl/key.pem -out infra/nginx/ssl/cert.pem \
     -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
   ```

   Browsers will warn on a self-signed cert; that is expected, and it is not a
   substitute for a real certificate in a real deployment.

2. **Add the 443 server block** to `infra/nginx/nginx.conf` (see step 3 below
   for the block). nginx refuses to start if `ssl_certificate` points at a file
   that does not exist, which is why step 1 comes first.

3. **Re-add the port mapping** to the `nginx` service in
   `infra/docker-compose.yml` (and `infra/docker-compose.airgap.yml` if you run
   that stack):

   ```yaml
       ports:
         - "8080:80"
         - "8443:443"
   ```

Then `docker compose -f infra/docker-compose.yml up -d nginx` and verify with
`curl -k https://localhost:8443/health`.

#### Option A: Let's Encrypt (recommended)

Use certbot to obtain certificates:

```bash
sudo certbot certonly --standalone -d btagent.example.com
sudo cp /etc/letsencrypt/live/btagent.example.com/fullchain.pem infra/nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/btagent.example.com/privkey.pem infra/nginx/ssl/key.pem
```

#### Option B: Custom Certificates

Place your certificate and key in the nginx SSL directory:

```bash
cp your-cert.pem infra/nginx/ssl/cert.pem
cp your-key.pem infra/nginx/ssl/key.pem
```

### 3. Nginx Production Configuration

> **Hardened by default (B7):** The shipped frontend image
> (`infra/docker/Dockerfile.frontend`) and the cluster ingress
> (`infra/nginx/nginx.conf`) already emit the security headers below
> — HSTS, CSP (with `frame-ancestors`), `X-Frame-Options`,
> `X-Content-Type-Options`, and `Referrer-Policy` — out of the box. The
> backend's `SecurityHeadersMiddleware` sets the same baseline so the
> posture holds even without an nginx in front. The only step that
> remains manual is TLS termination (certs + the HTTPS `server` block).
> The Playwright `@nginx` security specs pin these header values.

The remaining production-specific work is adding TLS termination and the
HTTP→HTTPS redirect:

```nginx
server {
    listen 80;
    server_name btagent.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name btagent.example.com;

    ssl_certificate     /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss:;" always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    # ... location blocks remain the same
}
```

### 4. Database Backup Schedule

Set up automated PostgreSQL backups:

```bash
# Add to crontab (daily at 02:00 UTC)
0 2 * * * docker compose -f /path/to/infra/docker-compose.yml exec -T postgres \
  pg_dump -U btagent btagent | gzip > /backups/btagent-$(date +\%Y\%m\%d).sql.gz

# Retain 30 days of backups
0 3 * * * find /backups -name "btagent-*.sql.gz" -mtime +30 -delete
```

### 5. Deploy

```bash
docker compose -f infra/docker-compose.yml --env-file infra/.env.production up -d
```

**No separate migration step.** The compose file runs two one-shot services to
completion before `backend` and `scheduler` are allowed to start
(`depends_on: condition: service_completed_successfully`):

| Service | Command | Closes |
|---------|---------|--------|
| `migrate` | `sh -c "cd backend && alembic upgrade head"` | the backend booting against an empty schema and reporting `/health` OK until the first login fails on a missing `users` table |
| `init-storage` | `bt init-storage` | `/health/ready` reporting `s3: down`, and every evidence upload failing, because nobody ever created the bucket |

Both are idempotent, run on every `up`, and use the backend image, so an
upgrade migrates before the new code serves traffic. Check them with:

```bash
docker compose -f infra/docker-compose.yml logs migrate init-storage
```

`make db-migrate` still exists for host-side/dev use (it runs alembic from a
local virtualenv); it is no longer a required deploy step.

> **Do not run `make db-seed` in production.** It also inserts a sample
> investigation and demo users (`analyst1`, `senior1`) with random,
> unrecoverable passwords. Use the admin bootstrap below instead.

#### Bootstrap the admin user

This is the **only** manual step between `up` and a usable system. The first
admin account is created from `BTAGENT_SEED_ADMIN_PASSWORD`, and `bt` is a
console script inside the backend image, so this works with nothing but the
running stack — no repository, no virtualenv:

```bash
docker compose -f infra/docker-compose.yml \
  exec -e BTAGENT_SEED_ADMIN_PASSWORD="$(openssl rand -base64 24)" \
  backend bt create-admin
```

Capture the password you generate *before* running the command (it is never
printed, by design, and there is no way to read it back afterwards).

`bt create-admin` is idempotent: it creates the `admin` user if missing,
otherwise resets its password — so it doubles as the **password-reset /
recovery path**. Re-run it with a new value to rotate. Options:

```bash
# All of these run inside the container, i.e. after
#   docker compose -f infra/docker-compose.yml exec backend <cmd>

# a different account, or an explicit password (beware shell history)
bt create-admin --username soc-lead --password 'NEW_STRONG_PASSWORD'

# machine-readable; the payload never contains the password
bt --json create-admin

# from a Makefile on the host, which wraps the exec for you
# make create-admin BTAGENT_SEED_ADMIN_PASSWORD="$(openssl rand -base64 24)"
```

> If `BTAGENT_SEED_ADMIN_PASSWORD` is unset (and no `--password` is given) in a
> non-test environment, the command exits 1 rather than creating an account
> with an unrecoverable random password.

On a host checkout with a virtualenv, `make db-reset-admin`
(`infra/scripts/reset-admin-password.py`) does the same thing through the same
code path. It cannot be used in a container-only or air-gapped install, which
is why `bt create-admin` is the documented path.

### 6. Verify

```bash
# liveness — always 200 while the process is up
curl -sf http://localhost:8000/health

# readiness — 503 until DB, Redis and the S3 bucket all answer
curl -sf http://localhost:8000/health/ready
# {"status":"ready","checks":{"db":"ok","redis":"ok","s3":"ok"}}

# the UI, through the compose nginx
curl -sf http://localhost:8080/ | head -5

# log in with the password you just set
curl -sf -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<the password>"}'
```

`docker compose ps` should show `postgres`, `redis`, `minio`, `backend` and
`scheduler` healthy, and `migrate` / `init-storage` as `Exited (0)`. An
`Exited` code other than 0 on either one-shot means the stack never finished
bootstrapping — read its logs before anything else.

---

## Kubernetes (Helm)

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| kubectl | 1.28+ | Kubernetes CLI |
| helm | 3.14+ | Package manager |
| Cluster access | -- | EKS, GKE, AKS, or self-managed |

### 1. Configure Production Values

Edit `infra/helm/btagent/values-production.yaml`:

```yaml
# Replicas
replicaCount: 3
frontendReplicaCount: 2

image:
  repository: ghcr.io/nickatnight96/btagent-backend
  pullPolicy: Always
  tag: "0.3.0"   # Pin to a release tag

frontendImage:
  repository: ghcr.io/nickatnight96/btagent-frontend
  pullPolicy: Always
  tag: "0.3.0"

# Ingress -- update with your domain
ingress:
  hosts:
    - host: btagent.example.com
      paths:
        - path: /api
          pathType: Prefix
          service: backend
        - path: /ws
          pathType: Prefix
          service: backend
        - path: /
          pathType: Prefix
          service: frontend
  tls:
    - secretName: btagent-production-tls
      hosts:
        - btagent.example.com

# Resources -- adjust for your workload
resources:
  limits:
    cpu: 2000m
    memory: 4Gi
  requests:
    cpu: 500m
    memory: 1Gi

# Autoscaling
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

# Pod Disruption Budget
podDisruptionBudget:
  enabled: true
  minAvailable: 2

# Environment
env:
  BTAGENT_ENV: production
  BTAGENT_LOG_LEVEL: warning
  BTAGENT_OTEL_ENABLED: "true"
  BTAGENT_MOCK_CONNECTORS: "false"
```

### 2. Create Kubernetes Secrets

```bash
kubectl create namespace btagent

kubectl create secret generic btagent-secrets \
  --namespace btagent \
  --from-literal=BTAGENT_DATABASE_URL='postgresql+asyncpg://btagent:STRONG_PASSWORD@postgres-host:5432/btagent' \
  --from-literal=BTAGENT_REDIS_URL='redis://:STRONG_PASSWORD@redis-host:6379' \
  --from-literal=BTAGENT_JWT_SECRET="$(openssl rand -hex 32)" \
  --from-literal=BTAGENT_S3_ACCESS_KEY='your-s3-key' \
  --from-literal=BTAGENT_S3_SECRET_KEY='your-s3-secret' \
  --from-literal=ANTHROPIC_API_KEY='sk-ant-...' \
  --from-literal=BTAGENT_OPENAI_API_KEY='sk-...'
```

### 3. Deploy

```bash
helm install btagent infra/helm/btagent/ \
  --namespace btagent \
  --values infra/helm/btagent/values-production.yaml \
  --set secretEnv.existingSecret=btagent-secrets
```

### 4. Verify

```bash
# Check pods are running
kubectl get pods -n btagent

# Check pod logs
kubectl logs -n btagent deployment/btagent-backend --tail=50

# Port-forward to test health
kubectl port-forward -n btagent svc/btagent-backend 8000:8000
curl http://localhost:8000/health
```

### 5. Scaling

The Helm chart includes a Horizontal Pod Autoscaler (HPA). To manually scale:

```bash
# Scale backend
kubectl scale deployment btagent-backend --replicas=5 -n btagent

# View HPA status
kubectl get hpa -n btagent
```

HPA automatically scales between `minReplicas` and `maxReplicas` based on CPU and memory utilization thresholds defined in `values-production.yaml`.

### 6. Secrets Management

#### Option A: External Secrets Operator

Install the [External Secrets Operator](https://external-secrets.io/) to sync secrets from AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault:

```yaml
# external-secret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: btagent-secrets
  namespace: btagent
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: btagent-secrets
  data:
    - secretKey: BTAGENT_DATABASE_URL
      remoteRef:
        key: btagent/production/database-url
    - secretKey: BTAGENT_JWT_SECRET
      remoteRef:
        key: btagent/production/jwt-secret
    - secretKey: ANTHROPIC_API_KEY
      remoteRef:
        key: btagent/production/anthropic-key
```

```bash
kubectl apply -f external-secret.yaml
```

#### Option B: Sealed Secrets

Use [Bitnami Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) to encrypt secrets in Git:

```bash
kubeseal --format yaml < secret.yaml > sealed-secret.yaml
kubectl apply -f sealed-secret.yaml
```

### 7. Monitoring

#### Prometheus + Grafana

Deploy the monitoring stack:

```bash
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace

# Add BTagent ServiceMonitor
kubectl apply -f - <<EOF
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: btagent-backend
  namespace: btagent
spec:
  selector:
    matchLabels:
      app: btagent-backend
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
EOF
```

Import the Grafana dashboards from `infra/grafana/` for pre-built BTagent dashboards covering:
- HTTP request rates and latencies
- WebSocket connection counts
- Agent task durations
- LLM token usage and costs
- Database connection pool health

---

## AWS (Terraform)

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| AWS CLI | 2.x | AWS authentication |
| Terraform | 1.7+ | Infrastructure provisioning |

```bash
aws configure   # Set your AWS credentials and region
```

### 1. Configure Variables

Edit `infra/terraform/variables.tf` or create a `terraform.tfvars` file:

```hcl
# terraform.tfvars
aws_region          = "us-east-1"
environment         = "production"
vpc_cidr            = "10.0.0.0/16"
cluster_name        = "btagent-production"
cluster_version     = "1.29"
node_instance_types = ["t3.large"]
node_desired_size   = 3
node_min_size       = 2
node_max_size       = 10
db_instance_class   = "db.r6g.large"
db_name             = "btagent"
db_username         = "btagent"
db_multi_az         = true
```

### 2. Review the Modules

The Terraform configuration provisions:

| Module | Resources |
|--------|-----------|
| `vpc` | VPC, public/private subnets, NAT gateway, route tables |
| `eks` | EKS cluster, managed node group, IAM roles, OIDC provider |
| `rds` | RDS PostgreSQL with pgvector, subnet group, security group |
| `observability` | CloudWatch log groups, Container Insights |

### 3. Deploy

```bash
cd infra/terraform

# Initialize providers and modules
terraform init

# Preview changes
terraform plan -var-file="terraform.tfvars"

# Apply infrastructure
terraform apply -var-file="terraform.tfvars"
```

> **Warning:** `terraform apply` provisions billable AWS resources. Review the plan output carefully before confirming.

### 4. Post-Deploy

After Terraform completes:

```bash
# Configure kubectl for the new cluster
aws eks update-kubeconfig --name btagent-production --region us-east-1

# Verify cluster access
kubectl get nodes

# Deploy BTagent via Helm (see Kubernetes section above)
helm install btagent infra/helm/btagent/ \
  --namespace btagent \
  --create-namespace \
  --values infra/helm/btagent/values-production.yaml
```

#### DNS Configuration

Point your domain to the load balancer created by the Kubernetes Ingress:

```bash
# Get the load balancer hostname
kubectl get ingress -n btagent -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}'

# Create a CNAME record in your DNS provider:
# btagent.example.com -> <load-balancer-hostname>
```

#### SSL with AWS Certificate Manager

```bash
# Request a certificate
aws acm request-certificate \
  --domain-name btagent.example.com \
  --validation-method DNS

# Add the CNAME validation record to your DNS, then annotate the Ingress
kubectl annotate ingress btagent-ingress -n btagent \
  alb.ingress.kubernetes.io/certificate-arn=arn:aws:acm:...
```

---

## Environment Variables Reference

Complete list of all `BTAGENT_*` environment variables:

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `BTAGENT_ENV` | `dev` | No | Environment: `dev`, `staging`, `prod` |
| `BTAGENT_DEBUG` | `false` | No | Enable debug mode |
| `BTAGENT_LOG_LEVEL` | `info` | No | Log level: `debug`, `info`, `warning`, `error` |
| `BTAGENT_DATABASE_URL` | `postgresql+asyncpg://btagent:btagent@localhost:5432/btagent` | Yes (prod) | PostgreSQL connection string |
| `BTAGENT_DB_POOL_SIZE` | `20` | No | Database connection pool size |
| `BTAGENT_DB_MAX_OVERFLOW` | `10` | No | Max overflow connections |
| `BTAGENT_DB_ECHO` | `false` | No | Log SQL queries (never enable in production) |
| `BTAGENT_REDIS_URL` | `redis://localhost:6379` | Yes (prod) | Redis connection string |
| `BTAGENT_JWT_SECRET` | (insecure default) | **Yes** | JWT signing secret (min 32 chars in prod) |
| `BTAGENT_JWT_ALGORITHM` | `HS256` | No | JWT signing algorithm |
| `BTAGENT_ACCESS_TOKEN_TTL_MINUTES` | `15` | No | Access token lifetime |
| `BTAGENT_REFRESH_TOKEN_TTL_DAYS` | `7` | No | Refresh token lifetime |
| `BTAGENT_S3_ENDPOINT` | `http://localhost:9000` | No | MinIO/S3 endpoint |
| `BTAGENT_S3_ACCESS_KEY` | `minioadmin` | Yes (prod) | S3 access key |
| `BTAGENT_S3_SECRET_KEY` | `minioadmin` | Yes (prod) | S3 secret key |
| `BTAGENT_S3_BUCKET` | `btagent-evidence` | No | Evidence bucket name |
| `BTAGENT_S3_REGION` | `us-east-1` | No | S3 region |
| `BTAGENT_CORS_ORIGINS` | `["http://localhost:5173","http://localhost:3000"]` | Yes (prod) | Allowed CORS origins. In prod the backend fails to start if unset, `*`, or a localhost origin (B7). |
| `BTAGENT_DEFAULT_MODEL_PROVIDER` | `anthropic` | No | Preferred LLM provider |
| `BTAGENT_DEFAULT_MODEL_ID` | `claude-sonnet-4-20250514` | No | Default model ID |
| `BTAGENT_MOCK_CONNECTORS` | `false` | No | Use mock SIEM/CTI connectors |
| `BTAGENT_EMBEDDING_PROVIDER` | `openai` | No | Embedding provider: `openai`, `ollama` |
| `BTAGENT_EMBEDDING_MODEL` | `text-embedding-3-small` | No | Embedding model name |
| `BTAGENT_OPENAI_API_KEY` | (empty) | Conditional | Required if embedding_provider is openai |
| `BTAGENT_OLLAMA_BASE_URL` | `http://localhost:11434` | No | Ollama endpoint — used for both embeddings and chat completions |
| `BTAGENT_LOCAL_LLM_ONLY` | `false` | No | Restrict LLM routing to local providers (`ollama`/`vllm`) and fail closed when a TLP level authorises none. For air-gapped installs — see [`docs/deployment/air-gap.md`](deployment/air-gap.md) §4.5 |
| `BTAGENT_RATE_LIMIT_ENABLED` | `true` | No | Enable rate limiting |
| `BTAGENT_OTEL_ENABLED` | `false` | No | Enable OpenTelemetry |
| `BTAGENT_OTEL_ENDPOINT` | `http://localhost:4317` | No | OTLP collector endpoint |
| `BTAGENT_LANGFUSE_ENABLED` | `false` | No | Enable LangFuse |
| `BTAGENT_LANGFUSE_PUBLIC_KEY` | (empty) | Conditional | LangFuse public key |
| `BTAGENT_LANGFUSE_SECRET_KEY` | (empty) | Conditional | LangFuse secret key |
| `BTAGENT_LANGFUSE_HOST` | `https://cloud.langfuse.com` | No | LangFuse host |
| `BTAGENT_SLACK_BOT_TOKEN` | (empty) | No | Slack integration |
| `BTAGENT_SLACK_CHANNEL` | (empty) | No | Slack notification channel |
| `BTAGENT_EVENT_RETENTION_DAYS` | `90` | No | Agent event retention |
| `BTAGENT_AUDIT_RETENTION_YEARS` | `7` | No | Audit log retention |

---

## Backup and Recovery

### PostgreSQL Backup

```bash
# Full backup
docker compose -f infra/docker-compose.yml exec -T postgres \
  pg_dump -U btagent -Fc btagent > backup-$(date +%Y%m%d).dump

# Restore
docker compose -f infra/docker-compose.yml exec -T postgres \
  pg_restore -U btagent -d btagent --clean < backup-20260328.dump
```

### Kubernetes Backup

```bash
# Backup via CronJob
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: CronJob
metadata:
  name: pg-backup
  namespace: btagent
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:16
            command: ["pg_dump", "-Fc", "-f", "/backups/btagent-\$(date +%Y%m%d).dump"]
            envFrom:
            - secretRef:
                name: btagent-secrets
          restartPolicy: OnFailure
EOF
```

### Redis Backup

Redis data is ephemeral (pub/sub events and rate limit counters). No backup is required for production operation. If you need persistence, enable Redis AOF in your deployment.

### MinIO / S3 Backup

Evidence stored in MinIO should be replicated to a secondary bucket or backed up to a different storage tier:

```bash
# Using MinIO client
mc mirror minio/btagent-evidence backup/btagent-evidence
```

---

## Upgrade Procedures

### Docker Compose

```bash
# Pull new images
docker compose -f infra/docker-compose.yml pull

# Migrate. `up migrate` runs the one-shot to completion against the NEW image;
# do this before restarting the app so new code never meets an old schema.
docker compose -f infra/docker-compose.yml up migrate init-storage

# Restart with zero downtime (one service at a time).
# --no-deps is what makes this step skip the one-shots you just ran.
docker compose -f infra/docker-compose.yml up -d --no-deps backend
docker compose -f infra/docker-compose.yml up -d --no-deps scheduler
docker compose -f infra/docker-compose.yml up -d --no-deps frontend
```

### Helm (Zero-Downtime)

```bash
# Update the image tag in values
helm upgrade btagent infra/helm/btagent/ \
  --namespace btagent \
  --values infra/helm/btagent/values-production.yaml \
  --set image.tag="0.3.1" \
  --set frontendImage.tag="0.3.1"

# Monitor the rollout
kubectl rollout status deployment/btagent-backend -n btagent

# Rollback if needed
helm rollback btagent -n btagent
```

The Helm chart's PodDisruptionBudget (`minAvailable: 2`) ensures at least 2 backend pods remain available during rolling updates.

### Database Migrations

Always run migrations before deploying new application code:

```bash
# Option 1: Init container (recommended for Kubernetes)
# The Helm chart can include an init container that runs migrations

# Option 2: Manual
kubectl exec -n btagent deployment/btagent-backend -- alembic upgrade head

# Option 3: Job
kubectl create job --from=cronjob/db-migrate migrate-$(date +%s) -n btagent
```

> **Warning:** Never run `alembic downgrade` in production without a tested rollback plan and database backup.
