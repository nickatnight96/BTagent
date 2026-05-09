# Troubleshooting

Common issues and their solutions, organized by symptom.

## Backend Won't Start

### Database connection refused

**Symptom:** `ConnectionRefusedError: [Errno 111] Connection refused` on startup.

**Cause:** PostgreSQL is not running or the connection string is wrong.

**Solution:**

```bash
# 1. Check if PostgreSQL is running
docker compose -f infra/docker-compose.yml ps postgres

# 2. Verify it is healthy
docker compose -f infra/docker-compose.yml exec postgres pg_isready -U btagent

# 3. If not running, start it
docker compose -f infra/docker-compose.yml up -d postgres
make wait-healthy

# 4. Verify the connection string
echo $BTAGENT_DATABASE_URL
# Expected: postgresql+asyncpg://btagent:btagent@localhost:5432/btagent
```

### Missing environment variables

**Symptom:** `ValueError: CRITICAL: BTAGENT_JWT_SECRET is set to a known default value.`

**Cause:** In non-dev environments (`BTAGENT_ENV=staging` or `BTAGENT_ENV=prod`), BTagent refuses to start with known-insecure defaults for JWT secret and S3 credentials.

**Solution:**

```bash
# For development, set the environment explicitly
export BTAGENT_ENV=dev

# For staging/production, generate strong secrets
export BTAGENT_JWT_SECRET=$(openssl rand -hex 32)
export BTAGENT_S3_ACCESS_KEY=$(openssl rand -hex 16)
export BTAGENT_S3_SECRET_KEY=$(openssl rand -hex 32)
```

### Port already in use

**Symptom:** `OSError: [Errno 98] Address already in use` when starting uvicorn on port 8000.

**Solution:**

```bash
# Find the process using port 8000
lsof -i :8000

# Kill it or use a different port
uvicorn btagent_backend.main:app --reload --port 8001
```

---

## Agent Not Responding

### LLM API key missing

**Symptom:** Agent starts but produces no output. Errors in logs: `AuthenticationError` or `API key not found`.

**Solution:** Ensure at least one LLM provider API key is configured:

```bash
# Check which keys are set
env | grep -E "(ANTHROPIC|OPENAI|GOOGLE)_API_KEY"

# Set the default provider's key
export ANTHROPIC_API_KEY=sk-ant-...
```

### Ollama not running

**Symptom:** TLP:RED investigations fail with `Connection refused` to Ollama.

**Solution:**

```bash
# Start Ollama
docker compose -f infra/docker-compose.yml up -d ollama

# Pull a model
docker compose -f infra/docker-compose.yml exec ollama ollama pull llama3.3

# Verify
curl http://localhost:11434/api/tags
```

### Token budget exceeded

**Symptom:** Agent stops mid-investigation with `PromptBudgetExceeded` error.

**Cause:** The investigation has consumed its allocated token budget.

**Solution:**

1. Increase the token budget in the investigation config:

```bash
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Investigation",
    "config": {"max_tokens": 200000, "max_cost_usd": 5.0}
  }'
```

2. Or adjust the default budget in the agent configuration.

---

## WebSocket Disconnects

### Nginx proxy timeout

**Symptom:** WebSocket connection drops after 60 seconds of inactivity.

**Cause:** Default nginx `proxy_read_timeout` is too short.

**Solution:** The BTagent nginx config sets `proxy_read_timeout 86400s` for the `/ws/` location. If you are using a custom nginx or a load balancer, ensure the WebSocket timeout is sufficient:

```nginx
location /ws/ {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 86400s;   # 24 hours
    proxy_send_timeout 86400s;
}
```

### Token expiry

**Symptom:** WebSocket closes with `"Invalid or expired token"` message.

**Cause:** The JWT access token passed as `?token=` has expired (default: 15 minutes).

**Solution:** The frontend should automatically refresh the token and reconnect. If building a custom client:

1. Monitor for close events with code 4001 (auth failure)
2. Call `POST /api/v1/auth/refresh` to get a new token pair
3. Reconnect with the new access token

### Connection limits

**Symptom:** New WebSocket connections are refused.

**Cause:** The server has reached its maximum connection limit.

**Solution:** Check and increase the connection limit in your deployment:

```bash
# Check current connections
docker compose -f infra/docker-compose.yml exec backend \
  python -c "import asyncio; print('Check server logs for connection count')"

# For production, scale horizontally
kubectl scale deployment btagent-backend --replicas=5 -n btagent
```

---

## Webhook Not Creating Investigations

### Wrong secret

**Symptom:** Webhook returns `401 Unauthorized`.

**Solution:**

```bash
# Verify the secret matches
curl -v -X POST http://localhost:8000/api/v1/webhooks/splunk \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: your-secret-here" \
  -d '{"search_name": "test", "severity": "medium"}'

# Check the configured secret
echo $BTAGENT_WEBHOOK_SECRET
```

### Payload format mismatch

**Symptom:** Webhook returns `422 Unprocessable Entity`.

**Solution:** Each SIEM has a specific payload format. Refer to [SIEM_SETUP.md](SIEM_SETUP.md) for the exact schema for each platform.

### RBAC insufficient

**Symptom:** Webhook works but agent actions are blocked.

**Cause:** The webhook creates investigations with the system user, which may lack permissions for certain actions.

**Solution:** Verify the webhook handler has appropriate permissions in the backend configuration.

---

## IOC Enrichment Failing

### CTI API keys not configured

**Symptom:** Enrichment returns empty results or `AuthenticationError`.

**Solution:** Configure the required CTI provider API keys:

```bash
export BTAGENT_VIRUSTOTAL_API_KEY=your-key
export BTAGENT_SHODAN_API_KEY=your-key
export BTAGENT_ABUSEIPDB_API_KEY=your-key
export BTAGENT_GREYNOISE_API_KEY=your-key
```

### Rate limits

**Symptom:** Enrichment returns `429 Too Many Requests` from CTI providers.

**Solution:**
- VirusTotal free tier: 4 requests/minute. Wait or upgrade your plan.
- Shodan: 1 request/second on the free tier.
- The enrichment pipeline includes exponential backoff, but sustained high volumes may hit limits.

### Mock mode

**Symptom:** Enrichment returns mock/placeholder data.

**Cause:** `BTAGENT_MOCK_CONNECTORS=true` is set.

**Solution:** Set `BTAGENT_MOCK_CONNECTORS=false` and configure real API keys.

---

## Knowledge Base Empty Results

### Embeddings not generated

**Symptom:** `POST /api/v1/knowledge/query` returns zero results even after ingesting documents.

**Cause:** The embedding service failed during ingestion, so chunks have NULL embeddings.

**Solution:**

```bash
# Check if embedding provider is configured
echo $BTAGENT_EMBEDDING_PROVIDER   # Should be "openai" or "ollama"

# For OpenAI, verify the key
echo $BTAGENT_OPENAI_API_KEY

# For Ollama, verify the service and model
curl http://localhost:11434/api/tags
# If no embedding model, pull one:
docker compose -f infra/docker-compose.yml exec ollama ollama pull nomic-embed-text

# Re-ingest the document to regenerate embeddings
```

### pgvector extension not enabled

**Symptom:** Database errors mentioning `type "vector" does not exist`.

**Cause:** The pgvector extension is not installed in PostgreSQL.

**Solution:**

```bash
# The pgvector/pgvector:pg16 Docker image includes the extension
# Verify it is enabled:
docker compose -f infra/docker-compose.yml exec postgres \
  psql -U btagent -c "SELECT * FROM pg_extension WHERE extname = 'vector';"

# If not enabled, create it:
docker compose -f infra/docker-compose.yml exec postgres \
  psql -U btagent -c "CREATE EXTENSION IF NOT EXISTS vector;"

# Then re-run migrations
make db-migrate
```

---

## Playbook Execution Stuck

### HITL timeout

**Symptom:** Playbook execution status shows `waiting_hitl` indefinitely.

**Cause:** A HITL gate step is waiting for analyst approval and no one has responded.

**Solution:**

1. Check the investigation's event stream for the HITL checkpoint
2. Approve or reject via WebSocket or the UI
3. Adjust the HITL timeout in the playbook YAML (`timeout_seconds`)
4. The default timeout is 3600 seconds (1 hour)

### Step failure

**Symptom:** Playbook execution shows `failed` status.

**Solution:**

```bash
# Get execution details with step-by-step results
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/playbooks/executions/$EXECUTION_ID
```

Check the `step_results` field for error messages on the failed step. Common causes:
- Referenced tool not registered
- Tool execution timeout (default: 300 seconds)
- Decision condition evaluation error (check the condition syntax)

### Circuit breaker open

**Symptom:** MCP tool calls fail with `CircuitBreakerOpen` error.

**Cause:** The MCP connector has failed 5 consecutive times and the circuit breaker is in the OPEN state.

**Solution:** Wait 30 seconds for the circuit breaker to transition to HALF_OPEN, then it will retry. If the underlying service is down, fix the service and the circuit breaker will auto-recover after 2 successful calls.

---

## High Token Costs

### Model tier misconfiguration

**Symptom:** Token costs are higher than expected.

**Cause:** All tasks are routed to the PREMIUM tier model (e.g., claude-opus-4, o3).

**Solution:** Verify the model tier configuration. BTagent routes by task type:

| Task | Expected Tier | Model Example |
|------|--------------|---------------|
| Triage, classification | FAST | claude-haiku-4.5, gpt-4o-mini |
| Query generation, analysis | STANDARD | claude-sonnet-4, gpt-4o |
| Complex reasoning | PREMIUM | claude-opus-4, o3 |
| TLP:RED data | LOCAL | llama3.3 (Ollama) |

Check the agent config and ensure `default_model_provider` and `default_model_id` are set to a STANDARD tier model, not PREMIUM.

### Context cascade not working

**Symptom:** Token usage per turn is very high (>50k tokens).

**Cause:** The 4-layer context cascade (externalize, compress, prune, summarize) may not be triggered.

**Solution:** The context cascade activates when the context window approaches its limit. For investigations with many turns, verify that:

1. Old messages are being summarized
2. Tool outputs are externalized (stored in MinIO, referenced by hash)
3. The investigation config includes reasonable `max_tokens` limits

---

## Docker Compose Issues

### Port conflicts

**Symptom:** `docker compose up` fails with `Bind for 0.0.0.0:5432 failed: port is already allocated`.

**Solution:**

```bash
# Find what is using the port
lsof -i :5432

# Option 1: Stop the conflicting service
sudo systemctl stop postgresql

# Option 2: Change the host port in docker-compose.yml
# ports:
#   - "5433:5432"
```

### Volume permissions

**Symptom:** PostgreSQL fails to start with `FATAL: data directory has wrong ownership`.

**Solution:**

```bash
# Reset volumes (WARNING: this deletes all data)
docker compose -f infra/docker-compose.yml down -v
docker compose -f infra/docker-compose.yml up -d
make db-migrate
make db-seed
```

### Health check failures

**Symptom:** Backend container restarts repeatedly.

**Solution:**

```bash
# Check container logs
docker compose -f infra/docker-compose.yml logs backend --tail=50

# Check health status
docker compose -f infra/docker-compose.yml ps

# Common cause: database not ready yet
# The backend depends on postgres health, but the first migration hasn't run
make db-migrate
```

---

## Database Migration Errors

### Version conflicts

**Symptom:** `alembic upgrade head` fails with `Can't locate revision identified by`.

**Solution:**

```bash
# Check current migration state
cd backend && alembic current

# Check migration history
cd backend && alembic history --verbose

# If the database is ahead of the code (e.g., after a rollback):
# Stamp the current version to match the code
cd backend && alembic stamp head
```

### pgvector extension missing

**Symptom:** Migration fails with `ERROR: type "vector" does not exist`.

**Solution:** Ensure you are using the `pgvector/pgvector:pg16` Docker image (not standard PostgreSQL). The extension is created during migrations, but the library must be available:

```bash
# Verify the Docker image
docker compose -f infra/docker-compose.yml exec postgres \
  psql -U btagent -c "SELECT * FROM pg_available_extensions WHERE name = 'vector';"
```

---

## Debug Mode

### Enable verbose logging

```bash
# Set log level to debug
export BTAGENT_LOG_LEVEL=debug

# Restart the backend
cd backend && uvicorn btagent_backend.main:app --reload --port 8000
```

Debug logging includes:
- All HTTP requests with request IDs
- Database queries (if `BTAGENT_DB_ECHO=true`)
- Agent state transitions
- MCP connector calls and responses
- Token usage per LLM call

> **Warning:** Never enable `BTAGENT_DB_ECHO=true` in production. It logs all SQL queries including data values.

### OpenTelemetry tracing

Enable distributed tracing for end-to-end request visibility:

```bash
# Start the observability stack
make up-observability

# Enable OTEL in the backend
export BTAGENT_OTEL_ENABLED=true
export BTAGENT_OTEL_ENDPOINT=http://localhost:4317
```

Traces are exported to the OTLP collector and can be viewed in Grafana Tempo or Jaeger.

### Request ID tracing

Every API request includes an `X-Request-ID` header for correlation:

```bash
# Check request ID in response headers
curl -v http://localhost:8000/health 2>&1 | grep x-request-id

# Search backend logs by request ID
docker compose -f infra/docker-compose.yml logs backend | grep "req_01HX..."
```

### LangFuse LLM observability

For detailed LLM call tracing (prompts, completions, token usage, latency):

```bash
export BTAGENT_LANGFUSE_ENABLED=true
export BTAGENT_LANGFUSE_PUBLIC_KEY=pk-...
export BTAGENT_LANGFUSE_SECRET_KEY=sk-...
export BTAGENT_LANGFUSE_HOST=https://cloud.langfuse.com
```

Open the LangFuse dashboard to view traces for each agent invocation.

---

## Getting Help

### Check the logs first

```bash
# Backend logs
docker compose -f infra/docker-compose.yml logs backend --tail=100

# All service logs
docker compose -f infra/docker-compose.yml logs --tail=50

# Follow logs in real time
docker compose -f infra/docker-compose.yml logs -f backend
```

### Collect diagnostic information

When opening a GitHub issue, include:

1. **BTagent version:** Check `CHANGELOG.md` or the health endpoint response
2. **Environment:** `dev`, `staging`, or `prod`
3. **Deployment method:** Docker Compose, Helm, or Terraform
4. **Relevant logs:** Backend logs around the time of the error (redact secrets)
5. **Steps to reproduce:** Exact commands or actions that trigger the issue
6. **Expected vs actual behavior**

### Open a GitHub issue

Report bugs and request features at:

```
https://github.com/nickatnight96/BTagent/issues/new
```

Use the appropriate issue template:
- **Bug report:** For unexpected behavior or errors
- **Feature request:** For new capabilities
- **Security vulnerability:** Follow the [Security policy](../SECURITY.md) for responsible disclosure

### Related documentation

- [Getting Started](GETTING_STARTED.md) -- setup guide
- [Architecture](ARCHITECTURE.md) -- system design reference
- [API Reference](API.md) -- endpoint documentation
- [SIEM Setup](SIEM_SETUP.md) -- webhook connector guides
- [Deployment](DEPLOYMENT.md) -- production deployment
