# Knowledge Base Architecture

BTagent's knowledge base provides a retrieval-augmented generation (RAG) pipeline that enables agents to access organisational knowledge, prior investigation findings, threat intelligence reports, and security policies during investigation.

## Overview

```
 Document Ingestion                    Knowledge Retrieval
 +-----------------+                   +------------------+
 | POST /ingest    |                   | POST /query      |
 |   title         |                   |   query text     |
 |   content       |                   |   top_k          |
 |   source_type   |                   |   source_filter  |
 +-----------------+                   +------------------+
        |                                      |
        v                                      v
 +------------------+                  +-----------------+
 | Chunking Service |                  | Hybrid Search   |
 | (512 tokens,     |                  | vector + keyword|
 |  64 overlap)     |                  | + RRF fusion    |
 +------------------+                  +-----------------+
        |                                      |
        v                                      v
 +------------------+                  +-----------------+
 | Embedding Service|                  | Ranked Results  |
 | (OpenAI / Ollama)|                  | with citations  |
 +------------------+                  +-----------------+
        |                                      |
        v                                      v
 +------------------+                  +-----------------+
 | PostgreSQL       |                  | Agent Context   |
 | pgvector (1536d) |                  | Injection       |
 +------------------+                  +-----------------+
```

## Embedding Providers

### OpenAI (Default)

- Model: `text-embedding-3-small` (1536 dimensions)
- Used for TLP:GREEN and TLP:WHITE content
- Requires `BTAGENT_OPENAI_API_KEY` environment variable
- Batch embedding support for efficient ingestion

### Ollama (Local)

- Model: configurable (default: `nomic-embed-text`)
- Used for TLP:RED and TLP:AMBER_STRICT content (data stays local)
- Requires a running Ollama instance at `BTAGENT_OLLAMA_BASE_URL`
- No external API calls -- all processing on-premise

### Mock (Development)

- Deterministic hash-based embeddings for testing
- No external dependencies required
- Produces consistent results for the same input text
- Dimension: 1536 (matches OpenAI output)

### TLP-Aware Routing

| TLP Level | Embedding Provider |
|-----------|-------------------|
| RED | Ollama only (local) |
| AMBER_STRICT | Ollama only (local) |
| AMBER | OpenAI or Ollama |
| GREEN | OpenAI (preferred) or Ollama |
| WHITE | OpenAI (preferred) or Ollama |

## Chunking Strategy

The `ChunkingService` splits documents into overlapping chunks for embedding:

- **Chunk size**: 512 tokens (configurable)
- **Overlap**: 64 tokens between consecutive chunks
- **Splitting**: Paragraph-aware splitting that respects sentence boundaries
- **Token estimation**: Approximate token count using `len(text) // 4`
- **Metadata**: Each chunk preserves its index, token count, and parent document reference

### Why Overlap?

Overlap ensures that information near chunk boundaries is not lost. When a relevant passage spans two chunks, both chunks will contain enough context for the retrieval system to surface them.

## Hybrid Search

BTagent uses a hybrid search strategy combining semantic and lexical matching:

### 1. Vector Search (Semantic)

```sql
SELECT kc.id, 1 - (kc.embedding <=> :embedding::vector) AS similarity
FROM knowledge_chunks kc
ORDER BY kc.embedding <=> :embedding::vector
LIMIT :limit
```

Uses pgvector's cosine distance operator (`<=>`) against the query embedding. Retrieves semantically similar chunks even when exact keywords differ.

### 2. Keyword Search (Lexical)

```sql
SELECT kc.id, 1.0 AS score
FROM knowledge_chunks kc
WHERE kc.content ILIKE :pattern
LIMIT :limit
```

Uses PostgreSQL ILIKE for case-insensitive keyword matching. Catches exact matches that semantic search might rank lower.

### 3. Reciprocal Rank Fusion (RRF)

Results from both search methods are merged using RRF:

```
RRF_score(chunk) = sum(1 / (k + rank_i)) for each method i
```

Where `k = 60` (standard RRF constant). This produces a unified ranking that benefits from both semantic understanding and keyword precision.

## Auto-Indexing

When an investigation completes, BTagent automatically indexes the findings into the knowledge base:

### Investigation Auto-Index

Triggered by `TaskManager._on_investigation_complete()`:

1. Load the investigation record from the database
2. Compile findings: title, case ID, status, severity, TLP level, description
3. Append IOC summary (type, value, confidence for each IOC)
4. Ingest as a `investigation_report` source type document
5. Chunk and embed for future retrieval

### Enrichment Auto-Index

Also triggered on completion:

1. Query IOCs with non-empty enrichment data
2. Compile enrichment results: IOC type, value, confidence, source, enrichment field count
3. Ingest as an `enrichment_data` source type document
4. Chunk and embed for future retrieval

### Knowledge Injection

The `knowledge_injector` module bridges the knowledge base with the investigation graph:

1. Extract query terms from investigation state (IOCs, severity, task type, messages)
2. Query the knowledge base via HTTP (`POST /api/v1/knowledge/query`)
3. Format retrieved chunks as a `<knowledge-context>` block
4. Inject into the investigation state for system prompt augmentation
5. The `should_continue` edge can route to knowledge retrieval after enrichment

## Source Types

| Source Type | Description | Auto-Indexed |
|-------------|-------------|--------------|
| `policy_document` | Security policies and procedures | No |
| `runbook` | Operational runbooks | No |
| `threat_report` | CTI threat reports | No |
| `investigation_report` | Completed investigation findings | Yes |
| `enrichment_data` | IOC enrichment results | Yes |
| `cti_feed` | CTI feed data | No |
| `other` | Uncategorised documents | No |

## Database Schema

### knowledge_documents

| Column | Type | Description |
|--------|------|-------------|
| `id` | VARCHAR | Prefixed ULID (kd_...) |
| `title` | VARCHAR | Document title |
| `source_type` | VARCHAR | Source type classification |
| `content` | TEXT | Full document content |
| `doc_metadata` | JSONB | Additional metadata |
| `token_count` | INTEGER | Estimated token count |
| `created_at` | TIMESTAMP | Ingestion timestamp |

### knowledge_chunks

| Column | Type | Description |
|--------|------|-------------|
| `id` | VARCHAR | Prefixed ULID (kc_...) |
| `document_id` | VARCHAR | FK to knowledge_documents |
| `chunk_index` | INTEGER | Position within document |
| `content` | TEXT | Chunk text content |
| `embedding` | VECTOR(1536) | pgvector embedding |
| `chunk_metadata` | JSONB | Chunk-level metadata |
| `token_count` | INTEGER | Estimated token count |

## API Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST | /api/v1/knowledge/ingest | knowledge:ingest | Ingest a document |
| POST | /api/v1/knowledge/query | knowledge:query | Hybrid search |
| GET | /api/v1/knowledge/documents | knowledge:query | List documents |
| DELETE | /api/v1/knowledge/documents/{id} | knowledge:delete | Delete a document |
