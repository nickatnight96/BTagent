# BTagent Frontend

Development guide for the BTagent React frontend.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Directory Structure](#directory-structure)
- [Getting Started](#getting-started)
- [Zustand Stores](#zustand-stores)
- [Component Hierarchy](#component-hierarchy)
- [API Client Pattern](#api-client-pattern)
- [WebSocket Client](#websocket-client)
- [Dark Theme System](#dark-theme-system)
- [Adding a New Page](#adding-a-new-page)
- [Testing](#testing)
- [Build and Deploy](#build-and-deploy)

---

## Architecture Overview

The frontend is a single-page application built with:

| Technology | Purpose |
|------------|---------|
| **React 18** | UI library with concurrent features |
| **TypeScript** | Strict mode enabled, path aliases (`@/` maps to `src/`) |
| **Vite** | Build tool and dev server with hot module replacement |
| **Zustand** | State management (9 stores, no boilerplate) |
| **Tailwind CSS** | Utility-first CSS with dark security theme |
| **React Router v6** | Client-side routing with protected routes |

Data flows from the backend via two channels:

```
REST API (CRUD operations)
  Frontend -> fetch() -> FastAPI -> PostgreSQL
  Frontend <- JSON <- FastAPI

WebSocket (real-time events)
  Frontend <- EventEnvelope <- WebSocket Hub <- Redis Pub/Sub <- Agent Hooks
```

---

## Directory Structure

```
frontend/
  index.html                  Vite entry point
  package.json                Dependencies and scripts
  tsconfig.json               TypeScript config (strict mode)
  vite.config.ts              Vite config with path aliases
  tailwind.config.ts          Tailwind with dark theme palette
  postcss.config.js           PostCSS for Tailwind processing
  tests/                      Test files (vitest + Playwright)
  src/
    main.tsx                  React root mount
    App.tsx                   Router provider
    router.tsx                Route definitions with protected routes
    index.css                 Tailwind directives and global styles
    api/
      client.ts               REST API client (fetch-based, auto-refresh)
      ws.ts                   WebSocket client (reconnect, heartbeat)
      investigations.ts       Investigation API functions
      iocs.ts                 IOC API functions
      knowledge.ts            Knowledge base API functions
      mitre.ts                MITRE ATT&CK API functions
      playbooks.ts            Playbook API functions
    stores/
      authStore.ts            Authentication state and JWT management
      investigationStore.ts   Investigation CRUD and filtering
      agentStore.ts           Agent task state and chat history
      eventStore.ts           Real-time event stream with 50ms batching
      iocStore.ts             IOC management and enrichment
      knowledgeStore.ts       Knowledge base search and documents
      mitreStore.ts           MITRE ATT&CK techniques and coverage
      playbookStore.ts        Playbook definitions and executions
      uiStore.ts              UI state (sidebar, modals, theme)
    components/
      auth/                   LoginPage, ProtectedRoute
      layout/                 Layout shell, Sidebar, Header
      investigations/         InvestigationList (PunchList dashboard)
      workspace/              InvestigationWorkspace, AgentChat, EventStream, CostBadge
      iocs/                   IOCNotebook
      knowledge/              KnowledgePage
      mitre/                  MitreMatrix
      playbooks/              PlaybookList, PlaybookBuilder, PlaybookExecutionView
      ui/                     Shared UI primitives (buttons, badges, modals, inputs)
    types/                    TypeScript type definitions
    hooks/                    Custom React hooks
    utils/                    Utility functions
```

---

## Getting Started

### Prerequisites

- Node.js 20+
- npm

### Install and Run

```bash
cd frontend
npm install
npm run dev
```

The dev server starts at `http://localhost:5173` with hot module replacement.

### Environment Variables

Create a `.env.local` file in the `frontend/` directory if you need to override defaults:

```env
# API base URL (default: /api, proxied to backend in dev)
VITE_API_BASE_URL=http://localhost:8000

# WebSocket URL (default: auto-detected from window.location)
VITE_WS_URL=ws://localhost:8000/ws
```

---

## Zustand Stores

BTagent uses 9 Zustand stores for state management. Each store is a standalone module with no boilerplate -- just plain functions and state.

### Store Overview

| Store | File | Purpose |
|-------|------|---------|
| `authStore` | `authStore.ts` | JWT tokens, login/logout, user profile, auto-refresh |
| `investigationStore` | `investigationStore.ts` | Investigation list, CRUD, filtering, pagination |
| `agentStore` | `agentStore.ts` | Per-investigation agent state, chat messages, task status |
| `eventStore` | `eventStore.ts` | Real-time event stream, 50ms batching, event history |
| `iocStore` | `iocStore.ts` | IOC list, enrichment triggers, STIX export/import |
| `knowledgeStore` | `knowledgeStore.ts` | Knowledge base search, document list, ingest |
| `mitreStore` | `mitreStore.ts` | ATT&CK techniques, tactics, coverage map, navigator export |
| `playbookStore` | `playbookStore.ts` | Playbook CRUD, execution trigger, execution history |
| `uiStore` | `uiStore.ts` | Sidebar collapsed state, active modals, theme, notifications |

### Store Pattern

All stores follow the same pattern:

```typescript
import { create } from "zustand";

interface MyState {
  items: Item[];
  loading: boolean;
  error: string | null;
  fetchItems: () => Promise<void>;
}

export const useMyStore = create<MyState>((set) => ({
  items: [],
  loading: false,
  error: null,

  fetchItems: async () => {
    set({ loading: true, error: null });
    try {
      const data = await api.get<Item[]>("/v1/my-endpoint");
      set({ items: data, loading: false });
    } catch (err) {
      set({ error: (err as Error).message, loading: false });
    }
  },
}));
```

### Event Store Batching

The `eventStore` buffers incoming WebSocket events and flushes them to React state every 50ms. This prevents excessive re-renders during high-throughput agent activity:

```typescript
// Events arrive individually from WebSocket
wsClient.onEvent = (event) => eventStore.getState().bufferEvent(event);

// Flush timer consolidates batched events into state
setInterval(() => eventStore.getState().flushBuffer(), 50);
```

---

## Component Hierarchy

```
App
  RouterProvider
    LoginPage
    ProtectedRoute
      Layout
        Sidebar               Navigation links, investigation quick-access
        Header                User info, notifications, cost summary
        [Outlet]              Route-specific content:
          InvestigationList   PunchList dashboard (index route)
          InvestigationWorkspace
            AgentChat         Chat input and message history
            EventStream       Real-time agent event display
            CostBadge         Token usage and cost tracking
          IOCNotebook         IOC list, enrichment, export
          MitreMatrix         ATT&CK heatmap and technique details
          KnowledgePage       Search and document management
          PlaybookList        Browse playbooks
          PlaybookBuilder     Create/edit playbook YAML
          PlaybookExecutionView  Live execution monitoring
```

---

## API Client Pattern

The API client (`src/api/client.ts`) is a lightweight fetch wrapper with automatic JWT handling:

### Key Features

- **Auto-auth**: Attaches the `Authorization: Bearer` header from the auth store
- **Auto-refresh**: On 401 responses, automatically refreshes the JWT and retries the request
- **Typed responses**: Generic return types for type safety
- **Error handling**: Throws `ApiError` with status, statusText, and parsed body

### Usage

```typescript
import api from "@/api/client";

// GET with type inference
const investigations = await api.get<PaginatedResponse<Investigation>>("/v1/investigations");

// POST with body
const newInv = await api.post<Investigation>("/v1/investigations", {
  title: "Phishing investigation",
  severity: "high",
  template: "phishing",
});

// DELETE
await api.delete(`/v1/investigations/${id}`);
```

### Domain API Modules

Each domain has its own API module that wraps the client with typed functions:

- `investigations.ts` -- `fetchInvestigations()`, `createInvestigation()`, `pauseInvestigation()`, etc.
- `iocs.ts` -- `fetchIOCs()`, `createIOC()`, `enrichIOC()`, `exportSTIX()`, `importSTIX()`
- `knowledge.ts` -- `queryKnowledge()`, `ingestDocument()`, `fetchDocuments()`, `deleteDocument()`
- `mitre.ts` -- `fetchTechniques()`, `fetchTactics()`, `fetchCoverage()`, `exportNavigator()`
- `playbooks.ts` -- `fetchPlaybooks()`, `createPlaybook()`, `executePlaybook()`, `fetchExecutions()`

---

## WebSocket Client

The WebSocket client (`src/api/ws.ts`) provides real-time event streaming from the agent engine.

### Design

```
WebSocketClient (singleton)
  connect(token)          Establish connection with JWT
  sendChat(id, message)   Send chat message to investigation agent
  sendHITLResponse(...)   Respond to HITL checkpoint
  disconnect()            Clean shutdown

  Automatic features:
    Heartbeat             Sends ping every 30s to keep connection alive
    Reconnect             Exponential backoff (1s -> 2s -> 4s -> ... -> 30s max)
    Event parsing         Deserializes EventEnvelope JSON into typed AgentEvent
```

### Event Buffering

Events flow from the WebSocket through the event store's buffer before reaching React components:

```
WebSocket message
  -> JSON.parse -> EventEnvelope
  -> envelopeToEvent() -> AgentEvent
  -> eventStore.bufferEvent()
  -> [50ms flush interval]
  -> React re-render
```

### Subscribing to Investigations

After connecting, subscribe to a specific investigation to receive its events:

```typescript
ws.send(JSON.stringify({
  type: "subscribe",
  investigation_id: "inv_01HX..."
}));
```

---

## Dark Theme System

BTagent uses a dark, security-operations-themed design implemented entirely with Tailwind CSS classes.

### Color Palette

The theme is configured in `tailwind.config.ts`. Key color tokens:

| Token | Usage | Typical Value |
|-------|-------|---------------|
| `bg-primary` | Main background | Slate 900 |
| `bg-secondary` | Card/panel backgrounds | Slate 800 |
| `bg-tertiary` | Nested elements | Slate 700 |
| `text-primary` | Main text | Slate 100 |
| `text-secondary` | Muted text | Slate 400 |
| `border-default` | Standard borders | Slate 600 |

### Severity Colors

Used consistently across badges, alerts, and charts:

| Severity | Color | Tailwind Class |
|----------|-------|----------------|
| Critical | Red | `text-red-400`, `bg-red-900/30` |
| High | Orange | `text-orange-400`, `bg-orange-900/30` |
| Medium | Yellow | `text-yellow-400`, `bg-yellow-900/30` |
| Low | Blue | `text-blue-400`, `bg-blue-900/30` |
| Info | Gray | `text-slate-400`, `bg-slate-700/30` |

### TLP Colors

| TLP Level | Color | Tailwind Class |
|-----------|-------|----------------|
| RED | Red | `text-red-500`, `bg-red-900/40` |
| AMBER+STRICT | Amber | `text-amber-500`, `bg-amber-900/40` |
| AMBER | Amber | `text-amber-400`, `bg-amber-900/30` |
| GREEN | Green | `text-green-400`, `bg-green-900/30` |
| WHITE | White | `text-slate-300`, `bg-slate-700/30` |

### Applying Theme

All components use Tailwind utility classes directly. There is no CSS-in-JS or theme provider to configure. To maintain consistency:

- Use the token classes above rather than arbitrary Tailwind colors
- Use `ring-` classes for focus indicators (accessible on dark backgrounds)
- Use `transition-colors` for hover state changes

---

## Adding a New Page

Follow these steps to add a new page to the frontend:

### 1. Create the Component

```typescript
// src/components/myfeature/MyFeaturePage.tsx
export function MyFeaturePage() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold text-slate-100 mb-4">My Feature</h1>
      {/* Page content */}
    </div>
  );
}
```

### 2. Add the Route

```typescript
// src/router.tsx
import { MyFeaturePage } from "@/components/myfeature/MyFeaturePage";

// Add inside the Layout children array:
{
  path: "my-feature",
  element: <MyFeaturePage />,
}
```

### 3. Add Sidebar Navigation

Add an entry in the Layout sidebar component for the new route.

### 4. Create a Store (if needed)

```typescript
// src/stores/myFeatureStore.ts
import { create } from "zustand";
import api from "@/api/client";

interface MyFeatureState {
  data: MyData | null;
  loading: boolean;
  fetchData: () => Promise<void>;
}

export const useMyFeatureStore = create<MyFeatureState>((set) => ({
  data: null,
  loading: false,
  fetchData: async () => {
    set({ loading: true });
    const data = await api.get<MyData>("/v1/my-feature");
    set({ data, loading: false });
  },
}));
```

### 5. Create API Functions (if needed)

```typescript
// src/api/myFeature.ts
import api from "@/api/client";

export async function fetchMyData(): Promise<MyData> {
  return api.get<MyData>("/v1/my-feature");
}
```

---

## Testing

### Unit Tests (Vitest)

Unit tests focus on Zustand stores and utility functions.

```bash
cd frontend
npm run test           # Run all tests
npm run test -- --watch  # Watch mode
```

Example store test:

```typescript
import { describe, it, expect, beforeEach } from "vitest";
import { useMyStore } from "@/stores/myStore";

describe("myStore", () => {
  beforeEach(() => {
    useMyStore.setState({ items: [], loading: false, error: null });
  });

  it("should start with empty state", () => {
    const state = useMyStore.getState();
    expect(state.items).toEqual([]);
    expect(state.loading).toBe(false);
  });
});
```

### E2E Tests (Playwright)

End-to-end tests verify full user flows in a real browser.

```bash
# From the project root (requires running stack)
make e2e
```

Playwright tests live in `tests/` and cover:
- Login flow
- Investigation creation and workspace interaction
- IOC enrichment
- HITL checkpoint approval

### Running All Frontend Tests from Root

```bash
make test-frontend   # Vitest unit tests
make e2e             # Playwright E2E tests
```

---

## Build and Deploy

### Production Build

```bash
cd frontend
npm run build
```

This outputs optimized static files to `frontend/dist/`. The build:
- Compiles TypeScript with strict checks
- Tree-shakes unused code
- Minifies JavaScript and CSS
- Generates content-hashed filenames for cache busting

### Docker Build

```bash
docker compose -f infra/docker-compose.yml build frontend
```

The Docker image uses a multi-stage build:
1. **Build stage**: Node.js image runs `npm run build`
2. **Serve stage**: Nginx Alpine serves the static files

### Deployment

The frontend is a static SPA served by Nginx. In the Docker Compose stack, Nginx reverse-proxies API requests to the backend:

- `/` -- Frontend static files
- `/api/*` -- Proxied to backend on port 8000
- `/ws` -- Proxied to backend WebSocket endpoint

In Kubernetes (Helm), the frontend runs as a separate deployment behind the Ingress controller.

---

## Further Reading

- [Architecture Overview](../docs/ARCHITECTURE.md)
- [API Reference](../docs/API.md)
- [Contributing Guide](../docs/CONTRIBUTING.md)
- [Analyst Guide](../docs/ANALYST_GUIDE.md)
