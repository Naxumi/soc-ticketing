# SOC Ticketing System

A ticketing system for Security Operations Centers to manage, assign, and track security alerts. Built with a Go backend and React frontend.

## What it does

Analysts receive security alerts (from Wazuh or raw logs via webhooks), which are grouped into tickets. Each ticket goes through a workflow: `OPEN → IN_PROGRESS → ESCALATED → INVESTIGATING → RESOLVED/FALSE_POSITIVE`. An AI analysis endpoint can be triggered on any ticket to get automated threat assessment, MITRE ATT&CK mapping, and recommendations.

## Features

### Backend
- REST API built with Go and `go-chi`
- JWT authentication with access/refresh token rotation
- Role-based access: L1 Analyst, L2 Analyst, SOC Manager
- Ticket lifecycle with enforced status transitions (L1 can triage, L2 can investigate, Manager can override)
- Webhook ingestion for Wazuh alerts and raw log batches with automatic ticket grouping/aggregation
- AI-powered ticket analysis — forwards ticket data to an external AI engine, stores results (severity, threat category, MITRE techniques, recommendations)
- Notification system with read/unread tracking
- Real-time ticket streaming via Server-Sent Events (SSE)
- Audit logging for all ticket actions
- Dashboard with statistics
- PostgreSQL with database migrations

### Frontend
- React 19 + TypeScript + Vite
- TailwindCSS + Shadcn UI + Radix UI components
- Pages: Landing, Login, Dashboard, Tickets list, Ticket detail, Notifications, Users management, User detail
- Real-time updates using Server-Sent Events (`useTicketsStream`, `useNotificationsStream`)
- Data fetching with React Query
- Dark mode

## Roles & Permissions
- **L1 Analyst (`L1_ANALYST`)**: Can view Active tickets (`OPEN`, `IN_PROGRESS`) and History. Responsible for initial triage. Can transition tickets from `OPEN` to `IN_PROGRESS`, and then escalate them to `ESCALATED` or mark as `FALSE_POSITIVE`.
- **L2 Analyst (`L2_ANALYST`)**: Can view Active tickets (`ESCALATED`, `INVESTIGATING`) and History. Responsible for deep investigations. Can transition tickets from `ESCALATED` to `INVESTIGATING`, and then close them as `RESOLVED` or `FALSE_POSITIVE`.
- **SOC Manager (`SOC_MANAGER`)**: Has full access. Can view all tickets, override any ticket status, delegate assignments, view the dashboard statistics, and manage users (register analysts, change roles, revoke sessions, delete users).

## API Documentation
The backend serves an OpenAPI specification and a Swagger UI.
- **OpenAPI JSON**: `http://localhost:8080/api/openapi.json`
- **Swagger UI**: `http://localhost:8080/swagger/index.html`

*(Note: These files are served from the `backend/api` directory. You must run the server from the `backend` root folder for the API docs to load properly.)*

## How to run

### Backend

Requires Go 1.23+ and a running PostgreSQL instance.

```bash
cd backend
cp .env.example .env
# edit .env with your database credentials and JWT secret

go mod download
go run ./cmd/api/main.go
```

The server starts on `:8080` by default.

### Frontend

Requires Node.js 20+ and pnpm.

```bash
cd frontend
cp .env.example .env

pnpm install
pnpm run dev
```

The dev server starts on `http://localhost:5173`.

## Testing

Backend tests cover domain validation, service logic, HTTP response handling, and handler integration — no database needed.

```bash
cd backend
go test ./...
```

What's tested:
- **`internal/handler/http`** — Integration tests using `httptest.NewServer` with the real chi router and middleware chain. Tests login flow (invalid JSON, bad credentials, success), webhook API key enforcement (missing, wrong, valid key), JWT-protected routes (no token vs valid token), logout, 404, and 405
- **`internal/domain/ticket`** — Query parsing, input validation (status, severity, UUID, pagination bounds), `UpdateStatusRequest` validation
- **`internal/domain/auth`** — `RegisterRequest`, `LoginRequest`, `ChangePasswordRequest`, `RefreshTokenRequest`, `AdminUpdateAnalystRequest` validation (field constraints, role restrictions, length limits)
- **`internal/service/ticket`** — Status transition rules (valid/invalid flows), AI analyze URL building, severity parsing, severity-to-rule-level mapping, response language normalization, timestamp parsing, recommendation building, MITRE technique deduplication, string helpers
- **`internal/service/auth`** — Registration flow (role checks, validation, password hashing, repo error propagation)
- **`internal/handler/http/response`** — Error-to-HTTP-status mapping for all domain errors (auth, user, ticket, notification, validation), success response helpers
- **`internal/pkg/validator`** — `IsEmpty`, `ValidationErrors.Error()`, `ValidationErrors.ToMap()`

## Project structure

```
backend/
├── cmd/api/          # HTTP server entrypoint
├── cmd/seed/         # Database seeder
├── internal/
│   ├── config/       # Environment config loading
│   ├── domain/       # Entities, DTOs, interfaces (auth, ticket, user, notification, webhook, dashboard)
│   ├── handler/http/ # HTTP handlers + middleware + response helpers
│   ├── pkg/          # Shared packages (database, jwt, validator)
│   ├── repository/   # PostgreSQL implementations
│   └── service/      # Business logic (auth, ticket, notification, dashboard, webhook, ticketstream)
└── api/              # OpenAPI spec

frontend/
├── src/
│   ├── api/          # API client
│   ├── auth/         # Auth context/provider
│   ├── components/   # Reusable UI components
│   ├── hooks/        # SSE stream hooks
│   ├── layout/       # App layout
│   ├── lib/          # Utilities
│   └── pages/        # Route pages
└── public/
```
