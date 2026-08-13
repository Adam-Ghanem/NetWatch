# NetWatch Architecture Walkthrough

This page gives first-time contributors a mental model for how NetWatch is put together.

## High-level flow

NetWatch has four main layers:

1. **Dashboard** – the user-facing UI for viewing assets, scan results, and alerts.
2. **FastAPI API** – the backend service that serves data to the dashboard and exposes app endpoints.
3. **SQLite stores** – local persistence for assets, scan history, findings, and app state.
4. **Scanner + optional intelligence path** – the subsystem that performs network checks and, when enabled, enriches results with extra analysis.

A typical path looks like this:

`Dashboard -> FastAPI API -> SQLite / Scanner -> FastAPI API -> Dashboard`

## Components

### 1) Dashboard

The dashboard is the main entry point for users. It does not talk directly to scanners or databases. Instead, it requests data from the API and renders:

- discovered hosts and services
- scan progress and historical runs
- findings, warnings, and statuses
- configuration and operational views

This separation keeps the UI simple and lets the backend control data validation and access patterns.

### 2) FastAPI API

FastAPI is the application boundary. It is responsible for:

- receiving requests from the dashboard
- validating inputs
- reading and writing application state
- coordinating scan execution
- shaping responses for the UI

If you are adding a new feature, ask: "Should this be a UI change, an API change, a storage change, or scanner logic?" Most core behavior should live in the API or service layer, not in the dashboard.

### 3) SQLite stores

NetWatch uses SQLite for lightweight local persistence. The database layer typically stores:

- targets / assets
- scan jobs and scan history
- scan results and findings
- user-facing metadata and settings

SQLite keeps NetWatch easy to run locally and easy to test. Contributors should treat the database as the source of truth for persisted state.

### 4) Scanner boundaries

The scanner is the part of the system that interacts with the network. Its responsibility is to collect facts, not to decide how the dashboard should present them.

Keep scanner logic focused on:

- probing hosts and ports
- collecting service metadata
- recording observations
- returning structured results

The scanner should not:

- render UI
- directly manage dashboard state
- contain business rules unrelated to scanning
- write presentation-specific output

A good rule: if the code needs knowledge of web pages, buttons, or tables, it does not belong in the scanner.

## Optional intelligence path

Some deployments may enable an "intelligence" or enrichment path. This path is optional and should be treated as an add-on, not a hard dependency.

Typical uses include:

- summarizing scan findings
- classifying severity or relevance
- correlating results across multiple scans
- generating human-readable notes for operators

When enabled, the flow is usually:

`Scanner results -> enrichment / analysis -> API stores enriched output -> Dashboard displays it`

Design expectations for this path:

- it must fail safely if unavailable
- core scanning must still work without it
- outputs should remain structured and auditable
- the source scan data should remain available separately from any derived analysis

## Data ownership

A simple ownership model helps keep the codebase maintainable:

- **Dashboard** owns presentation state only.
- **API** owns request validation and orchestration.
- **Database layer** owns persistence.
- **Scanner** owns collection of network facts.
- **Optional intelligence** owns derived analysis, not raw facts.

## Common contributor questions

### Where should a new feature go?

- UI change: dashboard
- new endpoint: FastAPI API
- new persistent field: SQLite schema / model layer
- new network probe: scanner
- derived interpretation: optional intelligence path or service layer

### What should I avoid?

- putting scan logic in UI code
- making the scanner depend on dashboard components
- storing derived display text as the only record of a scan
- coupling optional features so tightly that the app breaks when they are disabled

## Extension checklist

Before adding a change, check:

- Does this affect user interaction, API behavior, persistence, or scanning?
- Is the data raw, derived, or both?
- Can the feature work without optional intelligence enabled?
- Does the change preserve a clear boundary between collection and presentation?

## One-sentence summary

NetWatch is a dashboard-driven app where FastAPI coordinates scan workflows, SQLite persists state, the scanner gathers network facts, and optional intelligence can enrich those facts without becoming a required dependency.
