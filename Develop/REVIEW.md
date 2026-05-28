# REVIEW.md — Gap Analysis & Roadmap

> **Status**: Snapshot from 2026-05-28. Items marked with [x] are implemented.

## Baseline

The following are implemented and deployed:

- Worker: Hono + Zod API (`/api/v1/public/*`, `/api/v1/admin/*`), scheduled monitor engine, retention, daily rollups
- Storage: D1 schema + migrations (monitors/state/results/outages/incidents/maintenance/notifications/settings/snapshots)
- Public: status snapshot, status page payload (monitors + heartbeat bars + 30d uptime bars + incidents + maintenance), latency/uptime/outages endpoints
- Admin: monitor CRUD + test, runtime state display, pause/resume, notification channel CRUD + test, incidents CRUD + updates + resolve, maintenance windows CRUD, analytics + CSV export API, settings
- CI/CD: GitHub Actions (lint + typecheck + test + auto-deploy), Node 24 JavaScript action preflight, post-deploy smoke checks

## Remaining Gaps

- [x] Public status page incident history view (resolved incidents visible)
- [x] Public status page heartbeat bar (last N checks) per monitor
- [x] Admin monitor list: show runtime state (UP/DOWN, last check, last error/latency)
- [x] Admin: pause/resume monitors from UI
- [x] Monitor creation UI: expose full HTTP config (headers, body, assertions)
- [x] Surface test results in UI (monitor test + webhook test)
- [x] CSV export buttons in admin UI
- [ ] Notification retry/backoff + delivery log UI
- [ ] Focused E2E/smoke coverage for OIDC admin login and callback behavior
- [ ] Broaden unit tests for core logic (state machine, uptime math, target validation, templates)
