# CyberSOC API Contract v1

Base URL: `/api` (same origin via Nginx; direct backend at `http://localhost:8000/api`).
Auth: `Authorization: Bearer <JWT>` header. Login/register are public; everything else requires auth.
Roles: `ADMIN`, `SOC_ANALYST`. Admin-only endpoints return `403` for analysts.
Errors: JSON `{ "detail": "..." }` with standard HTTP codes (400/401/403/404/409/422/429).

Conventions:
- Timestamps: ISO-8601 UTC (`2026-09-24T10:31:04Z`).
- Pagination: `?skip=0&limit=50` → `{ "items": [...], "total": N }`.
- Severities: `LOW | MEDIUM | HIGH | CRITICAL`.
- Alert statuses: `NEW | ACKNOWLEDGED | INVESTIGATING | RESOLVED | FALSE_POSITIVE`.
- Incident statuses: `DETECTED | INVESTIGATING | CONFIRMED | CONTAINED | RESOLVED`.
- Simulation statuses: `CREATED | RUNNING | PAUSED | COMPLETED | ABORTED`.
- Action types: `DISABLE_USER | BLOCK_IP | ISOLATE_ENDPOINT | REVOKE_SESSION | RESET_CREDENTIAL | ESCALATE_INCIDENT | MARK_FALSE_POSITIVE | RESOLVE_INCIDENT`.

---

## Auth (`tag: Auth`)
- `POST /api/auth/register` `{name, email, password}` → `201 {id, name, email, role, is_active, created_at}`. First-ever user becomes ADMIN; others default `SOC_ANALYST`.
- `POST /api/auth/login` `{email, password}` → `200 {access_token, token_type: "bearer"}`.
- `GET /api/auth/me` → current user object.

## Users (`tag: Users`, ADMIN only except me)
- `GET /api/users?skip=&limit=` → paginated users.
- `GET /api/users/{id}` → user.
- `PATCH /api/users/{id}` `{role?, is_active?}` → user.

## Scenarios (`tag: Scenarios`)
- `GET /api/scenarios?active_only=true` → `[{id, name, description, attack_type, difficulty, is_active, event_count, technique_ids, created_at}]`. Analysts never see solution fields.
- `GET /api/scenarios/{id}` → full scenario. Analyst view EXCLUDES `expected_actions`, `wrong_actions`, `scoring`; ADMIN sees everything.
- `POST /api/scenarios` (ADMIN) → create. Body: `{name, description, attack_type, difficulty, definition{...}, is_active}`.
- `PUT /api/scenarios/{id}` (ADMIN), `DELETE /api/scenarios/{id}` (ADMIN, soft-deactivate).

## Simulations (`tag: Simulations`)
- `POST /api/simulations` `{scenario_id, speed=1.0}` → session `{id, scenario_id, scenario_name, analyst_id, status, speed, started_at, sim_elapsed_sec, events_emitted, alerts_raised}`.
- `GET /api/simulations?status=` → own sessions (ADMIN: `?analyst_id=` for all).
- `GET /api/simulations/{id}` → session detail + scenario story + attack chain (no solutions for analysts).
- `POST /api/simulations/{id}/pause|resume|restart|complete|abort` → session.
- `GET /api/simulations/{id}/feed?since_event_id=0` → `{status, sim_elapsed_sec, events:[...], new_alerts:[...]}`. **Materializes due events** based on the sim clock (progressive release). Poll every 2–3s.
- `GET /api/simulations/{id}/timeline` → ordered `{events, alerts, actions}` for visualization.

## Events (`tag: Events`)
Event: `{id, simulation_id, timestamp, event_type, severity, source, destination, username, device, message, meta{}}`.
- `GET /api/simulations/{id}/events?event_type=&severity=&q=&skip=&limit=` → paginated.
- `GET /api/events/{id}` → event.

## Alerts (`tag: Alerts`)
Alert: `{id, simulation_id, event_id, severity, category, title, description, status, created_at, rule_id}`.
- `GET /api/simulations/{id}/alerts?status=&severity=` → list.
- `GET /api/alerts?status=&severity=&simulation_id=&skip=&limit=` → paginated alert queue across simulations (analysts: own simulations only; admins: all).
- `GET /api/alerts/{id}` → `{alert, event, related_alerts[], related_events[], mitre_techniques[]}`.
- `PATCH /api/alerts/{id}` `{status}` — allowed: NEW→ACKNOWLEDGED→INVESTIGATING→RESOLVED, any→FALSE_POSITIVE.

## Incidents (`tag: Incidents`)
Incident: `{id, simulation_id, analyst_id, title, description, severity, status, alert_ids[], created_at, updated_at, resolved_at}`.
- `POST /api/incidents` `{simulation_id, title, description, severity, alert_ids[]}` → incident (DETECTED).
- `GET /api/incidents?simulation_id=&status=` → list.
- `GET /api/incidents/{id}` → `{incident, alerts[], actions[], events[], timeline[], mitre_techniques[], assets[]}`.
- `PATCH /api/incidents/{id}` `{status}` — transitions: DETECTED→INVESTIGATING|CONFIRMED; INVESTIGATING→CONFIRMED|DETECTED; CONFIRMED→CONTAINED; CONTAINED→RESOLVED.
- `POST /api/incidents/{id}/alerts` `{alert_ids[]}` → correlate alerts.
- `POST /api/incidents/{id}/actions` `{action_type, target}` → `{action, asset, incident}` — simulated response; containment actions on a CONFIRMED incident auto-advance it to CONTAINED; each action is audit-logged.

## Analytics (`tag: Analytics`)
- `GET /api/analytics/overview` (ADMIN) → `{totals, avg_times, success_rates, common_mistakes[], attack_distribution[], difficulty_stats[]}`.
- `GET /api/analytics/me` → analyst personal stats + history: `{totals: {simulations, completed, avg_score, best_score, alerts_acknowledged, avg_time_to_detect_sec, avg_time_to_contain_sec}, running[]: {id, scenario_name, status, alerts_raised}, history[]: {id, scenario_name, status, score{total,grade,…}, time_to_detect_sec, time_to_contain_sec, started_at, completed_at}}`.

## MITRE (`tag: MITRE`)
- `GET /api/mitre/techniques` → `[{technique_id, name, description}]`.
- `GET /api/mitre/techniques/{technique_id}` → technique + linked scenarios.

## Reports (`tag: Reports`)
- `GET /api/simulations/{id}/report` → `{scenario, analyst, started_at, ended_at, attack_timeline[], indicators[], actions_taken[], incorrect_actions[], containment_actions[], mitre_techniques[], score{...}, recommendations[]}`.
- `GET /api/reports` → own completed-session reports (ADMIN: all).

## AI assistant (`tag: AI`)
- `POST /api/ai/assist` `{simulation_id?, incident_id?, question}` → `{answer, suggested_actions[], mitre_explanations[]}`. Rule-based, no external calls. Suggestions are advisory only.

## Misc
- `GET /api/health` → `{status: "ok"}`.
- `GET /api/audit?skip=&limit=` (ADMIN) → audit log entries.
