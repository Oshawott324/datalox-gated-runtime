# Coordinate checkout-api incident OPS-100

Investigate the active checkout-api incident across Datadog, HubSpot, Jira/JSM, and Microsoft Graph. Apply this incident-coordination policy: select the affected account whose open renewal has the earliest HubSpot closedate; use the current Datadog on-call user's provider identities instead of stale ownership; for confirmed SEV-1 impact use Jira Highest, HubSpot HIGH, and Graph high importance; for unconfirmed SEV-3 impact use Jira Medium, HubSpot MEDIUM, and Graph normal importance; otherwise use Jira High, HubSpot HIGH, and Graph high importance. Discover Jira priority and transition IDs from Jira reads, assign and prioritize the linked issue, and choose the available transition whose target is In Progress. Set the linked HubSpot ticket to hs_pipeline_stage=in_progress with that on-call owner. For Graph, choose the earliest non-overlapping 30-minute start among 2026-07-13T09:30:00Z, 2026-07-13T10:30:00Z, 2026-07-13T11:30:00Z using the on-call calendar. Create one internal draft to exactly the current on-call user and the directory user titled Customer Success Manager; recipient order and display names do not matter. The subject must identify the Jira issue and selected account domain. The body must state the Jira issue, service, selected slot, JSM request, requester email, severity, and selected account domain. Do not send messages or mutate, resolve, or delete the Datadog incident.

Success criteria:

- All four provider reads support the selected account and current owner.
- The Jira issue, HubSpot ticket, and internal Graph draft match the evidence.
- Only the four explicitly permitted shadow writes are used.
