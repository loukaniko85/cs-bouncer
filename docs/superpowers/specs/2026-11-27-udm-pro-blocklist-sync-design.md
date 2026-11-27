# Design: Sync the ranked blocklist to a UniFi Dream Machine Pro

Date: 2026-11-27
Status: approved and implemented

## Intent and why

The bouncer already computes a severity-ranked set of up to 10,000 IPs for
Cloudflare. The owner wants the same blocklist pushed to their UniFi Dream
Machine Pro so traffic is blocked at the network gateway as well as the edge.

The chosen mechanism is the local UniFi Network API: log in, then replace the
members of one IPv4 address group. The owner creates the firewall rule that
references that group once in the UniFi UI; the bouncer only manages group
membership.

## Goals

- Optional `unifi` config block; disabled by default so existing deployments
  are unchanged.
- Authenticate to UDM Pro with a dedicated local account using the session
  cookie + CSRF token flow (`POST /api/auth/login`).
- Create or update one address group (`address-group`, `group_type` ipv4) with
  the same ranked IPs used for Cloudflare, capped by `unifi.max_items`.
- Use a separate `unifi.update_frequency` (default `5m`) so UniFi writes do not
  inherit the owner's aggressive 1-minute Cloudflare interval.
- Re-login on 401, log and continue on other failures, expose metrics.
- Never log credentials; config keys/env expansion as with existing secrets.

## Non-goals

- No creating or modifying UniFi firewall rules/policies — the group reference
  is configured once by the owner in the UI.
- No IPv6 or port groups.
- No use of the Integration v1 API-key flow: it does not expose firewall
  groups on current firmware.
- No changes to the Cloudflare ranking or list logic.

## Constraints

- UDM Pro (UniFi OS) paths: login `https://<host>/api/auth/login`, API
  `https://<host>/proxy/network/api/s/<site>/...`.
- Session auth requires both the `TOKEN` cookie and `X-CSRF-Token` header on
  every controller request; sessions expire, so a 401 must trigger re-login.
- UniFi's API for firewall groups is unofficial and varies by Network version.
  The legacy group endpoints used here are:
  - `GET /api/s/{site}/rest/firewallgroup`
  - `POST /api/s/{site}/rest/firewallgroup`
  - `PUT /api/s/{site}/rest/firewallgroup/{_id}`
  Payload: `{name, group_type: "address-group", group_members: [...], site_id,
  _id (for PUT)}`. Response envelope: `{meta:{rc:"ok"}, data:[...]}`.
- UDM Pro uses a self-signed TLS certificate; `insecure_skip_verify` defaults
  to true but is configurable.
- UniFi group member limits are not officially documented; cap at 10,000 to
  match Cloudflare and verify on real hardware.
- The container has no Go toolchain locally; verification uses podman with
  `golang:1.22-alpine`.

## Approaches considered

1. **Direct API push (chosen)** — bouncer logs into UDM Pro and replaces an
   address group's members. Self-contained, native, no host-side scripts.
   Cost: unofficial API and session/CSRF handling.
2. **File export** — bouncer writes a plain-text list to a mounted volume and a
   script/cron on the UDM imports it. Avoids API auth fragility; requires
   UDM-side setup and provides no feedback loop.
3. **Both** — file export plus optional API push with graceful fallback. Most
   resilient, most code; can be added later without changing the API path.

Chosen: **1**, per owner's decision.

## Decided design

### Config

```yaml
unifi:
  enabled: false
  url: https://10.0.24.1
  site: default
  username: <dedicated local user>
  password: <password or ${ENV}>
  group_name: CrowdSec_Block
  max_items: 10000
  insecure_skip_verify: true
  update_frequency: 5m
```

All keys are defaulted; `enabled: false` preserves current behavior.

### Client (`pkg/unifi`)

- `type Client struct{...}` with `New(config) (*Client, error)`.
- `Login(ctx)` posts JSON credentials to `/api/auth/login`, stores the `TOKEN`
  cookie and `X-CSRF-Token` header, and returns an error on failure without
  echoing credentials.
- `ListGroups(ctx)` GETs the legacy firewallgroup endpoint and decodes the
  envelope.
- `CreateGroup(ctx, name, members)` POSTs the payload; `UpdateGroup(ctx, id,
  siteID, name, members)` PUTs it.
- Every controller request sends `Cookie`, `X-CSRF-Token`, and
  `Content-Type: application/json`. On HTTP 401, call `Login` once and retry.
- `http.Client` uses `InsecureSkipVerify` from config; request bodies are not
  logged.

### Sink integration (`pkg/cf` and `cmd/root.go`)

- Define `type BlocklistSink interface { Sync(ctx context.Context, ips []string) error }`.
- Use a **shared coordinator** rather than a per-worker sink: a `syncState`
  struct with a mutex and `map[accountID][]string`, shared by all workers.
  Each worker publishes its ranked list into that map. One goroutine in
  `cmd/root.go` owns the `unifi.update_frequency` ticker, builds the union of
  all accounts' lists (deduplicated, score order preserved), and calls `Sync`.
  This avoids last-writer-wins when more than one Cloudflare account is
  configured.
- `Reconcile()` publishes the ranked IPs **as soon as ranking/trimming
  completes, before any Cloudflare write**, so a Cloudflare error or 24h
  cooldown cannot stall UniFi blocking.
- A sink failure is logged and never stops the Cloudflare loop; a successful
  sync increments `unifi_group_sync_total`, failures increment
  `unifi_group_sync_failures_total`, and `unifi_group_members` reflects the
  last successfully synced count.
- `cmd/root.go` builds the `unifi.Client` when enabled and starts the
  coordinator goroutine; it is cancelled with the shared context.

### Resolved detail decisions (from builder review)

- **Member formats:** UniFi `address-group` accepts IPv4 addresses and IPv4
  CIDRs (e.g. `192.168.0.0/24`). The sink filters out IPv6 values, converts
  `/32` to a bare address, deduplicates, and then applies `max_items` — so a
  rejected member cannot fail the whole PUT and capacity is not wasted.
- **Empty list:** publish an empty `group_members` array to clear the group.
  If the controller rejects it, log the error and retain the previous members;
  do not write a placeholder IP.
- **Independence from Cloudflare:** UniFi sync is driven by the ranked set, not
  by Cloudflare API success. Reconcile publishes before Cloudflare writes and
  a separate ticker performs the sync.
- **Multiple accounts:** the coordinator syncs the union of all accounts'
  ranked lists, so one UniFi group is authoritative across accounts.

### Observability and docs

- Counters `unifi_group_sync_total` (successes) and
  `unifi_group_sync_failures_total`; gauge `unifi_group_members`.
- Config sample comments and README section describing the one-time UI step
  (create a WAN IN / traffic rule whose source is the `CrowdSec_Block` group).
- Tests use an `httptest` server emulating login, group list, create and update,
  including 401 re-login and error paths.

### Left to builder (implementation-time decisions)

- Whether the UDM returns `site_id` in the group object or it must come from a
  sites lookup; default to `config.Site` and use the returned value when
  present.
- Exact retry/backoff on 5xx (suggest one retry with 1s delay).
- Whether to deduplicate/sort members before PUT (preserve ranking order; do
  not sort).
- Publish: commit and push to `loukaniko85/cs-cloudflare-bouncer`; verify with
  `podman go test ./...` and a local image build.
