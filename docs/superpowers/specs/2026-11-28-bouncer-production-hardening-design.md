# Design: Production hardening, official UniFi API-key sync and project cleanup

Date: 2026-11-28
Status: awaiting approval

## Intent and why

A full audit found two Critical and seventeen Important defects in the
current bouncer. The highest-impact defects are out-of-order decision delivery,
the startup snapshot being treated as a delta, partial multi-account UniFi
merges, unsafe empty-list handling, `-t` mutating production resources, and
unbounded HTTP operations. Separately, the owner requires UniFi API-key auth
and generic UniFi OS support, a Docker-only CI workflow, and accurate
`cs-bouncer` project metadata.

This release fixes the Critical/Important findings, replaces the legacy UniFi
client with the official Traffic Matching List API, reduces CI to the container
workflow, and cleans up repo metadata/docs.

## Goals

### Correctness / reliability

- Replace the per-event goroutine fan-out and mixed startup/delta stream with
  one ordered LAPI poller: startup full snapshot first, then synchronous deltas
  in sequence, weekly full snapshot in the same ordered loop.
- UniFi coordinator waits until every configured Cloudflare account has
  published at least once before its first sync; later syncs use last-known-good
  per-account sets and deterministic config order.
- Remove the Cloudflare empty-list placeholder workaround; use the Lists API's
  supported empty replacement.
- `-t` only validates config and exits; no workers, LAPI loop, or Cloudflare
  writes.
- Add bounded HTTP/request deadlines and context-aware sleeps/sends/polling so
  SIGTERM cannot hang indefinitely.

### Security / safety

- Filter simulated decisions centrally, including COUNTRY/AS, and defensively
  in scoped-set refresh.
- Reject malformed decision values and null persisted decisions; validate
  capacity > 0.
- Redact secrets in `-T`; write generated config mode 0600; stop printing API
  keys in installers/logs; rotate or summarize API request logs.
- Default TLS verification on; support `ca_file`; reject plain HTTP unless
  explicitly enabled.
- Replace destructive legacy-list auto-migration with a clear fail-fast
  migration error (the owner already uses the neutral list).
- Enforce account-wide Cloudflare list capacity after accounting for other IP
  lists; cap inline COUNTRY/AS expressions with metrics.
- Strict YAML known-field validation; require at least one account and resolved
  non-empty IDs/secrets; reject unresolved `${...}` placeholders.

### UniFi

- Official `X-API-Key` client for `GET/POST/PUT
  /v1/sites/{siteId}/traffic-matching-lists` on UniFi OS consoles or the cloud
  connector. No username/password, cookie, CSRF, or `firewallgroup` API.
- Bouncer manages one IPv4 Traffic Matching List; firewall policy creation
  remains a one-time UI step. Empty list updates are skipped (API requires at
  least one item).

### Tooling / metadata

- Keep only `.github/workflows/build-container.yml`; it runs tests, vet, format
  check, govulncheck, image build/push, and digest reporting.
- Update Dockerfile/go.mod to a supported patched Go release and fixed module
  versions.
- Update repo About, README title/scope, config comments and Docker image names
  for `cs-bouncer`; publish a legacy image alias for one transition release.
- Fix packaging build dependencies and the small correctness/doc drifts found
  in the audit.

## Non-goals

- No UniFi-only mode without Cloudflare accounts; direct CrowdSec→UniFi is a
  follow-up feature.
- No legacy self-hosted UniFi controller support lacking the official API-key
  integration endpoint.
- No UniFi firewall policy creation/reordering.
- No automatic destructive migration of legacy `crowdsec_*` lists.

## Approaches

1. **Single ordered poller + fail-safe reconciliation (chosen)** — one LAPI
   goroutine owns full/delta sequence and synchronous fan-out. UniFi first sync
   requires all accounts. This directly fixes the two Critical findings.
2. **Keep StreamBouncer.Run and sequence around it** — less refactoring but
   cannot guarantee startup snapshot vs delta ordering.
3. **Independent Cloudflare and UniFi pipelines** — architecturally clean and
   enables UniFi-only mode, but much larger than the requested fix.

Chosen: **1**. UniFi-only mode is deferred to a future design.

## Decided design

### LAPI ordered poller (`cmd/root.go`)

- Use `csbouncer.StreamBouncer.Init()` only to build/configure the API client
  and ticker duration; do not call its `Run`.
- One goroutine: fetch `GetStream(Startup=true)` once, broadcast
  `DecisionEvent{FullSnapshot:true}` synchronously to each worker with
  `ctx.Done()` select; then poll deltas on ticker. When weekly resync is due,
  fetch full snapshot in the same loop before the next delta. No concurrent
  snapshot/delta requests.
- No per-event goroutines; sequence numbers remain as a defensive check.

### UniFi coordinator (`cmd/root.go`)

- Constructor receives the ordered configured account IDs.
- `Publish` stores a copy and marks initial publication.
- `Sync` returns nil until every configured account has published at least
  once; after that, it merges last-known-good sets in config order.

### Cloudflare safety (`pkg/cf`)

- `replaceListItems` sends the actual desired slice, including empty, directly
  to `ReplaceIPListItemsAsync`; no placeholder or deferred delete.
- Effective capacity = configured capacity minus `NumItems` of other IP lists
  discovered at startup; <=0 fails setup with an explicit quota error.
- Legacy list found under a different configured name → fail setup with manual
  migration instructions, never delete first.
- `refreshScopedSets` skips simulated decisions and caps country/AS sets at
  configurable limits (default 200 each) with counters.
- Ingest skips malformed values; `normalizeDecisionValue` returns `(string,
  error)`; persisted null decisions are rejected/dropped safely.

### HTTP / limiter

- `http.Client.Timeout` 30s for Cloudflare/UniFi; LAPI poller uses a 30s
  request context; bulk polling uses context-aware timers.
- `httplimit.Default` holds per-host limiters; after acquiring a token it
  rechecks that host's pause; `Retry-After` is honored in full (no shorter
  arbitrary cap), with cancellation support.

### Config / secrets

- New fields: `ca_file` (Cloudflare/UniFi), `allow_insecure_http` (UniFi),
  `max_country_decisions`, `max_as_decisions` (default 200).
- `yaml.Decoder.KnownFields(true)` in `NewConfig`; require accounts, IDs and
  resolved secrets; reject unresolved `${...}`.
- `-T` redacts `crowdsec_lapi_key`, `token`, `password`, `api_key` and file
  equivalents; generated config uses 0600 atomic writes.
- API logger uses lumberjack rotation and logs body size, not full bodies.
- SIGTERM/SIGINT returns nil after cancellation.

### Official UniFi API

See `2026-11-28-unifi-api-key-and-ci-cleanup-design.md` for the exact endpoint
contract. Replace `pkg/unifi` client and tests; config uses `mode`, `url`,
`console_id`, `api_key`/`api_key_file`, `site`, `list_name`.

### CI / project cleanup

- Delete all non-container workflow files. Keep tests/vet/format/govulncheck in
  `build-container.yml`.
- Go/toolchain and dependency versions are pinned to patched releases and
  `govulncheck` must pass in CI.
- README/repo About/package docs describe Cloudflare + UniFi `cs-bouncer`.
- Debian/RPM build metadata declares Go/Git/tooling.

### Tests

New regressions cover: startup snapshot replacing persisted state; ordered
out-of-order events; all-account UniFi readiness; empty Cloudflare list; `-t`
no writes; cancellation/timeouts; simulated COUNTRY/AS; malformed IPv6/state;
negative capacity; quota accounting; scoped caps; strict config; secret
redaction; official UniFi API-key URLs/payloads; per-host limiter behavior.

### Resolved detail decisions (from builder review)

- **Initial snapshot gating:** workers do not reconcile/publish until their
  first `FullSnapshot` event is applied. A startup flag in the worker guards
  `Reconcile`, so persisted state cannot satisfy UniFi readiness early.
- **Existing Cloudflare items:** setup imports the configured list's current
  items into `IPSet` before the first reconcile. Desired-vs-current comparison
  is therefore accurate even for an empty startup snapshot, and an empty
  desired set clears stale remote items.
- **UniFi pagination:** site and Traffic Matching List discovery follow
  `offset`/`limit`/`totalCount` until all pages are read.
- **LAPI auth:** require either `crowdsec_lapi_key` or a non-empty
  `cert_path` + `key_path` pair; mTLS remains valid without an API key.
- **TLS schema:** `insecure_skip_verify` defaults false, `ca_file` is supported,
  and plain HTTP requires `allow_insecure_http: true`.
- **COUNTRY/AS:** validate ISO-3166 alpha-2 country codes and numeric ASNs;
  rank per action with the same severity ranker, keep the top configured cap
  deterministically, and log/metrics trimmed values.
- **Empty UniFi list:** the official API requires at least one item. When the
  desired set is empty, write one reserved documentation-only placeholder
  (`192.0.2.1`) so old attacker entries are removed and no real traffic is
  blocked; metrics/logs report zero effective members.

### Left to builder

- Exact patched Go/module versions after running `govulncheck`.
- Country/AS cap values (defaults 200; configurable).
- Legacy image alias duration (one transition release).
- Repo About text and final README wording.
