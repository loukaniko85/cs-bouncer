# Design: Cloudflare Rulesets migration + severity-ranked 10k lists

Date: 2026-11-27
Status: awaiting approval

## Intent and why

The forked bouncer stopped working because Cloudflare deprecated the legacy
Firewall Rules API. On startup it calls `FirewallRules()` /
`CreateFirewallRules()` / `UpdateFilters()` and dies with
`firewallrules.api.deprecated (10020)`.

At the same time, Cloudflare allows only **10,000 list items per account** on
Free/Pro/Business plans. The bouncer puts every CrowdSec decision into an IP
list and references it from a small number of WAF rules. When there are more
decisions than fit, the bouncer must decide which ones earn a slot. Today it
keeps the most *recently seen* decisions, ranked by an in-memory timestamp that
is reset on restart and never imported from Cloudflare.

The owner wants severity-first selection: exploit / 0-day style decisions ahead
of brute-force and scanning noise, with recency only as a tiebreaker. Refresh
should be configurable, with a periodic full resync to heal drift.

## Goals

- Start and run cleanly against the current Cloudflare API (no 10020 fatal).
- Keep exactly **one IP list per account** — the existing `crowdsec_block` —
  filled to (at most) `total_ip_list_capacity` (default 10,000).
- Fill that budget using a deterministic, configurable severity score derived
  from decision data, so ordering survives container restarts.
- Refresh Cloudflare every `update_frequency` (default 5m) and do a full LAPI
  resync every `full_resync_frequency` (default 168h / weekly).
- Preserve: multi-account / multi-zone, IP / range / AS / country scopes,
  token auth, Prometheus metrics, and the `-g/-s/-d/-t/-T/-lc` CLI flags.
- Ship updated config samples, tests, docs, a GitHub Actions workflow that
  builds and publishes the container image, and push to the owner's fork.

## Non-goals

- No CrowdSec Live Exploit Tracker integration. Its per-CVE scores require a
  separate key/subscription. The design leaves a clean seam to add it later.
- No programmatic cleanup of *legacy* Firewall Rules/Filters: that API is
  deprecated and cannot be relied on. Cleanup instructions go in the docs.
- No change to LAPI decision filtering (`include_scenarios_containing`,
  `exclude_scenarios_containing`, `only_include_decisions_from`).
- No attempt to raise Cloudflare plan limits.

## Anti-goals (failure even if it "works")

- Exceeding 10k list items account-wide or Cloudflare's WAF rule caps.
- Overwriting rules the user created in the same zone ruleset.
- Losing severity ordering after a restart or silently dropping everything
  because of a bad score config.
- Committing the GitHub token or Cloudflare/LAPI keys to the repo.

## Constraints

- Cloudflare quotas (2026): custom list items 10,000 Free/Pro/Business
  (500,000 Enterprise); WAF custom rules 5 / 20 / 100 / 1,000 by plan;
  account-level custom rulesets require Enterprise, so rules stay **zone-level**.
- `models.Decision` (crowdsec v1.6.3) exposes only `Duration`, `ID`, `Origin`,
  `Scenario`, `Scope`, `Simulated`, `Type`, `Until`, `UUID`, `Value`. There is
  no severity field and no alert labels in the stream.
- Decision start can be reconstructed as `Until - Duration`, giving a
  restart-safe recency signal.
- The Lists API used for IP items is **not** deprecated and stays.
- Confirmed by screenshot of the live account: **1 of 1 custom lists used**,
  **10,000 / 10,000 items**, list `crowdsec_block` ("block IP list by
  crowdsec"), last modified ~8 months ago — i.e. the account allows only one
  list and it is completely full. The design must not try to create a second
  list per action.
- No Go toolchain in the current workspace; verification will use whatever Go
  toolchain/Docker is available at implementation time.

## Approaches considered

1. **Stream + ranked reconcile** — keep the CrowdSec stream, maintain an
   active decision set in memory, recompute the ranked top-N on each tick.
   Smallest change and near-real-time. Weakness: drift accumulates if a stream
   message is missed.
2. **Full poll each tick** — drop the stream, fetch all decisions every cycle.
   Simplest correctness, self-healing; more LAPI traffic and slower reaction.
3. **Hybrid (chosen)** — keep the stream for near-real-time deltas, plus a
   periodic full resync that replaces the decision set wholesale. Most robust
   against drift and restarts; slightly more code than (1).

Chosen: **3**, with a weekly resync. The owner explicitly chose this shape.
Approach 2 would multiply LAPI traffic for no practical benefit at a 5-minute
Cloudflare cadence; approach 1 alone cannot heal drift without a restart.

## Decided design

### Cloudflare rule management

- Remove every legacy Firewall Rules / Filters call from `pkg/cf`.
- Use a **single account-level IP list** named `<ip_list_prefix>_block`
  (default `crowdsec_block`), importing the existing one on startup. Do not
  create per-action lists. Optional `ip_list_name` overrides the name.
- Manage rules directly in each zone's `http_request_firewall_custom`
  **entry-point ruleset** via `GetEntrypointRuleset` /
  `UpdateEntrypointRuleset`. This avoids the per-zone custom-ruleset quota
  (which is 1 on Free) and avoids account-level/Enterprise requirements.
- Identify our rules by a description prefix (`CrowdSec `) and preserve all
  other rules in the entry point verbatim. One rule per configured action per
  zone; only update Cloudflare when an expression actually changes.
- Expressions stay in the current form:
  `(ip.src in $list) or (ip.geoip.country in {...}) or (ip.geoip.asnum in {...})`.
- With legacy calls removed, no `10020` remains at startup: Rulesets and Lists
  setup errors stay fatal (fail fast). Per-zone rule reconciliation errors are
  logged and retried on the next tick. The `-d` path deletes our ruleset rules
  via the Rulesets API before deleting the IP list; legacy leftovers are a
  documented manual cleanup.
- Upgrade `cloudflare-go` from the 2022 pseudo-version to a current release
  that supports the project's Go version; bump the Dockerfile builder image
  if needed.

### Ranking (new `pkg/rank` package)

Score each decision, highest wins:

- `patterns`: ordered list of `{name, pattern, score}` RE2 regexes matched
  against `Scenario` (case-insensitive). First match wins. A `{{YEAR}}` token
  is expanded at config load to the current year.
  Defaults: `0day|zero.?day|cve-{{YEAR}}` = 100; `exploit|rce|sqli|lfi|xxe`
  = 80; `bf|brute|credential|spray` = 40; `scan|probe|crawl|bot` = 10;
  unmatched = 20.
- `type_scores`: `ban` 20, `captcha` 5, `js_challenge` 5.
- `duration_bonus_per_hour` 1, capped at `duration_bonus_max` 20.
- `origin_scores`: `crowdsec`/`CAPI` 10, `cscli`/`lists` 0.
- Tiebreaker: decision start (`Until - Duration`) descending, then value
  ascending for determinism.
- Skip decisions with `Simulated == true` or `Until` already in the past.
- Normalize/dedupe as today (IPv4 `/32` stripped, IPv6 collapsed to `/64`),
  but keep the **highest-scoring** copy of a duplicate value.

### Budget and sync loop

- Rank all IP decisions globally, then fill the single list in score order up
  to `total_ip_list_capacity` (10,000). This fixes both the current bug where
  N actions could each request 10k items and the one-list-per-account quota.
- Country/AS sets keep their current in-rule inline behaviour.
- On each `update_frequency` tick: apply stream deltas, drop expired, recompute
  ranking, `ReplaceIPListItemsAsync` + poll only when the desired set changed,
  update ruleset rules only when expressions changed.
- On each `full_resync_frequency` tick: call the LAPI stream endpoint with
  `startup=true` using the same filters and replace the active set wholesale.
- New config keys (all defaulted, old configs keep working):
  `cloudflare_config.update_frequency: 5m`,
  `cloudflare_config.full_resync_frequency: 168h`, and
  `cloudflare_config.ranking: {...}` as described above.

### Container build and publish

- Add `.github/workflows/build-container.yml`: build the multi-stage Dockerfile
  on pushes to `main` and on `v*` tags, run `go test ./...` first, then push the
  image to GitHub Container Registry (`ghcr.io/loukaniko85/cs-cloudflare-bouncer`)
  using `GITHUB_TOKEN`. Tag pushes get both the version tag and `latest`.
  Keep registry/image name configurable via workflow env vars so Docker Hub can
  be swapped in later.
- Bump the Dockerfile Go builder to match `go.mod`; keep the small Alpine
  runtime image and the existing config path/entrypoint.

### Observability and docs

- Add metrics for dropped-by-budget decisions and current list item counts.
- Update `config/*.yaml` samples, README, and a migration note covering token
  permissions, the single-list 10k budget, and manual legacy-rule cleanup.

### Resolved detail decisions (from builder review)

- **Duplicate decisions / action disagreement:** with one shared list, action
  no longer determines list membership. Normalize and dedupe by value, keeping
  the highest-scoring copy; ties prefer `ban`, then earlier decision start.
  Action normalization stays in rule creation only. Maintain a value → active
  decisions map so an expiry removes the value only when no active copy remains.
- **Ranking config validation:** defaults are always pre-seeded. A non-empty
  `patterns` replaces the defaults; `patterns: []` keeps them and logs a
  warning. Invalid regex, negative scores, or non-numeric values fail config
  validation (`-t` and startup) with a field-specific error.
- **Rule caps:** keep the existing free-plan guard (a non-subscribed zone with
  more than one action is rejected). Do not attempt plan-cap discovery; warn if
  the entry-point ruleset already contains other rules.
- **List budget:** trust `total_ip_list_capacity` for our list; at startup warn
  if other custom lists exist whose items would push the account over 10,000.

### Left to the builder (implementation-time decisions)

- Exact current `cloudflare-go` version and method signatures; exact
  `apiclient.ListOpts` fields (the resync uses `GetStream(startup=true)`, which
  needs no pagination).
- Verification commands available in this environment (Go toolchain or Docker).
- Whether to add the optional periodic resync as a separate goroutine or a
  second ticker in the existing worker loop (recommended: second ticker).
- Publish step: commit and push to `loukaniko85/cs-cloudflare-bouncer` using
  the token supplied out of band, never written into the repo. Confirm whether
  the owner wants the workflow to publish to GHCR (default in this design) or
  to Docker Hub before enabling it.
