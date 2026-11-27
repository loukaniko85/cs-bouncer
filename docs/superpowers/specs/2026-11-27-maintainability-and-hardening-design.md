# Design: Maintainability and hardening follow-ups

Date: 2026-11-27
Status: awaiting approval

## Intent and why

After the Cloudflare Rulesets migration and the UniFi sync, the bouncer works but
has accumulated debt: one 700-line `cloudflare.go`, no persisted decision state,
no way to inspect what would be blocked without contacting Cloudflare/UniFi, a
crude fixed-sleep rate limiter that ignores `Retry-After`, credentials only in
the YAML, and no guidance for pinning the container image by digest. This batch
addresses those six items without changing blocking behavior.

## Goals

1. Split `pkg/cf/cloudflare.go` into focused files with unchanged public API.
2. Persist the active decision set to a JSON file and reload it at startup, so
   a restart does not depend solely on the LAPI startup snapshot.
3. Add `-dump` CLI flag that ranks decisions from LAPI and prints the top N
   without touching Cloudflare or UniFi.
4. Replace the fixed-sleep API throttle with a token bucket and honour
   `Retry-After` on HTTP 429 for both Cloudflare and UniFi.
5. Add `<field>_file` config options so secrets can come from mounted files
   (Docker secrets) for LAPI key, Cloudflare token and UniFi password.
6. Publish the image digest in the workflow and document pinning by digest in
   the README. The running container's deployment remains the owner's side.

## Non-goals

- No change to ranking rules, list capacity, Rulesets reconciliation or UniFi
  group semantics.
- No automatic migration of the owner's running container to a digest.
- No move of existing config keys — all current keys keep working.

## Constraints

- Go 1.22; no local Go toolchain, verification via podman alpine image with
  `API_KEY/CF_*` env set.
- `golang.org/x/time` is already an indirect dependency; promote it if needed.
- `cloudflare-go` v0.119.0 retries 429 internally; our transport-level
  `Retry-After` handling applies after those retries are exhausted.
- UniFi client uses its own `http.Client`; the limiter must be shared across
  both hosts without coupling the packages.
- State file must be written atomically (temp + rename) and failure to persist
  must never stop blocking.
- Secret files are read at config load; missing/unreadable files are hard
  config errors so a misconfigured secret is obvious.

## Approaches

1. **Do all six in one release (chosen)** — one design, one plan, sequential
   tasks, one push. Coherent because the file split touches every other item.
2. **Split into two releases** — refactoring/dump/state first, limiter/secrets/
   pinning second. Safer review surface but twice the deploy churn.
3. **Only hardening** (limiter, secrets, pinning) and leave the code structure
   alone. Smallest change but leaves the maintainability problem.

Chosen: **1** — the owner asked for all proposed changes.

## Decided design

### 1. File split (`pkg/cf`)

Keep `cloudflare.go` as the package entry with worker struct, `Init`, `Run`,
`reconcileTick` and event handling. Move:
- `state.go` — `IPSetItem`, `IPListState`, `CloudflareState`,
  `setToExprList`, `computeExpression`, `UpdateExpr`, `decisionKey`,
  `normalizeDecisionValue`, `calculateIPSetDiff`.
- `api.go` — `cloudflareAPI`, `NewCloudflareClient`, `InterceptLogger`,
  Prometheus metrics, `getAPI` and the new limiter.
- `list.go` — list import/create/delete, `replaceListItems`, `pruneExpired`,
  `refreshScopedSets`, `publishRankedIPs`, `Reconcile`, `cachedListZones`.
- `rules.go` — `rulesEqual`, `UpdateRules`, `DeleteCrowdSecRules`, `Setup`.

Public names and signatures are unchanged; tests are unchanged apart from the
new limiter/state tests.

### 2. Persisted state

- New config `state_file: ""` (disabled by default, opt-in) — owner can point
  it at a writable mounted path.
- `pkg/cf/state.go` gains `SaveState(path)` / `LoadState(path)` for
  `map[string]map[string]*models.Decision`, using JSON with RFC3339 fields and
  atomic rename.
- Worker loads at `Init` before zones are listed; saves (debounced to at most
  once per 30s) after `ApplyStream`/`ApplyFullSnapshot`. Errors are logged,
  never fatal.
- A persisted decision whose `Until` has passed is dropped on load.

### 3. `-dump` flag

- `cmd/root.go`: `-dump` prints the ranked top-N (capacity from config) as one
  IP per line and exits. It creates only the LAPI client, calls
  `Decisions.GetStream` with `Startup=true` and the same filters, ranks via
  `rank.New(cfg.Ranking)`, and writes to stdout.
- Helper `dumpRanked(decisions []*models.Decision, r *rank.Ranker, n int) []string`
  is unit-tested; the LAPI call itself is not.

### 4. Rate limiting and `Retry-After`

- New `pkg/httplimit` package: `RoundTripper` wrapping any transport, with a
  shared `rate.Limiter` (default 4 req/s, burst 4) keyed by host, and a
  `Retry-After` parser that pauses the limiter for the advertised duration
  after a 429.
- Cloudflare client and UniFi client both wrap their transports with it.
- Remove `TokenCallCount`, `CallsPerSecondLimit`, `getAPI` sleep, and the
  root.go reset ticker; `getAPI` becomes a thin wrapper returning `worker.API`.

### 5. Secret files

- Config fields: `crowdsec_lapi_key_file`, account `token_file`,
  `unifi.password_file`.
- At the end of `NewConfig`, if a `_file` field is set, read it (trim trailing
  newline) and override the corresponding inline value. Both set → error, so
  ambiguity is impossible.
- Tests use `t.TempDir()` files.

### 6. Digest pinning

- Workflow step writes the pushed digest to `$GITHUB_STEP_SUMMARY` and exposes
  it as a job output.
- README adds a deployment snippet using `image: ghcr.io/...@sha256:<digest>`
  and explains that `:latest` is convenient but mutable.

### Resolved detail decisions (from builder review)

- **State files:** `state_file` is top-level and supports an `{account}` token,
  e.g. `/var/lib/cs-cloudflare-bouncer/state_{account}.json`. Each worker saves
  its own file — no shared file or cross-worker locking. Empty `state_file`
  disables persistence.
- **`-dump` selection:** it mirrors the real pipeline. Extract
  `cf.RankDecisions(decisions, ranker, capacity, now) []string` (scope filter,
  normalize, dedupe, rank, cap) and use it from both `Reconcile` and `-dump`,
  so printed values are exactly what would be blocked. With several accounts,
  print the union capped at the largest configured capacity.
- **429 semantics:** the limiter pauses after `Retry-After` but does **not**
  replay the failed request. The tick's existing cooldown still applies; this
  avoids request-body replay complexity.
- **Limiter scope:** one shared default limiter (4 req/s, burst 4) used by both
  Cloudflare and UniFi transports, injected via `httplimit.Default` so public
  client signatures stay unchanged. Per-token/per-host bucketing can be added
  later if volume requires it.
- **Digest:** emit the digest from `build-container.yml` (the workflow that
  pushes `ghcr.io/loukaniko85/cs-cloudflare-bouncer`) and pin that image in the
  README. The pre-existing release workflow targets different image names and
  is left alone.

### Left to the builder

- Exact limiter rate/burst if 4/s proves too low (keep configurable later).
- Whether to persist on every event or only on a timer (start with 30s debounce).
- Whether `-dump` honours `-c` only or also env-based config (use existing
  config loading path).
- Publish: commit and push to `loukaniko85/cs-bouncer`; verify with podman and
  confirm workflow success.
