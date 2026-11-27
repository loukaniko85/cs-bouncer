# Maintainability and Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the six follow-ups: split `cloudflare.go`, persist decision state, add `-dump`, replace the API sleeper with a shared limiter that honours `Retry-After`, support secret files, and document digest pinning.

**Architecture:** `pkg/httplimit` provides one shared `RoundTripper` used by both Cloudflare and UniFi clients. Ranking selection is extracted as `cf.RankDecisions` and shared by the reconcile loop and the new `-dump` flag. State is persisted per account to an opt-in JSON file. Config gains `_file` variants for secrets.

**Tech Stack:** Go 1.22, `golang.org/x/time/rate`, `encoding/json`, `os`, `path/filepath`, `net/http`, podman verification, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-27-maintainability-and-hardening-design.md`

## Global Constraints

- No behavior change to ranking, capacity, Rulesets reconciliation, or UniFi groups.
- `state_file` default empty (disabled); supports `{account}` token; per-account files; atomic writes; errors never fatal.
- Secret `_file` fields override inline values; both set → config error; trim trailing newline.
- Limiter: `httplimit.Default` = 4 req/s, burst 4; on 429 read `Retry-After` (seconds or HTTP date), pause subsequent requests; do not replay the failed request.
- `-dump` prints exactly what `cf.RankDecisions` would block, one IP per line, no Cloudflare/UniFi writes.
- Verify with podman `golang:1.22-alpine`, `API_KEY/CF_*` env set; Docker socket unavailable.

## Review Focus

- Multiple accounts with one `state_file` template → distinct files: Task 5 (`TestStateFilePerAccount`).
- `-dump` must use the real selection pipeline, not raw `rank.Rank`: Task 4 (`TestRankDecisionsMatchesReconcile`).
- 429 handling must not replay bodies and must delay later calls: Task 2 (`TestRoundTripperRetryAfter`).
- Secret files must win over inline values and fail loudly when both set: Task 1 (`TestSecretFiles`).
- File split must preserve API: Task 7 compiles and runs the unchanged suite.

---

### Task 1: Config — state_file and secret files

**Files:** Modify `pkg/cfg/config.go`, `pkg/cfg/config_test.go`.

**Interfaces:**
- Consumes: `bouncerConfig`, `AccountConfig`, `UnifiConfig`.
- Produces: `bouncerConfig.StateFile string yaml:"state_file"`, `bouncerConfig.CrowdSecLAPIKeyFile string yaml:"crowdsec_lapi_key_file"`, `AccountConfig.TokenFile string yaml:"token_file"`, `UnifiConfig.PasswordFile string yaml:"password_file"`; resolution at end of `NewConfig`.

- [ ] **Step 1: Write failing tests** in `pkg/cfg/config_test.go`:

```go
func TestSecretFiles(t *testing.T) {
    // temp file with "secret-from-file\n"; config with crowdsec_lapi_key_file,
    // account token_file, unifi password_file (enabled) → values from files.
    // Also: inline + file both set → err containing "_file".
    // Also: missing file → err containing the path.
}
func TestStateFileDefaultAndOverride(t *testing.T) { ... }
```

- [ ] **Step 2: Run** — `podman run ... go test ./pkg/cfg/ -run 'TestSecretFiles|TestStateFile' -v`. Expected: FAIL.

- [ ] **Step 3: Implement** fields, defaults, and `resolveSecretFiles(config)` called after unmarshal; use `os.ReadFile`, `strings.TrimRight(..., "\r\n")`, clear error messages with field name. Apply the same defaults in `ConfigTokens`/`setDefaults`.

- [ ] **Step 4: Run** — same command. Expected: PASS, full `pkg/cfg` suite green.

- [ ] **Step 5: Commit** — `git add pkg/cfg && git commit -m "feat(cfg): support state file and secret files"`

---

### Task 2: Shared HTTP limiter with Retry-After

**Files:** Create `pkg/httplimit/limiter.go`, `pkg/httplimit/limiter_test.go`.

**Interfaces:**
- Consumes: `golang.org/x/time/rate`.
- Produces: `var Default *RoundTripper`, `type RoundTripper struct{ Next http.RoundTripper; Limiter *rate.Limiter }`, `func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error)`.

- [ ] **Step 1: Write failing tests**:

```go
func TestRoundTripperLimits(t *testing.T) { /* 5 rapid requests via httptest, elapsed >= ~1s */ }
func TestRoundTripperRetryAfter(t *testing.T) {
    // first response 429 with Retry-After: 1; second request delayed >= ~900ms
    // and no replay of the first request.
}
```

- [ ] **Step 2: Run** — `podman run ... go test ./pkg/httplimit/ -v`. Expected: FAIL (package absent).

- [ ] **Step 3: Implement**: `Default` with `rate.NewLimiter(4, 4)`. `RoundTrip` waits on an internal `pauseUntil` (mutex) then `Limiter.Wait(req.Context())`, calls `Next.RoundTrip`; if response status 429, parse `Retry-After` and set `pauseUntil` for subsequent requests; return the 429 unchanged. Handle nil `Next` as `http.DefaultTransport`.

- [ ] **Step 4: Run** — same command. Expected: PASS.

- [ ] **Step 5: Commit** — `git add pkg/httplimit && git commit -m "feat(httplimit): shared rate limiter with Retry-After"`

---

### Task 3: Wire limiter into both clients; remove old sleeper

**Files:** Modify `pkg/cf/cloudflare.go`, `pkg/cf/cloudflare_test.go`, `pkg/unifi/unifi.go`, `cmd/root.go`.

**Interfaces:**
- Consumes: `httplimit.Default`.
- Produces: `NewCloudflareClient` wraps its `InterceptLogger` with `httplimit.Default`; `unifi.New` wraps its TLS transport with `httplimit.Default`; `CloudflareWorker.getAPI()` no longer sleeps; `TokenCallCount`/`CallsPerSecondLimit` and root.go's `APICountByToken` reset ticker removed.

- [ ] **Step 1: Write failing test** in `pkg/cf/cloudflare_test.go`: `TestGetAPIIsNonBlocking` — 10 calls complete quickly (no 1s sleep).

- [ ] **Step 2: Run** — `podman run ... go test ./pkg/cf/ -run TestGetAPIIsNonBlocking -v`. Expected: FAIL.

- [ ] **Step 3: Implement** changes; update tests to drop `TokenCallCount` fields; ensure full suite compiles.

- [ ] **Step 4: Run** — `podman run ... go test ./...`. Expected: PASS.

- [ ] **Step 5: Commit** — `git add pkg/cf pkg/unifi cmd && git commit -m "refactor: use shared limiter for both APIs"`

---

### Task 4: Extract shared ranking selection and add `-dump`

**Files:** Modify `pkg/cf/cloudflare.go`, `pkg/cf/cloudflare_test.go`, `cmd/root.go`; new `cmd/dump.go` optional.

**Interfaces:**
- Consumes: `rank.Ranker`.
- Produces: `func RankDecisions(decisions []*models.Decision, r *rank.Ranker, capacity int, now time.Time) []string` — scope filter (IP/RANGE), normalize, dedupe/rank, trim, increment `RankingDroppedTotal`; `Reconcile` uses it; `-dump` flag prints its output.

- [ ] **Step 1: Write failing test** `TestRankDecisionsMatchesReconcile`: build worker with decisions including IPv6, `/32`, simulated, country/AS; assert `RankDecisions` output equals the keys in `IPSet` after `Reconcile`.

- [ ] **Step 2: Run** — `podman run ... go test ./pkg/cf/ -run TestRankDecisionsMatchesReconcile -v`. Expected: FAIL.

- [ ] **Step 3: Implement** extraction; change `publishRankedIPs` to accept `[]string`; implement `-dump` in `cmd/root.go` using `csbouncer.StreamBouncer.Init()` + `GetStream(startup=true)` with the existing filters, max capacity across accounts, prints to stdout and returns. No Cloudflare/UniFi objects created.

- [ ] **Step 4: Run** — `podman run ... go test ./...`. Expected: PASS.

- [ ] **Step 5: Commit** — `git add pkg/cf cmd && git commit -m "feat: add dump flag and shared ranking selection"`

---

### Task 5: Persist decision state

**Files:** Modify `pkg/cf/cloudflare.go`, `pkg/cf/cloudflare_test.go`, `pkg/cfg/config.go`, config samples.

**Interfaces:**
- Consumes: `ActiveDecisions` map, `StateFile` config.
- Produces: `func SaveState(path string, active map[string]map[string]*models.Decision) error`, `func LoadState(path string) (map[string]map[string]*models.Decision, error)`; worker field `StatePath string` with `{account}` replaced by account ID; load in `Init`, save debounced 30s after stream events.

- [ ] **Step 1: Write failing tests**:

```go
func TestStateRoundTrip(t *testing.T) { /* save/load map, values preserved */ }
func TestLoadStateDropsExpired(t *testing.T) { /* past Until removed */ }
func TestStateFilePerAccount(t *testing.T) { /* two workers, distinct paths */ }
```

- [ ] **Step 2: Run** — `podman run ... go test ./pkg/cf/ -run 'TestState' -v`. Expected: FAIL.

- [ ] **Step 3: Implement** JSON helpers with atomic rename; worker load/save with warning-only errors; add `state_file` comments to both sample YAMLs.

- [ ] **Step 4: Run** — `podman run ... go test ./...`. Expected: PASS.

- [ ] **Step 5: Commit** — `git add pkg/cf pkg/cfg config && git commit -m "feat: persist decision state per account"`

---

### Task 6: Split `cloudflare.go`

**Files:** Create `pkg/cf/state.go`, `pkg/cf/api.go`, `pkg/cf/list.go`, `pkg/cf/rules.go`, `pkg/cf/worker.go`; keep `pkg/cf/cloudflare.go` minimal.

**Interfaces:** Identical public API; tests unchanged.

- [ ] **Step 1: Check baseline** — `podman run ... go test ./pkg/cf/` passes before the split.

- [ ] **Step 2: Move code** (mechanical) per the spec's file map; keep imports correct with `goimports` or manual edits. No behavior changes.

- [ ] **Step 3: Verify** — `podman run ... go test ./...`. Expected: PASS.

- [ ] **Step 4: Commit** — `git add pkg/cf && git commit -m "refactor: split cloudflare.go into focused files"`

---

### Task 7: Digest output and pinning docs, verify, push

**Files:** Modify `.github/workflows/build-container.yml`, `README.md`.

- [ ] **Step 1: Workflow** — add a step that writes `digest=${{ steps.build.outputs.digest }}` to `$GITHUB_STEP_SUMMARY` and exposes it as a job output on `docker/build-push-action`.

- [ ] **Step 2: README** — add a snippet pinning `ghcr.io/loukaniko85/cs-cloudflare-bouncer@sha256:<digest>` and note `:latest` is mutable.

- [ ] **Step 3: Verify** — `podman run ... go test ./...` and `podman build -t cs-cloudflare-bouncer:test .`; both pass.

- [ ] **Step 4: Push** — fast-forward push to `main` of `loukaniko85/cs-bouncer` with token in command only; confirm workflow success and report commit SHA and image digest.
