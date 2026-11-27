# Cloudflare Rulesets + Ranked Lists Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the deprecated Cloudflare Firewall Rules calls with the Rulesets API and fill the account's single 10,000-item IP list with the most severe CrowdSec decisions, refreshed on a configurable cadence with a weekly full resync.

**Architecture:** Keep the LAPI stream as the source of deltas, hold active decisions in an in-memory map, and recompute a ranked desired list on each refresh tick. Cloudflare IP items stay in one account-level list referenced by zone-level custom rules in the `http_request_firewall_custom` entry-point ruleset. A separate weekly tick replaces the decision map with a fresh `startup=true` LAPI stream snapshot.

**Tech Stack:** Go 1.22, `cloudflare-go` v0.119.0, `crowdsec` v1.6.3, `go-cs-bouncer` v0.0.14, Docker + GitHub Actions/GHCR.

**Spec:** `docs/superpowers/specs/2026-11-27-cloudflare-rulesets-and-ranked-lists-design.md`

## Global Constraints

- Cloudflare account has **1 custom list** and **10,000 total list items** (Free/Pro/Business); never create a second list.
- Existing list is named `crowdsec_block` (prefix `crowdsec`, action `block`); import it, do not recreate.
- WAF rules are **zone-level** only; account-level rulesets require Enterprise.
- Remove all legacy API calls: `Filters`, `FirewallRules`, `CreateFirewallRules`, `DeleteFirewallRules`, `UpdateFilters`, `DeleteFilters`.
- `cloudflare-go` pinned to **v0.119.0** (go 1.21 floor, compatible with project's go 1.22).
- Default refresh `5m`; default full resync `168h`; default capacity `10000`.
- Ranking defaults: `0day|zero.?day|cve-{{YEAR}}`=100, `exploit|rce|sqli|lfi|xxe|ssrf|webshell`=80, `bf|brute|credential|spray`=40, `scan|probe|crawl|bot`=10, default 20; `ban`=20, `captcha`/`js_challenge`=5; duration bonus 1/hour capped 20; `crowdsec`/`CAPI` origin=10, `cscli`/`lists`=0.
- Recency is a tiebreaker only: `Until - Duration`, then value ascending.
- Never write the GitHub push token or any API key into the repo.
- No local Go toolchain: run Go commands via `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go ...`.

## Review Focus

- **Existing full list on a 1-list account** → startup imports `crowdsec_block` and never calls `CreateIPList` when it exists; test in Task 4 (`TestImportExistingSingleList`).
- **More than 10k decisions with mixed severity** → only the top 10,000 by score are kept, 0-day/CVE above brute-force above scanning; tests in Task 2 (`TestRankOrdersBySeverity`) and Task 4 (`TestReconcileCapsAtCapacity`).
- **Duplicate value with conflicting types, then one copy expires** → highest-scoring copy kept; value removed only when no active copy remains; tests in Task 2 (`TestRankDedupKeepsHighestScore`) and Task 4 (`TestApplyStreamDeltaExpiry`).
- **Invalid ranking config** (bad regex, negative score, non-positive intervals) → `NewConfig` fails with a field-specific error; test in Task 1 (`TestNewConfigRankingValidation`).
- **Zone entry-point ruleset contains user rules** → our update replaces only rules whose description starts with `CrowdSec ` and preserves the rest; test in Task 5 (`TestUpdateEntrypointRulesetPreservesUserRules`).
- Weekly resync replaces state wholesale rather than appending: Task 6 (`TestApplyFullSnapshot`).

---

### Task 1: Config schema, defaults and validation

**Files:**
- Modify: `pkg/cfg/config.go`
- Test: `pkg/cfg/config_test.go`

**Interfaces:**
- Consumes: existing `bouncerConfig`, `NewConfig(reader io.Reader) (*bouncerConfig, error)`.
- Produces: `RankingPattern{Name, Pattern string; Score int}`, `RankingConfig{Patterns []RankingPattern; DefaultScore int; TypeScores map[string]int; DurationBonusPerHour, DurationBonusMax int; OriginScores map[string]int}`, `CloudflareConfig.FullResyncFrequency time.Duration`, `CloudflareConfig.Ranking RankingConfig`, `AccountConfig.IPListName string`, unexported `defaultRankingConfig() RankingConfig`.

- [ ] **Step 1: Add failing tests** to `pkg/cfg/config_test.go`:

```go
func TestNewConfigRankingDefaults(t *testing.T) {
    c, err := NewConfig(strings.NewReader(minimalConfigYAML))
    require.NoError(t, err)
    require.Equal(t, 5*time.Minute, c.CloudflareConfig.UpdateFrequency)
    require.Equal(t, 168*time.Hour, c.CloudflareConfig.FullResyncFrequency)
    require.Len(t, c.CloudflareConfig.Ranking.Patterns, 4)
    require.Equal(t, 100, c.CloudflareConfig.Ranking.Patterns[0].Score)
    require.Contains(t, c.CloudflareConfig.Ranking.Patterns[0].Pattern, strconv.Itoa(time.Now().Year()))
    require.Equal(t, 20, c.CloudflareConfig.Ranking.TypeScores["ban"])
    require.Equal(t, "crowdsec_block", c.CloudflareConfig.Accounts[0].IPListName)
}

func TestNewConfigRankingValidation(t *testing.T) {
    // table: bad regex pattern, negative score, update_frequency: 0s,
    // full_resync_frequency: 0s; each must return err containing the field name
}

func TestNewConfigRankingPatternsOverride(t *testing.T) {
    // YAML supplies one pattern; result has exactly that one, defaults for
    // type_scores / origin_scores remain; patterns: [] keeps defaults
}
```

- [ ] **Step 2: Run tests** — `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go test ./pkg/cfg/ -run TestNewConfigRanking -v`. Expected: FAIL (types/fields undefined).

- [ ] **Step 3: Implement** in `pkg/cfg/config.go`: add the types and fields above; seed `config.CloudflareConfig.Ranking = defaultRankingConfig()` and intervals before `yaml.Unmarshal` so partial configs inherit defaults; expand `{{YEAR}}` in patterns via `strings.ReplaceAll(..., "{{YEAR}}", strconv.Itoa(time.Now().Year()))`; default `IPListName` from `IPListPrefix + "_block"`; validate regexes (`regexp.Compile`), non-negative scores, positive intervals, non-empty pattern names. Apply the same defaults in `ConfigTokens` so generated configs include the new keys. Keep all existing validation intact.

- [ ] **Step 4: Run tests** — same command. Expected: PASS, plus existing `pkg/cfg` tests pass.

- [ ] **Step 5: Commit** — `git add pkg/cfg/config.go pkg/cfg/config_test.go && git commit -m "feat(cfg): add ranking config with defaults and validation"`

---

### Task 2: Severity ranking package

**Files:**
- Create: `pkg/rank/rank.go`
- Test: `pkg/rank/rank_test.go`

**Interfaces:**
- Consumes: `github.com/crowdsecurity/crowdsec/pkg/models`, `cfg.RankingConfig`.
- Produces:
  - `type Ranker struct{...}`
  - `func New(cfg cfg.RankingConfig) (*Ranker, error)` (compiles patterns; `{{YEAR}}` already expanded by cfg)
  - `func (r *Ranker) Score(d *models.Decision, now time.Time) int`
  - `func (r *Ranker) StartTime(d *models.Decision) time.Time`
  - `func (r *Ranker) Rank(decisions []*models.Decision, now time.Time) []*models.Decision` — filters simulated/expired, dedupes by value keeping highest score, sorts by score desc → start desc → value asc.

- [ ] **Step 1: Write failing tests** in `pkg/rank/rank_test.go`:

```go
func TestRankOrdersBySeverity(t *testing.T) {
    // decisions: scanning "scan", ban "ssh-bf", "cve-2026-1234" captcha,
    // "0day-exploit" ban. Expect 0day first, CVE second, bf third, scan last.
}
func TestRankDedupKeepsHighestScore(t *testing.T) {
    // same normalized value with a low-score ban and high-score captcha:
    // require.Len(result, 1) and result[0].Type == "captcha"
}
func TestRankDropsSimulatedAndExpired(t *testing.T) { ... }
func TestStartTimeFromUntilMinusDuration(t *testing.T) {
    // Until "2026-11-27T12:00:00Z", Duration "4h" → 08:00Z
}
```

- [ ] **Step 2: Run tests** — `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go test ./pkg/rank/ -v`. Expected: FAIL (package absent).

- [ ] **Step 3: Implement** `pkg/rank/rank.go`. `Score` = first matching pattern score (default score if none) + `TypeScores[*d.Type]` + `min(DurationBonusPerHour*hours, DurationBonusMax)` + `OriginScores[*d.Origin]`, where `hours = int(now.Sub(start).Hours())` computed from `Until - Duration` clamped to >= 0. Use `time.ParseDuration` on `*d.Duration`. Never mutate decisions.

- [ ] **Step 4: Run tests** — same command. Expected: PASS.

- [ ] **Step 5: Commit** — `git add pkg/rank && git commit -m "feat(rank): severity-based decision ranking"`

---

### Task 3: Cloudflare client interface — drop legacy API, add Rulesets

**Files:**
- Modify: `pkg/cf/cloudflare.go` (interface block at lines ~169-185, deleted helper functions at ~265-387, ~427-437, ~439-466)
- Test: `pkg/cf/cloudflare_test.go` (mock methods at lines ~33-168)

**Interfaces:**
- Consumes: `cloudflare-go` v0.119.0 `ResourceContainer`, `Ruleset`, `RulesetRule`, `UpdateEntrypointRulesetParams`.
- Produces: `cloudflareAPI` with methods: existing `ListZones`, `CreateIPList`, `DeleteIPList`, `ListIPLists`, `ReplaceIPListItemsAsync`, `GetIPListBulkOperation`, `ListIPListItems`, `DeleteIPListItems`, plus
  - `GetEntrypointRuleset(ctx context.Context, rc *cloudflare.ResourceContainer, phase string) (cloudflare.Ruleset, error)`
  - `UpdateEntrypointRuleset(ctx context.Context, rc *cloudflare.ResourceContainer, params cloudflare.UpdateEntrypointRulesetParams) (cloudflare.Ruleset, error)`

- [ ] **Step 1: Write failing test** in `pkg/cf/cloudflare_test.go`:

```go
func TestNoLegacyFirewallAPIInInterface(t *testing.T) {
    // static assertion: var _ cloudflareAPI = (*mockCloudflareAPI)(nil)
    // mock implements only the new interface; compile fails until legacy
    // methods are removed from the interface.
}
```

- [ ] **Step 2: Run tests** — `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go test ./pkg/cf/ -run TestNoLegacy -v`. Expected: FAIL (mock missing new methods / interface still has legacy methods).

- [ ] **Step 3: Implement** the new interface, add the two ruleset methods to the mock with in-memory `Ruleset` storage, delete legacy methods and their helper functions (`deleteRulesContainingStringFromZoneIDs`, `importRulesAndFiltersForExistingIPList`, `deleteFiltersContainingStringFromZoneIDs`, `removeIPListDependencies`, `cachedFirewallRules`, `FirewallRulesByZoneID`, `ZoneLock`, `FilterIDByZoneID`), and remove `ZoneLock` wiring in `cmd/root.go` later (Task 6).

- [ ] **Step 4: Run tests** — same command. Expected: PASS.

- [ ] **Step 5: Commit** — `git add pkg/cf && git commit -m "refactor(cf): replace legacy firewall API with Rulesets API"`

---

### Task 4: Single-list state and ranked reconciliation

**Files:**
- Modify: `pkg/cf/cloudflare.go`
- Test: `pkg/cf/cloudflare_test.go`

**Interfaces:**
- Consumes: `rank.Ranker` from Task 2, `cloudflareAPI` from Task 3.
- Produces on `CloudflareWorker`:
  - `IPListState IPListState`
  - `ActiveDecisions map[string]map[string]*models.Decision` (value → decision-key → decision)
  - `Ranker *rank.Ranker`
  - `func decisionKey(d *models.Decision) string`
  - `func (w *CloudflareWorker) ApplyStream(s *models.DecisionsStreamResponse)`
  - `func (w *CloudflareWorker) ApplyFullSnapshot(s *models.DecisionsStreamResponse)`
  - `func (w *CloudflareWorker) Reconcile() error` — prune expired, rank IPs, replace list items when changed, refresh country/AS sets, then call Task 5's rule update.

- [ ] **Step 1: Write failing tests** in `pkg/cf/cloudflare_test.go`:

```go
func TestImportExistingSingleList(t *testing.T) {
    // mock ListIPLists returns crowdsec_block; SetUpCloudflareResources must
    // not call CreateIPList (counter stays 0) and w.IPListState.IPList.Name == "crowdsec_block"
}
func TestReconcileCapsAtCapacity(t *testing.T) {
    // 10005 decisions: five "0day" (score 100), rest scanning (10);
    // capacity 10000. List items must be exactly 10000 and include all five 0day values.
}
func TestApplyStreamDeltaExpiry(t *testing.T) {
    // add ban+captcha for same IP; delete captcha; value remains with ban.
    // delete ban; value gone.
}
```

- [ ] **Step 2: Run tests** — `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go test ./pkg/cf/ -run 'TestImportExistingSingleList|TestReconcileCapsAtCapacity|TestApplyStreamDeltaExpiry' -v`. Expected: FAIL.

- [ ] **Step 3: Implement**: single list imported by name from `Account.IPListName`, created only if absent; `Init` builds `CFStateByAction` for configured actions, assigns each state's `IPListState.IPList` the worker's single list pointer (so `computeExpression` is unchanged), and sets `CurrExpr`; replace old `NewIPDecisions`/`Expired*`/`CollectLAPIStream`/`UpdateIPLists`/`Send*`/`Delete*Bans` with the active-map methods; keep normalization helpers and the empty-list mock-IP workaround in `ReplaceIPListItemsAsync`; keep `TotalAPICalls`/rate-limit wrapper. Reconcile only writes when the desired set differs from `IPSet`. Add Prometheus `RankingDroppedTotal` counter (incremented by the number trimmed at capacity) and `ListItems` gauge (set to `len(IPSet)`), alongside existing `TotalAPICalls`/`ResponseTime`.

- [ ] **Step 4: Run tests** — same command. Expected: PASS, and full `go test ./pkg/cf/` passes.

- [ ] **Step 5: Commit** — `git add pkg/cf && git commit -m "feat(cf): rank decisions into a single capacity-capped list"`

---

### Task 5: Ruleset rule reconciliation

**Files:**
- Modify: `pkg/cf/cloudflare.go`
- Test: `pkg/cf/cloudflare_test.go`

**Interfaces:**
- Consumes: `cloudflareAPI` ruleset methods, `CloudflareState.CurrExpr`.
- Produces: `func (w *CloudflareWorker) UpdateRules() error` — for each configured zone, `GetEntrypointRuleset(zone, "http_request_firewall_custom")`, keep rules whose `Description` does not start with `"CrowdSec "`, append one rule per configured action with `Action`, `Expression`, `Description = "CrowdSec "+action+" rule"`, then `UpdateEntrypointRuleset` only when the desired rules differ from current. Activation is implicit: rules live in the entry point directly.

- [ ] **Step 1: Write failing tests** in `pkg/cf/cloudflare_test.go`:

```go
func TestUpdateEntrypointRulesetPreservesUserRules(t *testing.T) {
    // mock entrypoint has one user rule ("my rule") and one stale CrowdSec rule.
    // After UpdateRules, user rule is unchanged, stale rule is gone, one
    // fresh CrowdSec rule per configured action exists, and no API write when
    // rules are already correct.
}
func TestUpdateRulesUsesRulesetsAPI(t *testing.T) {
    // assert no legacy FirewallRules/Filters mock methods are invoked
}
```

- [ ] **Step 2: Run tests** — `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go test ./pkg/cf/ -run 'TestUpdateEntrypointRulesetPreservesUserRules|TestUpdateRulesUsesRulesetsAPI' -v`. Expected: FAIL.

- [ ] **Step 3: Implement** `UpdateRules` as described; compare desired vs current by `(description, action, expression)` so no-op ticks make zero writes. Use `cloudflare.ZoneIdentifier(zone.ID)`.

- [ ] **Step 4: Run tests** — same command. Expected: PASS.

- [ ] **Step 5: Commit** — `git add pkg/cf && git commit -m "feat(cf): manage CrowdSec rules via Rulesets API"`

---

### Task 6: Wire the daemon loop, weekly resync, config samples and docs

**Files:**
- Modify: `cmd/root.go`, `pkg/cf/cloudflare.go` (`Run`, `Init`), `config/crowdsec-cloudflare-bouncer.yaml`, `config/crowdsec-cloudflare-bouncer-docker.yaml`, `README.md`
- Test: `pkg/cf/cloudflare_test.go`

**Interfaces:**
- Consumes: `CloudflareWorker.ApplyStream`, `ApplyFullSnapshot`, `Reconcile`, `cfg` intervals.
- Produces: `CloudflareWorker.ResyncStream chan *models.DecisionsStreamResponse` and `Run()` with a second ticker for full resync; root.go builds `apiclient.DecisionsStreamOpts` once and uses it for both the bouncer and the weekly `APIClient.Decisions.GetStream(ctx, opts with Startup=true)` broadcast.

- [ ] **Step 1: Write failing test** in `pkg/cf/cloudflare_test.go`:

```go
func TestApplyFullSnapshot(t *testing.T) {
    // seed ActiveDecisions with stale values, then ApplyFullSnapshot with two
    // decisions; require exactly those two values remain.
}
```

- [ ] **Step 2: Run tests** — `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go test ./pkg/cf/ -run TestApplyFullSnapshot -v`. Expected: FAIL.

- [ ] **Step 3: Implement**: remove `ZoneLock` wiring from root.go; create `ResyncStream` per account; add weekly goroutine that calls `GetStream` with `Startup=true` using shared opts and broadcasts to all workers; worker `Run` selects on `LAPIStream`, `ResyncStream`, refresh ticker (`UpdateFrequency`), and resync ticker (`FullResyncFrequency`), calling `Reconcile()` after each. Add new config keys with comments to both YAML samples; update README with migration notes (token permissions: Zone WAF Write / Lists Write / Account Rulesets Read; single-list quota; manual legacy-rule cleanup).

- [ ] **Step 4: Run tests** — `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go test ./... -v`. Expected: PASS.

- [ ] **Step 5: Commit** — `git add cmd pkg/cf config README.md && git commit -m "feat: wire ranked sync loop with weekly full resync"`

---

### Task 7: Container build workflow and publish

**Files:**
- Modify: `go.mod`, `go.sum`, `Dockerfile`
- Create: `.github/workflows/build-container.yml`

**Interfaces:**
- Consumes: all prior tasks; GitHub Actions `GITHUB_TOKEN`.
- Produces: image `ghcr.io/loukaniko85/cs-cloudflare-bouncer`, tags `latest` and `v*` versions.

- [ ] **Step 1: Bump dependency** — set `github.com/cloudflare/cloudflare-go v0.119.0` in `go.mod`; run `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go mod tidy` to update `go.sum`. Expected: no compile errors.

- [ ] **Step 2: Verify build and image** — `docker build -t cs-cloudflare-bouncer:test .`. Expected: image builds, binary runs `-version` via `docker run --rm cs-cloudflare-bouncer:test -version`.

- [ ] **Step 3: Add workflow** `.github/workflows/build-container.yml`: on push to `main` and tags `v*`, checkout, set up Docker Buildx, log in to GHCR with `GITHUB_TOKEN` (`packages: write`), run `docker build` with tag `ghcr.io/loukaniko85/cs-cloudflare-bouncer:${GITHUB_REF_NAME}` and `latest` on tags, push. Add a `go test ./...` step via `golang:1.22-alpine` container before build.

- [ ] **Step 4: Verify tests** — `docker run --rm -v "$PWD":/src -w /src golang:1.22-alpine go test ./...`. Expected: PASS.

- [ ] **Step 5: Commit and publish** — `git add go.mod go.sum Dockerfile .github/workflows/build-container.yml && git commit -m "build: bump cloudflare-go and add GHCR workflow"`, then add remote `https://github.com/loukaniko85/cs-cloudflare-bouncer.git` using the supplied token in the command only (never committed), `git push` to the default branch, and report the commit SHA / workflow URL.
