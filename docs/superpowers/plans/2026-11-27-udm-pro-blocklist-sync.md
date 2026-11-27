# UDM Pro Blocklist Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Push the severity-ranked IP blocklist produced by the bouncer into an IPv4 address group on a UniFi Dream Machine Pro.

**Architecture:** A shared coordinator collects each Cloudflare worker's ranked IPs after ranking (before any Cloudflare write) and, on its own 5-minute ticker, calls a UniFi client that logs in with cookie+CSRF and creates or replaces one address group. UniFi failures never stop Cloudflare reconciliation.

**Tech Stack:** Go 1.22, `net/http`, `encoding/json`, `context`, `sync`, Prometheus client, podman + `golang:1.22-alpine` for verification, GHCR workflow for publishing.

**Spec:** `docs/superpowers/specs/2026-11-27-udm-pro-blocklist-sync-design.md`

## Global Constraints

- UniFi disabled unless `unifi.enabled: true`; default `site=default`, `group_name=CrowdSec_Block`, `max_items=10000`, `update_frequency=5m`, `insecure_skip_verify=true`.
- UDM Pro paths: login `POST {url}/api/auth/login`; API `{url}/proxy/network/api/s/{site}/rest/firewallgroup` and `/{_id}`.
- Every controller request carries `Cookie: TOKEN=...` and `X-CSRF-Token: ...` from login; on HTTP 401 re-login once and retry.
- Group payload: `{name, group_type:"address-group", group_members:[...], site_id, _id (PUT only)}`; response envelope `{meta:{rc:"ok"}, data:[...]}`.
- Members: IPv4 addresses/CIDRs only; `/32` becomes a bare IP; dedupe; cap at `max_items` **after** filtering; preserve ranked order; no sorting.
- No UniFi firewall rules/policies are created; no IPv6 groups.
- Credentials never logged. Verify with `podman run ... golang:1.22-alpine go test ./...` (Docker socket is unavailable; use podman and `API_KEY/CF_*` env vars).

## Review Focus

- Multiple Cloudflare accounts → one union group, no last-writer-wins: tests in Task 4 (`TestCoordinatorMergesAccounts`) and Task 5 wiring.
- IPv6 / `/32` / duplicate members → filtered before PUT, cap after filtering: Task 3 (`TestPrepareMembers`).
- Empty desired list → PUT with empty `group_members`; if rejected, log and keep old: Task 3 (`TestSyncGroupEmptyMembers`).
- Cloudflare failure/cooldown must not stall UniFi → publish happens before CF writes: Task 4 (`TestReconcilePublishesBeforeCloudflareError`).
- Session expiry → 401 triggers one re-login and retry: Task 2 (`TestSyncReloginOn401`).

---

### Task 1: Config schema, defaults and validation

**Files:**
- Modify: `pkg/cfg/config.go`
- Test: `pkg/cfg/config_test.go`

**Interfaces:**
- Consumes: `bouncerConfig`, `NewConfig(reader io.Reader) (*bouncerConfig, error)`.
- Produces: `UnifiConfig{Enabled bool; URL, Site, Username, Password, GroupName string; MaxItems int; InsecureSkipVerify bool; UpdateFrequency time.Duration}` with yaml tags `enabled,url,site,username,password,group_name,max_items,insecure_skip_verify,update_frequency`; field `bouncerConfig.Unifi UnifiConfig yaml:"unifi"`; defaults seeded before unmarshal.

- [ ] **Step 1: Write failing tests** in `pkg/cfg/config_test.go`:

```go
func TestNewConfigUnifiDefaults(t *testing.T) {
    // minimal config without unifi block: Enabled false, Site "default",
    // GroupName "CrowdSec_Block", MaxItems 10000, UpdateFrequency 5m,
    // InsecureSkipVerify true.
}
func TestNewConfigUnifiValidation(t *testing.T) {
    // enabled:true with missing url / username / password, max_items:0,
    // update_frequency:0s → err containing the field name.
}
func TestNewConfigUnifiEnabled(t *testing.T) {
    // enabled:true with url/user/pass → values preserved; password from
    // ${UNIFI_PASSWORD} expands via existing csstring.StrictExpand.
}
```

- [ ] **Step 2: Run tests** — `podman run --rm -e API_KEY=test -e CF_ACC_ID=test -e CF_TOKEN=test -e CF_ZONE_ID=test -e UNIFI_PASSWORD=secret -v "$PWD":/src -w /src docker.io/library/golang:1.22-alpine go test ./pkg/cfg/ -run TestNewConfigUnifi -v`. Expected: FAIL (undefined fields).

- [ ] **Step 3: Implement** in `pkg/cfg/config.go`: add types/field; seed defaults in `NewConfig` before `yaml.Unmarshal`; validate only when `Enabled`, requiring URL/username/password, `MaxItems > 0`, `UpdateFrequency > 0`; set the same defaults in `ConfigTokens`. Keep all existing validation intact.

- [ ] **Step 4: Run tests** — same command. Expected: PASS, plus existing `pkg/cfg` tests pass.

- [ ] **Step 5: Commit** — `git add pkg/cfg && git commit -m "feat(cfg): add UniFi blocklist sync config"`

---

### Task 2: UniFi client authentication

**Files:**
- Create: `pkg/unifi/unifi.go`
- Test: `pkg/unifi/unifi_test.go`

**Interfaces:**
- Consumes: `cfg.UnifiConfig`.
- Produces:
  - `type Client struct{...}`
  - `func New(config cfg.UnifiConfig) *Client`
  - `func (c *Client) login(ctx context.Context) error` (unexported; stores cookie + CSRF)
  - `func (c *Client) do(ctx context.Context, method, path string, body any, out any) error` (unexported; applies headers, re-logins once on 401)

- [ ] **Step 1: Write failing tests** in `pkg/unifi/unifi_test.go` using `httptest.NewTLSServer`:

```go
func TestLoginStoresCookieAndCSRF(t *testing.T) {
    // server asserts POST /api/auth/login JSON username/password, responds
    // Set-Cookie TOKEN=abc and X-CSRF-Token: csrf123; c.login succeeds.
}
func TestDoReloginOn401(t *testing.T) {
    // first GET returns 401, second (after re-login) returns 200;
    // require.Equal(t, 2, loginCount) and request headers contain both tokens.
}
func TestDoFailsWhenLoginFails(t *testing.T) { ... }
```

- [ ] **Step 2: Run tests** — `podman run --rm -v "$PWD":/src -w /src docker.io/library/golang:1.22-alpine go test ./pkg/unifi/ -v`. Expected: FAIL (package absent).

- [ ] **Step 3: Implement** `pkg/unifi/unifi.go`: `http.Client` with `TLSClientConfig.InsecureSkipVerify` from config; `login` posts JSON to `/api/auth/login`, parses `Set-Cookie` for `TOKEN` and the `X-CSRF-Token` response header; `do` marshals body, sets `Cookie`, `X-CSRF-Token`, `Content-Type`, checks status, unmarshals into `out`; on 401 calls `login` once then retries. Never include credentials in errors or logs.

- [ ] **Step 4: Run tests** — same command. Expected: PASS.

- [ ] **Step 5: Commit** — `git add pkg/unifi && git commit -m "feat(unifi): authenticated controller client"`

---

### Task 3: Group create/update, member preparation and metrics

**Files:**
- Modify: `pkg/unifi/unifi.go`
- Test: `pkg/unifi/unifi_test.go`

**Interfaces:**
- Consumes: client `do` from Task 2.
- Produces:
  - `func prepareMembers(ips []string, maxItems int) []string` (unexported)
  - `func (c *Client) SyncGroup(ctx context.Context, members []string) error` — GET groups, find by `c.config.GroupName`, POST or PUT, decode `{meta:{rc:"ok"},data:[...]}`
  - Prometheus `SyncTotal`, `SyncFailures`, `GroupMembers` in `pkg/unifi`.

- [ ] **Step 1: Write failing tests** in `pkg/unifi/unifi_test.go`:

```go
func TestPrepareMembers(t *testing.T) {
    // input: "1.2.3.4", "1.2.3.4/32", "2001:db8::/64", "5.6.7.0/24", dup "1.2.3.4"
    // want: ["1.2.3.4", "5.6.7.0/24"]; MaxItems=1 → only "1.2.3.4".
}
func TestSyncGroupCreatesAndUpdates(t *testing.T) {
    // first GET returns empty data → POST with group_members, then GET returns
    // one group → next SyncGroup issues PUT to /rest/firewallgroup/<_id>.
}
func TestSyncGroupEmptyMembers(t *testing.T) {
    // members [] → PUT with "group_members":[]; on 400 the error is returned
    // and no placeholder IP is written.
}
func TestSyncGroupRejectsNonOkMeta(t *testing.T) { ... }
```

- [ ] **Step 2: Run tests** — `podman run --rm -v "$PWD":/src -w /src docker.io/library/golang:1.22-alpine go test ./pkg/unifi/ -run 'TestPrepareMembers|TestSyncGroup' -v`. Expected: FAIL.

- [ ] **Step 3: Implement**: `prepareMembers` uses `net.ParseIP`/`net.ParseCIDR`; strips `/32`; drops IPv6; dedupes; caps. `SyncGroup` GETs `/api/s/{site}/rest/firewallgroup`, matches name, builds payload with `site_id` from the found group or config site, POSTs/PUTs, checks `meta.rc == "ok"`, increments metrics and sets `GroupMembers` on success. On error increment `SyncFailures` and return a wrapped error.

- [ ] **Step 4: Run tests** — same command. Expected: PASS, full `go test ./...` green.

- [ ] **Step 5: Commit** — `git add pkg/unifi && git commit -m "feat(unifi): create and update IPv4 address group"`

---

### Task 4: Worker publishes ranked IPs before Cloudflare writes

**Files:**
- Modify: `pkg/cf/cloudflare.go`
- Test: `pkg/cf/cloudflare_test.go`

**Interfaces:**
- Consumes: `rank.Ranker` output in `Reconcile`.
- Produces: `type RankedBlocklistListener interface { Publish(accountID string, ips []string) }`; `CloudflareWorker.BlocklistListener RankedBlocklistListener`; `func (w *CloudflareWorker) publishRankedIPs(ranked []*models.Decision)` which converts to string values and calls `Publish` when non-nil.

- [ ] **Step 1: Write failing tests** in `pkg/cf/cloudflare_test.go`:

```go
type recordingListener struct{ accounts []string; ips [][]string }
func (r *recordingListener) Publish(account string, ips []string) { ... }

func TestReconcilePublishesRankedIPs(t *testing.T) {
    // worker with listener; ApplyFullSnapshot with IPs; Reconcile;
    // require listener received the ranked values.
}
func TestReconcilePublishesBeforeCloudflareError(t *testing.T) {
    // mock EntrypointErr set; Reconcile returns error but listener still got IPs.
}
```

- [ ] **Step 2: Run tests** — `podman run --rm -e API_KEY=test -e CF_ACC_ID=test -e CF_TOKEN=test -e CF_ZONE_ID=test -v "$PWD":/src -w /src docker.io/library/golang:1.22-alpine go test ./pkg/cf/ -run 'TestReconcilePublishes' -v`. Expected: FAIL.

- [ ] **Step 3: Implement**: add interface/field/method; call `publishRankedIPs(ranked)` immediately after the capacity trim and before `replaceListItems`. Ensure no listener = no-op. Do not change Cloudflare error behavior.

- [ ] **Step 4: Run tests** — same command. Expected: PASS, full suite green.

- [ ] **Step 5: Commit** — `git add pkg/cf && git commit -m "feat(cf): publish ranked blocklist to UniFi sink"`

---

### Task 5: Root wiring, shared coordinator, samples and docs

**Files:**
- Modify: `cmd/root.go`, `config/crowdsec-cloudflare-bouncer.yaml`, `config/crowdsec-cloudflare-bouncer-docker.yaml`, `README.md`
- Test: `cmd/root_test.go` (new; coordinator unit test)

**Interfaces:**
- Consumes: `unifi.Client`, `cf.RankedBlocklistListener`.
- Produces: unexported `blocklistCoordinator` in `cmd/root.go` with `Publish(accountID string, ips []string)` and `Sync(ctx context.Context) error`, guarded by `sync.Mutex`; union of account lists deduped in insertion order.

- [ ] **Step 1: Write failing test** `cmd/root_test.go`:

```go
func TestCoordinatorMergesAccounts(t *testing.T) {
    c := &blocklistCoordinator{}
    c.Publish("a", []string{"1.1.1.1", "2.2.2.2"})
    c.Publish("b", []string{"2.2.2.2", "3.3.3.3"})
    got := c.snapshot()
    require.Equal(t, []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, got)
}
```

- [ ] **Step 2: Run tests** — `podman run --rm -v "$PWD":/src -w /src docker.io/library/golang:1.22-alpine go test ./cmd/ -run TestCoordinatorMergesAccounts -v`. Expected: FAIL.

- [ ] **Step 3: Implement**: coordinator struct with mutex and `map[string][]string`; `snapshot()` returns deduped union preserving insertion order; `Sync` calls `client.SyncGroup(ctx, snapshot)`; in `Execute`, when `conf.Unifi.Enabled`, create client, shared coordinator, assign `worker.BlocklistListener = coordinator` for every worker, start a goroutine with `time.NewTicker(conf.Unifi.UpdateFrequency)` calling `coordinator.Sync(ctx)` and logging failures (non-fatal). Add config keys/comments to both sample YAMLs and a README section (one-time UI rule with source = `CrowdSec_Block` group).

- [ ] **Step 4: Run tests** — `podman run --rm -e API_KEY=test -e CF_ACC_ID=test -e CF_TOKEN=test -e CF_ZONE_ID=test -v "$PWD":/src -w /src docker.io/library/golang:1.22-alpine go test ./...`. Expected: PASS.

- [ ] **Step 5: Commit** — `git add cmd config README.md && git commit -m "feat: wire UniFi group sync into daemon"`

---

### Task 6: Verify, publish and push

**Files:** none new; verify existing.

- [ ] **Step 1: Full suite** — `podman run --rm -e API_KEY=test -e CF_ACC_ID=test -e CF_TOKEN=test -e CF_ZONE_ID=test -v "$PWD":/src -w /src docker.io/library/golang:1.22-alpine go test ./...`. Expected: PASS.

- [ ] **Step 2: Build image** — `podman build -t cs-cloudflare-bouncer:test .`. Expected: success; `podman run --rm cs-cloudflare-bouncer:test -version` prints version.

- [ ] **Step 3: Push** — push current branch as fast-forward to `main` of `loukaniko85/cs-cloudflare-bouncer` using the supplied token in the command only. Confirm workflow build succeeds via GitHub API and report commit SHA.
