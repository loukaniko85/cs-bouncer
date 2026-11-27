# Bouncer Production Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all Critical/Important audit findings, replace UniFi with the official API-key Traffic Matching List API, reduce CI to the Docker workflow, and update project metadata for `cs-bouncer`.

**Architecture:** One ordered LAPI poller owns startup/delta/weekly snapshot ordering and synchronously fans out to workers. Workers gate reconciliation on the first full snapshot. Cloudflare setup hydrates existing list state and computes effective account-wide capacity. UniFi is an independent API-key client using official paginated endpoints; its first sync waits for every account's first publication.

**Tech Stack:** Go 1.27, `cloudflare-go` v0.119.0, CrowdSec v1.6.3, `golang.org/x/time/rate`, Prometheus, YAML v3 strict decode, podman `golang:1.27-alpine`, GitHub Actions/GHCR.

**Specs:** `docs/superpowers/specs/2026-11-28-bouncer-production-hardening-design.md`, `docs/superpowers/specs/2026-11-28-unifi-api-key-and-ci-cleanup-design.md`

## Global Constraints

- No behavior regressions in ranking, Rulesets reconciliation or list naming.
- Ordered LAPI: startup full snapshot first, then deltas, weekly snapshot in same loop; no per-event goroutines.
- Workers skip `Reconcile` until first full snapshot; UniFi waits for every configured account's first publication.
- Cloudflare empty list uses direct empty replacement; existing items hydrated at setup.
- Strict YAML; require account/zone IDs and resolved secrets; API key or mTLS for LAPI.
- Official UniFi: `X-API-Key`, `/proxy/network/integration/v1`, paginated sites/lists, IPv4 Traffic Matching List, empty placeholder `192.0.2.1`.
- TLS verification on by default; optional `ca_file`; HTTP only with explicit `allow_insecure_http`.
- CI: only `build-container.yml`; tests + vet + gofmt + govulncheck + build/push + digest.
- Verify via podman `golang:1.27-alpine` with `API_KEY/CF_ACC_ID/CF_TOKEN/CF_ZONE_ID=test`.

## Review Focus

- Startup snapshot replaces persisted state and deleted-while-down decisions disappear: Task 5.
- Out-of-order/blocked event sends cannot lose or reorder decisions: Task 5.
- UniFi first sync cannot happen with only a subset of accounts: Task 6.
- Existing non-empty Cloudflare list + empty snapshot is cleared: Task 3.
- Official UniFi requests use API key and correct base/pagination: Task 8.

---

### Task 1: Strict config, TLS and validation

**Files:** `pkg/cfg/config.go`, `pkg/cfg/config_test.go`, sample YAMLs.

**Interfaces:** `NewConfig` uses `yaml.Decoder.KnownFields(true)`; new `CAFile`, `AllowInsecureHTTP`, `MaxCountryDecisions`, `MaxASDecisions`; LAPI auth accepts API key or cert+key; require accounts/IDs; reject unresolved `${...}`; capacity > 0.

- [ ] Write failing tests: unknown YAML key, no accounts, empty account/zone ID, unresolved env placeholder, negative capacity, missing LAPI auth, valid mTLS, UniFi TLS defaults.
- [ ] Run: `podman ... go test ./pkg/cfg/ -run 'TestConfigHardening' -v`; expect FAIL.
- [ ] Implement strict decode/validation/defaults; update sample YAMLs (`log_max_files`, metrics bind `0.0.0.0`, new fields).
- [ ] Run full suite; commit `feat(cfg): strict validation and TLS defaults`.

### Task 2: Input/state safety and simulated filtering

**Files:** `pkg/cf/state.go`, `pkg/cf/worker.go`, `pkg/cf/list.go`, `pkg/rank/rank.go`, tests.

**Interfaces:** `normalizeDecisionValue(string) (string,error)`; ingest skips invalid/simulated/null; state load skips nil decisions; scoped refresh defensive; symmetric ban tie-break.

- [ ] Failing tests: malformed colon value, null persisted decision, simulated COUNTRY/AS, equal-score ban/captcha both orders.
- [ ] Run tests; expect FAIL/panic.
- [ ] Implement guards and symmetric comparison; run full suite; commit `fix(cf): reject malformed and simulated decisions safely`.

### Task 3: Cloudflare reconciliation safety

**Files:** `pkg/cf/list.go`, `pkg/cf/worker.go`, `pkg/cf/api.go`, tests/mocks.

**Interfaces:** setup imports `ListIPListItems` into `IPSet`; direct empty replacement; effective capacity subtracts other IP list items; legacy-name mismatch fails setup; scoped sets validated/ranked/capped; metrics labelled by account.

- [ ] Failing tests: existing list + empty snapshot clears; other lists reduce capacity; legacy migration fails without deletion; empty replacement has no placeholder; COUNTRY/AS invalid values and caps; account-labelled metrics.
- [ ] Run tests; expect FAIL.
- [ ] Implement; run full suite; commit `fix(cf): safe list hydration, quota and scoped reconciliation`.

### Task 4: HTTP deadlines and per-host limiter

**Files:** `pkg/httplimit/limiter.go`, tests, `pkg/cf/api.go`, `pkg/cf/list.go`, `pkg/unifi/unifi.go`.

**Interfaces:** 30s client timeouts; context-aware bulk polling; per-host limiter map; recheck pause after token wait; honor full `Retry-After` (no shorter cap).

- [ ] Failing tests: per-host independence, pause extension while waiting token, cancellation, client timeout.
- [ ] Run tests; expect FAIL.
- [ ] Implement; run full suite; commit `fix(http): bounded requests and per-host rate limiting`.

### Task 5: Ordered LAPI poller and snapshot gating

**Files:** `cmd/root.go`, new `cmd/lapi.go`/tests, `pkg/cf/worker.go`/tests.

**Interfaces:** `runLAPIPoller(ctx, bouncer, streams, resyncFrequency)`; first `Startup=true` full snapshot, synchronous fan-out with ctx select, then deltas; weekly snapshot in same loop; worker `hasFullSnapshot` guards Reconcile.

- [ ] Failing tests: first event FullSnapshot replaces persisted state; out-of-order sequence rejected; blocked worker respects cancellation; no Reconcile before snapshot.
- [ ] Run tests; expect FAIL.
- [ ] Implement; stop using `StreamBouncer.Run`; run full suite; commit `fix(lapi): ordered snapshot and delta processing`.

### Task 6: All-account UniFi readiness

**Files:** `cmd/root.go`, `cmd/root_test.go`.

**Interfaces:** coordinator constructed with ordered account IDs; initial sync requires a publication from every account; later syncs use last-known-good sets.

- [ ] Failing test: two accounts, one publishes → Sync makes no client call; both publish → union sync.
- [ ] Run; expect FAIL.
- [ ] Implement; run full suite; commit `fix(unifi): require all accounts before first sync`.

### Task 7: CLI, secrets, logging and shutdown hygiene

**Files:** `cmd/root.go`, `cmd/root_test.go`, `scripts/install.sh`, config service, `docker/README.md`.

**Interfaces:** `-t` exits before workers/LAPI; `-T` redacts secrets; generated config 0600 atomic; expected signals return nil; API log rotates and logs body size; config generator index fix.

- [ ] Failing tests: `-t` no worker calls, redaction, ConfigTokens multi-token zone assignment, signal nil.
- [ ] Run; expect FAIL.
- [ ] Implement; run full suite; commit `fix(cli): safe config checks, redaction and shutdown`.

### Task 8: Official UniFi API-key client

**Files:** rewrite `pkg/unifi/unifi.go`/tests, `pkg/cfg/config.go`, `cmd/root.go`, sample YAMLs/README.

**Interfaces:** `New(config)`, `SyncGroup(ctx, ips)`; `X-API-Key`; local/cloud base; paginated `/v1/sites` and `/v1/sites/{id}/traffic-matching-lists`; payload `IPV4_ADDRESSES` with IP_ADDRESS/SUBNET; placeholder when empty; metrics retained.

- [ ] Failing tests: API-key header/no login, local/cloud URL, site resolution, pagination, create/update payload, empty placeholder, 401/403.
- [ ] Run; expect FAIL.
- [ ] Implement; remove username/password/cookie/CSRF/group code; run full suite; commit `feat(unifi): official API-key traffic matching lists`.

### Task 9: Toolchain, dependencies and Docker-only CI

**Files:** `go.mod`, `go.sum`, `Dockerfile`, `.github/workflows/*`, `.github/workflows/build-container.yml`.

**Interfaces:** Go 1.27; patched modules; only build-container workflow; test/vet/gofmt/govulncheck/build/push/digest; publish `cs-bouncer` plus legacy alias for transition.

- [ ] Bump Go/deps; run `go mod tidy`, `govulncheck ./...`; resolve reachable vulnerabilities.
- [ ] Delete non-container workflows; update build-container with checks and tags.
- [ ] Run full verification + image build; commit `build: patched toolchain and Docker-only CI`.

### Task 10: Packaging, metadata and final publish

**Files:** `debian/control`, `rpm/SPECS/*.spec`, README/docker docs, repo About via GitHub API.

- [ ] Declare Go/Git/build dependencies in packaging.
- [ ] Update README title/scope, UniFi API-key setup, metrics, migration, image names; fix stale examples.
- [ ] Run gofmt, vet, govulncheck, tests, podman build.
- [ ] Commit; push fast-forward to `loukaniko85/cs-bouncer:main`; update GitHub About; confirm workflow success; report commit/digest.
