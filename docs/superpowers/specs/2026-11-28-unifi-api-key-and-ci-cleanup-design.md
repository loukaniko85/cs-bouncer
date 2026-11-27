# Design: Official UniFi API-key sync + CI and metadata cleanup

Date: 2026-11-28
Status: awaiting approval

## Intent and why

The current UniFi integration uses the unofficial controller session API
(`/api/auth/login`, `TOKEN` cookie, CSRF token, legacy `rest/firewallgroup`). It
works on UDM Pro but is tied to local accounts and the legacy firewall-group
API. Ubiquiti's current official Network API (v11) provides API-key access to
IPv4 Traffic Matching Lists and works across UniFi OS consoles, not only UDM
Pro. The owner also wants CI reduced to the Docker-container workflow and repo
metadata/docs updated to describe a generic CrowdSec bouncer rather than a
Cloudflare-only project.

## Goals

- Replace UniFi session auth with `X-API-Key` auth and official
  `/v1/sites/{siteId}/traffic-matching-lists` create/update endpoints.
- Support any UniFi OS console (UDM/UDM SE, CloudKey with UniFi OS, UOS Server)
  through the local API, plus the cloud connector (`api.ui.com`).
- Keep the bouncer managing only the IPv4 list; the owner creates the firewall
  policy once that references the list. No policy creation/mutation.
- Remove all non-container GitHub Actions workflows; keep tests + image
  build/push + digest reporting in `build-container.yml`.
- Update repo About description, README title/scope, config comments, and
  image naming/docs for `cs-bouncer`.

## Non-goals

- No UniFi-only mode in this release: ranking is currently produced by the
  Cloudflare workers, so at least one Cloudflare account must be configured.
  A direct CrowdSec-to-UniFi pipeline is a follow-up feature.
- No support for legacy self-hosted UniFi Network controllers that do not
  expose the official API-key integration endpoint.
- No IPv6 Traffic Matching List (Cloudflare side still supports IPv6).
- No UniFi firewall policy creation/reordering.
- No migration of existing legacy address groups; the new official list has a
  distinct default name (`CrowdSec_Blocklist`).

## Constraints

- Official API contract: `developer.ui.com/network/v11.0.97/openapi.json`.
- Local base: `{url}/proxy/network/integration/v1`.
- Cloud base: `https://api.ui.com/v1/connector/consoles/{console_id}/proxy/network/integration/v1`.
- Auth header: `X-API-Key` on every request. Keys are generated at
  `unifi.ui.com`; no username/password, cookies, or CSRF.
- List create/update payload:
  `{name, type:"IPV4_ADDRESSES", items:[{type:"IP_ADDRESS"|"SUBNET", value:"..."}]}`.
  `items` has `minItems: 1`. An empty desired set is represented by one
  reserved documentation-only placeholder (`192.0.2.1`) so stale attacker
  entries are removed without blocking real traffic.
- Sites endpoint `GET /v1/sites` returns `{id,name,internalReference}`; resolve
  configured site name to UUID when needed.
- Keep `insecure_skip_verify` for local self-signed certificates.
- CI must still run `go test ./...` before building/pushing the image.

## Approaches

1. **Official API-key Traffic Matching List (chosen)** — generic UniFi OS
   support, stable contract, no local credentials. Cost: legacy self-hosted
   controllers are not supported; empty lists use a documentation-only
   placeholder because the API requires at least one item.
2. **Keep session-cookie legacy groups** — broadest controller coverage but
   violates the owner's API-key requirement and remains UDM/legacy-specific.
3. **Support both auth modes** — API key preferred, session fallback. Most
   compatible but doubles attack surface and maintenance for a legacy path
   the owner does not want.

Chosen: **1**.

## Decided design

### Config migration

```yaml
unifi:
  enabled: false
  mode: local                 # local | cloud
  url: https://10.0.24.1      # local UniFi OS console
  console_id: <console-id>    # required only for mode: cloud
  api_key: ${UNIFI_API_KEY}
  # api_key_file: /run/secrets/unifi_api_key
  site: default               # site name or internal reference; resolved via /v1/sites
  list_name: CrowdSec_Blocklist
  max_items: 10000
  insecure_skip_verify: false
  ca_file: /path/to/unifi-ca.pem # optional; for private/self-signed CA
  allow_insecure_http: false
  update_frequency: 5m
```

- Remove `username`, `password`, `password_file`, `group_name`.
- `api_key` and `api_key_file` are mutually exclusive; exactly one required
  when enabled.
- Keep `site` name resolution for portability; cache the resolved UUID.

### Client (`pkg/unifi`)

- `New(config)` builds `http.Client` with `httplimit.Default` and optional TLS
  skip; no login function.
- `do(ctx, method, path, body, out)` sets `X-API-Key`, encodes/decodes JSON,
  checks status, and returns structured errors without credentials.
- `resolveSite(ctx)` calls `GET /v1/sites`, matches `site` against `name` or
  `internalReference`, returns UUID; `SyncGroup` calls it once and caches it.
- `SyncGroup(ctx, ips)`:
  1. filter/normalize/dedupe IPv4 members;
  2. if empty: substitute `192.0.2.1` as a documentation-only placeholder,
     log zero effective members, and continue;
  3. GET traffic-matching-lists, find by `list_name`;
  4. POST create or PUT `/traffic-matching-lists/{id}` with the official
     payload; metrics use existing names for dashboard compatibility.

### CI

- Delete `.github/workflows/*.yml/.yaml` except `build-container.yml`.
- Keep build-container's test step, Buildx, GHCR login, build/push, digest
  summary, and job output.
- Publish `ghcr.io/loukaniko85/cs-bouncer:<ref>` and `:latest`; also tag the
  legacy `ghcr.io/loukaniko85/cs-cloudflare-bouncer` name for one transition
  release so existing deployments keep pulling.

### Metadata and docs

- GitHub About: `CrowdSec bouncer for Cloudflare and UniFi with severity-ranked blocklists`.
- README title/scope: `CrowdSec Bouncer (Cloudflare + UniFi)`; replace UDM
  language with UniFi OS / cloud connector; document official API-key setup,
  Traffic Matching List policy reference, CI reduction, and image migration.
- Keep Go module path and binary/config paths unchanged for backward
  compatibility; repo and image names carry the new `cs-bouncer` branding.

### Tests

- `httptest` asserts `X-API-Key` on every request and asserts no login endpoint
  is called.
- Local/cloud base URL tests; site resolution by name/internal reference;
  create/update list payload; IPv4/IP address/subnet mapping; empty-list
  placeholder; pagination; API-key header and error paths;
  401/403 errors; metrics unchanged.

### Left to builder

- Exact site-name matching precedence (name first, then internalReference).
- Whether to cache the resolved site UUID permanently or re-resolve on 404.
- Update repo About via GitHub API after push, with the supplied token used
  per-command only.
