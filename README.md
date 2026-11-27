<p align="center">
<img src="https://github.com/crowdsecurity/cs-cloudflare-bouncer/raw/main/docs/assets/crowdsec_cloudfare.png" alt="CrowdSec" title="CrowdSec" width="280" height="300" />
</p>
<p align="center">
<img src="https://img.shields.io/badge/build-pass-green">
<img src="https://img.shields.io/badge/tests-pass-green">
</p>
<p align="center">
&#x1F4A0; <a href="https://hub.crowdsec.net">Hub</a>
&#128172; <a href="https://discourse.crowdsec.net">Discourse </a>
</p>

# CrowdSec Bouncer (Cloudflare + UniFi)

A bouncer for Cloudflare.

## How does it work

A bouncer that syncs CrowdSec decisions to Cloudflare and UniFi using severity-ranked blocklists. Supports multi-account / multi-zone Cloudflare setups and IPv4 IP, range, country and AS decisions.

## Ranked IP list and refresh cadence

The bouncer maintains **one IP list per account** (default `wafblocklist`) and
keeps it under Cloudflare's 10,000-item quota. When there are more decisions
than slots, decisions are scored by scenario severity — 0-day / current-year
CVE first, then exploits, brute-force and scanning — with ban type, decision
age and trusted origin as modifiers. Recency is only a tiebreaker. Scores
are derived from decision data, so ordering survives a container restart.

`cloudflare_config.update_frequency` (default `5m`) controls how often the list
and rules are reconciled. `cloudflare_config.full_resync_frequency` (default
`168h`, weekly) replaces the in-memory decision set with a fresh LAPI snapshot
to heal any drift.

The `ranking` block in the config is fully tunable; a `{{YEAR}}` token in a
pattern is expanded to the current year. An invalid regex or negative score
fails config validation at startup.

## UniFi sync (optional, official API key)

Set `unifi.enabled: true` and configure a UniFi OS console (`mode: local`) or
the cloud connector (`mode: cloud`). Generate an API key at `unifi.ui.com` and
provide it via `api_key` or `api_key_file`. On each `unifi.update_frequency`
tick (default `5m`) the bouncer creates or replaces one IPv4 **Traffic Matching
List** with the same ranked blocklist used for Cloudflare. Only IPv4 addresses
and CIDRs are written; `/32` is collapsed to a bare address, and the list is
capped at `max_items` (10,000).

Create one firewall policy **once** in UniFi Network whose source references the
`CrowdSec_Blocklist` Traffic Matching List and whose action is Block. The
bouncer only manages list membership — it never creates or modifies policies.
This works across UniFi OS consoles, not only UDM Pro. Legacy self-hosted
controllers without the official API-key integration endpoint are not
supported.

TLS verification is on by default. For a private/self-signed CA, set `ca_file`;
use `insecure_skip_verify: true` only as an explicit last resort. Plain HTTP
requires `allow_insecure_http: true`.

## Inspecting the blocklist and secrets from files

`-dump` prints the ranked top-N IPs that would be written, one per line,
without contacting Cloudflare or UniFi:

```sh
crowdsec-cloudflare-bouncer -c /etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml -dump
```

`state_file` (default disabled) persists the active decision set per account;
use an `{account}` token in the path, e.g.
`state_file: /var/lib/cs-cloudflare-bouncer/state_{account}.json`.

Sensitive values can be read from mounted files instead of inline YAML:
`crowdsec_lapi_key_file`, `token_file` under an account, and
`unifi.api_key_file`. Setting both a value and its `_file` variant is a
config error.

## Pinning the container image

`:latest` is convenient but mutable. Each successful `build-container` workflow
run prints the pushed image digest in its job summary. For production, pin that
digest instead:

```yaml
image: ghcr.io/loukaniko85/cs-cloudflare-bouncer@<full digest from workflow summary>
```

## Migration notes

This version uses Cloudflare's **Rulesets API** for WAF rules; the legacy
Firewall Rules API is no longer called and would fail with error 10020.
CrowdSec rules are managed in each zone's `http_request_firewall_custom`
entry-point ruleset and are identified by the `CrowdSec ` description prefix —
other rules in that ruleset are preserved.

Cloudflare limits lists that look CrowdSec-managed (name `crowdsec_*` or "IP list by crowdsec" description) to **one bulk item update every 24 hours**. The bouncer uses a neutral list name so frequent updates work; on startup it removes the legacy `crowdsec_block` list and its rules and creates the replacement automatically.

Required Cloudflare token permissions: Zone WAF Read/Write, Account Rulesets Read/Write (or Account WAF Read/Write), and Account Filter Lists Edit.
Legacy Firewall Rules/Filters created by older versions
cannot be deleted through the deprecated API; remove them manually in the
Cloudflare dashboard if they are still present.

# Documentation

Please follow the [official documentation](https://docs.crowdsec.net/docs/bouncers/cloudflare).