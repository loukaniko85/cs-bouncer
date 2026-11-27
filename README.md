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

# CrowdSec Cloudflare Bouncer

A bouncer for Cloudflare.

## How does it work

A bouncer that syncs the decisions made by CrowdSec with CloudFlare's firewall. Manages multi user, multi account, multi zone setup. Supports IP, Country and AS scoped decisions.

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

## UniFi Dream Machine Pro sync (optional)

Set `unifi.enabled: true` and fill in the UDM Pro URL, site, and a dedicated
local account. On each `unifi.update_frequency` tick (default `5m`) the bouncer
replaces the members of one IPv4 address group with the same ranked blocklist
used for Cloudflare. Only IPv4 addresses and CIDRs are written; `/32` is
collapsed to a bare address, and the group is capped at `max_items` (10,000).

You create the firewall rule **once** in UniFi Network: Settings → Routing &
Firewall → Firewall, a WAN IN / traffic rule whose source is the
`CrowdSec_Block` address group and whose action is Drop. The bouncer only
manages group membership — it never creates or modifies rules.

UniFi's controller API is unofficial and session-based; the bouncer logs in
with the cookie/CSRF flow and re-authenticates on 401. Failures are logged and
retried on the next tick, and never stop Cloudflare updates. Use a dedicated
local UniFi user, and pass the password via `${UNIFI_PASSWORD}` rather than
storing it in plain text.

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
`unifi.password_file`. Setting both a value and its `_file` variant is a
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