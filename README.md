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

The bouncer maintains **one IP list per account** (default `crowdsec_block`) and
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

## Migration notes

This version uses Cloudflare's **Rulesets API** for WAF rules; the legacy
Firewall Rules API is no longer called and would fail with error 10020.
CrowdSec rules are managed in each zone's `http_request_firewall_custom`
entry-point ruleset and are identified by the `CrowdSec ` description prefix —
other rules in that ruleset are preserved.

Required Cloudflare token permissions: Zone WAF Write and Lists Write.
Legacy Firewall Rules/Filters created by older versions
cannot be deleted through the deprecated API; remove them manually in the
Cloudflare dashboard if they are still present.

# Documentation

Please follow the [official documentation](https://docs.crowdsec.net/docs/bouncers/cloudflare).