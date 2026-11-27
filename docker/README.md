# cs-bouncer container

The container synces CrowdSec decisions to Cloudflare and optionally to a
UniFi Traffic Matching List. It ranks decisions by severity and keeps the most
relevant entries within the configured capacity.

## Run

```bash
docker run -d --name wafblocklist \
  -v "$PWD/crowdsec-cloudflare-bouncer.yaml:/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml:ro" \
  -p 2112:2112 \
  ghcr.io/loukaniko85/cs-bouncer:latest
```

The legacy image name `ghcr.io/loukaniko85/cs-cloudflare-bouncer:latest` is
still published during the transition. New deployments should use
`ghcr.io/loukaniko85/cs-bouncer`.

## Configuration

See the root README and `config/crowdsec-cloudflare-bouncer-docker.yaml`.
Important points:

- `crowdsec_lapi_url` must be reachable from the container.
- Cloudflare requires at least one account and zone, a token with Zone WAF,
  Account Rulesets and Account Filter Lists permissions, and a neutral
  `ip_list_name` (default `wafblocklist`).
- UniFi is disabled by default. Enable it with an official API key generated at
  `unifi.ui.com`; create one firewall policy referencing the
  `CrowdSec_Blocklist` Traffic Matching List.
- Metrics listen on `0.0.0.0:2112` in the container sample.
- Secrets can be supplied via `${ENV}` or `_file` keys backed by Docker secrets.

## Helpers

Generate Cloudflare config (comma-separated tokens):

```bash
docker run --rm ghcr.io/loukaniko85/cs-bouncer:latest \
  -g '<TOKEN_1>,<TOKEN_2>' > cfg.yaml
```

Create Cloudflare lists/rules and exit:

```bash
docker run --rm \
  -v "$PWD/cfg.yaml:/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml:ro" \
  ghcr.io/loukaniko85/cs-bouncer:latest -s
```

Delete bouncer-managed Cloudflare rules/lists and exit:

```bash
docker run --rm \
  -v "$PWD/cfg.yaml:/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml:ro" \
  ghcr.io/loukaniko85/cs-bouncer:latest -d
```

Validate config without contacting Cloudflare or UniFi:

```bash
docker run --rm \
  -v "$PWD/cfg.yaml:/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml:ro" \
  ghcr.io/loukaniko85/cs-bouncer:latest -t
```
