# LIKVID Blocklist Builder

A standalone, scheduled collector that builds a normalized hybrid IP/CIDR blocklist from public sources. It does not change the LIKVID VPN parser; the main repository can consume the generated `dist/blocked_cidrs.txt` later.

## Sources

Configured in `config/sources.json`:

1. `antifilter.download` — `allyouneed.lst`
2. `Russia Blocked IPs` — `ip.txt` and its `manifest.json`
3. `BlockedIn` — API v3 `/ips/`

The sources have different meanings and reliability. The combined file is an **aggregated signal**, not proof that every address is blocked by RKN or that a proxy will fail. Do not use the broad aggregated list blindly without considering false positives.

## Output files

- `dist/blocked_cidrs.txt` — one normalized IP/CIDR per line, deduplicated and collapsed within each address family.
- `dist/source_cidrs/<source>.txt` — normalized list per source, for auditing and future source weighting.
- `dist/records.jsonl` — provenance records; one network per line with the sources that reported it.
- `dist/manifest.json` — timestamp, counts, SHA-256 hashes, source statuses and URLs.
- `dist/report.json` — parse and validation statistics.

## Run locally

Requires Python 3.11+ and only the standard library.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
python -m blocklist_builder --config config/sources.json
```

Or, without installing:

```powershell
python -m blocklist_builder --config config/sources.json
```

By default, cache is stored under `data/cache/`; generated files are written to `dist/`.

## Safety behavior

- HTTPS requests use certificate validation; redirects and response sizes are bounded.
- No domains are resolved into IPs. DNS resolution of a domain can create false positives and transient results; domain matching is a separate future feature.
- Invalid entries, multicast, private, loopback, link-local and other non-global ranges are excluded.
- Extremely broad networks are rejected as suspicious.
- A source's newly downloaded list is not accepted if it is empty, too small, malformed, or drops too sharply versus its previous good version.
- If a source fails, its last known-good cache is used. On a first run, at least 2 of the 3 configured sources must pass validation; otherwise the build fails and does not publish a combined list.
- Writes use temporary files and atomic replacement.
- `manifest.json` records provenance; `blocked_cidrs.txt` alone does not retain per-source provenance.

## Updating

GitHub Actions runs every 6 hours and can also be started manually. The workflow commits changed `dist/` and cache files back to the repository. Configure repository Actions permissions to **Read and write permissions**.

## Important limitation

This first version is the **standalone collection/normalization repository**, not yet integrated with LIKVID VPN. Before using the combined list to reject proxy configurations, we'll implement the consumer in the main repository and decide how to treat single-source vs multi-source matches.
