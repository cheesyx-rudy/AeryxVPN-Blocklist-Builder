from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

TOKEN_RE = re.compile(
    r"(?<![0-9A-Fa-f:.])"
    r"(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
    r"|[0-9A-Fa-f:]{2,}(?:/\d{1,3})?"
    r")"
    r"(?![0-9A-Fa-f:.])"
)
PRIVATE_OR_SPECIAL = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("2001:db8::/32"),
)


class BuildError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def fetch(url: str, timeout: int, max_bytes: int, user_agent: str) -> bytes:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise BuildError(f"Only HTTPS sources are allowed: {url}")
    request = Request(url, headers={"User-Agent": user_agent, "Accept": "*/*"})
    try:
        with urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            if urlparse(final_url).scheme != "https":
                raise BuildError(f"Redirected to a non-HTTPS URL: {final_url}")
            status = getattr(response, "status", 200)
            if status < 200 or status >= 300:
                raise BuildError(f"HTTP status {status}")
            declared = response.headers.get("Content-Length")
            if declared and int(declared) > max_bytes:
                raise BuildError(f"Response too large ({declared} bytes)")
            data = response.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise BuildError(f"Response exceeds {max_bytes} bytes")
            return data
    except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
        raise BuildError(f"Download failed: {exc}") from exc


def recursively_collect_strings(value: Any, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, list):
        for item in value:
            recursively_collect_strings(item, out)
    elif isinstance(value, dict):
        for key, item in value.items():
            # API fields named URL or domain are deliberately not used to resolve domains.
            if isinstance(item, (str, list, dict)):
                recursively_collect_strings(item, out)


def parse_candidates(raw: bytes, fmt: str) -> tuple[set[str], dict[str, int]]:
    text = raw.decode("utf-8-sig", errors="replace")
    parse_texts = [text]
    if fmt == "auto":
        try:
            parsed = json.loads(text)
            strings: list[str] = []
            recursively_collect_strings(parsed, strings)
            parse_texts = strings
        except json.JSONDecodeError:
            pass

    networks: set[str] = set()
    stats = {"tokens_seen": 0, "invalid": 0, "non_global": 0, "too_broad": 0, "accepted": 0}
    for content in parse_texts:
        for match in TOKEN_RE.finditer(content):
            token = match.group(0).strip().strip("[](){}<>,;\"'")
            # A token must be a syntactically valid IP or CIDR, not an arbitrary hex string.
            if ":" not in token and "." not in token:
                continue
            stats["tokens_seen"] += 1
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError:
                stats["invalid"] += 1
                continue

            if network.version == 4 and network.prefixlen < 8:
                stats["too_broad"] += 1
                continue
            if network.version == 6 and network.prefixlen < 16:
                stats["too_broad"] += 1
                continue
            if any(network.version == special.version and network.overlaps(special)
                   for special in PRIVATE_OR_SPECIAL):
                # Avoid filtering proxy endpoints because a source included a non-public range.
                stats["non_global"] += 1
                continue
            if not network.network_address.is_global:
                stats["non_global"] += 1
                continue
            networks.add(network.with_prefixlen)
    stats["accepted"] = len(networks)
    return networks, stats


def canonicalize(network_strings: set[str]) -> list[str]:
    parsed = [ipaddress.ip_network(item, strict=False) for item in network_strings]
    v4 = list(ipaddress.collapse_addresses(n for n in parsed if n.version == 4))
    v6 = list(ipaddress.collapse_addresses(n for n in parsed if n.version == 6))
    return [n.with_prefixlen for n in sorted(v4 + v6, key=lambda n: (n.version, int(n.network_address), n.prefixlen))]


def read_cache(path: Path) -> set[str] | None:
    if not path.exists():
        return None
    data = path.read_text(encoding="utf-8", errors="replace")
    result, _ = parse_candidates(data.encode("utf-8"), "text")
    return result if result else None


def validate_source(
    source: dict[str, Any], networks: set[str], stats: dict[str, int],
    minimum: int, max_drop_ratio: float, old: set[str] | None
) -> None:
    if len(networks) < minimum:
        raise BuildError(f"Too few accepted entries: {len(networks)} < {minimum}")
    if stats["tokens_seen"] and stats["invalid"] / stats["tokens_seen"] > 0.25:
        raise BuildError("Too many invalid IP/CIDR tokens")
    if old and len(networks) < int(len(old) * (1.0 - max_drop_ratio)):
        raise BuildError(f"Entry count dropped from {len(old)} to {len(networks)}; refusing update")


def build(config_path: Path, root: Path) -> dict[str, Any]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    cache_dir = root / "data" / "cache"
    dist_dir = root / "dist"
    timeout = int(config.get("timeout_seconds", 25))
    max_bytes = int(config.get("max_response_bytes", 20 * 1024 * 1024))
    minimum = int(config.get("minimum_entries_per_source", 100))
    max_drop = float(config.get("maximum_drop_ratio", 0.50))
    min_success = int(config.get("minimum_successful_sources", len(config["sources"])))
    user_agent = str(config.get("user_agent", "LIKVID-Blocklist-Builder/0.1"))

    source_results: dict[str, dict[str, Any]] = {}
    source_networks: dict[str, set[str]] = {}
    failures: list[str] = []

    for source in config["sources"]:
        sid = source["id"]
        cache_path = cache_dir / f"{sid}.txt"
        old = read_cache(cache_path)
        status = "downloaded"
        error = None
        try:
            raw = fetch(source["url"], timeout, max_bytes, user_agent)
            if source.get("manifest_url"):
                manifest_raw = fetch(source["manifest_url"], timeout, min(max_bytes, 2 * 1024 * 1024), user_agent)
                manifest = json.loads(manifest_raw.decode("utf-8"))
                expected_hash = manifest.get("sha256")
                if expected_hash and sha256_bytes(raw) != expected_hash:
                    raise BuildError("Source manifest SHA-256 does not match downloaded list")
            networks, stats = parse_candidates(raw, source.get("format", "auto"))
            validate_source(source, networks, stats, minimum, max_drop, old)
            canonical = canonicalize(networks)
            atomic_write(cache_path, ("\n".join(canonical) + "\n").encode("utf-8"))
        except Exception as exc:
            error = str(exc)
            if old:
                networks = old
                stats = {"tokens_seen": len(old), "invalid": 0, "non_global": 0, "too_broad": 0, "accepted": len(old)}
                status = "cached_fallback"
            else:
                failures.append(f"{sid}: {error}")
                source_results[sid] = {
                    "id": sid, "name": source.get("name", sid), "url": source["url"],
                    "status": "failed", "error": error, "entries": 0
                }
                continue

        source_networks[sid] = networks
        source_results[sid] = {
            "id": sid,
            "name": source.get("name", sid),
            "url": source["url"],
            "status": status,
            "entries": len(networks),
            "stats": stats,
            "error": error,
        }
        atomic_write(dist_dir / "source_cidrs" / f"{sid}.txt",
                     ("\n".join(canonicalize(networks)) + "\n").encode("utf-8"))

    if len(source_networks) < min_success:
        raise BuildError(
            f"Only {len(source_networks)} sources available; at least {min_success} required. "
            "Previous dist files are left untouched. " + "; ".join(failures)
        )

    provenance: dict[str, set[str]] = defaultdict(set)
    for sid, networks in source_networks.items():
        for network in networks:
            provenance[network].add(sid)

    # Build union after preserving source-level provenance.
    union = canonicalize(set().union(*source_networks.values()))
    records = []
    for network in sorted(provenance, key=lambda item: (ipaddress.ip_network(item).version,
                                                         int(ipaddress.ip_network(item).network_address),
                                                         ipaddress.ip_network(item).prefixlen)):
        records.append({
            "network": network,
            "sources": sorted(provenance[network]),
            "source_count": len(provenance[network]),
        })

    combined_bytes = ("\n".join(union) + "\n").encode("utf-8")
    records_bytes = "".join(json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n"
                            for row in records).encode("utf-8")
    report = {
        "generated_at": utc_now(),
        "source_count": len(source_networks),
        "sources": source_results,
        "unique_source_records": len(provenance),
        "combined_cidr_count": len(union),
        "record_count_before_collapse": len(records),
        "combined_sha256": sha256_bytes(combined_bytes),
        "notes": [
            "The aggregate is a multi-source signal, not proof of an official block.",
            "Domains are not resolved into IP addresses.",
            "Private and special-use address ranges and overly broad prefixes are excluded."
        ]
    }
    manifest = {
        "name": "LIKVID Hybrid Blocklist",
        "schema_version": 1,
        "generated_at": report["generated_at"],
        "description": "Normalized union of configured public IP/CIDR sources",
        "combined_file": "blocked_cidrs.txt",
        "combined_sha256": report["combined_sha256"],
        "combined_cidr_count": len(union),
        "source_count": len(source_networks),
        "sources": [
            {
                "id": sid,
                "name": item["name"],
                "url": item["url"],
                "status": item["status"],
                "entries": item["entries"],
                "error": item.get("error"),
            }
            for sid, item in sorted(source_results.items())
        ],
    }

    # Publish outputs only after all sources pass quality checks.
    atomic_write(dist_dir / "blocked_cidrs.txt", combined_bytes)
    atomic_write(dist_dir / "records.jsonl", records_bytes)
    atomic_write(dist_dir / "report.json", (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    atomic_write(dist_dir / "manifest.json", (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a normalized hybrid IP/CIDR blocklist.")
    parser.add_argument("--config", default="config/sources.json")
    parser.add_argument("--root", default=".")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = root / config_path
    try:
        report = build(config_path, root)
    except (BuildError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Build failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "ok",
        "generated_at": report["generated_at"],
        "combined_cidr_count": report["combined_cidr_count"],
        "source_count": report["source_count"],
        "sha256": report["combined_sha256"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
