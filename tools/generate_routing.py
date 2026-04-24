#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Iterable


OWNER = "dennech"
REPO = "ru-asn-list"
BRANCH = "main"
RAW_BASE_URL = f"https://raw.githubusercontent.com/{OWNER}/{REPO}/{BRANCH}"
ROUTING_URL = f"{RAW_BASE_URL}/routing.conf"
DIRECT_URL = f"{RAW_BASE_URL}/rules/direct.list"
PROXY_URL = f"{RAW_BASE_URL}/rules/proxy.list"

BASE_CONFIG_URL = (
    "https://raw.githubusercontent.com/misha-tgshv/shadowrocket-configuration-file/"
    "refs/heads/main/conf/sr_ru_basic.conf"
)

USER_AGENT = "ru-asn-list-routing/1.0"
ATTEMPTS = 3
TIMEOUT_SECONDS = 20

REPO_ROOT = Path(__file__).resolve().parent.parent
ROUTING_PATH = REPO_ROOT / "routing.conf"
META_PATH = REPO_ROOT / "routing.meta.json"
DIRECT_PATH = REPO_ROOT / "rules" / "direct.list"
PROXY_PATH = REPO_ROOT / "rules" / "proxy.list"

RULE_RE = re.compile(r"^[A-Z0-9-]+,.+")
TWITCH_MARKERS = (
    "twitch",
    "ttvnw",
    "jtvnw",
    "twitchcdn",
    "twitchsvc",
    "live-video",
    "ext-twitch",
    "rootonline",
)

GENERAL_KEYS = {
    "bypass-system",
    "ipv6",
    "prefer-ipv6",
    "private-ip-answer",
    "dns-direct-system",
    "dns-fallback-system",
    "dns-direct-fallback-proxy",
    "dns-server",
    "fallback-dns-server",
    "hijack-dns",
    "skip-proxy",
    "tun-excluded-routes",
    "always-real-ip",
    "icmp-auto-reply",
    "always-reject-url-rewrite",
    "udp-policy-not-supported-behaviour",
}

ALLOWED_RULE_PREFIXES = {
    "DOMAIN",
    "DOMAIN-KEYWORD",
    "DOMAIN-SUFFIX",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "USER-AGENT",
    "URL-REGEX",
}


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    mode: str = "shadowrocket"
    allowed_prefixes: frozenset[str] | None = None


DIRECT_SOURCE = Source(
    name="direct",
    url=(
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
        "rule/Shadowrocket/Twitch/Twitch.list"
    ),
)

PROXY_SOURCES = (
    Source(
        name="community",
        url=(
            "https://raw.githubusercontent.com/misha-tgshv/"
            "shadowrocket-configuration-file/main/rules/domains_community.list"
        ),
    ),
    Source(
        name="community-ip",
        url=(
            "https://raw.githubusercontent.com/misha-tgshv/"
            "shadowrocket-configuration-file/main/rules/domain_ips.list"
        ),
        mode="cidr",
    ),
    Source(
        name="whatsapp-cidr",
        url=(
            "https://raw.githubusercontent.com/HybridNetworks/whatsapp-cidr/"
            "refs/heads/main/WhatsApp/whatsapp_cidr_ipv4.list"
        ),
        mode="cidr",
    ),
    Source(
        name="telegram",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/Telegram/Telegram.list"
        ),
    ),
    Source(
        name="discord",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/Discord/Discord.list"
        ),
    ),
    Source(
        name="youtube",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/YouTube/YouTube.list"
        ),
    ),
    Source(
        name="twitter",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/Twitter/Twitter.list"
        ),
    ),
    Source(
        name="whatsapp",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/Whatsapp/Whatsapp.list"
        ),
    ),
    Source(
        name="facebook",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/Facebook/Facebook.list"
        ),
    ),
    Source(
        name="instagram",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/Instagram/Instagram.list"
        ),
    ),
    Source(
        name="openai",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/OpenAI/OpenAI.list"
        ),
    ),
    Source(
        name="paypal",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/PayPal/PayPal.list"
        ),
    ),
    Source(
        name="gemini",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/Gemini/Gemini.list"
        ),
    ),
    Source(
        name="cloudflare-domains",
        url=(
            "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
            "rule/Shadowrocket/Cloudflare/Cloudflare.list"
        ),
        allowed_prefixes=frozenset({"DOMAIN", "DOMAIN-KEYWORD", "DOMAIN-SUFFIX"}),
    ),
)

EXTRA_DIRECT_RULES = (
    "DOMAIN-SUFFIX,contribute.live-video.net",
    "DOMAIN-SUFFIX,ext-twitch.tv",
    "DOMAIN-SUFFIX,global-contribute.live-video.net",
    "DOMAIN-SUFFIX,jtvnw.net",
    "DOMAIN-SUFFIX,live-video.net",
    "DOMAIN-SUFFIX,ttvnw.net",
    "DOMAIN-SUFFIX,twitch.tv",
    "DOMAIN-SUFFIX,twitchcdn.net",
    "DOMAIN-SUFFIX,twitchsvc.net",
    "DOMAIN-KEYWORD,twitch",
    "DOMAIN-KEYWORD,ttvnw",
)

EXTRA_PROXY_RULES = (
    "DOMAIN-SUFFIX,accounts.google.com",
    "DOMAIN-SUFFIX,ai.google.dev",
    "DOMAIN-SUFFIX,aistudio.google.com",
    "DOMAIN-SUFFIX,apis.google.com",
    "DOMAIN-SUFFIX,clients1.google.com",
    "DOMAIN-SUFFIX,clients2.google.com",
    "DOMAIN-SUFFIX,clients3.google.com",
    "DOMAIN-SUFFIX,clients4.google.com",
    "DOMAIN-SUFFIX,clients5.google.com",
    "DOMAIN-SUFFIX,clients6.google.com",
    "DOMAIN-SUFFIX,chatgpt.com",
    "DOMAIN-SUFFIX,chatgpt.livekit.cloud",
    "DOMAIN-SUFFIX,fiverr-res.cloudinary.com",
    "DOMAIN-SUFFIX,fiverr.com",
    "DOMAIN-SUFFIX,fiverrcdn.com",
    "DOMAIN-SUFFIX,geolocation.googleapis.com",
    "DOMAIN-SUFFIX,generativelanguage.googleapis.com",
    "DOMAIN-SUFFIX,gemini.google.com",
    "DOMAIN-SUFFIX,generativeai.google",
    "DOMAIN-SUFFIX,ggpht.com",
    "DOMAIN-SUFFIX,googleapis.com",
    "DOMAIN-SUFFIX,googleusercontent.com",
    "DOMAIN-SUFFIX,gstatic.com",
    "DOMAIN-SUFFIX,gvt1.com",
    "DOMAIN-SUFFIX,gvt2.com",
    "DOMAIN-SUFFIX,locationhistory-pa.googleapis.com",
    "DOMAIN-SUFFIX,myaccount.google.com",
    "DOMAIN-SUFFIX,oauth2.googleapis.com",
    "DOMAIN-SUFFIX,oauthaccountmanager.googleapis.com",
    "DOMAIN-SUFFIX,ogs.google.com",
    "DOMAIN-SUFFIX,openai.com",
    "DOMAIN-SUFFIX,oaistatic.com",
    "DOMAIN-SUFFIX,oaiusercontent.com",
    "DOMAIN-SUFFIX,odesk.com",
    "DOMAIN-SUFFIX,paypal.com",
    "DOMAIN-SUFFIX,paypalobjects.com",
    "DOMAIN-SUFFIX,people-pa.googleapis.com",
    "DOMAIN-SUFFIX,people.googleapis.com",
    "DOMAIN-SUFFIX,semanticlocation-pa.googleapis.com",
    "DOMAIN-SUFFIX,signin.google.com",
    "DOMAIN-SUFFIX,upwork.com",
    "DOMAIN-SUFFIX,upworkcdn.com",
    "DOMAIN-SUFFIX,upworkstatic.com",
    "DOMAIN-SUFFIX,www.google.com",
    "DOMAIN-KEYWORD,chatgpt",
    "DOMAIN-KEYWORD,fiverr",
    "DOMAIN-KEYWORD,openai",
    "DOMAIN-KEYWORD,paypal",
    "DOMAIN-KEYWORD,upwork",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate routing.conf artifacts.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate existing routing.conf and rule lists without downloading data",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def fetch_text(url: str) -> str:
    delay_seconds = 1.0
    errors: list[str] = []
    headers = {"User-Agent": USER_AGENT, "Accept": "text/plain,*/*"}

    for attempt in range(1, ATTEMPTS + 1):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                if getattr(response, "status", 200) != 200:
                    raise RuntimeError(f"unexpected HTTP status {response.status}")
                return response.read().decode("utf-8")
        except (
            OSError,
            RuntimeError,
            TimeoutError,
            UnicodeDecodeError,
            urllib.error.HTTPError,
            urllib.error.URLError,
        ) as exc:
            errors.append(f"attempt {attempt}: {exc}")
            if attempt == ATTEMPTS:
                break
            time.sleep(delay_seconds)
            delay_seconds *= 2

    raise RuntimeError(f"failed to fetch {url}: " + "; ".join(errors))


def normalize_rule_line(line: str, source: Source) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if source.mode == "cidr" or "," not in line:
        return normalize_cidr_rule(line)

    if not RULE_RE.match(line):
        return None

    parts = [part.strip() for part in line.split(",")]
    prefix = parts[0].upper()
    if prefix not in ALLOWED_RULE_PREFIXES:
        return None
    if source.allowed_prefixes is not None and prefix not in source.allowed_prefixes:
        return None

    if prefix in {"IP-CIDR", "IP-CIDR6"} and len(parts) >= 2:
        return normalize_cidr_rule(parts[1])

    payload = ",".join(parts[1:]).strip()
    if not payload:
        return None
    return f"{prefix},{payload}"


def normalize_cidr_rule(value: str) -> str | None:
    value = value.strip()
    if not value or value.startswith("#"):
        return None
    if "," in value:
        value = value.split(",", 1)[0].strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    return f"IP-CIDR,{network.with_prefixlen},no-resolve"


def dedupe_preserve_order(rules: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for rule in rules:
        if rule not in seen:
            result.append(rule)
            seen.add(rule)
    return result


def source_rules(source: Source, text: str) -> list[str]:
    rules: list[str] = []
    for line in text.splitlines():
        rule = normalize_rule_line(line, source)
        if rule is not None:
            rules.append(rule)
    return rules


def rule_network(rule: str) -> ipaddress._BaseNetwork | None:
    parts = rule.split(",")
    if len(parts) < 2 or parts[0] not in {"IP-CIDR", "IP-CIDR6"}:
        return None
    try:
        return ipaddress.ip_network(parts[1], strict=False)
    except ValueError:
        return None


def is_twitch_related(rule: str, direct_networks: list[ipaddress._BaseNetwork]) -> bool:
    lower = rule.lower()
    if any(marker in lower for marker in TWITCH_MARKERS):
        return True
    network = rule_network(rule)
    return network is not None and any(network.overlaps(item) for item in direct_networks)


def render_rule_list(rules: list[str]) -> bytes:
    return ("\n".join(rules) + "\n").encode("utf-8")


def extract_general_settings(base_config: str) -> list[str]:
    settings: list[str] = ["[General]"]
    in_general = False
    for raw_line in base_config.splitlines():
        line = raw_line.strip()
        if line == "[General]":
            in_general = True
            continue
        if line.startswith("[") and line.endswith("]"):
            in_general = False
        if not in_general or not line or line.startswith("#") or "=" not in line:
            continue

        key = line.split("=", 1)[0].strip()
        if key in GENERAL_KEYS:
            settings.append(f"{key} = {clean_general_value(key, line.split('=', 1)[1])}")

    settings.append(f"update-url = {ROUTING_URL}")
    return settings


def clean_general_value(key: str, value: str) -> str:
    value = value.strip()
    if key == "dns-server":
        value = value.replace(
            "2001:4860:4860::88448.8.8.8",
            "2001:4860:4860::8844,8.8.8.8",
        )
        value = ",".join(part.strip() for part in value.split(",") if part.strip())
    return value


def render_config(base_config: str) -> bytes:
    lines = extract_general_settings(base_config)
    lines.extend(
        [
            "",
            "[Rule]",
            f"RULE-SET,{DIRECT_URL},DIRECT",
            f"RULE-SET,{PROXY_URL},PROXY",
            "FINAL,DIRECT",
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def render_meta(
    source_stats: list[dict[str, object]],
    routing_bytes: bytes,
    direct_bytes: bytes,
    proxy_bytes: bytes,
    direct_count: int,
    proxy_count: int,
) -> bytes:
    meta = {
        "generated_at_utc": utc_now(),
        "routing_url": ROUTING_URL,
        "direct_rule_count": direct_count,
        "proxy_rule_count": proxy_count,
        "sha256": {
            "routing.conf": sha256(routing_bytes),
            "rules/direct.list": sha256(direct_bytes),
            "rules/proxy.list": sha256(proxy_bytes),
        },
        "sources": source_stats,
    }
    return (json.dumps(meta, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def load_existing_meta() -> dict[str, object] | None:
    if not META_PATH.exists():
        return None
    try:
        return json.loads(META_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def maybe_preserve_meta(
    meta_bytes: bytes,
    routing_bytes: bytes,
    direct_bytes: bytes,
    proxy_bytes: bytes,
) -> bytes:
    existing = load_existing_meta()
    if existing is None:
        return meta_bytes
    existing_hashes = existing.get("sha256")
    expected_hashes = {
        "routing.conf": sha256(routing_bytes),
        "rules/direct.list": sha256(direct_bytes),
        "rules/proxy.list": sha256(proxy_bytes),
    }
    if existing_hashes == expected_hashes:
        return META_PATH.read_bytes()
    return meta_bytes


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == content:
        return

    temp_name: str | None = None
    try:
        with NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            delete=False,
            prefix=f".{path.name}.",
            suffix=".tmp",
        ) as temp_file:
            temp_file.write(content)
            temp_file.flush()
            os.fsync(temp_file.fileno())
            temp_name = temp_file.name
        os.replace(temp_name, path)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)


def build_artifacts() -> tuple[bytes, bytes, bytes, bytes]:
    base_config = fetch_text(BASE_CONFIG_URL)

    direct_text = fetch_text(DIRECT_SOURCE.url)
    direct_rules = source_rules(DIRECT_SOURCE, direct_text)
    direct_rules = dedupe_preserve_order([*direct_rules, *EXTRA_DIRECT_RULES])
    direct_networks = [
        network for rule in direct_rules if (network := rule_network(rule)) is not None
    ]

    proxy_rules: list[str] = []
    source_stats: list[dict[str, object]] = [
        {"name": "base", "url": BASE_CONFIG_URL},
        {"name": DIRECT_SOURCE.name, "url": DIRECT_SOURCE.url, "rule_count": len(direct_rules)},
    ]
    for source in PROXY_SOURCES:
        text = fetch_text(source.url)
        rules = source_rules(source, text)
        proxy_rules.extend(rules)
        source_stats.append(
            {"name": source.name, "url": source.url, "rule_count": len(rules)}
        )
    proxy_rules.extend(EXTRA_PROXY_RULES)
    source_stats.append({"name": "extra-proxy", "rule_count": len(EXTRA_PROXY_RULES)})

    proxy_rules = [
        rule for rule in dedupe_preserve_order(proxy_rules)
        if not is_twitch_related(rule, direct_networks)
    ]

    routing_bytes = render_config(base_config)
    direct_bytes = render_rule_list(direct_rules)
    proxy_bytes = render_rule_list(proxy_rules)
    validate_artifacts(routing_bytes, direct_bytes, proxy_bytes)
    meta_bytes = render_meta(
        source_stats,
        routing_bytes,
        direct_bytes,
        proxy_bytes,
        len(direct_rules),
        len(proxy_rules),
    )
    meta_bytes = maybe_preserve_meta(meta_bytes, routing_bytes, direct_bytes, proxy_bytes)
    return routing_bytes, direct_bytes, proxy_bytes, meta_bytes


def validate_rule_list(content: bytes, label: str) -> list[str]:
    if not content:
        raise ValueError(f"{label} is empty")
    if content.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{label} must be UTF-8 without BOM")
    if b"\r" in content:
        raise ValueError(f"{label} must use LF line endings")
    if not content.endswith(b"\n"):
        raise ValueError(f"{label} must end with a trailing newline")

    rules = content.decode("utf-8").splitlines()
    if not rules:
        raise ValueError(f"{label} has no rules")
    for index, rule in enumerate(rules, start=1):
        normalized = normalize_rule_line(rule, Source(name=label, url="local"))
        if normalized != rule:
            raise ValueError(f"{label} line {index} is invalid: {rule!r}")
    if len(rules) != len(set(rules)):
        raise ValueError(f"{label} contains duplicate rules")
    return rules


def validate_artifacts(
    routing_bytes: bytes,
    direct_bytes: bytes,
    proxy_bytes: bytes,
) -> None:
    direct_rules = validate_rule_list(direct_bytes, "rules/direct.list")
    proxy_rules = validate_rule_list(proxy_bytes, "rules/proxy.list")

    required_direct = (
        "twitch.tv",
        "ttvnw.net",
        "jtvnw.net",
        "live-video.net",
        "contribute.live-video.net",
    )
    direct_text = "\n".join(direct_rules).lower()
    missing = [value for value in required_direct if value not in direct_text]
    if missing:
        raise ValueError("rules/direct.list is missing: " + ", ".join(missing))

    required_proxy = (
        "paypal.com",
        "fiverr.com",
        "upwork.com",
        "gemini.google.com",
        "chatgpt.com",
        "accounts.google.com",
        "geolocation.googleapis.com",
        "www.google.com",
    )
    proxy_text = "\n".join(proxy_rules).lower()
    missing_proxy = [value for value in required_proxy if value not in proxy_text]
    if missing_proxy:
        raise ValueError("rules/proxy.list is missing: " + ", ".join(missing_proxy))

    direct_networks = [
        network for rule in direct_rules if (network := rule_network(rule)) is not None
    ]
    blocked_proxy = [
        rule for rule in proxy_rules if is_twitch_related(rule, direct_networks)
    ]
    if blocked_proxy:
        raise ValueError("rules/proxy.list contains direct-related rules")

    routing = routing_bytes.decode("utf-8")
    direct_rule = f"RULE-SET,{DIRECT_URL},DIRECT"
    proxy_rule = f"RULE-SET,{PROXY_URL},PROXY"
    if direct_rule not in routing or proxy_rule not in routing:
        raise ValueError("routing.conf is missing required rule-set lines")
    if routing.index(direct_rule) > routing.index(proxy_rule):
        raise ValueError("routing.conf must place direct rules before proxy rules")
    if not routing.rstrip().endswith("FINAL,DIRECT"):
        raise ValueError("routing.conf must end with FINAL,DIRECT")
    if "include =" in routing:
        raise ValueError("routing.conf must not include external configs")


def write_artifacts() -> None:
    routing_bytes, direct_bytes, proxy_bytes, meta_bytes = build_artifacts()
    atomic_write(ROUTING_PATH, routing_bytes)
    atomic_write(DIRECT_PATH, direct_bytes)
    atomic_write(PROXY_PATH, proxy_bytes)
    atomic_write(META_PATH, meta_bytes)
    print(
        "Generated routing.conf: "
        f"direct={len(direct_bytes.decode('utf-8').splitlines())}, "
        f"proxy={len(proxy_bytes.decode('utf-8').splitlines())}"
    )


def check_existing() -> None:
    for path in (ROUTING_PATH, DIRECT_PATH, PROXY_PATH):
        if not path.exists():
            raise FileNotFoundError(f"{path} does not exist")
    validate_artifacts(
        ROUTING_PATH.read_bytes(),
        DIRECT_PATH.read_bytes(),
        PROXY_PATH.read_bytes(),
    )
    print("Validated routing.conf and rule lists")


def main() -> int:
    args = parse_args()
    if args.check:
        check_existing()
    else:
        write_artifacts()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
