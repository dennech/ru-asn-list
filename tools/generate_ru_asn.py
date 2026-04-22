#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


SOURCE_URL = "https://stat.ripe.net/data/country-resource-list/data.json?resource=ru"
USER_AGENT = "ru-asn-list/1.0"
ATTEMPTS = 3
TIMEOUT_SECONDS = 20
LINE_RE = re.compile(r"^IP-ASN,[1-9][0-9]*$")

REPO_ROOT = Path(__file__).resolve().parent.parent
LIST_PATH = REPO_ROOT / "ru_asn.list"
META_PATH = REPO_ROOT / "ru_asn.meta.json"
SITE_DIR = REPO_ROOT / "site"
SITE_LIST_PATH = SITE_DIR / "ru_asn.list"
SITE_META_PATH = SITE_DIR / "ru_asn.meta.json"
SITE_INDEX_PATH = SITE_DIR / "index.html"
SITE_NOJEKYLL_PATH = SITE_DIR / ".nojekyll"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate and validate ru_asn.list from RIPEstat."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the existing ru_asn.list without downloading new data",
    )
    parser.add_argument(
        "--force-large-change",
        action="store_true",
        help="allow publishing when ASN count drops below 50%% of the previous value",
    )
    parser.add_argument(
        "--publish-pages",
        action="store_true",
        help="also generate site/ artifacts for GitHub Pages",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def fetch_payload() -> dict[str, Any]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    delay_seconds = 1.0
    errors: list[str] = []

    for attempt in range(1, ATTEMPTS + 1):
        try:
            request = urllib.request.Request(SOURCE_URL, headers=headers)
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                if getattr(response, "status", 200) != 200:
                    raise RuntimeError(f"unexpected HTTP status {response.status}")
                raw = response.read()
            return json.loads(raw.decode("utf-8"))
        except (
            OSError,
            RuntimeError,
            TimeoutError,
            ValueError,
            urllib.error.HTTPError,
            urllib.error.URLError,
        ) as exc:
            errors.append(f"attempt {attempt}: {exc}")
            if attempt == ATTEMPTS:
                break
            time.sleep(delay_seconds)
            delay_seconds *= 2

    raise RuntimeError(
        "failed to fetch RIPEstat data after retries: " + "; ".join(errors)
    )


def extract_asns(payload: dict[str, Any]) -> list[int]:
    resources = payload.get("data", {}).get("resources", {}).get("asn")
    if not isinstance(resources, list):
        raise ValueError("missing data.resources.asn list in source payload")

    values: list[int] = []
    for raw_value in resources:
        try:
            value = int(raw_value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid ASN value {raw_value!r}") from exc
        if value <= 0:
            raise ValueError(f"ASN must be positive, got {value}")
        values.append(value)

    unique_sorted = sorted(set(values))
    if not unique_sorted:
        raise ValueError("source ASN list is empty")
    return unique_sorted


def render_list_bytes(asns: list[int]) -> bytes:
    return "".join(f"IP-ASN,{asn}\n" for asn in asns).encode("utf-8")


def compute_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def build_meta(payload: dict[str, Any], list_bytes: bytes, asn_count: int) -> dict[str, Any]:
    query_time = payload.get("data", {}).get("query_time")
    if query_time in (None, ""):
        query_time = payload.get("query_time")

    meta: dict[str, Any] = {
        "country": "RU",
        "source_url": SOURCE_URL,
        "generated_at_utc": utc_now(),
        "asn_count": asn_count,
        "sha256": compute_sha256(list_bytes),
    }
    if query_time not in (None, ""):
        meta["query_time"] = query_time
        meta = {
            "country": meta["country"],
            "source_url": meta["source_url"],
            "query_time": meta["query_time"],
            "generated_at_utc": meta["generated_at_utc"],
            "asn_count": meta["asn_count"],
            "sha256": meta["sha256"],
        }
    return meta


def render_meta_bytes(meta: dict[str, Any]) -> bytes:
    return (json.dumps(meta, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def render_pages_index(meta: dict[str, Any]) -> bytes:
    title = "RU ASN List"
    generated_at = escape(str(meta["generated_at_utc"]))
    sha256 = escape(str(meta["sha256"]))
    asn_count = escape(str(meta["asn_count"]))
    body = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{title}</title>
    <style>
      :root {{
        color-scheme: light;
        font-family: "SF Mono", "Cascadia Code", Menlo, monospace;
      }}
      body {{
        margin: 0;
        background: #f5f7fb;
        color: #132033;
      }}
      main {{
        max-width: 760px;
        margin: 48px auto;
        padding: 32px;
        background: white;
        border-radius: 18px;
        box-shadow: 0 18px 50px rgba(19, 32, 51, 0.12);
      }}
      a {{
        color: #0b5bd3;
      }}
      code {{
        overflow-wrap: anywhere;
      }}
    </style>
  </head>
  <body>
    <main>
      <h1>{title}</h1>
      <p><a href="./ru_asn.list">Download ru_asn.list</a></p>
      <p>ASN count: <strong>{asn_count}</strong></p>
      <p>Generated at UTC: <strong>{generated_at}</strong></p>
      <p>SHA256: <code>{sha256}</code></p>
    </main>
  </body>
</html>
"""
    return body.encode("utf-8")


def validate_list_bytes(content: bytes, source_label: str) -> list[int]:
    if not content:
        raise ValueError(f"{source_label} is empty")
    if content.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{source_label} must be UTF-8 without BOM")
    if b"\r" in content:
        raise ValueError(f"{source_label} must use LF line endings")
    if not content.endswith(b"\n"):
        raise ValueError(f"{source_label} must end with a trailing newline")

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{source_label} is not valid UTF-8") from exc

    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    if not lines:
        raise ValueError(f"{source_label} has no entries")

    values: list[int] = []
    seen: set[int] = set()
    previous: int | None = None

    for index, line in enumerate(lines, start=1):
        if not LINE_RE.fullmatch(line):
            raise ValueError(
                f"{source_label} line {index} does not match IP-ASN,<number>: {line!r}"
            )
        value = int(line.split(",", 1)[1])
        if value in seen:
            raise ValueError(f"{source_label} contains duplicate ASN {value}")
        if previous is not None and value <= previous:
            raise ValueError(
                f"{source_label} is not strictly sorted numerically at line {index}"
            )
        seen.add(value)
        values.append(value)
        previous = value

    return values


def load_previous_count() -> int | None:
    if not META_PATH.exists():
        return None
    try:
        meta = json.loads(META_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"failed to read previous meta file: {exc}") from exc

    previous_count = meta.get("asn_count")
    if previous_count is None:
        return None
    if not isinstance(previous_count, int) or previous_count <= 0:
        raise RuntimeError("previous ru_asn.meta.json has invalid asn_count")
    return previous_count


def guard_large_change(new_count: int, force_large_change: bool) -> None:
    previous_count = load_previous_count()
    if previous_count is None:
        return
    if new_count * 2 < previous_count and not force_large_change:
        raise RuntimeError(
            "refusing to publish suspicious drop in ASN count: "
            f"previous={previous_count}, new={new_count}. "
            "Re-run with --force-large-change to override."
        )


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


def generate_outputs(force_large_change: bool, publish_pages: bool) -> dict[str, Any]:
    payload = fetch_payload()
    asns = extract_asns(payload)
    list_bytes = render_list_bytes(asns)
    validate_list_bytes(list_bytes, "generated ru_asn.list")
    guard_large_change(len(asns), force_large_change)

    meta = build_meta(payload, list_bytes, len(asns))
    meta_bytes = render_meta_bytes(meta)

    atomic_write(LIST_PATH, list_bytes)
    atomic_write(META_PATH, meta_bytes)

    if publish_pages:
        atomic_write(SITE_LIST_PATH, list_bytes)
        atomic_write(SITE_META_PATH, meta_bytes)
        atomic_write(SITE_INDEX_PATH, render_pages_index(meta))
        atomic_write(SITE_NOJEKYLL_PATH, b"")

    return meta


def check_existing_list() -> int:
    if not LIST_PATH.exists():
        raise FileNotFoundError(f"{LIST_PATH} does not exist")
    values = validate_list_bytes(LIST_PATH.read_bytes(), str(LIST_PATH))
    return len(values)


def main() -> int:
    args = parse_args()

    if args.check:
        count = check_existing_list()
        print(f"Validated {LIST_PATH.name}: {count} ASN entries")
        return 0

    meta = generate_outputs(
        force_large_change=args.force_large_change,
        publish_pages=args.publish_pages,
    )
    print(
        "Generated ru_asn.list with "
        f"{meta['asn_count']} ASN entries; sha256={meta['sha256']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
