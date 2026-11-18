from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "tools" / "generate_ru_asn.py"


def load_module():
    spec = importlib.util.spec_from_file_location("generate_ru_asn", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load generate_ru_asn.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GenerateRuAsnTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        root = Path(self.temp_dir.name)
        self.module.LIST_PATH = root / "ru_asn.list"
        self.module.META_PATH = root / "ru_asn.meta.json"
        self.module.SITE_DIR = root / "site"
        self.module.SITE_LIST_PATH = self.module.SITE_DIR / "ru_asn.list"
        self.module.SITE_META_PATH = self.module.SITE_DIR / "ru_asn.meta.json"
        self.module.SITE_INDEX_PATH = self.module.SITE_DIR / "index.html"
        self.module.SITE_NOJEKYLL_PATH = self.module.SITE_DIR / ".nojekyll"

    def test_generates_from_source_payload(self) -> None:
        self.module.fetch_payload = lambda: {
            "data": {
                "query_time": "2026-06-15T00:00:00",
                "resources": {"asn": ["64512", 64510, "64512"]},
            }
        }

        meta = self.module.generate_outputs(False, False)

        self.assertEqual(
            self.module.LIST_PATH.read_text(encoding="utf-8"),
            "IP-ASN,64510\nIP-ASN,64512\n",
        )
        self.assertEqual(meta["asn_count"], 2)
        self.assertEqual(meta["query_time"], "2026-06-15T00:00:00")
        self.assertNotIn("source_status", meta)

    def test_preserves_existing_valid_list_when_source_fetch_fails(self) -> None:
        existing_list = b"IP-ASN,64510\nIP-ASN,64512\n"
        self.module.LIST_PATH.write_bytes(existing_list)
        self.module.META_PATH.write_text(
            json.dumps(
                {
                    "country": "RU",
                    "source_url": self.module.SOURCE_URL,
                    "query_time": "2026-06-15T00:00:00",
                    "generated_at_utc": "2026-06-16T09:04:46Z",
                    "asn_count": 2,
                    "sha256": self.module.compute_sha256(existing_list),
                }
            )
            + "\n",
            encoding="utf-8",
        )

        source_error = getattr(self.module, "SourceFetchError", RuntimeError)

        def fail_fetch():
            raise source_error("failed to fetch RIPEstat data after retries")

        self.module.fetch_payload = fail_fetch

        meta = self.module.generate_outputs(False, True)

        self.assertEqual(self.module.LIST_PATH.read_bytes(), existing_list)
        self.assertEqual(self.module.SITE_LIST_PATH.read_bytes(), existing_list)
        self.assertEqual(meta["asn_count"], 2)
        self.assertEqual(meta["sha256"], self.module.compute_sha256(existing_list))
        self.assertEqual(meta["query_time"], "2026-06-15T00:00:00")
        self.assertEqual(meta["source_status"], "fallback_existing")
        self.assertEqual(meta["source_error"], "fetch_failed_after_retries")

    def test_refreshes_metadata_after_recovery_with_unchanged_asns(self) -> None:
        payload = {
            "data": {
                "query_time": "2026-06-15T00:00:00",
                "resources": {"asn": [64510, 64512]},
            }
        }

        with patch.object(self.module.urllib.request, "urlopen") as urlopen:
            urlopen.return_value = io.BytesIO(json.dumps(payload).encode("utf-8"))
            self.module.generate_outputs(False, False)
            existing_list = self.module.LIST_PATH.read_bytes()

            urlopen.side_effect = urllib.error.HTTPError(
                self.module.SOURCE_URL, 503, "Service Unavailable", None, None
            )
            with patch.object(self.module.time, "sleep"):
                self.module.generate_outputs(False, False)
            self.assertEqual(self.module.LIST_PATH.read_bytes(), existing_list)
            fallback = json.loads(self.module.META_PATH.read_text(encoding="utf-8"))
            self.assertEqual(fallback["source_status"], "fallback_existing")

            payload["data"]["query_time"] = "2026-06-16T00:00:00"
            urlopen.side_effect = None
            urlopen.return_value = io.BytesIO(json.dumps(payload).encode("utf-8"))
            self.module.generate_outputs(False, False)

        self.assertEqual(self.module.LIST_PATH.read_bytes(), existing_list)
        recovered = json.loads(self.module.META_PATH.read_text(encoding="utf-8"))
        self.assertNotIn("source_status", recovered)
        self.assertNotIn("source_error", recovered)
        self.assertEqual(recovered["query_time"], "2026-06-16T00:00:00")

    def test_fetch_failure_without_existing_list_fails_closed(self) -> None:
        source_error = getattr(self.module, "SourceFetchError", RuntimeError)

        def fail_fetch():
            raise source_error("failed to fetch RIPEstat data after retries")

        self.module.fetch_payload = fail_fetch

        with self.assertRaisesRegex(RuntimeError, "no existing ru_asn.list"):
            self.module.generate_outputs(False, False)

    def test_fetch_failure_with_invalid_existing_list_fails_closed(self) -> None:
        self.module.LIST_PATH.write_text(
            "IP-ASN,64512\nIP-ASN,64510\n",
            encoding="utf-8",
        )

        source_error = getattr(self.module, "SourceFetchError", RuntimeError)

        def fail_fetch():
            raise source_error("failed to fetch RIPEstat data after retries")

        self.module.fetch_payload = fail_fetch

        with self.assertRaisesRegex(ValueError, "not strictly sorted"):
            self.module.generate_outputs(False, False)


if __name__ == "__main__":
    unittest.main()
