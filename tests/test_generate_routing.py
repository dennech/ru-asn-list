from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import generate_routing as routing


class GenerateRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        root = Path(temp_dir.name)
        paths = patch.multiple(
            routing,
            ROUTING_PATH=root / "routing.conf",
            META_PATH=root / "routing.meta.json",
            DIRECT_PATH=root / "rules" / "direct.list",
            PROXY_PATH=root / "rules" / "proxy.list",
        )
        paths.start()
        self.addCleanup(paths.stop)
        self.paths = (routing.ROUTING_PATH, routing.DIRECT_PATH, routing.PROXY_PATH)
        self.sources = (routing.DIRECT_SOURCE, *routing.PROXY_SOURCES)
        self.responses = {routing.BASE_CONFIG_URL: "[General]\nipv6 = false\n"}
        for source in self.sources:
            if source.mode == "cidr":
                lines = [f"192.0.2.{number}/32" for number in range(4)]
            else:
                lines = [f"DOMAIN,rule{number}.{source.name}.example" for number in range(4)]
            self.responses[source.url] = "\n".join(lines) + "\n"

        urlopen = patch.object(routing.urllib.request, "urlopen", side_effect=self.respond)
        urlopen.start()
        self.addCleanup(urlopen.stop)

    def respond(self, request, *, timeout):
        return io.BytesIO(self.responses[request.full_url].encode("utf-8"))

    def snapshot(self):
        return [path.read_bytes() for path in (*self.paths, routing.META_PATH)]

    def test_rejects_any_empty_upstream_list_without_writing_artifacts(self) -> None:
        routing.write_artifacts()
        previous = self.snapshot()

        for source in self.sources:
            with self.subTest(source=source.name):
                original = self.responses[source.url]
                self.responses[source.url] = "# No rules\n"
                try:
                    with self.assertRaisesRegex(ValueError, f"{source.name}.*no usable rules"):
                        routing.write_artifacts()
                    self.assertEqual(self.snapshot(), previous)
                finally:
                    self.responses[source.url] = original

    def test_rejects_large_drop_even_if_remaining_rule_is_repeated(self) -> None:
        routing.write_artifacts()
        previous = self.snapshot()

        for source in (routing.DIRECT_SOURCE, routing.PROXY_SOURCES[0]):
            with self.subTest(source=source.name):
                original = self.responses[source.url]
                self.responses[source.url] = (original.splitlines()[0] + "\n") * 4
                try:
                    with self.assertRaisesRegex(ValueError, f"{source.name}.*4 to 1"):
                        routing.write_artifacts()
                    self.assertEqual(self.snapshot(), previous)
                finally:
                    self.responses[source.url] = original

    def test_updates_source_counts_when_output_lists_are_unchanged(self) -> None:
        routing.write_artifacts()
        previous = self.snapshot()
        community = routing.PROXY_SOURCES[0]
        telegram = next(source for source in routing.PROXY_SOURCES if source.name == "telegram")
        self.responses[telegram.url] += self.responses[community.url].splitlines()[0] + "\n"

        routing.write_artifacts()

        self.assertEqual(self.snapshot()[:-1], previous[:-1])
        meta = json.loads(routing.META_PATH.read_bytes())
        counts = {source["name"]: source.get("rule_count") for source in meta["sources"]}
        self.assertEqual(counts[telegram.name], 5)

    def test_legacy_direct_count_does_not_include_local_rules_in_threshold(self) -> None:
        routing.write_artifacts()
        meta = json.loads(routing.META_PATH.read_bytes())
        direct = next(source for source in meta["sources"] if source["name"] == "direct")
        del direct["upstream_rule_count"]
        routing.META_PATH.write_text(json.dumps(meta), encoding="utf-8")

        url = routing.DIRECT_SOURCE.url
        self.responses[url] = "\n".join(self.responses[url].splitlines()[:2]) + "\n"
        routing.write_artifacts()

        meta = json.loads(routing.META_PATH.read_bytes())
        direct = next(source for source in meta["sources"] if source["name"] == "direct")
        self.assertEqual(direct["upstream_rule_count"], 2)
