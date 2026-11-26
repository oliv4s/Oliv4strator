"""Synthetic, offline program-policy regression tests; no network traffic."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import lab_bridge
import program_policy


class SyntheticProgramProfileTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        self.program = self.root / "programs" / "sample-program"
        self.program.mkdir(parents=True)
        source = b"Fictitious authorization and scope for offline tests only.\n"
        (self.program / "source.txt").write_bytes(source)
        policy = {
            "schema_version": "0.1-draft", "program_id": "sample-program",
            "name": "Sample synthetic program", "state": "draft_not_enforced",
            "default_decision": "deny",
            "source": {"raw_file": "source.txt", "raw_sha256": hashlib.sha256(source).hexdigest()},
            "web_assets": [
                {"id": "portal", "kind": "exact_host_set", "scheme": "https",
                 "hosts": ["portal.example.test"], "application_boundary": "all_routes"},
                {"id": "api", "kind": "exact_host_plus_subdomains", "scheme": "https",
                 "base_host": "api.example.test", "include_base_host": True,
                 "include_subdomains": True},
                {"id": "docs_children", "kind": "subdomains_only", "scheme": "https",
                 "base_host": "docs.example.test", "include_base_host": False,
                 "include_subdomains": True},
            ],
            "required_http_headers": {"user_agent_append": " -Sample-Offline-Test "},
        }
        (self.program / "policy.draft.json").write_text(json.dumps(policy))
        self.policy, self.digest = program_policy.load(self.root, "sample-program")

    def tearDown(self):
        self.folder.cleanup()

    def test_exact_and_subdomain_boundaries(self):
        good = {
            "https://portal.example.test/": "portal",
            "https://api.example.test/": "api",
            "https://v1.api.example.test/a": "api",
            "https://x.docs.example.test/": "docs_children",
        }
        for url, asset in good.items():
            with self.subTest(url=url):
                result = program_policy.evaluate(self.policy, url)
                self.assertEqual(result["decision"], "allow")
                self.assertEqual(result["matched_asset"], asset)
        bad = (
            "https://docs.example.test/", "https://other-portal.example.test/",
            "https://api.example.test.invalid/", "https://evilapi.example.test/",
            "http://api.example.test/", "https://api.example.test:8443/",
        )
        for url in bad:
            with self.subTest(url=url):
                self.assertEqual(program_policy.evaluate(self.policy, url)["decision"], "deny")

    def test_source_integrity(self):
        (self.program / "source.txt").write_text("Changed source")
        with self.assertRaisesRegex(ValueError, "texto fuente"):
            program_policy.load(self.root, "sample-program")

    def test_activation_and_http_header_offline(self):
        originals = {key: getattr(lab_bridge, key) for key in
                     ("ROOT", "SCOPE", "RUNS", "ARTIFACTS", "MEMORY", "ATTEMPTS")}
        try:
            lab_bridge.ROOT = self.root
            lab_bridge.SCOPE = self.root / "scope.json"
            lab_bridge.RUNS = self.root / "runs"
            lab_bridge.ARTIFACTS = self.root / "artifacts"
            lab_bridge.MEMORY = self.root / "memory"
            lab_bridge.ATTEMPTS = lab_bridge.MEMORY / "attempts.jsonl"
            lab_bridge.SCOPE.write_text("{}")
            lab_bridge.dispatch({"operation": "program_activate", "program_id": "sample-program",
                                 "authorization_note": "Synthetic offline test policy"})
            status = lab_bridge.dispatch({"operation": "program_status"})
            self.assertEqual(len(status["web_assets"]), 3)
            response = {"status": 200, "bytes": 2, "text": "ok", "headers": {}, "path": "/"}
            with patch.object(lab_bridge.lab_http, "request", return_value=response) as fetch:
                lab_bridge.dispatch({"operation": "program_http", "url": "https://api.example.test/"})
            self.assertEqual(fetch.call_args.kwargs["user_agent_suffix"], " -Sample-Offline-Test ")
        finally:
            for name, value in originals.items():
                setattr(lab_bridge, name, value)


if __name__ == "__main__":
    unittest.main()
