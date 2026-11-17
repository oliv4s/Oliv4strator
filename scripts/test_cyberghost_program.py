"""Offline tests for CyberGhost's documented web scope; no target traffic."""

import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import lab_bridge
import program_policy


class CyberGhostProfileTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        target = self.root / "programs" / "cyberghost"
        shutil.copytree(ROOT / "programs" / "cyberghost", target)
        self.policy, self.digest = program_policy.load(self.root, "cyberghost")

    def tearDown(self):
        self.folder.cleanup()

    def test_scope_matches_exact_and_child_hosts_without_base_leak(self):
        check = lambda url: program_policy.evaluate(self.policy, url)
        expected = {
            "https://cyberghost.com/": "cyberghost_com",
            "https://cyberghost.app/": "cyberghost_app",
            "https://www.cyberghost.com/": "cyberghost_com_subdomains",
            "https://a.b.cyberghost.com/": "cyberghost_com_subdomains",
            "https://api.cyberghostvpn.com/v1/": "cyberghost_api",
            "https://www.cyberghostvpn.com/": "cyberghostvpn_com_subdomains",
            "https://a.b.cyberghostvpn.com/": "cyberghostvpn_com_subdomains",
        }
        for url, asset in expected.items():
            with self.subTest(url=url):
                result = check(url)
                self.assertEqual(result["decision"], "allow")
                self.assertEqual(result["matched_asset"], asset)
        for url in ("https://cyberghostvpn.com/", "https://evilcyberghost.com/",
                    "https://cyberghost.com.evil.test/", "https://another-kape-domain.test/",
                    "http://www.cyberghostvpn.com/", "https://api.cyberghostvpn.com:8443/"):
            with self.subTest(url=url):
                self.assertEqual(check(url)["decision"], "deny")

    def test_profile_inventory_and_user_agent_without_network(self):
        self.assertEqual(len(self.policy["web_assets"]), 5)
        self.assertEqual(len(self.policy["manual_assets"]), 7)
        self.assertEqual(self.policy["required_http_headers"]["user_agent_append"],
                         " -BugBounty-CyberGhost--31337 ")
        originals = {name: getattr(lab_bridge, name) for name in
                     ("ROOT", "SCOPE", "RUNS", "ARTIFACTS", "MEMORY", "ATTEMPTS")}
        try:
            lab_bridge.ROOT = self.root
            lab_bridge.SCOPE = self.root / "scope.json"
            lab_bridge.RUNS = self.root / "runs"
            lab_bridge.ARTIFACTS = self.root / "artifacts"
            lab_bridge.MEMORY = self.root / "memory"
            lab_bridge.ATTEMPTS = self.root / "memory" / "attempts.jsonl"
            lab_bridge.SCOPE.write_text(json.dumps({}), encoding="utf-8")
            lab_bridge.dispatch({"operation": "program_activate", "program_id": "cyberghost",
                                 "authorization_note": "Programa público revisado por el investigador"})
            status = lab_bridge.dispatch({"operation": "program_status"})
            self.assertEqual(len(status["web_assets"]), 5)
            self.assertEqual(len(status["manual_assets"]), 7)
            response = {"status": 200, "bytes": 2, "text": "ok", "headers": {}, "path": "/"}
            with patch.object(lab_bridge.lab_http, "request", return_value=response) as fetch:
                lab_bridge.dispatch({"operation": "program_http",
                                     "url": "https://api.cyberghostvpn.com/"})
            self.assertEqual(fetch.call_args.kwargs["user_agent_suffix"],
                             " -BugBounty-CyberGhost--31337 ")
        finally:
            for name, value in originals.items():
                setattr(lab_bridge, name, value)


if __name__ == "__main__":
    unittest.main()
