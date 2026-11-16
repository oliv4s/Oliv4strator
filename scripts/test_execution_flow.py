"""Offline checks for replay memory and callback preparation."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import lab_bridge
import casebook


class ExecutionFlowTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        (self.root / "scope.json").write_text(json.dumps({"target_ip": "10.10.10.10"}), encoding="utf-8")
        self.original = {name: getattr(lab_bridge, name) for name in
                         ("ROOT", "SCOPE", "RUNS", "ARTIFACTS", "MEMORY", "ATTEMPTS", "scan")}
        lab_bridge.ROOT = self.root
        lab_bridge.SCOPE = self.root / "scope.json"
        lab_bridge.RUNS = self.root / "runs"
        lab_bridge.ARTIFACTS = self.root / "artifacts"
        lab_bridge.MEMORY = self.root / "memory"
        lab_bridge.ATTEMPTS = self.root / "memory" / "attempts.jsonl"
        lab_bridge.scan = lambda _: {"ports_requested": "80", "observed": []}

    def tearDown(self):
        for name, value in self.original.items():
            setattr(lab_bridge, name, value)
        self.folder.cleanup()

    def test_repeat_skips_static_probe_until_new_reason(self):
        self.assertEqual(lab_bridge.dispatch({"operation": "status"})["engagement_mode"], "lab_machine")
        request = {"operation": "scan", "ports": "80"}
        first = lab_bridge.dispatch(request)
        self.assertIn("attempt_id", first)
        second = lab_bridge.dispatch(request)
        self.assertTrue(second["skipped"])
        self.assertEqual(second["prior_attempt_id"], first["attempt_id"])
        self.assertEqual(len(lab_bridge.recent_attempts()), 1)
        third = lab_bridge.dispatch({**request, "retry_reason": "nuevo servicio observado"})
        self.assertEqual(third["repeat_of"], first["attempt_id"])
        ledger = lab_bridge.dispatch({"operation": "attempts", "filter_operation": "scan", "limit": 10})
        self.assertEqual(ledger["total_attempts"], 2)
        self.assertEqual(ledger["distinct_tests"], 1)
        self.assertEqual(ledger["tests"][0]["count"], 2)

    def test_shell_history_survives_chat_context(self):
        casebook.record_event(self.root, "10.10.10.10", "shell", {
            "command": "ss -ltn", "command_sha256": "abc", "output_excerpt": "LISTEN ..."})
        casebook.record_event(self.root, "10.10.10.10", "shell", {
            "command": "ss -ltn", "command_sha256": "abc", "output_excerpt": "LISTEN ..."})
        ledger = lab_bridge.dispatch({"operation": "attempts", "filter_operation": "shell"})
        self.assertEqual(ledger["shell_calls"], 2)
        self.assertEqual(ledger["distinct_tests"], 1)
        self.assertEqual(ledger["tests"][0]["count"], 2)

    def test_new_inventory_allows_same_read_probe(self):
        request = {"operation": "http", "method": "GET", "port": 80, "path": "/"}
        with patch.object(lab_bridge, "http_request", side_effect=lambda _: {"status": 200, "text": "ok"}) as probe:
            first = lab_bridge.dispatch(request)
            self.assertTrue(lab_bridge.dispatch(request)["skipped"])
            lab_bridge.RUNS.mkdir(exist_ok=True)
            (lab_bridge.RUNS / "services.json").write_text(
                json.dumps({"target_ip": "10.10.10.10", "ports": {"80": {"state": "open"}}}),
                encoding="utf-8")
            again = lab_bridge.dispatch(request)
        self.assertEqual(probe.call_count, 2)
        self.assertNotEqual(first["attempt_id"], again["attempt_id"])

    def test_preflight_reports_route_and_listener_without_network(self):
        def fake_run(argv, **_):
            if argv[0] == "ip":
                return subprocess.CompletedProcess(argv, 0, '[{"dev":"tun0","prefsrc":"10.10.14.1"}]', "")
            return subprocess.CompletedProcess(argv, 0, "LISTEN 0 10 0.0.0.0:4444 0.0.0.0:*\n", "")
        with patch.object(lab_bridge.subprocess, "run", side_effect=fake_run):
            result = lab_bridge.dispatch({"operation": "preflight", "listener_port": 4444,
                                          "callback_host": "10.10.14.1"})
        self.assertEqual(result["route"]["dev"], "tun0")
        self.assertTrue(result["listener"]["callback_ready"])
        self.assertEqual(result["listener"]["state"], "ready")
        self.assertTrue(result["callback_host_matches_route"])
        self.assertTrue(result["listener"]["accepts_callback_host"])

        def loopback_run(argv, **_):
            if argv[0] == "ip":
                return subprocess.CompletedProcess(argv, 0, '[{"dev":"tun0"}]', "")
            return subprocess.CompletedProcess(argv, 0, "LISTEN 0 10 127.0.0.1:4444 0.0.0.0:*\n", "")
        with patch.object(lab_bridge.subprocess, "run", side_effect=loopback_run):
            loopback = lab_bridge.dispatch({"operation": "preflight", "listener_port": 4444})
        self.assertEqual(loopback["listener"]["state"], "loopback_only")


if __name__ == "__main__":
    unittest.main()
