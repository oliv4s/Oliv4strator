"""Offline policy, budget and HTTP boundary checks; no requests to the program."""

import json
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import lab_bridge
import lab_http
import program_policy


class ProgramPolicyTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        source = ROOT / "programs" / "demo-program"
        target = self.root / "programs" / "demo-program"
        target.mkdir(parents=True)
        shutil.copy2(source / "policy.draft.json", target / "policy.draft.json")
        shutil.copy2(source / "source.txt", target / "source.txt")
        self.program_id = "demo-program"
        self.policy, _ = program_policy.load(self.root, self.program_id)

    def tearDown(self):
        self.folder.cleanup()

    def test_explicit_assets_exclusions_and_surface(self):
        evaluate = lambda url, **kw: program_policy.evaluate(self.policy, url, **kw)
        self.assertEqual(evaluate("https://api.example.test/v1")["decision"], "allow")
        self.assertEqual(evaluate("https://a.b.api.example.test/v1")["decision"], "allow")
        self.assertEqual(evaluate("https://shop.example.test/")["decision"], "review")
        self.assertEqual(evaluate("https://shop.example.test/", surface="ecommerce",
                                  basis="Ruta de la tienda regional observada")["decision"], "allow")
        for url in ("https://blog.example.test/", "https://portal.example.test/dispatch",
                    "https://www.example.cn/", "http://shop.example.test/",
                    "https://api.example.test:8443/", "https://api.example.test.evil.test/"):
            self.assertEqual(evaluate(url)["decision"], "deny", url)
        with self.assertRaises(ValueError):
            evaluate("https://user:pass@api.example.test/")

    def test_source_or_policy_change_requires_new_approval(self):
        scope = {"program_id": self.program_id,
                 "program_policy_sha256": program_policy.load(self.root, self.program_id)[1]}
        program_policy.active(self.root, scope)
        policy_path = self.root / "programs" / self.program_id / "policy.draft.json"
        original = policy_path.read_bytes()
        policy_path.write_bytes(original + b" ")
        with self.assertRaisesRegex(ValueError, "cambió"):
            program_policy.active(self.root, scope)
        policy_path.write_bytes(original)
        path = self.root / "programs" / self.program_id / "source.txt"
        path.write_text(path.read_text(encoding="utf-8") + "\nchanged", encoding="utf-8")
        with self.assertRaises(ValueError):
            program_policy.active(self.root, scope)

    def test_budget_serializes_requests_and_pauses_after_429(self):
        with patch.object(program_policy.time, "time", return_value=1000.0):
            token = program_policy.reserve(self.root, self.program_id, 2)
            with self.assertRaisesRegex(program_policy.BudgetPause, "en curso"):
                program_policy.reserve(self.root, self.program_id, 2)
            program_policy.release(self.root, self.program_id, token)
        with patch.object(program_policy.time, "time", return_value=1003.0):
            token = program_policy.reserve(self.root, self.program_id, 2)
            program_policy.release(self.root, self.program_id, token, 429, "300")
            self.assertEqual(program_policy.budget(self.root, self.program_id, 2)["remaining_last_hour"], 0)
        with patch.object(program_policy.time, "time", return_value=1006.0):
            with self.assertRaisesRegex(program_policy.BudgetPause, "Pausa"):
                program_policy.reserve(self.root, self.program_id, 2)

    def test_no_implicit_hourly_cap_or_fixed_interval(self):
        with patch.object(program_policy.time, "time", return_value=1000.0):
            first = program_policy.reserve(self.root, self.program_id, None)
            program_policy.release(self.root, self.program_id, first)
            second = program_policy.reserve(self.root, self.program_id, None)
            program_policy.release(self.root, self.program_id, second)
            status = program_policy.budget(self.root, self.program_id, None)
        self.assertEqual(status["used_last_hour"], 2)
        self.assertIsNone(status["hourly_limit"])
        self.assertIsNone(status["remaining_last_hour"])

    def test_retry_after_only_when_server_sends_it(self):
        with patch.object(program_policy.time, "time", return_value=1000.0):
            first = program_policy.reserve(self.root, self.program_id, None)
            program_policy.release(self.root, self.program_id, first, 429)
            self.assertEqual(program_policy.budget(self.root, self.program_id, None)["cooldown_seconds"], 0)
            header = format_datetime(datetime.fromtimestamp(1120, timezone.utc), usegmt=True)
            self.assertEqual(program_policy.retry_after_seconds(header), 120)

    def test_activation_and_http_use_policy_without_network(self):
        (self.root / "scope.json").write_text(json.dumps({"target_ip": "10.10.10.10"}), encoding="utf-8")
        (self.root / "runs").mkdir()
        (self.root / "runs" / "services.json").write_text(
            json.dumps({"target_ip": "10.10.10.10", "ports": {"80": {"state": "open", "service": "http"}}}),
            encoding="utf-8")
        original = {name: getattr(lab_bridge, name) for name in
                    ("ROOT", "SCOPE", "RUNS", "ARTIFACTS", "MEMORY", "ATTEMPTS")}
        try:
            lab_bridge.ROOT = self.root
            lab_bridge.SCOPE = self.root / "scope.json"
            lab_bridge.RUNS = self.root / "runs"
            lab_bridge.ARTIFACTS = self.root / "artifacts"
            lab_bridge.MEMORY = self.root / "memory"
            lab_bridge.ATTEMPTS = self.root / "memory" / "attempts.jsonl"
            activated = lab_bridge.dispatch({"operation": "program_activate", "program_id": self.program_id,
                                             "authorization_note": "Programa público aceptado por el investigador"})
            self.assertEqual(activated["program_id"], self.program_id)
            initial = lab_bridge.dispatch({"operation": "program_status"})
            self.assertEqual(initial["budget"]["used_last_hour"], 0)
            self.assertIsNone(initial["budget"]["hourly_limit"])
            self.assertEqual(initial["min_interval_seconds"], 0)
            mode = lab_bridge.dispatch({"operation": "status"})
            self.assertEqual(mode["engagement_mode"], "bug_bounty")
            self.assertEqual(mode["workflow"]["goal"], "minimal_reproducible_poc")
            fake_response = {"status": 200, "bytes": 2, "text": "ok", "headers": {}, "path": "/v1"}
            with patch.object(lab_bridge.lab_http, "request", return_value=fake_response) as fetch:
                result = lab_bridge.dispatch({"operation": "program_http", "url": "https://api.example.test/v1",
                                              "method": "GET"})
            self.assertEqual(result["status"], 200)
            self.assertFalse(fetch.call_args.kwargs["save_artifacts"])
            self.assertFalse(fetch.call_args.args[4]["follow_redirects"])
            self.assertEqual(fetch.call_args.kwargs["response_limit"], 65_536)
            self.assertIn("demo-agent", fetch.call_args.kwargs["user_agent_suffix"])
            self.assertEqual(lab_bridge.dispatch({"operation": "program_status"})["budget"]["used_last_hour"], 1)
            with patch.object(program_policy, "reserve",
                              side_effect=program_policy.BudgetPause("Intervalo mínimo", 2)), \
                    patch.object(lab_bridge.lab_http, "request") as fetch:
                deferred = lab_bridge.dispatch({"operation": "program_http",
                                                "url": "https://api.example.test/v2", "method": "GET"})
                self.assertTrue(deferred["deferred"])
                self.assertEqual(deferred["retry_after_seconds"], 2)
                fetch.assert_not_called()
            self.assertEqual(lab_bridge.dispatch({"operation": "attempts"})["total_attempts"], 1)
            discovery_response = {"status": 200, "bytes": 62,
                                  "text": '<html><a href="/v2">next</a></html>',
                                  "headers": {"content-type": "text/html"}, "path": "/v1"}
            with patch.object(lab_bridge.lab_http, "request", return_value=discovery_response) as fetch:
                discovered = lab_bridge.dispatch({"operation": "program_discover",
                                                  "url": "https://api.example.test/v1"})
            self.assertEqual(discovered["candidate_count"], 1)
            self.assertEqual(discovered["candidates"][0]["url"], "https://api.example.test/v2")
            self.assertNotIn("text", discovered)
            self.assertEqual(fetch.call_count, 1)
            finding = lab_bridge.dispatch({
                "operation": "program_finding", "title": "PoC mínima de prueba de API",
                "category": "Control de acceso", "affected_url": "https://api.example.test/v1",
                "proof": "La respuesta de control mostró un resultado diferente verificable.",
                "impact_hypothesis": "La misma condición podría afectar recursos de otras cuentas.",
                "technical_reproduction": "curl -i https://api.example.test/v1 con la cuenta de prueba",
                "reproduction_steps": ["Preparar dos cuentas de prueba propias",
                                       "Enviar GET /v1 y comparar la respuesta observada"],
                "confirming_attempt_ids": [result["attempt_id"], discovered["attempt_id"]],
            })
            self.assertTrue(Path(finding["report_file"]).is_file())
            self.assertEqual(lab_bridge.dispatch({"operation": "program_findings"})["total"], 1)
            batch_rows = [{"status": 200, "bytes": 0, "text": "", "headers": {}, "path": "/a"},
                          {"status": 429, "bytes": 0, "text": "", "headers": {}, "path": "/b"}]
            with patch.object(lab_bridge.lab_http, "request", side_effect=batch_rows) as fetch:
                batch = lab_bridge.dispatch({"operation": "program_paths",
                                             "base_url": "https://api.example.test/",
                                             "paths": ["/a", "/b", "/c"],
                                             "reason": "Rutas observadas en el HTML de la aplicación"})
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(batch["tested"], 2)
            self.assertEqual(batch["next_index"], 2)
            self.assertIn("429/503", batch["stopped_reason"])
            with patch.object(lab_bridge.lab_http, "request") as fetch:
                with self.assertRaises(ValueError):
                    lab_bridge.dispatch({"operation": "program_http", "url": "https://blog.example.test/",
                                         "method": "GET"})
                fetch.assert_not_called()
            self.assertEqual(json.loads((self.root / "cases" / "10.10.10.10" / "services.json").read_text())
                             ["ports"]["80"]["service"], "http")
        finally:
            for name, value in original.items():
                setattr(lab_bridge, name, value)

    def test_http_header_and_response_cap(self):
        sent = {}

        class FakeResponse:
            status = 200
            def read(self, amount):
                sent["read_limit"] = amount
                return b"x" * amount
            def getheaders(self):
                return []

        class FakeConnection:
            def __init__(self, *args, **kwargs):
                pass
            def request(self, method, path, body, headers):
                sent["headers"] = headers
            def getresponse(self):
                return FakeResponse()
            def close(self):
                pass

        with patch.object(lab_http.http.client, "HTTPSConnection", FakeConnection):
            result = lab_http.request(self.root, self.root / "artifacts", "api.example.test", 443,
                                      {"method": "GET", "path": "/", "headers": {"user-agent": "Custom"}},
                                      web_origin="https://api.example.test",
                                      response_limit=100, text_limit=10, save_artifacts=False,
                                      user_agent_suffix=" demo-agent ")
        self.assertEqual(sent["headers"]["User-Agent"], "Custom demo-agent ")
        self.assertEqual(sum(key.lower() == "user-agent" for key in sent["headers"]), 1)
        self.assertEqual(sent["read_limit"], 101)
        self.assertTrue(result["response_capped"])
        self.assertFalse((self.root / "artifacts").exists())


if __name__ == "__main__":
    unittest.main()
