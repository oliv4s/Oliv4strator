"""Offline integration checks for LAB, BB-Web compatibility and BB-Code."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import casebook
import code_checkout
import lab_bridge
import program_policy
import scope_target


class ThreeProfilesTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        (self.root / "scope.json").write_text("{}", encoding="utf-8")
        self.original = {name: getattr(lab_bridge, name) for name in
                         ("ROOT", "SCOPE", "RUNS", "ARTIFACTS", "MEMORY", "ATTEMPTS")}
        lab_bridge.ROOT = self.root
        lab_bridge.SCOPE = self.root / "scope.json"
        lab_bridge.RUNS = self.root / "runs"
        lab_bridge.ARTIFACTS = self.root / "artifacts"
        lab_bridge.MEMORY = self.root / "memory"
        lab_bridge.ATTEMPTS = self.root / "memory" / "attempts.jsonl"

    def tearDown(self):
        for name, value in self.original.items():
            setattr(lab_bridge, name, value)
        self.folder.cleanup()

    def test_lab_target_from_prompt_needs_no_note(self):
        lab_bridge.dispatch({"operation": "scope", "ip": "198.51.100.42"})
        status = lab_bridge.dispatch({"operation": "status"})
        self.assertEqual(status["profile"], "LAB")
        self.assertEqual(status["scope"]["target_ip"], "198.51.100.42")
        self.assertIn("prompt", status["scope"]["authorization_note"])
        lab_bridge.dispatch({"operation": "scope", "url": "https://challenge.example/level1"})
        self.assertEqual(lab_bridge.dispatch({"operation": "status"})["profile"], "LAB")

    def test_code_policy_activation_and_report_without_target_traffic(self):
        folder = self.root / "programs" / "code-example"
        folder.mkdir(parents=True)
        source = b"Synthetic program: only https://github.com/example/project is in scope."
        (folder / "source.txt").write_bytes(source)
        repository = "https://github.com/example/project"
        policy = {"program_id": "code-example", "name": "Synthetic code program",
                  "program_type": "bug_bounty", "state": "draft_not_enforced",
                  "default_decision": "deny", "web_assets": [],
                  "code_assets": [{"id": "project", "kind": "git_repository", "url": repository}],
                  "source": {"raw_sha256": hashlib.sha256(source).hexdigest()},
                  "operator_workflow": {"goal": "reproducible_local_poc"}}
        (folder / "policy.draft.json").write_text(json.dumps(policy), encoding="utf-8")
        checkout = self.root / "checkout"
        checkout.mkdir()
        self.assertEqual(program_policy.evaluate_code(policy, repository)["decision"], "allow")
        self.assertEqual(program_policy.evaluate_code(policy, repository + "-fork")["decision"], "deny")
        lab_bridge.dispatch({"operation": "program_activate", "program_id": "code-example",
                             "checkout_path": str(checkout)})
        status = lab_bridge.dispatch({"operation": "status"})
        self.assertEqual(status["profile"], "BB-Code")
        self.assertEqual(status["engagement_mode"], "bug_bounty_code")
        self.assertEqual(lab_bridge.dispatch({"operation": "program_status"})["checkout_path"], str(checkout))
        self.assertFalse(lab_bridge.dispatch({"operation": "code_status"})["git_repository"])
        self.assertEqual(lab_bridge.dispatch({"operation": "program_check",
                                              "repository_url": repository})["decision"], "allow")
        with self.assertRaisesRegex(ValueError, "BB-Web"):
            lab_bridge.dispatch({"operation": "program_http", "url": "https://example.test/", "method": "GET"})
        identifier = scope_target.active_case_id(status["scope"])
        event = casebook.record_event(self.root, identifier, "shell",
                                      {"command_sha256": "test", "output_sha256": "test"})
        observation = lab_bridge.dispatch({"operation": "evidence", "source": "local_test",
                                           "observation": "The isolated parser returned a second header.",
                                           "control": "The fixed parser returned only the intended header."})
        finding_request = {
            "operation": "code_finding", "title": "Untrusted input reaches a sensitive sink",
            "category": "input_validation", "affected_version": "v1.0.0",
            "source_location": "src/parser.go: ParseHeader",
            "conditions": "An application passes untrusted input to the affected parser.",
            "proof": "A local test produced an additional parsed header; no network request was sent.",
            "impact_hypothesis": "A downstream consumer might treat the extra header as authoritative.",
            "technical_reproduction": "go test ./... -run TestInjectedHeader -count=1",
            "reproduction_steps": ["Check out the affected version in a local folder.",
                                   "Run the isolated parser test with a negative control."],
            "confirming_evidence_ids": [event["event_id"], observation["evidence_id"]],
            "related_advisories": "No related public advisory found in this synthetic test."}
        with self.assertRaisesRegex(ValueError, "Avisos relacionados"):
            lab_bridge.dispatch({key: value for key, value in finding_request.items()
                                 if key != "related_advisories"})
        finding = lab_bridge.dispatch(finding_request)
        self.assertTrue(Path(finding["report_file"]).exists())
        self.assertEqual(lab_bridge.dispatch({"operation": "program_findings"})["total"], 1)
        self.assertEqual(lab_bridge.dispatch({"operation": "review"})["learning_candidates"][0]["evidence_id"],
                         finding["evidence_id"])
        method = lab_bridge.dispatch({
            "operation": "method", "action": "add", "phase": "code_review",
            "technology": "go", "signal": "A public helper writes untrusted metadata without filtering controls.",
            "question": "Can crafted input alter a serialized field instead of remaining data?",
            "test": "Serialize a controlled value and compare it with a benign control.",
            "supports": "An additional parsed field appears in the output.",
            "refutes": "The parser preserves the value without structural change.",
            "next_if_supported": "Trace the output to a downstream consumer in an isolated harness.",
            "next_if_refuted": "Close this sink and inspect a different trust boundary.",
            "pitfall": "A newline alone does not prove a new parsed field.",
            "evidence_id": finding["evidence_id"], "result": "supported"})
        self.assertEqual(method["method"]["phase"], "code_review")
        self.assertFalse(lab_bridge.dispatch({"operation": "review"})["learning_candidates"])
        self.assertEqual(len(lab_bridge.dispatch({"operation": "memory", "technology": "go",
                                                  "phase": "code_review"})["methods"]), 1)
        self.assertEqual(code_checkout.canonical_remote("git@github.com:example/project.git"), repository)
        remote = ["git@github.com:example/project.git"]

        def fake_git(_checkout, *args):
            if args == ("rev-parse", "--show-toplevel"):
                return str(checkout)
            if args == ("remote", "get-url", "origin"):
                return remote[0]
            return "a" * 40

        with patch.object(code_checkout, "_git", side_effect=fake_git):
            self.assertTrue(lab_bridge.dispatch({"operation": "code_status"})["matches_scope"])
            remote[0] = "https://github.com/example/other-project"
            self.assertFalse(lab_bridge.dispatch({"operation": "code_status"})["matches_scope"])
            with self.assertRaisesRegex(ValueError, "no coincide"):
                lab_bridge.dispatch({"operation": "program_activate", "program_id": "code-example",
                                     "checkout_path": str(checkout)})

    def test_web_report_accepts_native_tool_evidence(self):
        folder = self.root / "programs" / "web-example"
        folder.mkdir(parents=True)
        source = b"Synthetic program: only https://app.example.test is in scope."
        (folder / "source.txt").write_bytes(source)
        policy = {"program_id": "web-example", "name": "Synthetic web program",
                  "state": "draft_not_enforced", "default_decision": "deny",
                  "web_assets": [{"id": "app", "kind": "exact_host_set", "scheme": "https",
                                  "hosts": ["app.example.test"], "application_boundary": "all_routes"}],
                  "source": {"raw_sha256": hashlib.sha256(source).hexdigest()}}
        (folder / "policy.draft.json").write_text(json.dumps(policy), encoding="utf-8")
        lab_bridge.dispatch({"operation": "program_activate", "program_id": "web-example"})
        self.assertEqual(lab_bridge.dispatch({"operation": "status"})["profile"], "BB-Web")
        observation = lab_bridge.dispatch({"operation": "evidence", "source": "browser",
                                           "observation": "A controlled request crossed an account boundary in a local fixture.",
                                           "control": "The same request without authorization returned a denial."})
        finding = lab_bridge.dispatch({
            "operation": "program_finding", "title": "Controlled account boundary failure",
            "category": "authorization", "affected_url": "https://app.example.test/resource",
            "proof": "The controlled request returned a different account's fixture record.",
            "impact_hypothesis": "A real deployment might disclose another user's record.",
            "technical_reproduction": "GET /resource with the test account token; compare to the anonymous control.",
            "reproduction_steps": ["Create two accounts owned by the researcher.",
                                   "Compare the authorized and unauthorized response."],
            "confirming_attempt_ids": [observation["evidence_id"]]})
        self.assertTrue(Path(finding["report_file"]).exists())


if __name__ == "__main__":
    unittest.main()
