"""Offline contract checks for Codex MCP and local hooks."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import codex_hook
import codex_lab_mcp
import casebook
import configure_codex
import scope_target


class CodexAdapterTests(unittest.TestCase):
    def test_mcp_stdio_handshake_and_catalogue(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "oliva_progress", "arguments": {}}},
        ]
        run = subprocess.run([sys.executable, str(ROOT / "codex_lab_mcp.py")],
                             input="\n".join(json.dumps(row) for row in requests) + "\n",
                             text=True, capture_output=True, cwd=ROOT, timeout=15, check=True)
        lines = [json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual([row["id"] for row in lines], [1, 2, 3])
        self.assertEqual(lines[0]["result"]["serverInfo"]["name"], "oliv4strator-lab")
        names = {row["name"] for row in lines[1]["result"]["tools"]}
        # The harness evolves; check catalogue consistency rather than a stale count.
        self.assertEqual(names, {row["name"] for row in codex_lab_mcp.TOOLS})
        self.assertEqual(len(names), len(codex_lab_mcp.TOOLS))
        self.assertIn("lab_scope", names)
        self.assertIn("lab_attempts", names)
        self.assertIn("lab_preflight", names)
        self.assertIn("lab_program_http", names)
        self.assertIn("lab_program_discover", names)
        self.assertIn("lab_program_paths", names)
        self.assertIn("lab_program_finding", names)
        self.assertIn("lab_program_findings", names)
        self.assertIn("lab_code_finding", names)
        self.assertIn("lab_evidence", names)
        self.assertIn("lab_code_status", names)
        self.assertFalse(lines[2]["result"]["isError"])
        self.assertTrue(codex_lab_mcp.call("lab_scope", {"operation": "scope"})["isError"])

    def test_codex_config_uses_auto_profile_switches(self):
        # config.toml is intentionally Git-ignored; git-archive only contains the template.
        config_path = ROOT / ".codex" / "config.toml"
        if not config_path.exists():
            config_path = ROOT / ".codex" / "config.example.toml"
        current = config_path.read_text(encoding="utf-8")
        configured = configure_codex.absolute_config(current)
        config = tomllib.loads(configured)
        server = config["mcp_servers"]["oliva_lab"]
        self.assertEqual(server["default_tools_approval_mode"], "auto")
        self.assertEqual(server["tools"]["lab_scope"]["approval_mode"], "auto")
        self.assertEqual(server["tools"]["lab_program_activate"]["approval_mode"], "auto")
        self.assertIn(Path(server["command"]).stem, {"python", "python3"})
        absolute = tomllib.loads(configured)["mcp_servers"]["oliva_lab"]
        self.assertEqual(absolute["args"], [str(ROOT / "codex_lab_mcp.py")])
        self.assertEqual(absolute["cwd"], str(ROOT))

    def test_hook_blocks_out_of_scope_without_requiring_focus(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "scope.json").write_text(json.dumps({"target_ip": "10.10.10.10"}), encoding="utf-8")
            original = codex_hook.ROOT
            codex_hook.ROOT = root
            try:
                local = {"tool_name": "Bash", "tool_input": {"command": "cat local.txt"}}
                self.assertIsNone(codex_hook.handle("pre", local))
                direct = {"tool_name": "Bash", "tool_input": {"command": "curl http://10.10.10.20/"}}
                self.assertEqual(codex_hook.handle("pre", direct)["hookSpecificOutput"]["permissionDecision"], "deny")
                script = {"tool_name": "Bash", "tool_input": {"command": "python3 probe.py"}}
                self.assertIsNone(codex_hook.handle("pre", script))
                codex_hook.handle("post", {**local, "tool_response": "sample"})
                self.assertEqual(casebook.events(root, "10.10.10.10", 1)[0]["kind"], "shell")
                (root / "scope.json").write_text(json.dumps({"program_id": "demo-program"}), encoding="utf-8")
                self.assertIsNone(codex_hook.handle("pre", local))
                codex_hook.handle("post", {**local, "tool_response": "secret-token"})
                program_case = casebook.events(root, scope_target.active_case_id({"program_id": "demo-program"}), 1)[0]
                self.assertNotIn("command", program_case["detail"])
                self.assertNotIn("output_excerpt", program_case["detail"])
            finally:
                codex_hook.ROOT = original


if __name__ == "__main__":
    unittest.main()
