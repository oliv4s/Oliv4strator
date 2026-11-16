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


class CodexAdapterTests(unittest.TestCase):
    def test_mcp_stdio_handshake_and_catalogue(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "lab_status", "arguments": {}}},
        ]
        run = subprocess.run([sys.executable, str(ROOT / "codex_lab_mcp.py")],
                             input="\n".join(json.dumps(row) for row in requests) + "\n",
                             text=True, capture_output=True, cwd=ROOT, timeout=15, check=True)
        lines = [json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual([row["id"] for row in lines], [1, 2, 3])
        self.assertEqual(lines[0]["result"]["serverInfo"]["name"], "oliv4strator-lab")
        names = {row["name"] for row in lines[1]["result"]["tools"]}
        self.assertEqual(len(names), 26)
        self.assertIn("lab_scope", names)
        self.assertIn("lab_attempts", names)
        self.assertIn("lab_preflight", names)
        self.assertIn("lab_program_http", names)
        self.assertIn("lab_program_discover", names)
        self.assertIn("lab_program_paths", names)
        self.assertIn("lab_program_finding", names)
        self.assertIn("lab_program_findings", names)
        self.assertFalse(lines[2]["result"]["isError"])
        self.assertTrue(codex_lab_mcp.call("lab_scope", {"operation": "scope"})["isError"])

    def test_codex_config_approves_only_scope(self):
        config = tomllib.loads((ROOT / ".codex" / "config.toml").read_text(encoding="utf-8"))
        server = config["mcp_servers"]["oliva_lab"]
        self.assertEqual(server["default_tools_approval_mode"], "auto")
        self.assertEqual(server["tools"]["lab_scope"]["approval_mode"], "approve")
        self.assertEqual(server["tools"]["lab_program_activate"]["approval_mode"], "approve")
        self.assertIn(Path(server["command"]).stem, {"python", "python3"})
        configured = configure_codex.absolute_config((ROOT / ".codex" / "config.toml").read_text(encoding="utf-8"))
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
                self.assertEqual(codex_hook.handle("pre", local)["hookSpecificOutput"]["permissionDecision"], "deny")
            finally:
                codex_hook.ROOT = original


if __name__ == "__main__":
    unittest.main()
