"""Offline inventory and quarantine maintenance regression tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness.efficiency import artifacts, workspace
from scripts.oliva_sessions import inventory
from scripts.oliva_run import report_local_session
from contextlib import redirect_stderr
from io import StringIO


class SessionMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.case, self.session = "192.0.2.1", "run-1"
        self.home = Path(artifacts.prepare(self.repo, self.case, self.session)["workspace"])
        (self.home / "scratch.txt").write_text("temporary test file")

    def tearDown(self):
        self.tmp.cleanup()

    def test_launcher_reports_unfinished_session_without_deletion(self):
        output = StringIO()
        with redirect_stderr(output):
            report_local_session(self.repo, self.case, self.session)
        self.assertIn('active', output.getvalue())
        self.assertTrue((self.home / 'scratch.txt').exists())

    def test_launcher_reports_completed_cleanup(self):
        artifacts.finalize(self.repo, self.case, self.session)
        output = StringIO()
        with redirect_stderr(output):
            report_local_session(self.repo, self.case, self.session)
        self.assertIn('finalized', output.getvalue())
        self.assertIn('quarantined=', output.getvalue())

    def test_inventory_is_read_only_and_no_contents(self):
        result = inventory(self.repo)
        self.assertEqual(result["total"], 1)
        item = result["sessions"][0]
        self.assertEqual(item["state"], "active")
        self.assertEqual(item["file_count"], 1)
        self.assertNotIn("temporary test file", json.dumps(result))
        self.assertTrue((self.home / "scratch.txt").exists())

    def test_invalid_marker_is_ignored_not_adopted(self):
        bogus = self.repo / "work" / "temp" / "fake-case" / "fake-run"
        bogus.mkdir(parents=True)
        (bogus / "test.txt").write_text("not ours")
        result = inventory(self.repo)
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["skipped_invalid"], 1)
        self.assertTrue(bogus.exists())

    def test_finalized_session_preview_then_apply(self):
        artifacts.finalize(self.repo, self.case, self.session)
        result = inventory(self.repo)
        self.assertEqual(result["sessions"][0]["state"], "finalized")
        quarantine = self.repo / "work" / "quarantine" / self.case / self.session
        marker_path = quarantine / workspace.MARKER
        marker = json.loads(marker_path.read_text())
        marker["finalized_at"] = "2020-01-01T00:00:00+00:00"
        marker_path.write_text(json.dumps(marker))
        os.utime(marker_path, (1, 1))
        os.utime(quarantine / "scratch.txt", (1, 1))
        before = artifacts.prune(self.repo, dry_run=True)
        self.assertEqual(before["eligible"], 1)
        self.assertEqual(before["expired"], 0)
        self.assertTrue(quarantine.exists())
        after = artifacts.prune(self.repo)
        self.assertEqual(after["expired"], 1)
        self.assertFalse(quarantine.exists())

    def test_recent_quarantine_never_removed(self):
        artifacts.finalize(self.repo, self.case, self.session)
        preview = artifacts.prune(self.repo, dry_run=True)
        self.assertEqual(preview["eligible"], 0)
        applied = artifacts.prune(self.repo)
        self.assertEqual(applied["expired"], 0)


if __name__ == "__main__":
    unittest.main()
