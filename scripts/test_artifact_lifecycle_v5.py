"""Filesystem-only tests for v5 managed artifact lifecycle."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import casebook
import codex_lab_mcp
import oliva_mcp_catalog
from harness.efficiency import artifacts, workspace


class ArtifactLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.case_id = '10.10.10.10'
        self.session_id = 'session-01'
        self.home = Path(artifacts.prepare(self.repo, self.case_id, self.session_id)['workspace'])

    def tearDown(self):
        self.tmp.cleanup()

    def test_retention_discard_and_quarantine_unknown(self):
        event = casebook.record_event(self.repo, self.case_id, 'observation', {'note': 'test evidence'})
        (self.home / 'proof.txt').write_text('verified result')
        (self.home / 'throwaway.tmp').write_text('temporary')
        (self.home / 'unknown.txt').write_text('needs review')
        keep = artifacts.register(self.repo, self.case_id, self.session_id,
                                  'proof.txt', 'retain', [event['event_id']], 'Checked')
        artifacts.register(self.repo, self.case_id, self.session_id, 'throwaway.tmp', 'discard')
        result = artifacts.finalize(self.repo, self.case_id, self.session_id)
        self.assertEqual(result['state'], 'finalized')
        self.assertEqual(result['retained'], 1)
        self.assertEqual(result['discarded'], 1)
        quarantine = Path(result['recovery_path'])
        self.assertFalse(self.home.exists())
        self.assertTrue(quarantine.joinpath('unknown.txt').exists())
        self.assertTrue(quarantine.joinpath('proof.txt').exists())
        self.assertFalse(quarantine.joinpath('throwaway.tmp').exists())
        self.assertEqual((self.repo / keep['case_path']).read_text(), 'verified result')

    def test_finalize_is_idempotent_and_no_session_reuse(self):
        one = artifacts.finalize(self.repo, self.case_id, self.session_id)
        two = artifacts.finalize(self.repo, self.case_id, self.session_id)
        self.assertFalse(one['already_finalized'])
        self.assertTrue(two['already_finalized'])
        with self.assertRaisesRegex(ValueError, 'finalized'):
            artifacts.prepare(self.repo, self.case_id, self.session_id)

    def test_invalid_evidence_rejected(self):
        (self.home / 'proof.txt').write_text('payload')
        with self.assertRaisesRegex(ValueError, 'must exist'):
            artifacts.register(self.repo, self.case_id, self.session_id,
                               'proof.txt', 'retain', ['20261126T100523Z-e79db5ffe5d4'])

    def test_modified_disposable_is_quarantined(self):
        (self.home / 'log.txt').write_text('before')
        artifacts.register(self.repo, self.case_id, self.session_id, 'log.txt', 'discard')
        (self.home / 'log.txt').write_text('after')
        result = artifacts.finalize(self.repo, self.case_id, self.session_id)
        self.assertTrue((Path(result['recovery_path']) / 'log.txt').exists())
        self.assertEqual(result['discarded'], 0)

    def test_no_auto_finalization_when_not_called(self):
        (self.home / 'log.txt').write_text('keep')
        self.assertEqual(artifacts.status(self.repo, self.case_id, self.session_id)['state'], 'active')
        self.assertTrue(self.home.exists())

    def test_symlinks_refuse_finalize(self):
        other = self.repo / 'important.txt'
        other.write_text('preserve')
        (self.home / 'link').symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            artifacts.finalize(self.repo, self.case_id, self.session_id)
        self.assertTrue(self.home.exists())
        self.assertEqual(other.read_text(), 'preserve')

    def test_restore_reopens_quarantine(self):
        artifact = self.home / 'unknown.txt'
        artifact.write_text('safe')
        artifacts.finalize(self.repo, self.case_id, self.session_id, 'partial')
        result = artifacts.restore(self.repo, self.case_id, self.session_id)
        self.assertTrue(result['restored'])
        self.assertEqual((self.home / 'unknown.txt').read_text(), 'safe')

    def test_prune_only_expired_quarantine(self):
        artifacts.finalize(self.repo, self.case_id, self.session_id)
        self.assertEqual(artifacts.prune(self.repo)['expired'], 0)
        quarantine = self.repo / 'work' / 'quarantine' / self.case_id / self.session_id
        marker = json.loads((quarantine / workspace.MARKER).read_text())
        marker['finalized_at'] = '2020-01-01T00:00:00+00:00'
        (quarantine / workspace.MARKER).write_text(json.dumps(marker))
        # Test-only backdating. Production files expire naturally after 7 days.
        import os
        os.utime(quarantine / workspace.MARKER, (1, 1))
        self.assertEqual(artifacts.prune(self.repo)['expired'], 1)
        self.assertFalse(quarantine.exists())

    def test_retained_source_changes_require_refresh(self):
        event = casebook.record_event(self.repo, self.case_id, 'observation', {'test': True})
        file = self.home / 'poc.py'
        file.write_text('v1')
        artifacts.register(self.repo, self.case_id, self.session_id, 'poc.py',
                           'retain', [event['event_id']])
        file.write_text('v2')
        with self.assertRaisesRegex(ValueError, 'changed'):
            artifacts.finalize(self.repo, self.case_id, self.session_id)
        artifacts.register(self.repo, self.case_id, self.session_id, 'poc.py',
                           'retain', [event['event_id']])
        self.assertEqual(artifacts.finalize(self.repo, self.case_id, self.session_id)['retained'], 1)

    def test_mcp_uses_launcher_session_and_generic_catalog(self):
        fake_module = self.repo / 'codex_lab_mcp.py'
        env = {'OLIVA_CASE_ID': self.case_id, 'OLIVA_SESSION_ID': self.session_id,
               'OLIVA_MCP_NAMES': 'generic', 'OLIVA_MCP_PROFILE': 'BB-Code'}
        self.assertIn('oliva_artifact', {tool['name'] for tool in
                                         oliva_mcp_catalog.visible(codex_lab_mcp.TOOLS)})
        with patch.dict(os.environ, env), patch.object(codex_lab_mcp, '__file__', str(fake_module)):
            response = codex_lab_mcp.call('oliva_artifact', {'action': 'status'})
            self.assertFalse(response['isError'])
            data = json.loads(response['content'][0]['text'])
            self.assertEqual(data['state'], 'active')
            done = codex_lab_mcp.call('oliva_artifact', {'action': 'finalize'})
            self.assertFalse(done['isError'])
            self.assertEqual(json.loads(done['content'][0]['text'])['state'], 'finalized')

    def test_bad_discard_reference_or_path(self):
        (self.home / 'check.txt').write_text('x')
        with self.assertRaises(ValueError):
            artifacts.register(self.repo, self.case_id, self.session_id, '../outside', 'discard')
        with self.assertRaises(ValueError):
            artifacts.register(self.repo, self.case_id, self.session_id, 'check.txt', 'discard', ['e1'])


if __name__ == '__main__':
    unittest.main()
