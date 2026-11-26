"""Offline tests for managed case workspaces and safe hypothesis updates."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import casebook
from harness.efficiency import workspace, mcp_lifecycle


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.case = '10.10.10.10'
        self.session = 'trial-1'

    def tearDown(self):
        self.temp.cleanup()

    def test_create_and_inspect_idempotently(self):
        first = workspace.prepare(self.repo, self.case, self.session)
        second = workspace.prepare(self.repo, self.case, self.session)
        self.assertEqual(first, second)
        self.assertEqual(first.stat().st_mode & 0o777, 0o700)
        self.assertEqual(workspace.inspect(self.repo, self.case, self.session)['files'], 0)
        self.assertEqual((first / workspace.MARKER).stat().st_mode & 0o777, 0o600)

    def test_retain_and_manual_cleanup_preserve_selected_artifact(self):
        path = workspace.prepare(self.repo, self.case, self.session)
        (path / 'my-script.py').write_text('print(123)\n')
        (path / 'throwaway.txt').write_text('not retained')
        item = workspace.retain(self.repo, self.case, self.session, 'my-script.py', 'Reviewed evidence script')
        self.assertEqual(len(item['sha256']), 64)
        self.assertTrue((self.repo / item['path']).is_file())
        preview = workspace.clean(self.repo, self.case, self.session)
        self.assertFalse(preview['deleted'])
        self.assertTrue(path.exists())
        result = workspace.clean(self.repo, self.case, self.session, apply=True, min_age_hours=0)
        self.assertTrue(result['deleted'])
        self.assertFalse(path.exists())
        self.assertTrue((self.repo / item['path']).is_file())

    def test_reject_traversal_and_symlink(self):
        path = workspace.prepare(self.repo, self.case, self.session)
        outside = self.repo / 'do-not-delete.txt'
        outside.write_text('safe')
        (path / 'external').symlink_to(outside)
        with self.assertRaises(ValueError):
            workspace.retain(self.repo, self.case, self.session, '../do-not-delete.txt')
        with self.assertRaises(ValueError):
            workspace.retain(self.repo, self.case, self.session, 'external')
        with self.assertRaises(ValueError):
            workspace.clean(self.repo, self.case, self.session, apply=True, min_age_hours=0)
        self.assertEqual(outside.read_text(), 'safe')

    def test_recent_workspace_refuses_cleanup(self):
        workspace.prepare(self.repo, self.case, self.session)
        with self.assertRaisesRegex(ValueError, 'recently'):
            workspace.clean(self.repo, self.case, self.session, apply=True)

    def test_unmanaged_and_invalid_ids_are_rejected(self):
        path = workspace.location(self.repo, self.case, self.session)
        path.mkdir(parents=True)
        (path / 'stranger.txt').write_text('do not delete')
        with self.assertRaises(ValueError):
            workspace.prepare(self.repo, self.case, self.session)
        with self.assertRaises(ValueError):
            workspace.clean(self.repo, self.case, self.session, apply=True, min_age_hours=0)
        with self.assertRaises(ValueError):
            workspace.location(self.repo, '../../etc', self.session)
        self.assertTrue((path / 'stranger.txt').exists())

    def test_retention_is_deduplicated(self):
        path = workspace.prepare(self.repo, self.case, self.session)
        (path / 'log.txt').write_text('example')
        a = workspace.retain(self.repo, self.case, self.session, 'log.txt')
        b = workspace.retain(self.repo, self.case, self.session, 'log.txt')
        self.assertEqual(a['sha256'], b['sha256'])
        self.assertEqual(workspace.inspect(self.repo,self.case,self.session)['retained_count'],1)


class HypothesisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.case = '10.10.10.10'
        self.evidence = {f'{i:012x}' for i in range(1, 8)}

    def tearDown(self):
        self.temp.cleanup()

    def _proposal(self, i):
        return {'action':'propose', 'claim':f'The example hypothesis number {i}',
                'expected':'A synthetic observation would be present',
                'next_test':'Review the provided fixture in an offline context',
                'confidence':'low', 'evidence_ids':[f'{i:012x}']}

    def test_concurrent_changes_do_not_lose_updates(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda i: casebook.change_hypothesis(
                self.repo, self.case, self._proposal(i), self.evidence), [1,2,3,4]))
        rows = casebook.hypotheses(self.repo, self.case)
        self.assertEqual(len(rows), 4)
        self.assertEqual(len({r['hypothesis_id'] for r in rows}),4)

    def test_duplicate_propose_and_assess_do_not_rewrite(self):
        request = self._proposal(1)
        a = casebook.change_hypothesis(self.repo, self.case, request, self.evidence)
        b = casebook.change_hypothesis(self.repo, self.case, request, self.evidence)
        self.assertTrue(b['existing'])
        self.assertEqual(a['hypothesis']['hypothesis_id'], b['hypothesis']['hypothesis_id'])
        review = {'action':'assess','hypothesis_id':a['hypothesis']['hypothesis_id'],
                  'status':'supported','evidence_ids':['000000000002'],
                  'note':'Fixture corroborates the claim'}
        x = casebook.change_hypothesis(self.repo, self.case, review, self.evidence)
        y = casebook.change_hypothesis(self.repo, self.case, review, self.evidence)
        self.assertFalse(x['existing'])
        self.assertTrue(y['existing'])
        self.assertEqual(len(casebook.hypotheses(self.repo,self.case)),1)

    def test_lock_is_bounded(self):
        with casebook.hypothesis_lock(self.repo,self.case):
            import threading
            failures=[]
            def blocked():
                try:
                    with casebook.hypothesis_lock(self.repo,self.case,timeout_seconds=0.12):
                        pass
                except TimeoutError as exc:
                    failures.append(str(exc))
            thread=threading.Thread(target=blocked)
            thread.start()
            thread.join(timeout=1)
            self.assertEqual(len(failures),1)


class DiagnosticsTests(unittest.TestCase):
    def test_trace_has_no_arguments_or_results(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'OLIVA_TRACE_MCP':'1'}):
            repo=Path(d)
            token=mcp_lifecycle.start(repo,'lab_hypothesis')
            mcp_lifecycle.finish(repo, token, error=False)
            data=[json.loads(x) for x in (repo/'work/efficiency/mcp_lifecycle.jsonl').read_text().splitlines()]
            self.assertEqual([x['event'] for x in data], ['started','finished'])
            self.assertEqual(data[0]['id'],data[1]['id'])
            self.assertEqual(data[0]['tool'],'lab_hypothesis')
            self.assertEqual(data[1]['error'],False)
            self.assertNotIn('args',json.dumps(data))

if __name__ == '__main__':
    unittest.main()
