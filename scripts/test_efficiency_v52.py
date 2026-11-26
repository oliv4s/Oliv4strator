"""Offline regression checks: research cannot become arbitrary network access."""
from __future__ import annotations
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness.efficiency import artifacts, approvals, research, output_manager
import codex_lab_mcp
import casebook
import codex_hook


class ResearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_nvd_compact_result_and_cached(self):
        fixture = {'vulnerabilities': [{'cve': {'id': 'CVE-2025-12345',
            'descriptions': [{'lang': 'en', 'value': 'Example synthetic finding.'}],
            'published': '2025-01-01'}}]}
        with patch.object(research, '_fetch_json', return_value=fixture) as fetch:
            one = research.lookup(self.repo, 'nvd', cve_id='CVE-2025-12345')
            two = research.lookup(self.repo, 'nvd', cve_id='CVE-2025-12345')
        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(one['cache'], 'miss')
        self.assertEqual(two['cache'], 'hit')
        self.assertEqual(one['records'][0]['id'], 'CVE-2025-12345')

    def test_invalid_inputs_rejected_without_traffic(self):
        with patch.object(research, '_fetch_json', side_effect=AssertionError('network happened')):
            invalid = [dict(source='nvd', cve_id='CVE-9999-ABC'),
                       dict(source='github_repo', repository='../../etc/passwd'),
                       dict(source='github_repo', repository='org/repo', keyword='target'),
                       dict(source='github_advisory', cve_id=''),
                       dict(source='google', keyword='anything'),
                       dict(source='nvd', keyword='x'),
                       dict(source='nvd', cve_id=None)]
            for opts in invalid:
                with self.subTest(opts=opts), self.assertRaises(ValueError):
                    research.lookup(self.repo, **opts)

    def test_github_advisory(self):
        with patch.object(research, '_fetch_json', return_value=[{
            'ghsa_id': 'GHSA-aaaa-bbbb-cccc', 'cve_id': 'CVE-2025-12345',
            'summary': 'Fixed in upstream', 'html_url': 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc'}]):
            got = research.lookup(self.repo, 'github_advisory', cve_id='CVE-2025-12345')
        self.assertEqual(got['count'], 1)
        self.assertEqual(got['records'][0]['cve_id'], 'CVE-2025-12345')

    def test_url_policy_blocks_arbitrary_hosts_and_paths(self):
        for url in ['http://api.github.com/advisories',
                    'https://example.org/advisories',
                    'https://api.github.com/repos/org/repo/contents/secrets',
                    'https://services.nvd.nist.gov/other']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                research._fetch_json(url)

    def test_no_redirects(self):
        with self.assertRaises(ValueError):
            research.NoRedirect().redirect_request(None, None, 302, 'redirect', {}, 'https://bad.invalid/')

    def test_cache_symlink_refused(self):
        (self.repo / 'work').mkdir()
        (self.repo / 'work' / 'research-cache').symlink_to(self.repo, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            research.lookup(self.repo, 'nvd', cve_id='CVE-2025-12345')


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.case, self.session = '192.0.2.42', 'run-001'
        self.root = Path(artifacts.prepare(self.repo, self.case, self.session)['workspace'])
        (self.root / 'large.txt').write_text('\n'.join('Example synthetic output ' + str(i) for i in range(150)))

    def tearDown(self):
        self.temp.cleanup()

    def test_summary_is_bounded(self):
        item = output_manager.inspect(self.repo, self.case, self.session, 'large.txt')
        self.assertLessEqual(len('\n'.join(item['lines'])), 1450)
        self.assertTrue(item['has_more'])

    def test_read_with_line_offset(self):
        item = output_manager.inspect(self.repo, self.case, self.session, 'large.txt',
                                     mode='lines', start_line=25, max_lines=2)
        self.assertIn('24', item['lines'][0])
        self.assertEqual(item['shown_lines'], 2)

    def test_read_rejects_escape(self):
        (self.repo / 'secret.txt').write_text('never read')
        for path in ['../../secret.txt', '/etc/passwd', '.oliva-workspace.json']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                output_manager.inspect(self.repo, self.case, self.session, path)

    def test_read_rejects_symlink(self):
        (self.root / 'alias.txt').symlink_to(self.root / 'large.txt')
        with self.assertRaises(ValueError):
            output_manager.inspect(self.repo, self.case, self.session, 'alias.txt')


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_counts_do_not_include_command(self):
        approvals.record(self.repo, 'Host secret.example fuera del alcance; solicita lab_scope')
        report = approvals.summary(self.repo)
        self.assertEqual(report['categories']['out_of_scope'], 1)
        self.assertNotIn('secret.example', (self.repo / 'work/efficiency/hook_denials.jsonl').read_text())
        self.assertEqual(report['native_codex_approvals'], 'not_observable')

    def test_hook_event_is_anonymized(self):
        (self.repo / 'scope.json').write_text(json.dumps({'target_ip': '10.10.10.10'}))
        old = codex_hook.ROOT
        codex_hook.ROOT = self.repo
        try:
            result = codex_hook.handle('pre', {'tool_name': 'Bash',
                     'tool_input': {'command': 'curl http://10.10.10.20/'}})
        finally:
            codex_hook.ROOT = old
        self.assertEqual(result['hookSpecificOutput']['permissionDecision'], 'deny')
        self.assertEqual(approvals.summary(self.repo)['hook_denials'], 1)

    def test_mcp_tool_contract(self):
        names = {item['name'] for item in codex_lab_mcp.TOOLS}
        self.assertTrue({'oliva_research', 'oliva_output', 'oliva_diagnostics'} <= names)
        self.assertEqual(codex_lab_mcp.call('oliva_diagnostics', {})['isError'], False)


class FinalizationTests(unittest.TestCase):
    def test_summary_survives_retries(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder)
            artifacts.prepare(repo, '192.0.2.55', 'run001')
            once = artifacts.finalize(repo, '192.0.2.55', 'run001')
            twice = artifacts.finalize(repo, '192.0.2.55', 'run001')
            report = repo / 'cases/192.0.2.55/session-reports/run001.json'
            self.assertTrue(report.is_file())
            self.assertTrue(once['report_saved'])
            self.assertTrue(twice['already_finalized'])
            doc = json.loads(report.read_text())
            self.assertEqual(doc['outcome'], 'completed')
            self.assertNotIn('recovery_path', doc)


if __name__ == '__main__':
    unittest.main()
