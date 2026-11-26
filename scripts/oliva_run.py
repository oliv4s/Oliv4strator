#!/usr/bin/env python3
"""Start a local Codex or Claude session with a managed, isolated scratch folder.

This wrapper never performs external actions by itself. Finalization is an
explicit terminal step in the agent workflow via the oliva_artifact MCP tool.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness.efficiency import artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', required=True, dest='case_id')
    parser.add_argument('--client', choices=['codex', 'claude'], default='codex')
    parser.add_argument('--session', dest='session_id')
    parser.add_argument('--profile', help='Client profile; currently used by Codex')
    args = parser.parse_args()
    if args.client != 'codex' and args.profile:
        parser.error('--profile is only available for codex')
    session = args.session_id or 'run-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    state = artifacts.prepare(ROOT, args.case_id, session)
    env = os.environ.copy()
    env.update({'TMPDIR': state['workspace'], 'TMP': state['workspace'],
                'TEMP': state['workspace'], 'OLIVA_CASE_ID': args.case_id,
                'OLIVA_SESSION_ID': session, 'OLIVA_WORKSPACE': state['workspace']})
    argv = [args.client]
    if args.profile:
        argv += ['--profile', args.profile]
    print(f'Oliva session: {session} | workspace: {state["workspace"]}', flush=True)
    print('At task completion the agent should call oliva_artifact(action=finalize).', flush=True)
    try:
        return subprocess.call(argv, cwd=ROOT, env=env)
    except FileNotFoundError:
        print(f'Missing executable: {args.client}', file=sys.stderr)
        return 127
    # Never finalize on Ctrl-C/crash/normal process exit: explicit task-end
    # verification is required. Scratch remains intact for resumption.


if __name__ == '__main__':
    raise SystemExit(main())
