#!/usr/bin/env python3
"""CLI for per-case scratch workspaces. No automatic cleanup or global /tmp deletion."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness.efficiency import workspace


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=ROOT)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('init', 'inspect', 'retain', 'clean'):
        p = sub.add_parser(action)
        p.add_argument('--case', required=True, dest='case_id')
        p.add_argument('--session', required=True, dest='session_id')
        if action == 'retain':
            p.add_argument('--file', required=True)
            p.add_argument('--note', default='')
        if action == 'clean':
            p.add_argument('--apply', action='store_true')
            p.add_argument('--min-age-hours', type=float, default=24.0)
    a = parser.parse_args()
    if a.action == 'init':
        print(workspace.prepare(a.repo, a.case_id, a.session_id))
    else:
        function = {'inspect': workspace.inspect, 'retain': workspace.retain,
                    'clean': workspace.clean}[a.action]
        kw = ({'relative_file': a.file, 'note': a.note} if a.action == 'retain'
              else {'apply': a.apply, 'min_age_hours': a.min_age_hours}
              if a.action == 'clean' else {})
        print(json.dumps(function(a.repo, a.case_id, a.session_id, **kw), indent=2))

if __name__ == '__main__':
    main()
