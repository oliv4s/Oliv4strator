#!/usr/bin/env python3
"""Compare two sanitized Codex export metrics files offline; no network calls."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness.efficiency.benchmark import summarize, compare


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,required=True,help='codex_metrics.json from baseline run')
    parser.add_argument('--candidate',type=Path,required=True,help='codex_metrics.json from candidate run')
    parser.add_argument('--baseline-outcome',choices=['unknown','completed','partial','failed'],default='unknown')
    parser.add_argument('--candidate-outcome',choices=['unknown','completed','partial','failed'],default='unknown')
    parser.add_argument('--baseline-cost',type=float)
    parser.add_argument('--candidate-cost',type=float)
    parser.add_argument('--same-task',action='store_true',help='Only set when tasks/conditions really matched')
    parser.add_argument('--output',type=Path,help='write JSON comparison')
    opt=parser.parse_args()
    a=summarize(json.loads(opt.baseline.read_text(encoding='utf-8')),
                outcome=opt.baseline_outcome,cost_usd=opt.baseline_cost)
    b=summarize(json.loads(opt.candidate.read_text(encoding='utf-8')),
                outcome=opt.candidate_outcome,cost_usd=opt.candidate_cost)
    result=compare(a,b,same_task=opt.same_task)
    body=json.dumps(result,indent=2,ensure_ascii=False)+'\n'
    if opt.output:
        opt.output.write_text(body,encoding='utf-8')
        print('Comparison saved to',opt.output)
    else:
        print(body)

if __name__=='__main__':
    main()
