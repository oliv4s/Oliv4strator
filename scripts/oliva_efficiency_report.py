#!/usr/bin/env python3
"""Usage: python scripts/oliva_efficiency_report.py --metrics ... [--timeline ...]."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness.efficiency.telemetry import from_files
from harness.efficiency.watch import summarize


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--metrics", type=Path, required=True)
    p.add_argument("--timeline", type=Path)
    p.add_argument("--repo", type=Path)
    p.add_argument("--outcome", choices=["unknown", "completed", "partial", "failed"], default="unknown")
    p.add_argument("--output", type=Path)
    opts = p.parse_args()
    result = from_files(opts.metrics, opts.timeline, opts.outcome)
    if opts.repo:
        result["mcp_watch"] = summarize(opts.repo)
    printed = json.dumps(result, indent=2, ensure_ascii=False)
    if opts.output:
        opts.output.write_text(printed + "\n", encoding="utf-8")
        print(f"Report saved to: {opts.output}")
    else:
        print(printed)


if __name__ == "__main__":
    main()
