#!/usr/bin/env python3
"""List managed local sessions and preview/expire old quarantine safely."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from harness.efficiency import artifacts, workspace


def inventory(repo: Path, case_id: str | None = None) -> dict:
    """Read only validated markers; never read artifact contents or other /tmp files."""
    entries = []
    skipped = 0
    for location, state in (("temp", "active"), ("quarantine", "finalized")):
        home = Path(repo) / "work" / location
        if not home.exists():
            continue
        workspace._directory(home)
        for case_path in sorted(home.iterdir()):
            if case_id and case_path.name != case_id:
                continue
            if not case_path.is_dir() or case_path.is_symlink():
                skipped += 1
                continue
            for session_path in sorted(case_path.iterdir()):
                try:
                    workspace._directory(session_path)
                    marker = workspace._marker(session_path, case_path.name, session_path.name)
                    files, total, newest = workspace._scan(session_path)
                    entries.append({
                        "case_id": case_path.name,
                        "session_id": session_path.name,
                        "state": state if marker.get("state", state) == state else "review",
                        "file_count": max(0, len(files) - 1),
                        "bytes": total,
                        "retained": len(marker.get("retained", [])),
                        "last_modified_utc": datetime.fromtimestamp(newest, timezone.utc).isoformat() if newest else None,
                    })
                except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError):
                    skipped += 1
    return {"sessions": entries, "total": len(entries), "skipped_invalid": skipped}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="action", required=True)
    listing = sub.add_parser("list", help="read-only inventory")
    listing.add_argument("--case", dest="case_id")
    pruning = sub.add_parser("prune", help="preview by default; only --apply removes expired quarantine")
    pruning.add_argument("--min-age-days", type=int, default=artifacts.QUARANTINE_DAYS)
    pruning.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "list":
            result = inventory(args.repo, args.case_id)
        else:
            result = artifacts.prune(args.repo, min_age_days=args.min_age_days,
                                     dry_run=not args.apply)
            result["dry_run"] = not args.apply
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError) as error:
        print(f"Session maintenance: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
