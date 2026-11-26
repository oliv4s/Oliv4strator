# Efficiency layer v2 (optional, client-independent)

This layer is intended for the existing **non-main** Oliv4strator optimizer-v1 branch. It does not change scope permissions, policy, legacy cases, `lab_bridge`, or client/provider configuration. No agent self-editing and no network operations are implemented.

## What's active and what's not

- `oliva_checkpoint`: explicit, compact, revisioned per-case continuity records under `work/efficiency/checkpoints/`. Each record contains only short IDs, evidence references and optional one-line notes. Source casebook and program policy remain authoritative; checkpoints confer **no authorization**.
- `oliva_visual`: digest and optional one-line observation for local screenshots under `cases/`, `work/`, `outputs/` or `evidence/`. Exact-byte duplicates can reuse a prior *human/model supplied note*, but visual similarity is not semantic equivalence. It **does not intercept** Codex `view_image` or automatically hide changed screenshots. Avoid invoking it for every first-time screenshot; use only when repeated visual observation is suspected.
- `oliva_progress`: on-demand, read-only review of patterns detected by the optional MCP watcher. No blocking, no automatic retries.
- `OLIVA_WATCH=1`: optional passive MCP tool instrumentation. Journals only salted signatures, tool names, UTC timestamps and result sizes under `work/efficiency/`. Logs never include prompt, argument strings, command text, HTTP bodies or image bytes. Default is **off**. Client-native `exec_command`, `view_image`, `write_stdin` are outside this instrumentation.
- `scripts/oliva_efficiency_report.py`: offline scorecard from previously exported, redacted Codex metrics/timeline. Cached input is included within input, not added twice. A reported success is **not** independently verified.
- Existing `oliva_context` and the profile-filtered MCP catalogue from v1 remain available. `lab_*` aliases remain for compatibility.
- Existing `oliva_eval.py` remains the quality gate. The next optimization cycle is **propose -> offline probe -> compare -> human review**, inspired by Nesicode, not automatic modification of authorization boundaries.

## Safe calls

A model may call `oliva_checkpoint` with `{"action":"save","case_id":"case-123","payload":{"state":"open","facts":[{"id":"f1","evidence_ids":["e1"]}],"decisions":[],"pending":[]}}`. It may later call `{"action":"load","case_id":"case-123","mode":"summary"}` after a compaction. Never copy raw tool logs, secrets or exploitation outputs into checkpoint notes.

For `oliva_visual`: `{ "case_id":"case-123", "image_path":"/path/inside/repo/cases/image.png" }` checks a digest. To record an observation: set `record:true` and optional `note:"No visible change in synthetic UI"`. Exact repeated bytes return the saved note. If the UI state or context may have changed, inspect the screenshot anyway.

MCP watch is optional and local:

```bash
OLIVA_WATCH=1 codex
python3 -c 'from pathlib import Path; from harness.efficiency.watch import summarize; print(summarize(Path.cwd()))'
```

Offline DeepSeek baseline (example):

```bash
python3 scripts/oliva_efficiency_report.py \
  --metrics /path/to/codex_metrics.json \
  --timeline /path/to/tool_timeline.json \
  --outcome completed --output /tmp/oliva-baseline.json
```

To compare model/client baselines, keep task, objective, authorized scope, tool versions, starting case state and grading rubric fixed. Distinguish token estimates from provider counters and invoices. For the local sample, much of the activity belongs to Codex native tools, which cannot be reduced solely by modifying this MCP.

## Security and limits

- Do not enable these tools on third-party assets without authorization. This extension itself sends no network traffic.
- `work/efficiency/` should be ignored by Git; it contains potentially sensitive engagement identifiers and analyst notes. Run `git status` before every commit.
- The v2 installer refuses `main`, a dirty worktree, unexpected anchors, existing files and a different optional `--expected-head` SHA. It backs up original files in ignored `work/efficiency-v2-upgrade-backup/` and supports rollback until edited.
- This is a **source-compatible overlay**, not a confirmed remote commit. Run the repo's existing tests and a live MCP handshake on your own feature branch before pushing.
