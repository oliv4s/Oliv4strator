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

## Efficiency measurement v3 (offline, general-purpose)

**Why:** the first two DeepSeek Flash runs were different tasks. The second one completed
its objective for a *user-reported* $0.51, but their relative token consumption
cannot establish a causal improvement by the harness. In particular, native Codex
`exec_command`, `write_stdin`, and `view_image` remain outside the MCP layer.

### Checkpoint deduplication

`oliva_checkpoint` now returns `changed: false` and the unchanged revision for a
semantically identical save, instead of writing another checkpoint. An explicit,
stale `expected_revision` still fails. No authorization settings or scope records
are altered. Existing v2 checkpoint files stay readable; no migration is needed.

### Compare two exports without rerunning a target

```bash
python3 scripts/oliva_compare_runs.py \
  --baseline /path/to/first/codex_metrics.json \
  --candidate /path/to/second/codex_metrics.json \
  --baseline-outcome completed --candidate-outcome completed \
  --candidate-cost 0.51 --output /tmp/oliva-compare.json
```

If the verified invoice cost of the first run is unknown, omit `--baseline-cost`.
The report will show a null comparison for dollars rather than invent it.
Do **not** use `--same-task` for different lab machines. Reported outcomes are
not independently verified. Cost-per-success is meaningful only across comparable
batches that include failures; do not infer it from two successes.

### MCP startup preflight (static only)

```bash
python3 scripts/oliva_mcp_preflight.py --repo .
```

This checks whether the project-level `oliva_lab` command, Python entrypoint, and
working directory appear to exist. It does not start Codex or expose configuration
keys. If configured only at global level, `--config ~/.codex/config.toml` can be
used. Python 3.11+ is required for this optional TOML parser.

### Guardrails, token discipline and Nesicode comparison

- Prefer concise status summaries and references; expand details when necessary.
- Before rerunning a deterministic local operation, check whether an unchanged
  result already exists; do not suppress legitimate retries or changing state.
- Avoid repeated checkpoint writes unless the underlying facts/decisions changed.
- Preserve full evidence outside conversation context; never invent success.
- Use offline synthetic tests to evaluate improvements. Inspired by Nesicode's
  compare-and-review approach; **no autonomous self-modification or approval bypass**.
- Codex approval requirements are separate from agent initiative. Keep them in place.

## V4 - per-case temporary workspaces and MCP diagnostics

Scratch files for a session should use `work/temp/<case_id>/<session_id>/`, **not** the
shared global `/tmp`. The directory is local and Git-ignored. Its marker
`.oliva-workspace.json` records only the case/session identity and explicitly
retained artifacts. `scripts/oliva_workspace.py` supports:

```bash
# From repository root, before launching Codex:
CASE_ID=10.10.10.10
SESSION_ID=test-01
WORKSPACE="$(python3 scripts/oliva_workspace.py init --case "$CASE_ID" --session "$SESSION_ID")"
TMPDIR="$WORKSPACE" codex --profile deepseek

# Review, retain a necessary file, then preview cleanup:
python3 scripts/oliva_workspace.py inspect --case "$CASE_ID" --session "$SESSION_ID"
python3 scripts/oliva_workspace.py retain --case "$CASE_ID" --session "$SESSION_ID" --file sample.txt --note "Reviewed result"
python3 scripts/oliva_workspace.py clean --case "$CASE_ID" --session "$SESSION_ID"
# When the session is definitely over and after 24h by default:
python3 scripts/oliva_workspace.py clean --case "$CASE_ID" --session "$SESSION_ID" --apply
```

`TMPDIR` is inherited by child processes but does not redirect commands that
explicitly target `/tmp`. This code never scans or deletes existing global
`/tmp` files. Existing leftovers must be reviewed separately.

The cleanup is a deliberate operator action, not an automatic post-session step;
it refuses recent sessions, symlinks, hardlinks and unmanaged directories. Artifact
retention copies a reviewed file to `cases/<case_id>/evidence/retained-artifacts`
and records SHA-256 in the marker. Do not retain private keys, flags or secrets
in an export intended for sharing. Retained artifacts can still contain sensitive
material and should be treated as private local case data.

For debugging a stalled stdio MCP tool call, launch Codex with
`OLIVA_TRACE_MCP=1`. The local journal at
`work/efficiency/mcp_lifecycle.jsonl` records start/end timestamps, operation
IDs, names, duration and errors. It intentionally omits tool arguments and
responses. An unmatched `started` entry suggests an incomplete call, but does
not prove a deadlock or explain its root cause. `lab_hypothesis` updates use a
short bounded POSIX advisory lock and retry-safe duplicate detection.


## V5 - automatic task-end artifact lifecycle

V4's manual `retain` and `clean` remain available for compatibility, but the
**normal v5 path** is an MCP operation performed by the agent at verified
completion, without manual cleanup scripts:

1. Launch the client with `python3 scripts/oliva_run.py --case <case_id> --client codex --profile deepseek` to set `TMPDIR` and session IDs.
2. For a reusable file supported by a *real case evidence event*, call
   `oliva_artifact(action="register", file="proof.txt", disposition="retain", evidence_ids=["<real_event_id>"])`.
3. For clearly disposable scratch, use `oliva_artifact(action="register", file="intermediate.log", disposition="discard")`. Unknown or ambiguous files stay protected.
4. When the task ends, no subprocesses remain, and results are checked, call
   **once** `oliva_artifact(action="finalize", outcome="completed")`. If the
   case is left incomplete but the session is intentionally ending, use
   `outcome="partial"` or `"stopped"`. Repeating finalize returns the prior
   result instead of creating duplicate operations.

**What actually happens:** retained evidence is copied with SHA-256 into
`cases/<case_id>/evidence/retained-artifacts/`; unchanged explicit disposable
files are removed; everything else is atomically moved to
`work/quarantine/<case_id>/<session_id>/` and can be recovered. Quarantines
are eligible for expiry after **7 days** and are pruned on later finalizations;
there is no timer/background daemon. This is a bounded local filesystem
operation, not remote host cleanup.

**Failure and security semantics:** if Codex is interrupted or the agent omits
`finalize`, nothing is auto-deleted; old content remains in `work/temp`.
Refuse symlinks, hardlinks, device files, invalid paths, changed disposables,
missing/invalid evidence IDs, and tampered retained copies. Only registered
and unchanged disposables are deleted immediately. If retained evidence changes
since registration, finalization fails safely until it is re-registered.
No implicit approval escalation or bypass of Codex sandbox is performed.

Manual CLI inspection and emergency restore remain possible:

```bash
python3 scripts/oliva_workspace.py status --case <case_id> --session <session_id>
python3 scripts/oliva_workspace.py restore --case <case_id> --session <session_id>
```

Run `python3 -m unittest discover -s scripts -p 'test_*.py' -q` before committing.
The v5 lifecycle introduces no new LLM calls beyond the single end-of-task
MCP call and selective artifact registrations. Whether it saves tokens must
be validated against comparable tasks; unrelated lab difficulty changes do
not establish causality.
