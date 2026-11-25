# Harness modules and token budget

`AGENTS.md` is the short, always-on router. Profile documents under `harness/profiles/` are read *only* when the relevant scope/profile is active. The installer preserves the original AGENTS instructions under `harness/reference/AGENTS.original.md` for human migration and audit, not automatic prompt loading.

`oliva_context` is an optional read-only MCP tool returning an allowlisted, budgeted snapshot. It does not replace policy checks, and it does not remove or rewrite evidence. Call `lab_case`/`lab_memory` explicitly when the snapshot omits a fact you need.

Set `OLIVA_MCP_PROFILE=LAB`, `BB-Web`, or `BB-Code` **before starting** Codex/Claude to publish a smaller MCP tool catalog. Unset it to publish the full compatible catalog. For neutral tool names set `OLIVA_MCP_NAMES=generic` before startup (e.g., `oliva_case` instead of `lab_case`). The selected catalog is fixed for the MCP process lifetime; restart the client/MCP to switch profiles. Capability filtering is not a security boundary: the underlying host must separately enforce actual execution restrictions.

The `oliva_eval.py` script compares offline, synthetic/approved answer artifacts with expected evidence and assertions. Its quality gate is conservative: a cheaper answer is not preferred if required assertions or evidence are missing. It does not execute actions against targets and it does not change skills automatically.

Token counts from character length / 4 are **estimates**; inspect real Codex/Claude API usage or provider billing to measure true token consumption.
