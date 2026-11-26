# BB-Code profile

Read program rules and the reviewed code asset policy before treating a repository as authorized. Confirm the checkout origin and revision using `lab_code_status`; if provenance cannot be established, ask the user rather than assuming permission. Keep analysis and verification local, isolated and non-production.

Use bounded file reads and targeted tests; do not ingest entire repositories when a symbol or small module suffices. Distinguish demonstrated effects from plausible but unverified impacts. Check for prior art before declaring novelty. Record code revision, file locations, artifacts and negative controls with each finding, and keep original checkouts clean.

Only promote general, non-target-specific methodology after offline review. Do not include secrets or private source in shared skills. Finding reports remain local drafts for human review.
