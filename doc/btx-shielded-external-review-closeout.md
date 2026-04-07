# BTX Shielded External Review Closeout

## Purpose
This document defines how external cryptographic-review and proof-focused
red-team findings should be returned, triaged, and closed out before DoD 8 can
be considered satisfied.

It does not replace the external review or external campaign. It standardizes
how their output should be captured once they occur.

## Required Inputs
- The external cryptographic review report
- The external red-team or adversarial proof-focused testnet report
- Exact commands and environment details for each reported issue
- Returned logs, corpora, malformed payloads, traces, and hashes
- A severity classification for each finding

## Required Closeout Rules
1. Every returned finding must receive a stable report id.
2. Every critical or high-severity finding must be either:
   - fixed and revalidated, or
   - proven not applicable with attached evidence.
3. Every claimed verifier disagreement, consensus issue, or malformed-proof
   success path must have an attached deterministic reproduction.
4. The final sign-off record must state explicitly whether DoD 8 is satisfied.
5. Tracker and readiness docs must be updated to reflect the actual external
   evidence, not assumptions about what reviewers probably found.

## Recommended In-Repo Intake Path
- Generate an intake packet with:
  - `python3 scripts/m24_shielded_external_findings_intake.py --output-dir /tmp/btx-m24-external-findings-intake --source-packet /tmp/btx-m23-external-redteam-packet --audit-bundle /tmp/btx-m20-audit-handoff-bundle --hosted-run-dir /tmp/btx-m22-remote-redteam-run9 --hosted-validation-dir /tmp/btx-m26-remote-validation-run2`
- The generated packet preserves repo-relative `doc/`, `scripts/`, and
  `infra/` paths, so the copied `scripts/m25_shielded_external_closeout_check.py`
  can be run directly from the unpacked packet root
- Include the latest hosted `m26` validation baseline whenever it exists so
  external findings can be compared against the same simulated-testnet /
  proof-size / TPS evidence the repo currently relies on
- Put incoming reviewer reports in `received/`
- Put returned corpora, traces, and logs in `received/artifacts/`
- Use `templates/findings_template.json` and `templates/finding_template.md`
  to normalize reports into `received/findings.json`
- Record the final operator decision in `closeout/signoff_record.md`
- Record per-finding remediation in `closeout/finding_resolution_log.md`
- Record machine-readable closeout state in `closeout/signoff_status.json`
- Validate the populated packet with:
  - `python3 scripts/m25_shielded_external_closeout_check.py --intake-dir /tmp/btx-m24-external-findings-intake`

## Minimum Evidence For A DoD 8 Closeout Claim
- External cryptographic review completed
- External adversarial proof-focused campaign completed
- No unresolved critical findings remain
- No unresolved high-severity findings remain
- Sign-off record and finding-resolution log are attached
- Machine-readable closeout summary passes `m25`
- Tracker and readiness matrix updated with the actual closeout evidence
