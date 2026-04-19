# BTX Shielded External Red-Team Window Guide

## Purpose
This document turns the in-repo audit artifacts into an operator-facing plan for
an invited external proof-focused red-team window. It does not replace the
independence requirement in Definition-of-Done item 8; it exists so operators
can hand external reviewers a consistent packet and a bounded execution model.

## Inputs
- `scripts/m20_shielded_audit_handoff_bundle.py`
- `scripts/m21_shielded_redteam_campaign.sh`
- `scripts/m22_remote_shielded_redteam_campaign.py`
- `scripts/m26_remote_shielded_validation_suite.py`
- `scripts/m24_shielded_external_findings_intake.py`
- `scripts/m25_shielded_external_closeout_check.py`
- `doc/btx-shielded-external-review-closeout.md`
- `infra/btx-seed-server-spec.md`

## Recommended Window Shape
- Use short-lived disposable infrastructure, not a shared permanent testnet.
- Keep the participant scope proof-focused:
  - malformed-proof rejection
  - verifier disagreement
  - transcript malleability
  - parser and serializer edge cases
  - resource-exhaustion behavior
- Keep at least one hosted baseline run on hand so participants can compare
  their results against known-good `m22` and `m26` outcomes. When packaging an
  older hosted baseline into `m23` or `m24`, the packet builders now
  normalize the copied hosted manifests so creator-machine local paths are
  rewritten to portable `<repo>`, `~/...`, or packet-relative forms.

## Operator Checklist
1. Regenerate the audit handoff bundle from the current branch tip.
2. Confirm the hosted malformed-proof wrapper and the hosted full validation
   suite still pass on disposable infrastructure.
3. Package the docs, scripts, and latest baseline artifacts into a single
   participant packet.
4. Share only the packet contents needed for the campaign; do not share
   unrelated operational secrets.
5. Require returned findings to include exact commands, corpora, logs, traces,
   and a clear success/failure statement.
6. Include the in-repo intake and closeout materials in the participant packet
   so the return path is explicit before the window opens.
7. Preserve repo-relative `doc/`, `scripts/`, and `infra/` paths in the
   unpacked packet so the bundled helper commands can be run directly from the
   packet root.

## Participant Expectations
- Attempt proof forgery, verifier disagreement, transcript malleability, and
  malformed-proof resource-exhaustion attacks.
- Preserve every generated malformed proof or corpus.
- Report whether attacks left mempool residue, triggered inconsistent rejection,
  or created consensus divergence.
- Return machine-readable evidence, not only narrative summaries.

## Closeout Criteria
- All participant submissions are archived with checksums.
- Any cloud resources created for the window are torn down.
- Findings and reproductions are fed back into the tracker and readiness matrix.
- Returned reports and artifacts are normalized through
  `scripts/m24_shielded_external_findings_intake.py` or an equivalent
  machine-readable intake path.
- The populated intake packet is checked with
  `scripts/m25_shielded_external_closeout_check.py` before any DoD 8 closeout
  claim is made.
- When using the generated packet directly, run those commands from the
  unpacked packet root so the bundled `doc/`, `scripts/`, and `infra/`
  references resolve without extra repo context.
- Launch status does not change until the external review and the external
  red-team window both complete with explicit evidence.
