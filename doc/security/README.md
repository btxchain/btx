# BTX Security Documentation

This directory is the stable entrypoint for BTX security hardening, audit
closeout, and forward-looking security work.

Report BTX security issues to the BTX Development Team at `team@btx.dev`.

Use these files in the following order:

1. [current-status.md](current-status.md)
   - Current security status for the active codebase and hardening branch.
2. [hardfork-61000.md](hardfork-61000.md)
   - What the `61000` shielded hardening fork changes, and what stays
     backwards-compatible.
3. [roadmap.md](roadmap.md)
   - Remaining security-margin work and future upgrade lanes.
4. [findings/audit-20260328-closeout.md](findings/audit-20260328-closeout.md)
   - High-level closeout summary for the 2026-03-28 source audit.
5. [findings/pr134-20260401-lifecycle-followon-closeout.md](findings/pr134-20260401-lifecycle-followon-closeout.md)
   - Closeout for the later PR #134 lifecycle/operator-note follow-on review.
6. [findings/l12-pq128-parameter-upgrade.md](findings/l12-pq128-parameter-upgrade.md)
   - The remaining open PQ-128 parameter-set redesign item.
7. [../btx-security-audit-report-2026-06-06-reassessment.md](../btx-security-audit-report-2026-06-06-reassessment.md)
   - Reassessment of the June 2026 security report after the 125,000 shielded-sunset
     and MatMul nonce-seed hardening work.
8. [../btx-matmul-nonce-seed-v2-125000.md](../btx-matmul-nonce-seed-v2-125000.md)
   - Height-125,000 MatMul nonce-bound seed-v2 activation note.
9. [../btx-c002-lattice-review-2026-06-07.md](../btx-c002-lattice-review-2026-06-07.md)
   - Internal C-002 lattice-focused review of the post-123,000 SMILE2 verifier path.
10. [../../formal-verification/PLAN.md](../../formal-verification/PLAN.md)
   - Tiered formal verification of the shielded value-soundness stack:
     Tier 1 accounting firewall (turnstile / supply floor / velocity cap),
     Tier 2 verifier-relation binding (serial<->key, value/inflation), Tier 3
     reduction to Module-SIS. 21 machine-checked obligations plus a
     paper-rigorous `PROOFS.md` per tier; run `python3
     formal-verification/run_all.py`.

Detailed tracker:

- [../btx-security-fixes-20260328-tracker.md](../btx-security-fixes-20260328-tracker.md)

Directory policy:

- keep one stable summary file per active security program or unresolved item
- prefer durable filenames over `tmp-*` or `*-temp-*` trackers
- when a finding is closed, keep the closeout summary here and archive the
  implementation details into the code/tests rather than a temporary scratch
  file
