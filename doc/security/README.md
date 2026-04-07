# BTX Security Documentation

This directory is the stable entrypoint for BTX security hardening, audit
closeout, and forward-looking security work.

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

Detailed tracker:

- [../btx-security-fixes-20260328-tracker.md](../btx-security-fixes-20260328-tracker.md)

Directory policy:

- keep one stable summary file per active security program or unresolved item
- prefer durable filenames over `tmp-*` or `*-temp-*` trackers
- when a finding is closed, keep the closeout summary here and archive the
  implementation details into the code/tests rather than a temporary scratch
  file
