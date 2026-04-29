# Shielded Audit Tracker (Historical Snapshot)

Date: 2026-03-20
Historical branch: `codex/smile-shared-ring-fix`
Historical PR: `#108`

This file records a March 20 point-in-time audit snapshot and is no longer the
current source of truth.

Current mainline status:
- `main` routes wallet-built deposit, direct send, mixed unshield, and note
  merge through `v2_send`
- `DIRECT_SMILE` is the live default direct-spend backend on `main`
- account-registry activation and future-proofed settlement slack are merged on
  `main`

Use these docs instead:
- `doc/btx-shielded-production-status-2026-03-20.md`
- `doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md`
- `doc/btx-smile-v2-transaction-family-transition-2026-03-23.md`
- `doc/btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md`

## Historical Snapshot

At the time of this note:

- multi-input `v2_send` SMILE ring mismatch had been fixed on branch head
  `36a19d103b`
- legacy direct-spend and unshield wallet construction remained MatRiCT-only
- transparent wallet send construction absorbed small post-sizing fee
  shortfalls from change instead of aborting with `Fee needed > fee paid`

That assessment was superseded by the later March 20-23 mainline work that
completed the shipped `DIRECT_SMILE` + committed-account-registry +
future-proofed-settlement launch surface.
