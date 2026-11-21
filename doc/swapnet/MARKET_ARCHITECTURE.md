# Native open-market extension

The maintained SwapNet engine remains responsible for exact bilateral HTLC negotiation, native PQ signing, independent BTC/EVM verification and durable recovery. The market extension is a subclass of its application layer and adds public offers, finite capacity, modes, previews, invitations and opt-in receipts. It does not fork the signing or settlement implementation.

Data path:

```
Atlas native review / CLI
        | authenticated RPC principal
        v
Market Application -> PublicMarket / Preview / Participation
        | exact requester-bound legacy quote + owner mandate
        v
Maintained Coordinator -> native wallet + independent BTC / EVM drivers
        | immutable operations / preimage / fee caps / finality
        v
Actual chain contracts and fixed-beneficiary recovery
```

Transport path:

```
BTX peer connection -> SwapNet bounded transport --\
                                                   > btxd authoritative shared service core
ModelNet strict PQ1 -> supervised helper -> IPC ---/
```

The common core handles service admission, byte accounting, public cache mirrors and route alternatives. Protocol-specific codecs, signatures and semantic journals stay within their service. No ModelNet method has wallet authority. Public records are untrusted until their respective adapter verifies them.

Atlas public reads use its explicit native read allowlist. New mutation methods go through native prepare/execute review. The startup invitation inbox stores only bounded untrusted text; it cannot dial without the connection review. Browser/demo execution is forbidden.

See PUBLIC_MARKET.md for capacity semantics, MIGRATION_AND_RECOVERY.md for schema/rollback behavior, and the machine-readable QA report for evidence. The presence of this architecture document does not certify every native path has been built or executed.
