# Cognitive Reserve v1.1 baseline freeze

HEAD at kickoff: `573b4aa41f26ea6c61a00ee6096c5ff4de319335` on `/home/administrator/btx-0.34.7-private`.

Package: `~/Downloads/BTX_CEX_Cognitive_Reserve_Framework_v1_1.zip` extracted untracked to
`/home/administrator/Documents/btxchain/.0348-crf-package.local/BTX_CEX_Cognitive_Reserve_Framework_v1_1/`.

## Frozen contracts

- HCP/1 34 operations and seven statements remain byte-stable. No Core v4, no second `HcpEngine`, no second customer ledger, no new downloader.
- Body-ID domain remains `BTX/HCP/<object_type>/v1` with BTX-PJSON1 + SHA-384. V1_1 names are an exact reviewed allowlist; underscores are not a general charset relaxation.
- Capacity: `max(0, min(E-P, R))` with checked integers. E excludes pending deposits, expected refunds, sibling-entity funds, forecast savings, cognitive holdings, and does not double-subtract existing holds.
- Human quorum counts distinct verified people. Family/group view is not debit authority. Refunds do not replenish lifetime mandate by default.
- AllocationPlan ≤32 legs, depth ≤16, reject cycles. Financial children reuse FinanceIntent; local children reuse CapabilityHandoff.

## Implementation map

| Piece | Location |
|---|---|
| Types / errors | `src/modelnet/hcp_types.h` |
| Capacity/TCO/DAG/quorum | `src/modelnet/hcp_cr11.cpp` |
| 50 REST ops | `src/modelnet/hcp_cr11_engine.inc.cpp` via existing `HcpEngine::HandleLocked` |
| Native cases | `src/test/modelnet_cr11_*_tests.cpp` (190 + 20 journeys) |
| Process E2E | `test/functional/feature_modelnet_cr11.py`, `feature_modelnet_cr11_journeys.py` |
| Specs | `doc/modelnet/crf/` |
| Schemas | `src/modelnet/crf/schemas/` |

`automatic_spend_atoms` stays 0. Isolated prefix only. No push/merge/tag/`IS_RELEASE`. Production attestor not replaced.
