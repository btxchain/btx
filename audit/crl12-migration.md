# CRL/1.2 migration

v1.1 discovery `GET /extensions/cognitive-reserve` is unchanged.

v1.2 is a further negotiated extension at `GET /extensions/cognitive-reserve/v1.2`.

Disabling `cr12_enabled` returns `PROFILE_UNSUPPORTED` on layer/institutional routes. CR11 capital/reserve/funding recovery remains available.

`translatePortfolioInstruction` writes v1.1 `CapitalPlanV1_1` / `AllocationPlanV1_1` drafts only. `POST /capital/allocations/{id}/execute` remains the money path.

Jobs created by projection/import/scenario/adapter-validate are layer jobs. `cancelLayerJob` does not cancel HCP finance jobs.

No schema rewrite of stored v1.1 envelopes. Combined contract count: 84 preserved + 43 new = 127.
