# Extra High review R2 — metrics

Tree: `/home/administrator/btx-0.34.7-private`  
Branch: `feat/0.34.8-modelnet-first-run`  
Method: implementation vs spec only. No compile, ninja, `test_btx`, production `btxd`, commit, or push.  
Spec: `doc/modelnet/crl12/02_Neutral_Provider_and_Institutional_Spec.md` §§7–8, 13; `04_Whole_Portfolio_Integration_Guide.md` §6; `ACCEPTANCE_TESTS.md` CR12-METRIC / VALUE / EXPOSURE / J03 / J04 / J07 / J14.  
Engine: `Crl12MetricEligible` in `hcp_crl12.cpp`; `Aggregate` and exposure POST in `hcp_crl12_engine.inc.cpp`.  
Native tests: `modelnet_cr12_metric_tests.cpp`, `value_tests.cpp`, `exposure_tests.cpp`, journeys J03/J04/J07/J14.

## Verdict

Mandate **filters** for AUM vs AUC vs AUA vs capability exclusion are present and the Boost cases check `eligible_count`. That is the only solid native slice.

The aggregator does not sum bound valuations, does not select one economic position, does not honor `DIRECT_ONLY` vs look-through, does not apply valuation `(as_of, observed_cutoff)`, and will emit a **complete `"0"`** for a fully priced non-zero book. `no_grand_total` is a constant JSON flag, not a computation. Several native cases **assert the wrong institutional count** (J03 AUC=2 for one lot; J07 NAV=3 for parent+children) or HonestNotRun the collapse. **Fix the aggregator now.** Do not treat CR12-METRIC-* as PASS. Do not invent a 10m-lab metric result.

---

## Findings

### R2-01 BLOCKER — `Aggregate` never adds money; complete books report `"0"`

**File:line:** `hcp_crl12_engine.inc.cpp:628-711`, especially `635` `amount = "0"` (never updated) and `708`  
`o.pushKV("value", known_zero && eligible > 0 ? "0" : (complete ? amount : UniValue()))`.  
**Expected:** Spec §7.2 MetricResult is nullable Money **or** count. A priced eligible set returns the summed accepted position values (exact decimal). Known zero is distinct from missing (`CR12-VALUE-01` vs `02`). Do not invent AUM (`04_Whole_Portfolio` §6; J14).  
**Actual:** valuations are scanned only for stale/FX/empty/zero **flags**. Non-zero strings are ignored. If `complete && !unpriced && !known_zero`, `value` is still `"0"`. A book marked 50 (`whole_position`) is a fabricated complete zero.  
**Native tests:** `cr12_value_01` checks known zero `"0"` (would pass). `cr12_value_05` posts `"50"` and **only** asserts `eligible_count==1`. `cr12_metric_08` empty book `"0"` is the legitimate complete-zero case. **Invented zero is not covered** — tests would go green.

### R2-02 BLOCKER — valuations are not bound to a position and ignore cutoffs

**File:line:** `hcp_crl12_engine.inc.cpp:659-684` inner loop over **all** `crl12.valuations` with no `position_ref` / `asset_ref` match and **no** `effective_at` / `recorded_at` vs `as_of` / `observed_cutoff`. Spec §7.1: value is the total of the **referenced** position; §6.1 / §8: only records effective by `as_of` and accepted by `observed_cutoff`.  
**Actual:** one STALE row poisons every eligible position (`complete=false`). One `"0"` sets `known_zero` globally. Mix `unpriced && known_zero` skips the UNAVAILABLE branch (`695`) and returns `"0"` (`708`). Late marks feed a new projection even when `observed_cutoff` is historical.  
**Native tests:** `cr12_value_09` creates two projections with the same cutoff strings; does not GET a frozen projection after a late mark and does not assert values. `cr12_recovery_05` shows **stored** projection JSON stays PARTIAL (object freeze), which is not bitemporal re-aggregation.

### R2-03 BLOCKER — AUM/AUC/NAV count every matching OPEN row (no economic key, no DIRECT_ONLY)

**File:line:** `hcp_crl12_engine.inc.cpp:648-658, 707`; eligibility `hcp_crl12.cpp:68-81`. Spec §6.3: one economic position, many observations; §7.3: FINANCIAL_NAV/AUM default `DIRECT_ONLY`; look-through **replaces** parent with children, never adds both. J03: AUC counts **one** beneficial position. J07: direct NAV counts parent once.  
**Actual:** `++eligible` per OPEN row passing `Crl12MetricEligible`. No `economic_position_key` / `beneficial_id` collapse. No `view`. Metric definition `basis` is stored (`hcp_crl12_engine.inc.cpp:618`) and **never read** by `Aggregate`. `FINANCIAL_NAV` includes `MANAGED|CUSTODY|OWNER` (`hcp_crl12.cpp:77`), so parent OWNER + child CUSTODY all count.  
**Native tests:**  
- `cr12_j03` **asserts `eligible_count==2`** for two CUSTODY rows of `lot-j03`, then HonestNotRun “not unique beneficial_id collapse”.  
- `cr12_j07` **asserts FINANCIAL_NAV `eligible_count==3`**.  
- `cr12_metric_06` only checks `no_grand_total` true on separate AUM/AUC posts.  
- `cr12_exposure_01` rejects client flag `add_parent_and_children`; does not run look-through in `Aggregate`.  
**Catalogue J03/J07 fail vs spec; Boost cases encode the bug.**

### R2-04 BLOCKER — `source_unavailable` is dead; source gaps do not make metrics incomplete by themselves

**File:line:** `hcp_engine.cpp:442` default `false`; persist dump `2080`; **no assignment** in `HandleCrl12Locked`. Sequence gap opens a break but still publishes (`hcp_crl12_engine.inc.cpp:426-431, 456-457`). `Aggregate` only short-circuits on `crl12.source_unavailable` (`639-647`). Spec §7.2 / CR12-METRIC-09: a required source that might conceal holdings must not claim complete zero or full coverage.  
**Actual:** gap + current valuations → `complete` can be true. `projection_06` / `metric_09` look PARTIAL because there is **no valuation** (`unpriced`), not because of the gap.  
**Native tests:** do not add a CURRENT mark after a gap and re-project. **Not covered.**

### R2-05 MAJOR — `mandate_required` is AUM-only on the definition; eligibility is a side table

**File:line:** define metric `608-620` `mandate_required = (kind == "AUM")`; `Crl12MetricEligible` `hcp_crl12.cpp:73-76`. Spec §7.2: AUM needs management mandate; AUC custody; AUA administration. `HCP_ERR_MANDATE_REQUIRED` (`hcp_types.h:159`) is unused.  
**Actual:** AUC/AUA **definitions** have `mandate_required=false` while eligibility still requires `CUSTODY` / `ADMIN`. `Aggregate` does not load `MetricDefinition` at all — only `Jstr("metric_kind","AUM")` on the projection request. Wrong kind with no mandate → `eligible_count=0` and, if no rows, **complete `"0"`** (`686-693`), which is empty-book zero, not `METRIC_INELIGIBLE`.  
**Native tests:** `cr12_metric_01/02/03/04` check `eligible_count` via the helper. `cr12_ux_03` / `j04` assert AUM `mandate_required` true; AUC definition flag **not** asserted. Covered as filter, not as definition/policy bind.

### R2-06 MAJOR — CAPABILITY_COUNT is mixed with money `"0"`

**File:line:** `hcp_crl12.cpp:70-71, 79`; Aggregate `681-684, 708`. Spec §7.2: count only for CAPABILITY_COUNT; value **or** count, never both populated; replica devices are not extra assets (CR12-METRIC-05). Schema `MetricResult` has nullable `value` and `count`.  
**Actual:** CAPABILITY/UTILITY skip missing-valuation unpriced (`681`). Then `value` is still `"0"` and `eligible_count` is the holding count. No `count` field. `UTILITY` is treated like capability (`70-71`); spec kinds are `CAPABILITY_RESOURCE`. Asset taxonomy is `FINANCIAL`/`CAPABILITY` vs spec `NATIVE_RESERVE` / `FINANCIAL_INSTRUMENT` / `CAPABILITY_RESOURCE`.  
**Native tests:** `cr12_metric_05` asserts `eligible_count==1` with 20 operational edges and one position — **covers replica-not-20-assets**. Does not assert `value` is null / `count` is set. `cr12_metric_04` capability excluded from AUM — covered.

### R2-07 MAJOR — `no_grand_total` is a constant, not overlap arithmetic

**File:line:** `hcp_crl12_engine.inc.cpp:645, 692, 702, 710` always `true`. Spec §7.2 / CR12-METRIC-06: display overlapping AUM and AUC separately; do not sum a combined balance.  
**Actual:** engine never sums AUM+AUC (there is no dashboard total). The flag cannot fail. Overlap still double-counts **inside** one kind (R2-03).  
**Native tests:** `cr12_metric_06` asserts the flag on two separate projections. Weak.

### R2-08 MAJOR — look-through graph is not used in projections

**File:line:** exposure POST `534-599` (cycle, depth 16, weight sum, residual bps); `Aggregate` never reads `crl12.exposures`. Spec §7.3 / CR12-EXPOSURE-01.  
**Actual:** graph validation is a write-time toy. Operational weights are skipped in the sum (`549-554`) — good. Financial look-through never substitutes children. Residual bps stored on the link object only (`594-597`).  
**Native tests:** `cr12_exposure_01..07,09` cover POST validation. `cr12_exposure_08` same `link_id` overwrites (one map key), not per-source identity. Projection look-through **not covered**.

### R2-09 MINOR — FX/stale/scenario-purpose gates are coarse but present

**File:line:** `661-672`, `hcp_crl12_engine.inc.cpp:495-516` valuation write. Spec CR12-VALUE-03/04/06.  
**Actual:** `REPLACEMENT_SCENARIO` skipped unless kind `SCENARIO_VALUE`. `STALE` sets incomplete. FX: any valuation currency ≠ `report_currency` without `accepted_fx` marks unpriced. Matching is not per position (R2-02). `std::stod` on exposure weights (`553`) is not exact decimal.  
**Native tests:** `cr12_value_02,03,04,06,08` cover the flags. `cr12_value_07` stores `"1.2500"`; no conversion vector. Exact rounding CR12-VALUE-07: **not proven**.

### R2-10 NOTE — empty complete book vs missing source

**File:line:** `686-693` no eligible rows + `complete` → `COMPLETE` `"0"` `eligible_count=0`. Spec CR12-METRIC-08 vs 09.  
**Actual:** empty map is treated as a verified empty book. There is no “expected sources” set, so an outage looks like empty complete unless unpriced rows exist. Combined with R2-04 this is dangerous.  
**Native tests:** `cr12_metric_08` empty AUM complete zero — matches 08, not 09.

---

## Eligibility helper (what is true)

`Crl12MetricEligible` (`hcp_crl12.cpp:68-81`):

| kind | included when |
|---|---|
| AUM | `mandate==MANAGED` and not CAPABILITY/UTILITY |
| AUC | `mandate==CUSTODY` |
| AUA | `mandate==ADMIN` |
| PLATFORM_ASSETS | ADMIN or PLATFORM |
| FINANCIAL_NAV | MANAGED or CUSTODY or OWNER |
| ACTUAL_COST | MANAGED or OWNER |
| CAPABILITY_COUNT | asset_kind CAPABILITY (and UTILITY via the first branch) |

Native `cr12_metric_01..04`, `j04` exercise AUM/AUC/AUA/capability exclusion **by eligible_count only**.

## HONEST_NOT_RUN

- Browser metric definitions (CR12-UX-03): HTML contains “AUM”/“AUC” strings under `MODELNET_CRL12_PORTAL_PATH`, not a dashboard.  
- J14 “technology vendor AUM is not invented”: native does not run a multi-client import mandate matrix beyond `eligible_count`.  
- 100k/10m **measured** aggregation: `cr12_projection_07` / `j17` load synthetic rows and count `position_refs` / `total_rows`; they do not check Money totals or peak memory. 10m is env-gated HonestNotRun in `j17`.  
- Package `test_reference.py` `metric()` is not native PASS.

## Fix now vs HONEST_NOT_RUN

**Fix now**

1. Bind each valuation to `position_ref`; filter both positions **and** marks by `(as_of, observed_cutoff)`; sum exact decimals once per economic key.  
2. Default AUM/NAV `DIRECT_ONLY`; look-through view replaces parent; never add parent+child; collapse duplicate source rows for one `beneficial_id` / economic key (J03).  
3. Stop returning complete `"0"` when priced values exist; CAPABILITY_COUNT → `count` set, `value` null.  
4. Wire metric definitions (kind, basis, `mandate_required` for AUC/AUA, valuation purpose) into `Aggregate`.  
5. Treat sequence-gap / missing expected source as incomplete (`source_unavailable` or break-driven coverage); do not rely on a flag that is never set.  
6. Delete or stop trusting `no_grand_total: true` as proof of CR12-METRIC-06.

**HONEST_NOT_RUN**

- CR12-METRIC-10 growth bridge (internal vs external) — `metric_10` uses mandate NONE vs MANAGED, not a performance/transfer ledger.  
- CR12-VALUE-07 pinned integer/decimal FX vectors.  
- CR12-PROJECTION-07 process memory budget; J17 10m lab (`BTX_CR12_10M_LAB`).  
- UX/browser partial-view and definition panels.
