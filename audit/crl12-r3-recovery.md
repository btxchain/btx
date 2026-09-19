# Extra High review R3 — recovery

Tree: `/home/administrator/btx-0.34.7-private`  
Branch: `feat/0.34.8-modelnet-first-run`  
Method: implementation vs spec only. No compile, ninja, `test_btx`, production `btxd`, commit, or push.  
Spec: `doc/modelnet/crl12/02_Neutral_Provider_and_Institutional_Spec.md` §§6, 10.3, 15–16; OPERATIONS `getPositionSnapshot`, `cancelLayerJob`, import commit; CR12-POSITION, CR12-RECOVERY, CR12-IMPORT-06/07, J08, J17, J19.  
Engine: position ingest/snapshot and jobs/import in `hcp_crl12_engine.inc.cpp`; `PersistObj` / `Restore` in `hcp_engine.cpp`.  
Native tests: `modelnet_cr12_recovery_tests.cpp`, `position_tests.cpp`, `import_tests.cpp`, `projection_tests.cpp`, journeys J08/J17/J19.

## Verdict

In-process, same-body replay vs different-body `OBSERVATION_CONFLICT`, mapping-digest CAS on import commit, and `Crl12SetEnabled(false)` → `PROFILE_UNSUPPORTED` while CR11 capital remains, all exist and have Boost cases.

Restart recovery is **not implemented**: `PersistObj` dumps CR12 maps and `cr12_enabled`; `Restore` ignores them. `Handle` never calls `Persist()`. Jobs succeed synchronously, so cancel cannot meet §10.3. Snapshot `as_of` / `observed_cutoff` are defaulted, and valuations are not cutoff-filtered (see R2-02). Native “recovery” cases mostly 404 fake job ids or construct a **new** `Lab()` engine. **Fix persist+restore and cancel-or-return-committed now.** Document process crash, DB failover, 10m lab, and incomplete TCP staging as **HONEST_NOT_RUN**. Do not fake a 10m lab.

---

## Findings

### R3-01 BLOCKER — persist writes CR12 state; Restore does not read it; Handle never persists

**File:line:** dump `hcp_engine.cpp:2038-2084` (`cr12_enabled`, `crl12_positions_map`, jobs, pos_hash, imports, …); restore `2098-2114` (only `enrolled`, `cr11_outstanding`, `cr11_lifetime_spent`); `Persist()` `2087-2096`; `Create` restore-on-dir `479-483`. No `Persist()` from `Handle` / `HandleCrl12Locked`. Spec §15: persist accepted manifests and immutable records before publishing cursors; CR12-RECOVERY / J19: disable v1.2 effects after restart with read evidence intact.  
**Actual:** if `persist_dir` is set and someone calls `Persist()`, the file contains maps. Next `Restore()` leaves `cfg.cr12_enabled` at **Create config** (hcp.h default `false`, funding lab `true`) and empty `crl12.*`. Lab tests use empty `persist_dir` (`Persist` no-ops).  
**Native tests:** `cr12_recovery_*` never call `Persist`/`Restore`. `cr12_recovery_01` builds a **second** `Lab()`. `cr12_recovery_07` / `j19` toggle `Crl12SetEnabled(false)` in **the same process**. **Restart persist of `cr12_enabled` + positions: not covered.**

### R3-02 BLOCKER — snapshot/projection cutoffs are optional defaults; valuations ignore them

**File:line:** GET positions `hcp_crl12_engine.inc.cpp:474-476` (`empty() ? cfg.clock_ms : stoll`); projection POST `721-722` `J64(..., cfg.clock_ms)`. OPERATIONS `getPositionSnapshot`: **requires** `as_of` and `observed_cutoff`; continuation pinned to both. Spec §6.1, schema `ProjectionRequest.required` includes both (`CognitiveReserveLayer.schema.json:2454-2457`). OpenAPI marks query params `required: false` (`openapi-v1.2.yaml:5859-5868`) — weaker than OPERATIONS; engine followed the weak file.  
**Actual:** omitted cutoffs become “now”. Aggregate applies cutoffs to **positions only** (R2-02). Stored projection objects are frozen copies (good for GET-by-id); a **new** projection with an old cutoff still sees all current marks.  
**Native tests:** `cr12_position_03` passes `as_of` only (observed defaults). `cr12_position_04` / `j08` pass both and check item **counts** (all rows in window, not latest sequence). `cr12_projection_05` repeats the same cutoff strings. Missing-param rejection **not covered**.

### R3-03 MAJOR — replay identity is HTTP-batch hash, not observation body ID; hash is written before publish

**File:line:** `hcp_crl12_engine.inc.cpp:406-424, 453-457`. Spec §6.2: same source/generation/sequence + identical body ID = replay; different body ID = `OBSERVATION_CONFLICT` + quarantine. Batch ingest is atomic; no partial watermark.  
**Actual:** `h = HashBody() + "|" + i` (`HashBody` = SHA-384 of the **entire request body**). Same logical row in a different batch envelope conflicts. On conflict mid-batch, earlier `pos_hash` / `pos_source_seq` are already updated (`453-454`) then `return Err` **before** `positions` publish (`456-458`). Retry of the same batch: earlier rows `continue` (not staged), conflict row still 409, **those sequences never publish**. `one_invalid` is a body flag checked **before** the loop (`402-404`), not a real invalid row.  
**Native tests:** `cr12_position_01` same full body twice → count 1 (happy path). `cr12_position_02` different quantity → `OBSERVATION_CONFLICT` + break. `cr12_position_07` uses `one_invalid`. Mid-batch conflict and wrapper-hash: **not covered**.

### R3-04 MAJOR — latest sequence is not selected; corrections double-count in metrics

**File:line:** GET snapshot `478-486` appends every row with `eff<=as_of && rec<=observed`; `CLOSED` dropped unless `view=historical`. Spec §6.1: within a source stream, select the latest applicable sequence; a future-effective higher sequence must not displace prematurely.  
**Actual:** listing returns orig **and** correction (`position_04` expects size 2 at later cutoff). `Aggregate` counts both if both OPEN and eligible. `j08` freezes old projection id (object identity) but GET positions at `observed_cutoff=2000` expects **2** rows for one lot.  
**Native tests:** encode listing-all, not supersession. Partial coverage of bitemporal **filters**, not of current-holdings selection.

### R3-05 MAJOR — `cancelLayerJob` 409s committed work; there is no in-flight job

**File:line:** `hcp_crl12_engine.inc.cpp:293-303`; `NewJob` `93-105` always `status=="SUCCEEDED"` / `committed=true` for projection, import, export, scenario, adapter. Spec OPERATIONS cancel: cancel before commit **or return the already committed result**; §10.3: once the publication marker exists, return the committed result rather than claim no effect. CR12-RECOVERY-02/03.  
**Actual:** unknown id → 404. Known succeeded job → `409 JOB_ALREADY_COMMITTED` (`hcp_types.h:162`), not the Job/import body. Client never sees `job_id` (R1-05). Cancel cannot run “before commit”. Does not touch CR11 capital jobs (good).  
**Native tests:** `cr12_recovery_02` cancel `job-running` → 404, import still `VALIDATED`. `cr12_recovery_03` cancel `job-committed` → 404 **or** `JOB_ALREADY_COMMITTED`; import GET still `PUBLISHED`. `j17` cancel `job-missing` 404 + HonestNotRun in-flight cancel. **Real cancel path not covered.**

### R3-06 — mapping CAS on import commit (native, with a hole)

**File:line:** `hcp_crl12_engine.inc.cpp:895-899`. Spec CR12-IMPORT-06: commit under another mapping digest is CAS reject.  
**Actual:** mismatch and **non-empty** new digest → `MAPPING_CAS`. Empty `mapping_digest` on commit (`!mapping.empty()`) **skips** CAS and publishes. Repeat commit of `PUBLISHED` returns the same object (`901-902`).  
**Native tests:** `cr12_import_06` mismatch `'e'` vs `'f'` — **covered**. Empty-digest skip: not covered. `cr12_import_08` idempotent commit — covered in-process. Crash-before/after marker (IMPORT-07): **HONEST_NOT_RUN**.

### R3-07 MINOR — staging accepts any complete in-process body; no declared hash at stage

**File:line:** `hcp_crl12_engine.inc.cpp:847-859`. Spec §10.2: verify declared length/SHA-384 **before** returning `StagedChunk`; incomplete upload leaves no handle; max 16 MiB.  
**Actual:** hashes whatever arrived; always 201; stores `HexStr` in a field named `bytes_b64`. Digest check is on **validate**, if the client sends `digest`. Incomplete TCP / restart orphan cleanup is not modeled.  
**Native tests:** `cr12_import_01/02` stage then validate. `cr12_recovery_01` validate missing chunk 404 on a fresh engine — not a crash mid-hash. Process incomplete upload: **HONEST_NOT_RUN**.

### R3-08 NOTE — `cr12_enabled` off blocks v1.2 routes in-process; persist will not keep that across restart

**File:line:** gate `hcp_crl12_engine.inc.cpp:5-7`; `Crl12SetEnabled` `hcp_engine.cpp:2808-2809`. Spec: persisted v1.2 data remains readable for reconcile when new effects are disabled; old capital recovery remains.  
**Actual:** disable in memory → all `/layer/` and `/institutional/` including **GET** return `PROFILE_UNSUPPORTED` (no read/reconcile path). CR11 `/capital/*` and `/extensions/cognitive-reserve` still work (`recovery_07`, `j19`). After a true restart, R3-01 would **re-enable** from lab config and **drop** positions.  
**Native tests:** same-process disable covered. Restart + read-only reconcile: **not covered**. GET-while-disabled for historical CR12 records: **not implemented**.

### R3-09 NOTE — outbox “failover” is the HCP lab outbox, not CR12 observation durability

**File:line:** `cr12_recovery_04` uses `CrashOutbox` / `RecoverOutbox` / `DeliverEventDuplicates` after a position POST. Spec CR12-RECOVERY-04: accepted observation + pending outbox, one published event.  
**Actual:** position maps are already in `crl12.positions` before outbox recovery. Duplicate deliver does not re-apply observations.  
**Native tests:** existence of GET after recover — not DB/process failover. **HONEST_NOT_RUN** as catalogue RECOVERY-04.

### R3-10 NOTE — mapping “rollback” is two export manifests, not a stored snapshot re-export

**File:line:** `cr12_recovery_08` two POSTs `/institutional/exports` with different `mapping_digest`; GET old id still `'a'`. Spec CR12-RECOVERY-08: return to previous mapping, re-export stored snapshot, versions explicit.  
**Actual:** in-memory export objects keyed by id. No mapping generation on the snapshot, no re-export of the same projection under old mapping. Weak native stand-in.

---

## What is actually covered natively

| Topic | Result |
|---|---|
| Exact same HTTP body replay | `position_01` count stays 1 |
| Different body, same source key | `position_02` `OBSERVATION_CONFLICT` |
| `as_of` hides future-effective | `position_03` (observed defaulted) |
| Recorded-time window includes later correction **as extra row** | `position_04`, `j08` |
| CLOSED hidden unless `view=historical` | `position_05` |
| Mapping digest mismatch on commit | `import_06` |
| Disable v1.2, CR11 still serves | `recovery_07`, `compat_06`, `j19` |
| `JOB_ALREADY_COMMITTED` on a real job id | **No** (tests use missing ids) |
| Persist/restore `cr12_enabled` + positions | **No** |
| 10m lab | `j17` HonestNotRun unless `BTX_CR12_10M_LAB` |
| Process crash / DB failover / incomplete chunk | **HONEST_NOT_RUN** |

`cr12_projection_07` / `j17` 100k `Crl12LoadSynthetic` is an in-memory map fill, then a signed projection that stuffs `position_refs` of size 100000 (spec §8: do not put the book in a 1 MiB signed body). That is not a streaming recovery lab.

## Fix now vs HONEST_NOT_RUN

**Fix now**

1. `Restore()` must apply `cr12_enabled` and the dumped `crl12_*` maps (or stop writing them). Call `Persist()` after accepted CR12 commits, or document that persist_dir is unused and fail tests that claim restart.  
2. Require `as_of` and `observed_cutoff` on snapshot and projection; apply both to positions **and** valuations; select latest sequence per economic key.  
3. Hash canonical observation bytes (body id), not the HTTP batch wrapper; apply `pos_hash` only after atomic publish.  
4. Cancel: in-flight → CANCELLED; after commit → return the committed Job/import (200), not only `409 JOB_ALREADY_COMMITTED`. Return `job_id` from async creates (R1-05).  
5. Mapping CAS: empty digest must not skip the compare.  
6. When `cr12_enabled` is false, keep **GET** of already accepted CR12 records for reconcile (spec §4), while blocking new effects.

**HONEST_NOT_RUN**

- CR12-RECOVERY-01 incomplete chunk after process kill.  
- CR12-RECOVERY-04 database/process failover and durable outbox consumers.  
- CR12-RECOVERY-09 export backpressure vs finance capacity (32 synthetic rows + `/health` is not that lab).  
- CR12-IMPORT-07 crash around commit marker.  
- J17 10-million-row institutional lab (`BTX_CR12_10M_LAB` unset).  
- J19 Core v3/v4 **package bytes** and consensus isolation beyond the `package_core_version` field.
