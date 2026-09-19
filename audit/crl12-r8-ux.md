# CRL/1.2 R8 — SDK / UX / portal (lane F)

- **Tree:** `/home/administrator/btx-0.34.7-private`
- **Branch:** `feat/0.34.8-modelnet-first-run` @ `573b4aa41f26ea6c61a00ee6096c5ff4de319335`
- **Date:** 2026-09-17
- **Lane:** F (portal / Python+TypeScript SDK / desktop context) from `doc/modelnet/crl12/05_UX_and_Product_Playbook.md`
- **Compiled:** **no.** No ninja, no `test_btx`, no `hcp_engine.cpp` / `helper.cpp` / CMake / RPC edits.
- **Production `btxd`:** untouched.

## 0. Verdict

The in-tree SDK and offline portal now carry the package v1.2 product rules without a C++ rebuild:

| Requirement | Status | Evidence |
|---|---|---|
| Portal min 44px targets | **PASS** (static) | `label{min-height:44px`, `button,select` `min-height:44px` + `min-width:44px` |
| `aria-live` status | **PASS** (static) | `#notice` `role="status"` `aria-live="polite"` `aria-atomic="true"` |
| No network in prototype | **PASS** (static) | no `fetch(`, `XMLHttpRequest`, `http://`, `https://` |
| Family-group read-only | **PASS** (static) | `selectedIndex===2` refuses `draft`/`research`/`bind` |
| `body_id` SHA-384 domain | **PASS** (Python ↔ TS) | `BTX/HCP/{type}/v1` ‖ `0x00` ‖ LE64(len) ‖ canonical JSON |
| No `/rpc` | **PASS** | 43 catalogue paths; client rejects `genericRpc`/`/rpc` |
| No `executeAllocation` operation | **PASS** | not in catalogue; client method raises `SCOPE_DENIED` |
| `automatic_spend_atoms` = 0 | **PASS** | Python + TS constants and client fields |
| Desktop apply is view/draft | **PASS** | INSPECT/COMPARE → GET; DRAFT → `preparePortfolioInstruction` `execute:false` |
| Package `test_reference.py` | **PASS** 82 | in-tree and package copy |
| TypeScript tests | **PASS** 16 | node v24.12.0 `--experimental-strip-types --test` |
| Playwright interaction | **HONEST_NOT_RUN** | `playwright` not installed |
| Native `HcpBodyId` / engine Lab() | **coordinator compile** | `modelnet_cr12_{ux,sdk,desktop}_tests.cpp` |

Classification: **SDK/UX fillable work is closed at the Python/TS/HTML tier.** Native Boost cases still need one incremental `test_btx` rebuild.

## 1. What landed (exclusive paths only)

- `contrib/modelnet/crl12-portal/index.html` kept as a byte copy of `contrib/modelnet/crl12/ux/index.html`.
- Portal/UX: skip-to-content, 44px labels, `aria-atomic` on the live region. Still six destinations; family-group view remains read-only.
- SDK: typed Python (`python/btx_crl12.py`) and TypeScript (`typescript/src/client.ts`) plus root transport `crl_client.py` / `crl_client.ts` refuse `/rpc` and `executeAllocation`; `automatic_spend_atoms` stays 0. Default catalogue path now finds `crl12-sdk/schemas/operations-v1.2.json`.
- Desktop apply (`python/desktop_context.py`, `typescript/src/desktop_context.ts`) stays view/draft, no HTTP client.
- Copied package `scripts/test_ux_prototype.py` to `contrib/modelnet/crl12/scripts/test_ux_prototype.py` and pointed it at **both** in-tree HTML files. Static a11y always runs; Playwright is optional.
- New `contrib/modelnet/crl12-sdk/python/test_portal_a11y.py` (no extra pip, no `btxd`).
- C++ tests (`modelnet_cr12_{ux,sdk,desktop}_tests.cpp`) extended with the same HTML/SDK assertions and `NODE_NO_WARNINGS=1` on node spawns. **Not compiled this round.**

Did **not** add `test/functional/feature_modelnet_cr12_portal.py`: static unittest + optional Playwright covers the 0-node portal check without starting `btxd`.

## 2. Runs this round

Working directory unless noted: `/home/administrator/btx-0.34.7-private`.

| Command | Result |
|---|---|
| `cmp` portal vs `crl12/ux/index.html` | **HTML_MATCH** |
| `python3 -m unittest contrib/modelnet/crl12-sdk/python/test_{body_id,desktop_context,portal_a11y}.py -v` | **PASS** 30 |
| `cd contrib/modelnet/crl12-sdk && python3 python/test_*.py` (C++ spawn shape) | **PASS** |
| `python3 python/apply_desktop_context.py fixtures/desktop-context.example.json` | **PASS** INSPECT, `execute:false`, no `executeAllocation` |
| `python3 -m unittest contrib/modelnet/crl12/tests/test_reference.py -v` | **PASS** 82 |
| `python3 -m unittest tests/test_reference.py -v` in `.0348-crl12-package.local/BTX_Cognitive_Reserve_Layer_v1_2` | **PASS** 82 |
| `env NODE_NO_WARNINGS=1 node --experimental-strip-types --test src/body_id.test.ts src/desktop_context.test.ts` | **PASS** 16 (node v24.12.0) |
| `python3 contrib/modelnet/crl12/scripts/test_ux_prototype.py` | static **PASS**; Playwright **HONEST_NOT_RUN** (`No module named 'playwright'`) |
| `ninja` / `test_btx` | **not run** (this worker forbidden) |

Python↔TS `body_id` for `LayerExtensionProfileV1_2` matched in `test_python_ts_body_id_parity_if_node`. That is **not** native `HcpBodyId` parity.

## 3. HONEST_NOT_RUN

| Item | Reason |
|---|---|
| Playwright / Chromium interaction (`test_ux_prototype.py` browser half) | extra pip (`playwright`) absent; not installed |
| Native Boost `modelnet_cr12_ux_tests` / `_sdk_tests` / `_desktop_tests` | no C++ compile this round |
| Native `HcpBodyId` vs SDK SHA-384 (`cr12_sdk_01_spawn_body_id`) | needs `test_btx` + `MODELNET_CRL12_PORTAL_PATH` |
| Engine Lab() journeys inside those three files (entity scope, partial projection, analytics execute 401, draft instruction) | same compile |
| Production portal bound to live HCP | prototype is synthetic/offline by design (`05` §11) |
| WCAG lab with a screen reader | static + optional Playwright only |

Do not relabel the Playwright row PASS without a real Chromium run.

## 4. Coordinator compile leftovers

One incremental Release rebuild of **existing** `test_btx` (do not configure a second tree). Then:

```text
test_btx --run_test=modelnet_cr12_ux_tests
test_btx --run_test=modelnet_cr12_sdk_tests
test_btx --run_test=modelnet_cr12_desktop_tests
```

Those suites now also spawn:

- `python/test_portal_a11y.py` (ux_05)
- full TS `--test` when `node` is on PATH (sdk_06)
- `compute_body_id.py` / `.ts` against a native envelope (sdk_01) — this is the remaining **native SHA-384** proof

CMake already defines `MODELNET_CRL12_PORTAL_PATH` to `contrib/modelnet/crl12-portal/index.html`. Do not edit `CMakeLists.txt` for this lane.

`automatic_spend_atoms` stays 0. QUIC stays NONSHIPPING. Do not stop production `btxd`.
