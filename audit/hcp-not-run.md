# HCP honest NOT_RUN list (0.34.8-dev)

This file records gaps that **must not** be reported as PASS. Native Boost
cases and process E2E **scripts** can exist without closing these rows.
This documentation session did **not** compile, did **not** run
`test_bitcoin`, and did **not** run `test_runner.py`.

In-process `OAUTH_LAB` (`LabAuthorize` / `LabToken` / `LabDpop` inside
`HcpEngine`) is **not** a live CEX identity provider.

## Live partner / hardware (always NOT_RUN here)

| Gap | Why it is still NOT_RUN | Closest in-tree stand-in (not a substitute) |
|---|---|---|
| Live CEX IdP | No partner issuer, browser sessions, or production token metadata | `OAUTH_LAB` in `src/test/modelnet_hcp_auth_tests.cpp` |
| Live custody HSM | No hardware signer, no production custody adapter | `HcpFundingLabPreset` + `BTX_NATIVE_TEMPLATES` lab in CUST/INTENT tests |
| Live CUDA DMA | No GPU transfer, no attestor GPU, no isolated CUDA worker for HCP | `hcp_local_06_cancel_under_dma` (`LEASE_FENCE` without a device) |
| Real browser portal vs live gateway | `hcp-portal/index.html` is a static shell | `hcp_j11_fleet_browser_journey` (in-process enroll/confirm/revoke) |
| Packet capture on a real NIC | PRIV-01 uses in-engine `TrafficCapture()` | `hcp_priv_01_prompts_stay_local` |
| Two independent production providers | Lab `SwitchProvider` / two `btx-hcpd` loopbacks | `feature_modelnet_hcp.py` (loopback only) |

## Build / product bars that remain NOT_RUN

| Gap | Honest note |
|---|---|
| `WITH_MODELNET=OFF` second cmake tree | Disk policy forbids a second full tree. `hcp_ops_02_money_only_regression` only asserts the version string contains `0.34.8`. Use `contrib/modelnet/check-with-modelnet-off.sh` grep/TU check; that is not a second Release tree. |
| F2 wallet-signed fail-closed | Not exercised as a live wallet signature path in HCP tests |
| `-modelindex` | Not an HCP proof |
| `BUILD_GUI` | `BUILD_GUI=OFF` in this compile policy. Qt Models/HCP UI is not claimed. |
| 400GiB payload | No large-fixture HCP run |
| uTP | Not HCP transport; not claimed |
| QUIC | **NONSHIPPING**. Do not advertise. |
| torrentd | Not an HCP proof |

## Spec-mandated environments vs lab

The acceptance catalogue (`doc/modelnet/hcp/ACCEPTANCE_TESTS.md`) still names
environments this tree has **not** run:

- AUTH: “real configured OAuth test identity provider” — **NOT_RUN** (lab only)
- CUST: “actual supported signer” / live HSM — **NOT_RUN**
- LOCAL-06: “active GPU transfer” — **NOT_RUN** (fence logic only)
- CHAIN: “native BTX test network with controllable reorgs” as a **process**
  regtest observer — **NOT_RUN** (in-process `SetNativeConfirmations` /
  `InjectReorg` only)
- LEDGER: “real partner ledger adapter” — **NOT_RUN** (in-process account map)
- FLEET: “real browser + owner-only client connector” — **NOT_RUN**
- OPS-04: load test with held-down native dependency — **NOT_RUN**
- OPS-05: live process/keys beside isolated prefix — **NOT_RUN** (must not
  touch production `btxd`)
- J03 release funding on a real test-network native transaction — **NOT_RUN**
- J06 refund to a custodial beneficiary on chain — **NOT_RUN**
- J10 restore from documented HSM/ledger backups — **NOT_RUN** (engine
  `Persist`/`Restore` only)

## What *is* present (still not live PASS)

- 132 unique Boost case names in `src/test/modelnet_hcp_*_tests.cpp`
- Process E2E scripts: `test/functional/feature_modelnet_hcp.py`,
  `test/functional/feature_modelnet_hcp_journeys.py`
- Reference simulator: `contrib/modelnet/hcp-reference/` (`SIMULATION_ONLY`)

See [hcp-evidence.md](hcp-evidence.md) for the per-ID map and
[hcp-journeys.csv](hcp-journeys.csv) for J01–J12 tiers.
