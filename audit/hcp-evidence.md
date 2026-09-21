# HCP evidence map (0.34.8-dev)

**Tree:** `/home/administrator/btx-0.34.7-private`  
**Spec:** `doc/modelnet/hcp/02_Hosted_Control_Plane_Implementation_Spec.md`  
**Catalogue:** `doc/modelnet/hcp/ACCEPTANCE_TESTS.md` (120 family cases + J01–J12)  
**This session:** documentation/audit only. Did **not** compile. Did **not** run
`test_bitcoin` or `test_runner.py`. A Boost **case name** below means the
unique `BOOST_AUTO_TEST_CASE` exists in source. It is **not** a recorded PASS
from an executed binary.

132 native cases: 15 families × 8 + J01–J12, in
`src/test/modelnet_hcp_*_tests.cpp`.

## Evidence tiers

| Tier | Meaning in this map |
|---|---|
| `NATIVE_UNIT` | Unique in-process Boost case exists (`HcpEngine` lab / codec). |
| `OAUTH_LAB` | Same process, in-engine issuer (`LabAuthorize` / `LabToken` / `LabDpop`). **Not** a live CEX IdP. |
| `CUSTODY_LAB` | Funding lab preset / native templates. **Not** a live HSM. |
| `PROCESS_E2E` | Functional script exists (`feature_modelnet_hcp.py` and/or `feature_modelnet_hcp_journeys.py`). Loopback `btx-hcpd` only. Script **not** executed this session. |
| `REFERENCE` | `contrib/modelnet/hcp-reference/` simulation. Never production evidence. |
| `NOT_RUN` | Required live/partner/hardware/second-tree environment is absent. |

`automatic_spend_atoms` stays **0**. QUIC stays **NONSHIPPING**.
Honest gaps: [hcp-not-run.md](hcp-not-run.md).

Process E2E coverage (scripts, not live CEX):

| Script | What it actually does |
|---|---|
| `test/functional/feature_modelnet_hcp.py` | Two `btx-hcpd` loopbacks; `GET /profile`; `btx-hosted walletless` JSON (`walletless=true`, `start_wallet=false`, `automatic_spend_atoms=0`); `POST /capabilities/search` |
| `test/functional/feature_modelnet_hcp_journeys.py` | Two gateways (A walletless, B `-finance=1`); J01 profile; J09/J12 second origin; J11 walletless finance HTTP ≥400; J03 unauthenticated quotes fail closed |

---

## HCP-FRM — Framing

Source: `src/test/modelnet_hcp_frm_tests.cpp`. Tier: `NATIVE_UNIT`.
Live CEX enrollment / WAN origin fetch: **NOT_RUN**.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-FRM-01 | `hcp_frm_01_canonical_statement_round_trip` | `HcpVerify`, `HcpBodyId`, `HcpCanonicalBody`, `DecodePjson1` | NATIVE_UNIT | — |
| HCP-FRM-02 | `hcp_frm_02_parser_differential_rejection` | `DecodePjson1` | NATIVE_UNIT | Independent SDK/API differential vs native not run as a third parser process |
| HCP-FRM-03 | `hcp_frm_03_domain_separation` | `HcpDomain` / envelope relabel | NATIVE_UNIT | — |
| HCP-FRM-04 | `hcp_frm_04_unknown_provider_self_signature` | `PreviewProvider` / enroll denied | NATIVE_UNIT | — |
| HCP-FRM-05 | `hcp_frm_05_operational_key_rotation` | `RotateOperationalKey` | NATIVE_UNIT | — |
| HCP-FRM-06 | `hcp_frm_06_origin_rebinding` | `FetchUrl` / origin change | NATIVE_UNIT | Live HTTP redirect **NOT_RUN** |
| HCP-FRM-07 | `hcp_frm_07_size_and_structural_bounds` | `HCP_MAX_BODY_BYTES` | NATIVE_UNIT | — |
| HCP-FRM-08 | `hcp_frm_08_role_separation_across_signatures` | `HcpVerify` role | NATIVE_UNIT | — |

## HCP-AUTH — Authentication

Source: `src/test/modelnet_hcp_auth_tests.cpp`.
Tier: `OAUTH_LAB` except AUTH-08 (`NATIVE_UNIT` redaction). **Live CEX IdP: NOT_RUN.**

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-AUTH-01 | `hcp_auth_01_authorization_code_pkce` | `LabAuthorize`, `LabCreatePkceChallenge`, `LabToken` | OAUTH_LAB | Live IdP / two browsers **NOT_RUN** |
| HCP-AUTH-02 | `hcp_auth_02_sender_constrained_token_theft` | `LabDpop`, thief `jkt` | OAUTH_LAB | Live DPoP/mTLS **NOT_RUN** |
| HCP-AUTH-03 | `hcp_auth_03_audience_enforcement` | `LabToken` `mcp_audience` | OAUTH_LAB | Live MCP audience **NOT_RUN** |
| HCP-AUTH-04 | `hcp_auth_04_scope_escalation` | `HcpEngine::Handle` 401 | OAUTH_LAB | — (lab scopes only) |
| HCP-AUTH-05 | `hcp_auth_05_tenant_object_isolation` | 404/401, no leak | OAUTH_LAB | — (lab accounts) |
| HCP-AUTH-06 | `hcp_auth_06_dpop_is_not_body_approval` | `expected_body_id` / INTENT_DIGEST | OAUTH_LAB | — |
| HCP-AUTH-07 | `hcp_auth_07_refresh_and_revocation` | `LabRevokeRefresh` | OAUTH_LAB | Live refresh rotation **NOT_RUN** |
| HCP-AUTH-08 | `hcp_auth_08_secret_leakage_sweep` | `ExportPublic`, `ChildRuntimeEnv`, `LogRedactionScan` | NATIVE_UNIT | Production log pipeline **NOT_RUN** |

## HCP-GRANT — Authority

Source: `src/test/modelnet_hcp_grant_tests.cpp`. Tier: `NATIVE_UNIT`.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-GRANT-01 | `hcp_grant_01_handoff_without_local_grant` | `AcceptHandoff`, `HCP_ERR_LOCAL_GRANT_REQUIRED` | NATIVE_UNIT | — |
| HCP-GRANT-02 | `hcp_grant_02_finite_first_use_convenience` | `EnsureLocal` twice | NATIVE_UNIT | — |
| HCP-GRANT-03 | `hcp_grant_03_financial_policy_cannot_launch` | `HCP_ERR_POLICY_FINANCE` | NATIVE_UNIT | — |
| HCP-GRANT-04 | `hcp_grant_04_local_grant_cannot_spend` | `local_grant_id` on `/finance/intents` | NATIVE_UNIT | Live ledger unchanged **NOT_RUN** |
| HCP-GRANT-05 | `hcp_grant_05_revocation_race` | `RevokeLocalGrant` | NATIVE_UNIT | Concurrent worker race **NOT_RUN** |
| HCP-GRANT-06 | `hcp_grant_06_resource_ceilings` | `EnsureLocal` | NATIVE_UNIT | Two concurrent jobs / host ceiling **NOT_RUN** (single ensure) |
| HCP-GRANT-07 | `hcp_grant_07_future_issuer_scope` | `SignAsProvider` `publisher-q` | NATIVE_UNIT | Root rotation + delegation policy **partial** |
| HCP-GRANT-08 | `hcp_grant_08_deadline_does_not_relax_policy` | `PlanLocal` + revoke | NATIVE_UNIT | Unreachable TTC deadline fixture **partial** |

## HCP-DISC — Discovery

Source: `src/test/modelnet_hcp_disc_hand_tests.cpp`. Tier: `NATIVE_UNIT`.
J01 also: `PROCESS_E2E` scripts for public `/profile` + search.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-DISC-01 | `hcp_disc_01_exact_package_preservation` | `GET /packages/{id}` two engines | NATIVE_UNIT | Two production CDNs **NOT_RUN** |
| HCP-DISC-02 | `hcp_disc_02_curation_versus_truth` | `PutOffer` sponsored vs `signature_status` | NATIVE_UNIT | — |
| HCP-DISC-03 | `hcp_disc_03_no_invented_capacity` | unknown stays unknown | NATIVE_UNIT | — |
| HCP-DISC-04 | `hcp_disc_04_catalogue_caching_isolation` | cache isolation | NATIVE_UNIT | Shared HTTP cache **NOT_RUN** |
| HCP-DISC-05 | `hcp_disc_05_bounded_natural_language_input` | query as data | NATIVE_UNIT | — |
| HCP-DISC-06 | `hcp_disc_06_economic_freshness` | dated vs current | NATIVE_UNIT | Live chain economy **NOT_RUN** |
| HCP-DISC-07 | `hcp_disc_07_capability_equivalence_guard` | recipe contract | NATIVE_UNIT | — |
| HCP-DISC-08 | `hcp_disc_08_independent_provider_alternative` | `SwitchProvider` | NATIVE_UNIT + PROCESS_E2E (two loopback profiles) | Live provider B **NOT_RUN** |

## HCP-HAND — Handoff

Source: `src/test/modelnet_hcp_disc_hand_tests.cpp`. Tier: `NATIVE_UNIT`.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-HAND-01 | `hcp_hand_01_device_and_nonce_binding` | device/nonce | NATIVE_UNIT | — |
| HCP-HAND-02 | `hcp_hand_02_expiry_and_clock_policy` | clock fixtures | NATIVE_UNIT | — |
| HCP-HAND-03 | `hcp_hand_03_package_substitution` | `PACKAGE_MISMATCH` | NATIVE_UNIT | — |
| HCP-HAND-04 | `hcp_hand_04_durable_duplicate_handoff` | duplicate job | NATIVE_UNIT | Client restart process **NOT_RUN** |
| HCP-HAND-05 | `hcp_hand_05_malicious_instruction_fields` | `FORBIDDEN_FIELD` | NATIVE_UNIT | — |
| HCP-HAND-06 | `hcp_hand_06_free_path` | no wallet touch | NATIVE_UNIT + PROCESS_E2E (`btx-hosted walletless`) | — |
| HCP-HAND-07 | `hcp_hand_07_optional_reporting` | reporting off | NATIVE_UNIT | — |
| HCP-HAND-08 | `hcp_hand_08_provider_disconnect` | disconnect | NATIVE_UNIT | — |

## HCP-LOCAL — Local runtime

Source: `src/test/modelnet_hcp_local_tests.cpp`. Tier: `NATIVE_UNIT`.
**Live CUDA DMA: NOT_RUN.**

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-LOCAL-01 | `hcp_local_01_resident_base_reuse` | `PlanLocal`, `PutResidentBase` | NATIVE_UNIT | Real LAN bytes **NOT_RUN** |
| HCP-LOCAL-02 | `hcp_local_02_faster_path_not_fixed_rank` | measured LAN vs net | NATIVE_UNIT | — |
| HCP-LOCAL-03 | `hcp_local_03_runtime_trust` | `HCP_ERR_SOFTWARE_TRUST` | NATIVE_UNIT | — |
| HCP-LOCAL-04 | `hcp_local_04_sparse_missing_extent` | `UNVERIFIED_RANGE` | NATIVE_UNIT | — |
| HCP-LOCAL-05 | `hcp_local_05_readiness_distinction` | transfer ≠ `runtime_ready` | NATIVE_UNIT | — |
| HCP-LOCAL-06 | `hcp_local_06_cancel_under_dma` | `SetDmaActive`, `LEASE_FENCE`, `FenceDma` | NATIVE_UNIT | **Live CUDA DMA NOT_RUN** |
| HCP-LOCAL-07 | `hcp_local_07_private_state_containment` | `ExportPublic` | NATIVE_UNIT | — |
| HCP-LOCAL-08 | `hcp_local_08_no_remote_inference_shortcut` | `remote_inference` false | NATIVE_UNIT | Live provider inference API **NOT_RUN** (must stay unused) |

## HCP-CUST — Custody

Source: `src/test/modelnet_hcp_cust_intent_tests.cpp`.
Tier: `NATIVE_UNIT` / `CUSTODY_LAB`. **Live HSM: NOT_RUN.**

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-CUST-01 | `hcp_cust_01_native_key_capability` | `HCP_CUSTODY_EVM_GENERIC`, `HCP_ERR_CUSTODY_UNSUPPORTED` | CUSTODY_LAB | Live EVM-only backend **NOT_RUN** |
| HCP-CUST-02 | `hcp_cust_02_frozen_script_validation` | submit terms mismatch | CUSTODY_LAB | Live signer independent check **NOT_RUN** |
| HCP-CUST-03 | `hcp_cust_03_customer_lot_attribution` | `AttributeOutput` | NATIVE_UNIT | — |
| HCP-CUST-04 | `hcp_cust_04_no_synthetic_council_seats` | `Statements` | NATIVE_UNIT | — |
| HCP-CUST-05 | `hcp_cust_05_signer_timeout_ambiguity` | `ForceBroadcastUnknown` | CUSTODY_LAB | Live signer lookup **NOT_RUN** |
| HCP-CUST-06 | `hcp_cust_06_recovery_drill` | `Persist` / `Restore` | NATIVE_UNIT | Live HSM+ledger backup **NOT_RUN** |
| HCP-CUST-07 | `hcp_cust_07_watch_only_export_honesty` | `ExportPublic` `self_custody=false` | NATIVE_UNIT | — |
| HCP-CUST-08 | `hcp_cust_08_signer_network_isolation` | `POST /rpc` → 404 `HCP_ERR_GENERIC_RPC` | NATIVE_UNIT + PROCESS_E2E (no `/rpc` on loopback) | Compromised helper probe **NOT_RUN** |

## HCP-INTENT — Finance intents

Source: `src/test/modelnet_hcp_cust_intent_tests.cpp`.
Tier: `NATIVE_UNIT` + `OAUTH_LAB` tokens. Live IdP/HSM **NOT_RUN**.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-INTENT-01 | `hcp_intent_01_idempotent_creation` | `client_operation_id` | NATIVE_UNIT | Multi-replica DB uniqueness **NOT_RUN** |
| HCP-INTENT-02 | `hcp_intent_02_authorization_binds_intent` | authorize digest | NATIVE_UNIT | — |
| HCP-INTENT-03 | `hcp_intent_03_expired_quote` | `QUOTE_EXPIRED` | NATIVE_UNIT | — |
| HCP-INTENT-04 | `hcp_intent_04_terms_change` | `TERMS_CHANGED` | NATIVE_UNIT | — |
| HCP-INTENT-05 | `hcp_intent_05_crash_before_broadcast` | persist signed bytes | NATIVE_UNIT | Process kill **NOT_RUN** |
| HCP-INTENT-06 | `hcp_intent_06_crash_after_broadcast` | `BROADCAST_UNKNOWN` | NATIVE_UNIT | Replica restart **NOT_RUN** |
| HCP-INTENT-07 | `hcp_intent_07_cancel_boundary` | cancel unsigned vs unknown | NATIVE_UNIT | — |
| HCP-INTENT-08 | `hcp_intent_08_conversion_partial_success` | conversion vs funding leg | NATIVE_UNIT | Live conversion **NOT_RUN** |

## HCP-LEDGER — Ledger

Source: `src/test/modelnet_hcp_ledger_chain_tests.cpp`.
Tier: `NATIVE_UNIT`. Partner ledger adapter **NOT_RUN**.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-LEDGER-01 | `hcp_ledger_01_concurrent_funds_reservation` | two threads `Handle` | NATIVE_UNIT | Real DB fencing **NOT_RUN** |
| HCP-LEDGER-02 | `hcp_ledger_02_principal_versus_fees` | `principal_in_native_sum` | NATIVE_UNIT | — |
| HCP-LEDGER-03 | `hcp_ledger_03_lifetime_limit` | `lifetime_principal_atoms` | NATIVE_UNIT | — |
| HCP-LEDGER-04 | `hcp_ledger_04_overlapping_batch_outputs` | `AttributeOutput` | NATIVE_UNIT | — |
| HCP-LEDGER-05 | `hcp_ledger_05_native_money_bounds` | MoneyRange | NATIVE_UNIT | — |
| HCP-LEDGER-06 | `hcp_ledger_06_fee_change` | fee cap | NATIVE_UNIT | — |
| HCP-LEDGER-07 | `hcp_ledger_07_reservation_persistence` | persist hold | NATIVE_UNIT | Crash-restore DB **NOT_RUN** |
| HCP-LEDGER-08 | `hcp_ledger_08_statements` | `Statements` | NATIVE_UNIT | Aggregate recon report **NOT_RUN** |

## HCP-CHAIN — Chain observation

Source: `src/test/modelnet_hcp_ledger_chain_tests.cpp`.
Tier: `NATIVE_UNIT` (in-process confirm/reorg model). **Native regtest observer process: NOT_RUN.**

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-CHAIN-01 | `hcp_chain_01_202_is_not_settlement` | HTTP 202, `funded` false | NATIVE_UNIT | — |
| HCP-CHAIN-02 | `hcp_chain_02_confirmation_policy` | `SetNativeConfirmations` | NATIVE_UNIT | Live regtest **NOT_RUN** |
| HCP-CHAIN-03 | `hcp_chain_03_reorg_correction` | `InjectReorg` | NATIVE_UNIT | Controllable reorg network **NOT_RUN** |
| HCP-CHAIN-04 | `hcp_chain_04_disclosed_secret_survives_reorg` | `DiscloseSecret` | NATIVE_UNIT | — |
| HCP-CHAIN-05 | `hcp_chain_05_observer_outage` | `SetObserverAvailable(false)` | NATIVE_UNIT | Helper-down vs money **NOT_RUN** as HCP process |
| HCP-CHAIN-06 | `hcp_chain_06_verifier_disagreement` | `HOSTED_ATTESTED` | NATIVE_UNIT | Independent verifier process **NOT_RUN** |
| HCP-CHAIN-07 | `hcp_chain_07_refund_conditions` | `SetRefundHeight` | NATIVE_UNIT | Eligible native refund tx **NOT_RUN** |
| HCP-CHAIN-08 | `hcp_chain_08_receipt_authority_label` | `ReceiptAuthorityLabel` | NATIVE_UNIT | Walletless client import UX **NOT_RUN** |

## HCP-EVENT — Events

Source: `src/test/modelnet_hcp_event_fleet_tests.cpp`. Tier: `NATIVE_UNIT`.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-EVENT-01 | `hcp_event_01_at_least_once_duplicate` | `DeliverEventDuplicates` | NATIVE_UNIT | SSE client restart **NOT_RUN** |
| HCP-EVENT-02 | `hcp_event_02_cursor_retention` | `HCP_ERR_CURSOR_TOO_OLD` | NATIVE_UNIT | — |
| HCP-EVENT-03 | `hcp_event_03_account_cursor_binding` | account_ref | NATIVE_UNIT | — |
| HCP-EVENT-04 | `hcp_event_04_future_subscription_race` | business key | NATIVE_UNIT | Many workers **NOT_RUN** |
| HCP-EVENT-05 | `hcp_event_05_catalogue_restore` | `RestoreCatalogueIndex` | NATIVE_UNIT | — |
| HCP-EVENT-06 | `hcp_event_06_outbox_crash` | `CrashOutbox` / `RecoverOutbox` | NATIVE_UNIT | Process crash **NOT_RUN** |
| HCP-EVENT-07 | `hcp_event_07_webhook_ssrf` | `WEBHOOK_SSRF` | NATIVE_UNIT | DNS rebinding **NOT_RUN** |
| HCP-EVENT-08 | `hcp_event_08_revoked_subscription` | revoke | NATIVE_UNIT | — |

## HCP-FLEET — Devices

Source: `src/test/modelnet_hcp_event_fleet_tests.cpp`. Tier: `NATIVE_UNIT`.
**Real browser: NOT_RUN.** J11 process E2E is walletless finance isolation only.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-FLEET-01 | `hcp_fleet_01_pair_exact_device` | `/devices/enroll` | NATIVE_UNIT | Real device key **NOT_RUN** |
| HCP-FLEET-02 | `hcp_fleet_02_no_ambient_localhost_api` | no ambient API | NATIVE_UNIT | Malicious web page **NOT_RUN** |
| HCP-FLEET-03 | `hcp_fleet_03_outbound_only_handoff` | outbound | NATIVE_UNIT | NAT device **NOT_RUN** |
| HCP-FLEET-04 | `hcp_fleet_04_device_revocation` | revoke | NATIVE_UNIT | — |
| HCP-FLEET-05 | `hcp_fleet_05_cross_device_replay` | binding | NATIVE_UNIT | — |
| HCP-FLEET-06 | `hcp_fleet_06_coarse_progress` | reports | NATIVE_UNIT | Portal UI **NOT_RUN** |
| HCP-FLEET-07 | `hcp_fleet_07_cex_cannot_administer_local_grant` | hosted ≠ grant | NATIVE_UNIT | CEX admin role **NOT_RUN** |
| HCP-FLEET-08 | `hcp_fleet_08_mixed_platform_fleet` | two platforms | NATIVE_UNIT | Two real OSes **NOT_RUN** |

## HCP-PRIV — Privacy

Source: `src/test/modelnet_hcp_priv_port_ops_tests.cpp`. Tier: `NATIVE_UNIT`.
Packet capture **NOT_RUN**.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-PRIV-01 | `hcp_priv_01_prompts_stay_local` | `TrafficCapture` | NATIVE_UNIT | NIC capture **NOT_RUN** |
| HCP-PRIV-02 | `hcp_priv_02_inventory_off_by_default` | `inventory_reported` | NATIVE_UNIT | — |
| HCP-PRIV-03 | `hcp_priv_03_private_url_redaction` | token query redacted | NATIVE_UNIT | — |
| HCP-PRIV-04 | `hcp_priv_04_tenant_analytics` | `cross_tenant` | NATIVE_UNIT | — |
| HCP-PRIV-05 | `hcp_priv_05_required_versus_optional_records` | reporting off | NATIVE_UNIT | Funded native action logs **NOT_RUN** |
| HCP-PRIV-06 | `hcp_priv_06_read_token_in_runtime` | `ChildRuntimeEnv` | NATIVE_UNIT | Real loader worker FDs **NOT_RUN** |
| HCP-PRIV-07 | `hcp_priv_07_native_only_acquisition` | `ORIGIN_DENIED` | NATIVE_UNIT | — |
| HCP-PRIV-08 | `hcp_priv_08_no_inference_billing` | `automatic_spend_atoms==0` | NATIVE_UNIT | — |

## HCP-PORT — Portability

Source: `src/test/modelnet_hcp_priv_port_ops_tests.cpp`. Tier: `NATIVE_UNIT`.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-PORT-01 | `hcp_port_01_discovery_switch` | `SwitchProvider` | NATIVE_UNIT + PROCESS_E2E (two origins) | — |
| HCP-PORT-02 | `hcp_port_02_uncertain_finance_across_providers` | no finance replay | NATIVE_UNIT | — |
| HCP-PORT-03 | `hcp_port_03_free_use_after_exit` | disconnect | NATIVE_UNIT | — |
| HCP-PORT-04 | `hcp_port_04_custody_exit_statement` | export not self-custody | NATIVE_UNIT | — |
| HCP-PORT-05 | `hcp_port_05_schema_evolution` | fail closed | NATIVE_UNIT | — |
| HCP-PORT-06 | `hcp_port_06_migration_interruption` | persist/restore | NATIVE_UNIT | Mid-write crash **NOT_RUN** |
| HCP-PORT-07 | `hcp_port_07_independent_sdk_parity` | body_id | NATIVE_UNIT | Python vs TS vs native vector run **NOT_RUN** as one job (`hcp-sdk` has local `body_id` tests) |
| HCP-PORT-08 | `hcp_port_08_no_native_core_rewrite` | wrapper strip | NATIVE_UNIT | — |

## HCP-OPS-01 .. HCP-OPS-08 — Operations

Source: `src/test/modelnet_hcp_priv_port_ops_tests.cpp`.

| ID | Boost case | Native symbols | Tier | Live gap |
|---|---|---|---|---|
| HCP-OPS-01 | `hcp_ops_01_public_bridge_isolation` | `HandleBridgeRequest` POST finance → 405 | NATIVE_UNIT | Live explorer **NOT_RUN** |
| HCP-OPS-02 | `hcp_ops_02_money_only_regression` | `FormatFullVersion` contains `0.34.8` | NATIVE_UNIT | **`WITH_MODELNET=OFF` second cmake tree NOT_RUN** |
| HCP-OPS-03 | `hcp_ops_03_replica_fencing` | `SetExecutorOwner`, `HCP_ERR_FENCED` | NATIVE_UNIT | Two finance executor processes **NOT_RUN** |
| HCP-OPS-04 | `hcp_ops_04_scale_within_limits` | oversized search → 413 | NATIVE_UNIT | Load test **NOT_RUN** |
| HCP-OPS-05 | `hcp_ops_05_no_production_side_effects` | `GoLiveManifest` `production_binary_replaced=false` | NATIVE_UNIT | Must not touch production `btxd` — **NOT_RUN** as a live-adjacent drill |
| HCP-OPS-06 | `hcp_ops_06_provider_compromise_drill` | `RotateOperationalKey` | NATIVE_UNIT | Independent enrolled root recovery **NOT_RUN** |
| HCP-OPS-07 | `hcp_ops_07_claimed_profile_evidence` | `proven.DISCOVERY` true, `proven.FUNDING` false | NATIVE_UNIT | Honest: FUNDING not claimed proven |
| HCP-OPS-08 | `hcp_ops_08_full_audit_closure` | `automatic_spend_atoms==0`, `not_run` present | NATIVE_UNIT | **Not** closure of live IdP/HSM/CUDA. Manifest retains `not_run`. |

J01 two-gateway requirement is also `PROCESS_E2E` via `feature_modelnet_hcp.py`.

---

## J01–J12

Boost source: `src/test/modelnet_hcp_journey_tests.cpp`.
CSV: [hcp-journeys.csv](hcp-journeys.csv).

| ID | Boost case | Native unit | Process E2E | Live IdP / HSM / CUDA |
|---|---|---|---|---|
| J01 | `hcp_j01_free_hosted_discovery` | SOURCE | `feature_modelnet_hcp.py` + journeys.py `/profile` | IdP n/a; CUDA **NOT_RUN** |
| J02 | `hcp_j02_locality_wins` | SOURCE | **NOT_RUN** | CUDA **NOT_RUN** |
| J03 | `hcp_j03_release_funding` | SOURCE (`OAUTH_LAB` Token, 202) | journeys.py unauth quotes ≥400 only | **IdP NOT_RUN, HSM NOT_RUN**, no native tx |
| J04 | `hcp_j04_conversion_partial_success` | SOURCE | **NOT_RUN** | conversion adapter **NOT_RUN** |
| J05 | `hcp_j05_unknown_broadcast` | SOURCE | **NOT_RUN** | mempool **NOT_RUN** |
| J06 | `hcp_j06_no_award_and_refund` | SOURCE (height flags) | **NOT_RUN** | **HSM/chain refund NOT_RUN** |
| J07 | `hcp_j07_subscription_under_concurrency` | SOURCE | **NOT_RUN** | — |
| J08 | `hcp_j08_malicious_provider` | SOURCE | **NOT_RUN** | — |
| J09 | `hcp_j09_provider_exit` | SOURCE | journeys.py second origin | live providers **NOT_RUN** |
| J10 | `hcp_j10_custody_failure_drill` | SOURCE Persist/Restore | **NOT_RUN** | **HSM NOT_RUN** |
| J11 | `hcp_j11_fleet_browser_journey` | SOURCE enroll/confirm/revoke | journeys.py walletless finance disabled | real browser **NOT_RUN** |
| J12 | `hcp_j12_privacy_and_service_independence` | SOURCE | journeys.py two origins | packet capture **NOT_RUN** |

---

## Counts

| Bucket | Count |
|---|---|
| Family Boost cases (FRM…OPS) | 120 |
| Journey Boost cases | 12 |
| **Total native unique cases** | **132** |
| Process E2E scripts | 2 |
| Live CEX IdP / live HSM / live CUDA DMA / second OFF tree / F2 / GUI / 400GiB / uTP / QUIC / torrentd | **NOT_RUN** (see [hcp-not-run.md](hcp-not-run.md)) |
