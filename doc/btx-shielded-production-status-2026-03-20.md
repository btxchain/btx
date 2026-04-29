<!--
  Updated after the genesis-reset DIRECT_SMILE + account-registry activation pass.
  This supersedes earlier transitional wording in the same path.
-->

> Status note (2026-04-02): this document is now a pre-`61000` launch-baseline
> snapshot. For the live hardening-fork state, remaining security work, and
> post-fork readiness numbers, use [doc/security/current-status.md](security/current-status.md)
> and [doc/security/README.md](security/README.md).

# BTX Shielded Production Status

Date: 2026-03-20 (updated 2026-03-24)

Paper working mirror:
- `doc/research/smile-2021-564-working-mirror.md`
- `doc/research/smile-2021-564.txt`
- source PDF mirrored from `/Users/admin/Downloads/2021-564.pdf`

## Status

BTX is production-ready for the genesis-reset shielded launch on the audited
SMILE v2 + committed-account-registry parameter surface now defined by
consensus and wallet code:

- `DIRECT_SMILE` is the default direct shielded spend backend.
- shared-ring `BATCH_SMILE` ingress is the live bridge-in backend.
- the supported direct CT anonymity-set surface is intentionally limited to
  `anon_set <= NUM_NTT_SLOTS` (`32`);
- the live chain launch default is now `RING_SIZE = 8`, while wallet-built
  direct sends can already raise the configured ring size anywhere in the
  supported `8..32` range without changing the transaction family or wire
  format;
- registry state now commits full shielded account-leaf payloads and snapshot
  restore rebuilds `CompactPublicAccount` state from authenticated entries;
- consumed-leaf transaction witnesses are lean on wire
  (`leaf_index + account_leaf_commitment + sibling_path`) while full nodes
  recover payloads from local consensus state;
- larger recursive CT sets are not part of the launch protocol and are now
  rejected instead of silently falling back to the old prototype verifier;
- MatRiCT and receipt-backed ingress remain in tree only as non-launch tooling
  for historical tests and fallback parsing, not as production backends.

This is a reset-from-genesis hard fork baseline. It predates the later
`61000` shielded hardening program documented under `doc/security/`.

## Future-Proofed Settlement Slack

`main` now also carries the first launch-safe bridge/proof upgrade
slack for a later high-aggregation settlement path:

- bridge batch statements now have a live `version = 5` surface that can carry
  an authenticated `aggregate_commitment` with:
  - `action_root`
  - `data_availability_root`
  - `recovery_or_exit_root`
  - `extension_flags`
  - `policy_commitment`
- bridge batch commitments now have a live `version = 3` surface that can
  carry the same aggregate commitment when an external anchor is present
- shared-ring ingress and egress builders populate a deterministic default
  aggregate commitment today:
  - `action_root = batch_root`
  - `data_availability_root = data_root`
  - `policy_commitment = proof_policy.descriptor_root` when a proof policy is
    committed
- the shielded proof envelope now carries an opaque `extension_digest`, and
  transaction header ids already commit to it
- wallet RPC encode/decode surfaces expose the aggregate commitment object, and
  external statement builders can override it while staying on the same launch
  proof / binding enums

This does not activate true multi-user L1 settlement semantics yet. It makes
the authenticated roots and proof/header binding bytes part of the launch
consensus surface now so a later tightening upgrade does not need to invent a
new proof or settlement-binding enum just to carry those roots.

## Final Pre-`61000` Launch Definition

The production shielded model for the reset chain is:

- SMILE v2 default direct wallet-to-wallet spends
- proofless transparent-to-shielded wallet deposit on `v2_send`
- mixed shielded-to-transparent wallet unshield on `v2_send`
- note merge / consolidation on `v2_send`
- SMILE-backed shielded send / sendmany / reorg / cross-wallet flows with
  account-registry recovery from committed state
- working shielded-to-transparent flows on the same launch surface
- bridge / covenant / PSBT / attested unshield / refund / rebalance flows
- explicit rejection of unsupported large recursive CT sets

The direct CT proof object now uses the final launch-surface tuple-account
relation rather than the old key-only placeholder:

- explicit `key_w0 = A*y0` rows are serialized
- the combined tuple-account `w0` rows are reconstructed from
  `key_w0 + input_tuples`
- live `m=1` CT uses the hidden tuple-account framework relation with
  `framework_omega`
- the verifier no longer runs public `matched_indices` recovery on the active
  launch path
- the prover and verifier both fail closed for `anon_set > NUM_NTT_SLOTS`

## Measured Runtime And Size

Benchmarks below were collected from the current `main` tip with:

- `build-btx/bin/gen_smile2_proof_redesign_report --profile=baseline --samples=1`
- `build-btx/bin/gen_smile2_proof_redesign_report --profile=fast --samples=1`
- `build-btx/bin/gen_shielded_v2_egress_runtime_report --warmup=1 --samples=3 --scenarios=32x32`
- `build-btx/bin/gen_shielded_v2_netting_capacity_report --warmup=1 --samples=3 --scenarios=2x50,8x80,32x95,64x99`
- `python3 build-btx/test/functional/wallet_smile_v2_benchmark.py`
- local transparent baseline probe on regtest with `-autoshieldcoinbase=0`
  measuring a canonical `1-in/2-out` `witness_v2_p2mr` send

Authoritative note:

- the redesign report is the current production benchmark source for canonical
  direct-send and ingress proof surfaces on the committed-account-registry
  launch surface
- the wallet benchmark is the production source for operator-facing live wallet
  transaction-family flows (deposit, wallet-produced `1x2` direct send, and
  mixed unshield)
- older standalone `gen_shielded_v2_send_runtime_report` and
  `gen_shielded_v2_chain_growth_projection_report` numbers are pre-registry
  planning artifacts and should not be used as the current launch baseline

### Headline mixed throughput assumption

For the README / operator-facing headline, BTX now uses a mixed L1 capacity
model rather than the shielded-only direct-send TPS:

- block size cap: `24 MB` serialized
- target block time: `90 s`
- `50%` of block bytes reserved for direct `1x2 v2_send`
- `50%` of block bytes reserved for canonical transparent
  `1-in/2-out witness_v2_p2mr`

Measured inputs:

- direct `1x2 v2_send`: `60,218` bytes
- transparent `1-in/2-out witness_v2_p2mr`: `3,916` bytes

Result:

- `199` shielded direct sends + `3,064` transparent sends
- `3,263` total tx / block
- about `36.26 TPS`

### Canonical direct `v2_send` proof profile

| Shape | Serialized bytes | Proof payload bytes | Mean build time | Mean verify time | 24 MB block fit |
| --- | ---: | ---: | ---: | ---: | ---: |
| `1x2` | `60,110` | `51,099` | `10.20 s` | `304.26 ms` | `399 tx/block` |
| `2x2` | `70,272` | `61,091` | `7.29 s` | `481.09 ms` | `341 tx/block` |
| `2x4` | `101,918` | `84,111` | `5.09 s` | `538.55 ms` | `235 tx/block` |

At the `90 s` launch cadence and `24 MB` serialized cap, that corresponds to:

- `1x2`: about `4.42 tx/s`
- `2x2`: about `3.79 tx/s`
- `2x4`: about `2.61 tx/s`

### Wallet transaction-family migration baseline

Measured from `python3 build-btx/test/functional/wallet_smile_v2_benchmark.py`
on the pre-`61000` `main` baseline:

| Flow | Live family | Serialized bytes | Sample build time on this host | 24 MB block fit | TPS @ 90 s |
| --- | --- | ---: | ---: | ---: | ---: |
| Transparent -> shielded deposit | proofless `v2_send` (prefork compatibility only) | `19,172` | `0.221 s` | `1,251` | `13.90` |
| Shielded -> shielded direct send | `DIRECT_SMILE v2_send` | `60,218` | `22.708 s` | `398` | `4.42` |
| Shielded -> transparent mixed unshield | `v2_send` (prefork compatibility only; post-`61000` settlement moves to bridge/egress) | `44,330` | `10.875 s` | `541` | `6.01` |

Operational interpretation:

- on the pre-`61000` baseline, `z_shieldfunds`, `z_shieldcoinbase`, and
  transparent-fallback `z_sendmany` build proofless `v2_send`
- `z_sendmany` / `z_sendtoaddress` shielded direct sends remain on
  `DIRECT_SMILE v2_send`
- on the pre-`61000` baseline, mixed unshield no longer falls back to the old
  legacy mixed proof path
- `z_mergenotes` now uses the same `v2_send` launch surface
- the wallet-produced `1x2` transaction is currently `108` bytes larger than
  the canonical redesign fixture, so operator-facing mixed-throughput math uses
  the wallet benchmark while proof-size / verifier tables use the redesign
  report
- wallet-path prove time is intentionally presented as a host-local sample
  rather than a deterministic median; note selection and prover retries make
  that wall-clock materially noisier than the stable block-fit / TPS figures

### Ingress / shared-ring `BATCH_SMILE`

| Shape | Serialized bytes | Proof payload bytes | Mean build time | Mean verify time | 24 MB block fit |
| --- | ---: | ---: | ---: | ---: | ---: |
| `1 reserve + 63 leaves / 8 spend inputs / 8 proof shards` | `312,364` | `281,622` | `109.86 s` | `5.69 s` | `76 tx/block` |

That represents about `4,788` represented ingress leaves per `24 MB` block on
the proven default-8 launch ceiling. The live ingress runtime sweep now shows
that the current shared-ring launch schedule tops out at `63` leaves before a
`9th` spend input would be required; larger shard counts remain supportable on
the same wire surface if the configured ring policy is raised later without a
transaction-family or consensus-format change.

### Egress / bridge-out

| Shape | Serialized bytes | Proof payload bytes | Mean full pipeline | Mean verify time | 24 MB block fit |
| --- | ---: | ---: | ---: | ---: | ---: |
| `32x32` | `470,168` | `433` | `463.14 ms` | `9.99 ms` | `51 tx/block` |

That represents about `1,632` shielded outputs per `24 MB` block.

### Rebalance / settlement capacity

Representative live-domain settlement capacity from the netting report:

| Scenario | Shape | Serialized bytes | Proof payload bytes | Mean build time | Mean validate time | 24 MB block fit |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `2x50` | rebalance | `2,748` | `430` | `0.39 ms` | `0.04 ms` | `2,400 tx/block` |
| `8x80` | rebalance | `9,813` | `1,720` | `0.88 ms` | `0.10 ms` | `2,400 tx/block` |
| `32x95` | rebalance | `38,073` | `6,880` | `3.12 ms` | `0.35 ms` | `630 tx/block` |
| `64x99` | rebalance | `75,753` | `13,760` | `5.67 ms` | `0.61 ms` | `316 tx/block` |
| `64x99` | settlement anchor | `3,597` | `433` | `0.12 ms` | `0.06 ms` | `2,400 tx/block` |

The netting report also shows effective capacity multipliers rising from
`2.0x` (`2x50`) to `196.875x` (`64x99`) as pairwise cancellation improves.

### Output footprint and witness surfaces

From the committed-account-registry redesign harness on the current `main` tip:

- direct-send output footprint: `3,784 -> 1,225` bytes
- ingress reserve fixture: `13,322 -> 75` bytes
- egress user fixture: `13,322 -> 75` bytes
- rebalance reserve fixture: `13,322 -> 75` bytes
- sample light-client registry proof: `13,554` bytes
- sample lean spend witness: `106` bytes

### Capacity reading

The current mixed-workload launch surface remains serialization / envelope
bound, not verifier-budget bound, on the direct-send, ingress, and egress
families. Settlement anchors bind on shielded verify units, while high-domain
rebalance traffic shifts toward serialized-size binding as domain count grows.

## Verified Coverage

### Unit / ctest

- `smile2_membership_tests/*`
- `smile2_ct_tests/p4_g0_selected_input_opening_must_match_public_coin`
- `smile2_ct_tests/p4_g1_balance_proof`
- `smile2_ct_tests/p4_g5_amortized_membership`
- `smile2_ct_tests/p4_g6_full_ct_small`
- `smile2_ct_tests/p4_g6b_repeated_two_input_proofs_stay_valid_and_nonlinkable`
- `smile2_ct_tests/p4_g7_large_ct_surface_rejected`
- `smile2_ct_tests/p4_g7b_live_single_round_aux_layout`
- `smile2_ct_tests/p4_g9_serialization_roundtrip`
- `smile2_integration_tests/p5_g1_consensus_accepts_valid`
- `smile2_integration_tests/p5_g2_consensus_rejects_invalid`
- `smile2_adversarial_tests/*`
- `smile2_deep_adversarial_tests/*`
- `smile2_extreme_adversarial_tests/*`
- `smile2_audit_tests`
- `shielded_v2_proof_tests/*`
- `shielded_account_registry_tests/*`
- `shielded_v2_send_tests/*`
- `shielded_v2_ingress_tests/*`
- `shielded_v2_egress_tests/*`
- `shielded_v2_bundle_tests/*`
- `smile2_proof_redesign_framework_tests/*`
- `shielded_v2_egress_runtime_report_tests`
- `shielded_v2_netting_capacity_report_tests`
- `shielded_validation_checks_tests`
- `bridge_wallet_tests`
- `shielded_coin_selection_tests`

### Functional

- `wallet_smile_v2_full_lifecycle.py --descriptors`
- `wallet_shielded_rpc_surface.py`
- `wallet_shielded_send_flow.py`
- `wallet_shielded_cross_wallet.py --descriptors`
- `wallet_shielded_reorg_recovery.py --descriptors`
- `wallet_shielded_sendmany_stress.py --descriptors`
- `wallet_smile_v2_benchmark.py --descriptors`
- `wallet_bridge_happy_path.py --descriptors`
- `wallet_bridge_psbt.py --descriptors`
- `wallet_bridge_attested_unshield.py --descriptors`
- `wallet_bridge_rebalance.py --descriptors`
- `wallet_bridge_batch_in.py --descriptors`
- `wallet_bridge_refund.py --descriptors`
- `wallet_bridge_refund_timeout.py --descriptors`

## Production Conclusion

The reset-chain launch posture is now:

- SMILE v2 default direct shielded transactions are ready on the supported
  single-round parameter surface with committed account-registry recovery;
- wallet-to-wallet, sendmany, ingress, egress, rebalance, refund, and
  transparent-edge flows are green on that same Smile-only launch surface;
- larger recursive CT anonymity sets are outside the launch protocol and are
  rejected by prover and verifier;
- MatRiCT and receipt-backed ingress are retained only as non-launch tooling,
  not as production backends.

That is the final production definition for the genesis-reset chain.

On `main`, that production definition is unchanged, and the additional
future-proofed settlement fields are already launch-safe because current
validation continues to accept both `null` and non-null proof-envelope
`extension_digest` values while the bridge statement hash already binds the new
aggregate commitment bytes.
