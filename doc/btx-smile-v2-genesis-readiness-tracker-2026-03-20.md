# BTX SMILE V2 Genesis-Reset Readiness Tracker

> Status note (2026-04-02): this tracker is preserved as the pre-`61000`
> genesis-reset readiness baseline. For the later hardening-fork state and the
> remaining open security item, use
> [doc/security/current-status.md](security/current-status.md) and
> [doc/security/README.md](security/README.md).

Date: 2026-03-20 (updated 2026-03-24)

Status: complete for the pre-`61000` reset-chain launch surface baseline

Paper working mirror:
- `doc/research/smile-2021-564-working-mirror.md`
- `doc/research/smile-2021-564.txt`
- source PDF mirrored from `/Users/admin/Downloads/2021-564.pdf`

## Protocol Definition

The reset chain now defines the production `DIRECT_SMILE` protocol as:

- default direct shielded backend
- direct CT anonymity sets limited to `anon_set <= NUM_NTT_SLOTS` (`32`)
- live launch wallet default fixed at `RING_SIZE = 8`
- larger configured rings already stay on the same supported wire surface up to
  `32`
- single-round CT only for consensus / wallet / mempool / validation
- larger recursive CT sets explicitly rejected by prover and verifier
- MatRiCT retained only as failover tooling outside the default launch path

Because this is a restart-from-genesis hard fork, this supported surface is the
final protocol definition rather than a temporary compatibility compromise.

## Completed Items

- Membership proof rewritten for both the large-ring standalone surface and the
  live single-round wallet surface.
- Public account / public coin tuple plumbing wired through wallet, proof,
  parser, validation, and test fixtures.
- Direct spend proof shard binding fixed to commit the real public payload and
  SMILE output coin hashes.
- Canonical SMILE serial hashing and output-coin hashing centralized and used
  consistently across wallet and validation.
- Direct CT prover now rejects mismatched selected input openings and missing
  output openings.
- Direct CT verifier now authenticates the live launch surface through the
  hidden tuple-account framework relation instead of public ring-index
  reconstruction.
- Explicit `key_w0 = A*y0` rows are serialized and used to reconstruct the
  tuple-account first-round surface.
- Full direct-send builder / parser / runtime-report / chain-growth tooling is
  aligned with canonical SMILE public accounts.
- Functional wallet, bridge, sendmany stress, and benchmark flows pass on the
  launch surface.
- Unsupported larger recursive CT sets are now rejected instead of falling
  back to the legacy prototype branch.

## Launch Checklist

- Default direct spend path is `DIRECT_SMILE`: done
- Wallet-to-wallet shielded flow: done
- Shielded sendmany flow: done
- Shielded-to-transparent edge flow: done
- Cross-wallet flow: done
- Reorg recovery: done
- Bridge happy path / PSBT / attested unshield / rebalance / refund flows: done
- Canonical public-account output model: done
- Canonical SMILE nullifier / serial-hash plumbing: done
- Launch-surface CT proof rewrite: done
- Legacy large-set CT path removed from production surface: done
- Benchmarks and chain-growth reports updated: done
- Docs updated to the final reset-chain protocol definition: done

## Verified Coverage

### Unit / ctest

- `smile2_membership_tests/*`
- `smile2_ct_tests/p4_g0_selected_input_opening_must_match_public_coin`
- `smile2_ct_tests/p4_g1_balance_proof`
- `smile2_ct_tests/p4_g5_amortized_membership`
- `smile2_ct_tests/p4_g6_full_ct_small`
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
- `shielded_v2_send_tests/*`

### Functional

- `wallet_smile_v2_full_lifecycle.py --descriptors`
- `wallet_shielded_ring_size_policy.py`
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

## Current Pre-`61000` Baseline Figures

This tracker is the launch-checklist baseline, not the primary benchmark
source. Current measured runtime and size numbers on merged `main` are:

- live wallet `1x2 v2_send`: `60,218` serialized bytes,
  `22.71 s` sample wallet first-prove, `398 tx/block`
- canonical redesign-report `1x2 v2_send`: `60,110` serialized bytes,
  `51,099` proof bytes, `10.20 s` build, `304.26 ms` verify, `399 tx/block`
- direct `2x2 v2_send`: `70,272` serialized bytes, `61,091` proof bytes,
  `7.29 s` build, `481.09 ms` verify, `341 tx/block`
- direct `2x4 v2_send`: `101,918` serialized bytes, `84,111` proof bytes,
  `5.09 s` build, `538.55 ms` verify, `235 tx/block`
- proofless deposit `v2_send` (prefork compatibility only): `19,172`
  serialized bytes, `0.221 s` build, `1,251 tx/block`, `13.90 TPS`
- mixed unshield `v2_send` (prefork compatibility only; post-`61000`
  transparent settlement moves to bridge/egress): `44,330` serialized bytes,
  `10.88 s` sample build, `541 tx/block`, `6.01 TPS`
- ingress `63 leaves / 8 spends / 1 reserve`: `312,364` serialized bytes,
  `281,622` proof bytes, `109.86 s` build, `5.69 s` verify, `76 tx/block`,
  `4,788 represented leaves/block`
- `32x32 v2_egress`: `470,168` serialized bytes, `433` proof bytes,
  `463.14 ms` full pipeline, `9.99 ms` verify, `51 tx/block`,
  `1,632 outputs/block`

For the canonical current-main runtime tables, mixed-workload headline, and
future soft-fork settlement boundary, use
`doc/btx-shielded-production-status-2026-03-20.md`.

## Conclusion

No launch blockers remain on the defined reset-chain protocol surface.

The only intentionally unsupported area is larger recursive CT anonymity sets
(`anon_set > 32`). Those are not part of the production protocol and are
rejected explicitly rather than left as latent prototype behavior.

Merged-main follow-ons after the original genesis-reset sign-off:

- account-registry activation and committed payload recovery are merged on
  `main`
- wallet-built deposit, direct send, mixed unshield, and note merge all now
  use `v2_send`
- future-proofed settlement slack is merged on `main` through
  `BridgeBatchStatement version = 5`, `BridgeBatchCommitment version = 3`, and
  `ProofEnvelope.extension_digest`

Follow-on proof-size / TPS optimization work is still tracked separately in
`doc/btx-smile-v2-optimization-tracker-2026-03-21.md`, while this tracker
remains the checklist baseline for the shipped reset-chain launch definition.
