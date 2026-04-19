# BTX Implementation Analysis

**Date**: 2026-03-07
**Branch**: `claude/review-branch-merge-BBa9g`
**Method**: Full source code audit of actual implemented, tested, and functional code

> Historical note: this report predates the March 20-23 shielded mainline
> merges. Current launch architecture and benchmark truth lives in
> [btx-shielded-production-status-2026-03-20.md](btx-shielded-production-status-2026-03-20.md),
> [btx-smile-v2-transaction-family-transition-2026-03-23.md](btx-smile-v2-transaction-family-transition-2026-03-23.md),
> and [btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md](btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md).

---

## Overview

BTX is a fully implemented cryptocurrency node with three major novel subsystems
built on top of a Bitcoin Core foundation:

| Subsystem | Source files | Lines of code | Unit tests | Functional tests |
|-----------|-------------|---------------|------------|------------------|
| MatMul PoW | 14 (src/matmul/) + pow.cpp | ~4,350 | 245 (16 suites) | 7 |
| Post-Quantum Scripts (P2MR) | 95 files touched | ~16,100 (script engine) | 262 (17 suites) | 7 |
| Shielded Pool | 39 files (src/shielded/) + wallet | ~11,800 | 404 (27 suites) | 16 |
| **Total** | **~148 files** | **~32,250** | **911** | **30** |

Total codebase: ~470,000 lines of C/C++/Rust across all source files.

---

## 1. MatMul Proof-of-Work

### Implementation Status: Complete

The MatMul PoW system is fully implemented in `src/matmul/` (14 files, ~2,600 lines)
plus `src/pow.cpp` (1,746 lines).

**Core modules:**

| File | Purpose |
|------|---------|
| `matmul/field.cpp/.h` | GF(2^31-1) Mersenne prime field arithmetic |
| `matmul/matrix.cpp/.h` | Matrix operations over the field |
| `matmul/noise.cpp/.h` | Low-rank noise generation (E, F matrices, rank r=8) |
| `matmul/transcript.cpp/.h` | Blocked matrix multiplication with Carter-Wegman transcript hashing |
| `matmul/matmul_pow.cpp/.h` | Mining loop and PoW coordination |
| `matmul/accelerated_solver.cpp/.h` | GPU/Metal accelerated mining backends |
| `matmul/backend_capabilities.cpp/.h` | Hardware capability detection |

**Verification pipeline (pow.cpp):**

- `CheckMatMulProofOfWork_Phase1` (line 1114): O(1) header-only validation — dimensions, seeds, digest <= target
- `CheckMatMulProofOfWork_Phase2` (line 1137): O(n^3) full recomputation via `CanonicalMatMul`
- `CheckMatMulProofOfWork_Phase2WithPayload` (line 1198): O(n^3) verification using block-carried matrix data

**Difficulty adjustment:**

ASERT (Absolutely Scheduled Exponentially Rising Targets) is the sole difficulty
algorithm for MatMul mining. DGW (DarkGravityWave) has been explicitly removed
from the MatMul difficulty path (commit `6d61408`). The design invariant is
documented in pow.cpp at line 681:

> "MatMul networks use ASERT exclusively for difficulty adjustment.
>  DarkGravityWave (DGW) must NOT be used for MatMul mining."

The `MatMulAsert()` function (line 689) implements:
- Fast-mining bootstrap phase with fixed genesis-derived difficulty
- Stateless, path-independent ASERT retargeting from `nMatMulAsertHeight` onward
- Polynomial approximation of 2^x using 3-term expansion with 16-bit radix precision

**Peer verification budget system (pow.cpp lines 1363-1412):**

- Per-peer rate limiting via `ConsumeMatMulPeerVerifyBudget()` with configurable budget per minute
- IBD-aware budget relaxation (2000 verifications/min during IBD vs normal rate)
- Fast-phase burst allowance (600/min during bootstrap)
- Global Phase 2 budget via `ConsumeGlobalMatMulPhase2Budget()` with mutex-protected accounting

**Test coverage: 245 unit tests across 16 test suites:**

- `matmul_field_tests` (38): Field arithmetic correctness
- `matmul_dgw_tests` (25): Difficulty adjustment (ASERT) validation
- `matmul_trust_model_tests` (24): Peer trust and budget enforcement
- `matmul_validation_tests` (20): End-to-end block validation
- `matmul_transcript_tests` (19): Transcript hash determinism
- `matmul_noise_tests` (18): Low-rank noise generation
- `matmul_pow_tests` (15): PoW verification correctness
- `matmul_accelerated_solver_tests` (13): GPU backend
- `matmul_backend_capabilities_tests` (13): Hardware detection
- `matmul_matrix_tests` (13): Matrix operations
- `matmul_header_tests` (10): Header serialization
- `matmul_metal_tests` (10): Apple Metal backend
- `matmul_params_tests` (10): Consensus parameter validation
- `matmul_block_capacity_tests` (6): Block size limits
- `matmul_subsidy_tests` (6): Mining reward schedule
- `matmul_mining_tests` (5): Mining loop

**Functional tests (7):**

- `feature_btx_matmul_consensus.py`: Full consensus validation over multi-node network
- `mining_matmul_basic.py`: Basic mining operation
- `p2p_matmul_budget_reconnect.py`: Peer budget enforcement with reconnection
- `p2p_matmul_dos_mitigation.py`: DoS resistance under adversarial conditions
- `p2p_matmul_ibd_budget_enforcement.py`: IBD-specific budget behavior
- `p2p_matmul_inbound_punishment.py`: Misbehavior detection and peer banning
- `feature_btx_matmul_metal_high_hash_repro.py`: Metal backend regression

---

## 2. Post-Quantum Cryptography & P2MR Scripts

### Implementation Status: Complete

BTX implements a full post-quantum signature scheme with novel script opcodes,
touching 95 source files across the codebase.

**Core PQ cryptographic library (`src/libbitcoinpqc/`, 360 files, ~42,500 lines):**

- SLH-DSA (SPHINCS+) signing and verification (`src/libbitcoinpqc/src/slh_dsa/`)
- ML-DSA key generation, signing, verification (`src/libbitcoinpqc/src/ml_dsa/`)
- Rust core with C bindings (`src/libbitcoinpqc/src/lib.rs`, `bitcoinpqc.c`)
- Python and Node.js SDK bindings with test suites
- Algorithm-level and serialization test suites in Rust

**Key management (`src/pqkey.cpp/.h`, 351 lines):**

PQ key types integrated into the node's key infrastructure.

**Script engine (`src/script/`, ~15,400 lines total):**

- `pqm.cpp/.h` (315 lines): P2MR (Pay-to-MatMul-Result) script module
- `interpreter.cpp` (2,576 lines): Extended with PQ opcodes including:
  - `OP_CHECKSIGFROMSTACK` / `OP_CHECKSIGFROMSTACK_PQ` (CSFS)
  - `OP_CHECKTEMPLATEVERIFY` (CTV)
  - SLH-DSA signature verification opcodes
  - P2MR leaf template evaluation
- `solver.cpp/.h`: PQ-aware output type resolution
- `descriptor.cpp/.h`: PQ descriptor support for wallet integration
- `sign.cpp/.h`: PQ transaction signing
- `miniscript.cpp/.h`: Miniscript extensions for PQ types

**Wallet integration:**

- `wallet/scriptpubkeyman.cpp/.h`: PQ key management in wallet
- `wallet/rpc/addresses.cpp`: PQ address generation RPCs
- `wallet/rpc/spend.cpp`: PQ-aware coin selection and spending
- `wallet/rpc/sweep.cpp`: PQ sweep operations
- `wallet/walletdb.cpp`: PQ key persistence

**Consensus integration:**

- `validation.cpp`: PQ transaction validation in block acceptance
- `node/miner.cpp`: PQ-aware block template construction
- `policy/policy.cpp`: PQ transaction relay policy
- `consensus/params.h`: PQ activation parameters

**Test coverage: 262 unit tests across 17 suites:**

- `pq_consensus_tests` (82): Full consensus validation for PQ transactions
- `pq_phase4_tests` (60): Phase 4 activation and enforcement
- `pq_descriptor_tests` (37): Descriptor parsing and serialization
- `pq_policy_tests` (30): Relay and mempool policy
- `pq_crypto_tests` (10): Cryptographic primitive correctness
- `pq_merkle_tests` (8): Merkle proof construction
- `pq_address_tests` (7): Address encoding/decoding
- `pq_keyderivation_tests` (6): Key derivation paths
- `pq_multisig_descriptor_tests` (6): Multisig descriptor support
- `pq_multisig_tests` (5): PQ multisig signing and verification
- `pq_genesis_tests` (4): Genesis block PQ configuration
- `pq_timing_tests` (4): Verification timing bounds
- `pq_mining_template_tests` (3): Block template with PQ transactions

**Functional tests (7):**

- `feature_p2mr_end_to_end.py` / `p2mr_end_to_end.py`: Full P2MR transaction lifecycle
- `feature_btx_pq_wallet_enforcement.py`: Wallet-level PQ enforcement
- `feature_pq_multisig.py`: PQ multisig workflow
- `rpc_pq_multisig.py`: RPC interface for PQ multisig
- `rpc_pq_wallet.py`: PQ wallet RPC operations
- `wallet_sendall_pq.py`: PQ-aware send-all

**Fuzz targets (3):**

- `fuzz/pq_merkle.cpp`: Merkle proof fuzzing
- `fuzz/pq_script_verify.cpp`: PQ script verification fuzzing
- `fuzz/pq_descriptor_parse.cpp`: Descriptor parser fuzzing

**Benchmarks (2):**

- `bench/pq_verify.cpp`: PQ signature verification throughput
- `bench/ml_kem_bench.cpp`: ML-KEM operation benchmarks

---

## 3. Shielded Pool

### Implementation Status: Complete

The shielded pool provides confidential transactions with RingCT-based privacy,
implemented across 39 source files (~7,400 lines) in `src/shielded/` plus wallet
integration (~4,400 lines).

**Cryptographic primitives (`src/shielded/`):**

| Component | Files | Purpose |
|-----------|-------|---------|
| RingCT ring signatures | `ringct/ring_signature.cpp/.h` | Linkable ring signatures for spend authorization |
| MatriCT proofs | `ringct/matrict.cpp/.h` | Lattice-based ring confidential transactions |
| Range proofs | `ringct/range_proof.cpp/.h` | Confidential amount range proofs |
| Balance proofs | `ringct/balance_proof.cpp/.h` | Input/output balance verification |
| Commitments | `ringct/commitment.cpp/.h` | Pedersen commitments for amounts |
| Ring selection | `ringct/ring_selection.cpp/.h` | Decoy selection algorithm |
| Proof encoding | `ringct/proof_encoding.h` | Serialization of proof structures |
| Merkle tree | `merkle_tree.cpp/.h` | Shielded note commitment tree |
| Nullifier set | `nullifier.cpp/.h` | Double-spend prevention |
| Note encryption | `note_encryption.cpp/.h` | Encrypted note payloads |
| Notes | `note.cpp/.h` | Shielded note structure |
| Spend authorization | `spend_auth.cpp/.h` | Spend key derivation and signing |
| Bundle | `bundle.cpp/.h` | Shielded transaction bundle construction |
| Validation | `validation.cpp/.h` | Shielded transaction consensus rules |
| Turnstile | `turnstile.cpp/.h` | Transparent-to-shielded value transfer |
| Lattice crypto | `lattice/poly.cpp/.h`, `polyvec.cpp/.h`, `ntt.cpp/.h`, `sampling.cpp/.h`, `params.h`, `polymat.h` | Post-quantum lattice primitives |

**Wallet integration:**

- `wallet/shielded_wallet.cpp/.h` (2,246 lines): Full shielded wallet with note tracking, key management, and transaction construction
- `wallet/shielded_rpc.cpp` (1,185 lines): RPC interface for shielded operations
- `wallet/shielded_coins.cpp/.h` (214 lines): Shielded UTXO management

**Consensus integration:**

- `consensus/tx_check.cpp`: Shielded bundle structural validation
- `consensus/tx_verify.cpp`: Shielded transaction contextual validation
- `validation.cpp`: Full block-level shielded validation
- `txmempool.cpp/.h`: Shielded-aware mempool with nullifier tracking
- `net_processing.cpp/.h`: Shielded transaction relay
- `node/miner.cpp/.h`: Shielded-aware block construction
- `policy/policy.cpp/.h`: Shielded relay policy
- `primitives/transaction.cpp/.h`: Shielded bundle in transaction structure
- `protocol.cpp/.h`: Shielded P2P message types

**Test coverage: 404 unit tests across 27 suites:**

- `shielded_merkle_tests` (42): Merkle tree operations
- `shielded_kat_tests` (44): Known-answer tests for crypto primitives
- `shielded_proof_adversarial_tests` (38): Adversarial proof manipulation
- `ringct_ring_signature_tests` (31): Ring signature correctness
- `shielded_transaction_tests` (25): End-to-end transaction validation
- `shielded_audit_regression_tests` (24): Regression tests from audit findings
- `shielded_validation_checks_tests` (19): Consensus rule enforcement
- `shielded_tx_check_tests` (18): Structural validation
- `shielded_hardening_tests` (14): Security hardening edge cases
- `ringct_range_proof_tests` (13): Range proof soundness
- `ring_selection_tests` (13): Decoy selection correctness
- `shielded_note_tests` (13): Note construction and encryption
- `shielded_stress_tests` (12): Performance under load
- `nullifier_set_tests` (11): Double-spend detection
- `ringct_matrict_tests` (11): MatriCT proof correctness
- `ringct_commitment_tests` (10): Commitment scheme
- `shielded_audit_compliance_tests` (10): Audit compliance
- `ringct_balance_proof_tests` (9): Balance verification
- `note_encryption_tests` (9): Note encryption/decryption
- `lattice_poly_tests` (7): Polynomial arithmetic
- `shielded_tx_verify_tests` (6): Contextual verification
- `shielded_turnstile_tests` (6): Value transfer
- `lattice_polyvec_tests` (5): Polynomial vector operations
- `shielded_mempool_tests` (4): Mempool integration
- `shielded_wallet_address_tests` (4): Address generation
- `shielded_coin_selection_tests` (3): Coin selection
- `shielded_merkle_serialization_tests` (3): Tree serialization

**Functional tests (16):**

- `p2p_shielded_relay.py`: P2P relay of shielded transactions
- `wallet_shielded_send_flow.py`: End-to-end send workflow
- `wallet_shielded_rpc_surface.py`: Complete RPC coverage
- `wallet_shielded_reorg_recovery.py`: Chain reorganization handling
- `wallet_shielded_restart_persistence.py`: Wallet persistence across restarts
- `wallet_shielded_encrypted_persistence.py`: Encrypted wallet storage
- `wallet_shielded_cross_wallet.py`: Cross-wallet transfers
- `wallet_shielded_anchor_window.py`: Anchor block window behavior
- `wallet_shielded_viewingkey_rescan.py`: View key import and rescan
- `wallet_shielded_mixed_stress.py`: Mixed transparent/shielded stress
- `wallet_shielded_sendmany_stress.py`: Batch sending stress
- `wallet_shielded_longhaul_sim.py`: Long-running simulation
- `wallet_shielded_randomized_sim.py`: Randomized transaction simulation
- `wallet_shielded_topology_sim.py`: Network topology simulation
- `shielded_reference_vectors.py`: Reference vector validation

**Fuzz targets (1):**

- `fuzz/shielded_proof_deserialize.cpp`: Proof deserialization fuzzing

**Benchmarks (5):**

- `bench/shielded_matrict_bench.cpp`: MatriCT proof generation/verification
- `bench/shielded_ring_signature_bench.cpp`: Ring signature performance
- `bench/shielded_merkle_bench.cpp`: Merkle tree operations
- `bench/shielded_note_bench.cpp`: Note operations
- `bench/shielded_turnstile_bench.cpp`: Turnstile operations

---

## 4. Security Infrastructure

### Reorg Depth Protection: Implemented

- Consensus parameter `nMaxReorgDepth` set to 144 blocks across all chain configurations (`src/consensus/params.h:148`, `src/kernel/chainparams.cpp`)
- Enforced in `validation.cpp:4330-4337` — reorgs exceeding the limit are rejected with a descriptive error

### Peer Verification Budget: Implemented

- Per-peer budget tracking via `ConsumeMatMulPeerVerifyBudget()` (`pow.cpp:1371`)
- IBD-aware budget relaxation to 2000/min (`pow.cpp:1365`)
- Fast-phase burst allowance of 600/min (`pow.cpp:1392`)
- Global Phase 2 budget with mutex-protected accounting (`pow.cpp:1403`)
- Validation window for skip-ahead during IBD (`nMatMulValidationWindow`)

### Launch Readiness Tests: Implemented

- `src/test/btx_launch_readiness_tests.cpp`: Dedicated test suite validating all consensus parameters, activation heights, and security settings are correctly configured for launch

---

## 5. Summary

BTX is a complete cryptocurrency node implementation featuring:

- **MatMul PoW**: Novel matrix multiplication proof-of-work over GF(2^31-1) with ASERT difficulty adjustment, GPU acceleration, and comprehensive DoS protection
- **Post-Quantum Cryptography**: Full SLH-DSA and ML-DSA signature support with P2MR script types, CSFS/CTV opcodes, and PQ multisig — backed by a 42,500-line dedicated PQC library
- **Shielded Pool**: RingCT-based confidential transactions evolving toward `DIRECT_SMILE` as the reset-chain default, with nullifier-based double-spend prevention and full wallet integration; MatRiCT remains in-tree as transitional fallback / failover while the SMILE public-account and verifier work lands

The codebase contains **911 unit test cases** across **60 test suites**, **30 functional tests**, **4 fuzz targets**, and **7 benchmark suites**. All three major subsystems are implemented end-to-end from consensus rules through wallet RPCs, but final launch-readiness claims for shielded direct spends must follow the newer March 20 production-status documents rather than this earlier architecture summary.
