# BTX Node

BTX is a post-quantum, AI-infrastructure-friendly blockchain derived from
[Bitcoin Knots](https://github.com/bitcoinknots/bitcoin) v29.2. It replaces
Bitcoin's SHA-256d proof of work with **MatMul PoW** — a novel consensus
mechanism based on matrix multiplication over a finite field — adds
**post-quantum transaction signatures** via witness v2 P2MR outputs, provides a
**shielded transaction pool** with lattice-based confidential transactions
active from genesis, enforces reduced-data transaction constraints (BIP
110-style) from genesis, and implements **Dandelion++ transaction relay** (BIP
156) for network-layer anonymity.

This repository contains the full node implementation, wallet, mining
infrastructure, and test suites.

Shielded launch status: the reset-chain Smile-only launch surface is live and
production ready on `main`. `DIRECT_SMILE` is the default
direct shielded spend backend, shared-ring `BATCH_SMILE` ingress is the live
bridge-in path, registry state now commits full shielded account-leaf payloads,
and consumed-leaf tx witnesses are lean on wire while full nodes recover
`CompactPublicAccount` state from authenticated consensus data. The supported
direct CT protocol remains intentionally limited to the audited single-round
SMILE surface `anon_set <= NUM_NTT_SLOTS` (`32`), and the live chain launch
wallet default ring size is `RING_SIZE = 8`, with larger configured rings
already supported on the same wire surface up to
`nMaxShieldedRingSize = 32`.

Current measured launch-surface figures on the pre-`61000` baseline surface:

- headline mixed L1 launch blend: `199` direct `1x2 v2_send` +
  `3,064` transparent `1-in/2-out witness_v2_p2mr` per `24 MB` block at a
  `50/50` block-space split, or `3,263 tx/block` and about `36.26 TPS`
- proofless deposit `v2_send` (prefork compatibility only; not part of the
  post-`61000` direct-send readiness surface): `19,172` tx bytes, `221 ms`
  sample build, `1,251 tx/block`
- live wallet direct send `1x2`: `60,218` tx bytes,
  `22.71 s` sample wallet first-prove, `398 tx/block`
- canonical redesign-report `1x2`: `60,110` tx bytes, `51,099` proof bytes,
  `10.20 s` build median, `304.26 ms` verify median, `399 tx/block`
- direct send `2x2`: `70,272` tx bytes, `61,091` proof bytes,
  `7.29 s` build median, `481.09 ms` verify median, `341 tx/block`
- direct send `2x4`: `101,918` tx bytes, `84,111` proof bytes,
  `5.09 s` build median, `538.55 ms` verify median, `235 tx/block`
- mixed unshield `v2_send` (prefork compatibility only; post-`61000` unshield
  moves to bridge/egress): `44,330` tx bytes, `10.88 s` sample build,
  `541 tx/block`
- ingress `63 leaves / 8 spends / 8 proof shards / 1 reserve`: `312,364`
  tx bytes, `281,622` proof bytes, `109.86 s` build median,
  `5.69 s` verify median, `76 tx/block`
- egress `32x32`: `470,168` tx bytes, `433` proof bytes,
  `463.14 ms` full pipeline median, `9.99 ms` verify median, `51 tx/block`

Current `main` already includes the account-registry activation, the remaining
wallet transaction-family transition onto `v2_send`, and the future-proofed
settlement slack for later bridge/L2 soft-fork tightening. The settlement-side
upgrade lane now lives on the existing bridge/proof envelope:

- `BridgeBatchStatement version = 5`
- `BridgeBatchCommitment version = 3`
- `BridgeBatchAggregateCommitment`
- `ProofEnvelope.extension_digest`

That means later settlement upgrades can tighten semantics around
`action_root`, `data_availability_root`, `recovery_or_exit_root`,
`extension_flags`, `policy_commitment`, and `extension_digest` without first
inventing a new outer settlement object. Post-launch hard-fork-only size/TPS
optimization work remains tracked in
[doc/btx-smile-v2-optimization-tracker-2026-03-21.md](doc/btx-smile-v2-optimization-tracker-2026-03-21.md)
and the stable follow-on roadmap in
[doc/btx-postlaunch-optimization-roadmap.md](doc/btx-postlaunch-optimization-roadmap.md).
The merged account-registry activation work is documented in
[doc/btx-smile-v2-shielded-account-registry-redesign-2026-03-22.md](doc/btx-smile-v2-shielded-account-registry-redesign-2026-03-22.md).
The merged future-proofed settlement work is documented in
[doc/btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md](doc/btx-smile-v2-future-proofed-settlement-tdd-2026-03-23.md).
Wave 3 also adds a shared proof-redesign gate via
`smile2_proof_redesign_framework_tests/*` and
`gen_smile2_proof_redesign_report` so every future proof-object rewrite is
checked against one consistent correctness / tamper / size / runtime baseline.

Current ring-size roadmap:

- launch defaults to `RING_SIZE = 8` for better base-layer capacity;
- operators can already raise the configured ring size within the supported
  `8..32` range on the current wire / consensus surface without a hard fork or
  transaction-family change;
- the longer-term throughput path is still aggregated settlement above L1, not
  relying only on progressively larger direct rings.
- the `61000` shielded hardening fork, security closeout, and later PQ-128
  upgrade lane are documented in
  [doc/security/README.md](doc/security/README.md).

## Table of Contents

- [Chain Parameters](#chain-parameters)
- [MatMul Proof of Work](#matmul-proof-of-work)
- [Post-Quantum Cryptography](#post-quantum-cryptography)
- [Shielded Pool](#shielded-pool)
- [Dandelion++ Transaction Relay](#dandelion-transaction-relay)
- [CTV + CSFS Covenants](#ctv--csfs-covenants)
- [Building from Source](#building-from-source)
- [Running a Node](#running-a-node)
- [Wallet Operations](#wallet-operations)
- [Key Management](#key-management)
- [Shielded Transfer Builder](#shielded-transfer-builder)
- [Mining](#mining)
- [Running Tests](#running-tests)
- [RPC Interface](#rpc-interface)
- [Network Configuration](#network-configuration)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

---

## Chain Parameters

| Parameter | Value |
|---|---|
| **PoW Algorithm** | MatMul PoW (matrix multiplication over F_{2^31 - 1}) |
| **Block Time** | 90 s target spacing from genesis |
| **Block Limits** | 24 MB serialized, 24 MWU weight, 480k sigops cost |
| **Max Supply** | 21 000 000 BTX |
| **Initial Block Reward** | 20 BTX |
| **Halving Interval** | 525 000 blocks |
| **Difficulty Adjustment** | ASERT (aserti3-2d), per-block, active from block 0 |
| **Address Format** | Bech32m witness v2 P2MR: `btx1z...` (HRP `btx`) |
| **Shielded Address Format** | `btxs1...` (Bech32m shielded) |
| **Mainnet P2P Port** | 19335 |
| **Mainnet RPC Port** | 19334 |
| **Consensus Outputs** | P2MR-only witness v2 `OP_2 <32>` + `OP_RETURN` (mainnet/testnet/testnet4) |
| **Consensus Features** | Reduced-data limits from genesis (BIP 110-style) |
| **PQ Signatures** | ML-DSA-44 (primary) + SLH-DSA-SHAKE-128s (backup) via witness v2 P2MR |
| **Shielded Pool** | Lattice-based confidential transactions, active from genesis |
| **Default Shielded Ring Size** | 8 |
| **Supported Shielded Ring Sizes** | 8..32 on the current wire / consensus surface |
| **Dandelion++ Relay** | Stem-then-fluff privacy relay, activates at block 250 000 |

### Block Reward Schedule

| Block Range | Reward |
|---|---|
| 0 -- 524 999 | 20 BTX |
| 525 000 -- 1 049 999 | 10 BTX |
| 1 050 000 -- 1 574 999 | 5 BTX |
| 1 575 000 -- 2 099 999 | 2.5 BTX |
| ... | halves every 525 000 blocks until 0 |

---

## MatMul Proof of Work

MatMul PoW is an AI-infrastructure-friendly proof of work based on the paper
*"Proofs of Useful Work from Arbitrary Matrix Multiplication"*
(Komargodski, Schen, Weinstein —
[arXiv:2504.09971](https://arxiv.org/abs/2504.09971), April 2025).

Instead of brute-force hashing, miners perform matrix multiplications over a
Mersenne prime field (q = 2^31 - 1). The core work unit — large dense matrix
multiplication — is the same operation that dominates GPU and TPU workloads for
AI/ML training and inference, making the mining hardware directly reusable for
productive computation.

### How It Works

1. **Seed derivation**: Two deterministic seeds (`seed_a`, `seed_b`) are derived
   from the previous block hash and current height. Miners cannot choose
   favorable matrices.

2. **Matrix generation**: Seeds expand into two n x n matrices (A, B) over F_q.

3. **Noise injection**: A low-rank noise perturbation (rank r) is generated from
   the block header and nonce, producing A' = A + E and B' = B + F. This
   prevents precomputation.

4. **Matrix multiplication**: The miner computes C' = A' x B' — a standard
   dense matrix product.

5. **Transcript hashing**: The result is canonicalized into block-sized chunks,
   compressed with a deterministic vector, and hashed with SHA-256.

6. **Difficulty check**: If the transcript hash meets the target, the block is
   valid.

### Two-Phase Validation

- **Phase 1** (O(1)): Checks header fields, dimension bounds, seed validity,
  and that the digest meets the target. Every node runs this on every block.
- **Phase 2** (O(n^3)): Reconstructs matrices, performs the full multiplication,
  and verifies the transcript hash. Rate-limited to 8 verifications per peer
  per minute. Only applied to recent blocks (last 1000 on mainnet).

From block `61000`, mainnet validation switches to the
product-committed digest path for MatMul proof-of-work hardening. The
historical bootstrap/ASERT/pre-hash mainnet schedule remains frozen at
`50000`; only the newer post-launch hardening activations live at `61000`.
The current source of truth for that transition and its regression coverage is
[doc/btx-matmul-product-digest-mining-fix-2026-04-03.md](doc/btx-matmul-product-digest-mining-fix-2026-04-03.md).

### Parameters by Network

| Parameter | Mainnet | Testnet | Regtest |
|---|---|---|---|
| Matrix dimension (n) | 512 | 256 | 64 |
| Transcript block size (b) | 16 | 8 | 8 |
| Noise rank (r) | 8 | 4 | 4 |
| Pre-hash epsilon bits | 10 (18 from block 50 000) | 10 | 10 |
| Validation window | 1000 | 500 | 10 |
| Phase 2 ban threshold | 3 | unlimited | unlimited |

### Block Header

The BTX block header extends Bitcoin's 80-byte header:

```
nVersion        (4 bytes)      Block version
hashPrevBlock   (32 bytes)     Previous block hash
hashMerkleRoot  (32 bytes)     Transaction merkle root
nTime           (4 bytes)      Block timestamp
nBits           (4 bytes)      Difficulty target (compact)
nNonce64        (8 bytes)      64-bit mining nonce
matmul_digest   (32 bytes)     SHA-256 of MatMul transcript
matmul_dim      (2 bytes)      Matrix dimension used
seed_a          (32 bytes)     Deterministic seed for matrix A
seed_b          (32 bytes)     Deterministic seed for matrix B
```

Total serialized header: ~182 bytes.

For the full MatMul PoW specification, see
[doc/btx-matmul-pow-spec.md](doc/btx-matmul-pow-spec.md).

---

## Post-Quantum Cryptography

BTX implements **NIST-standardized post-quantum digital signatures** through a
new output type called **P2MR** (Pay-to-Merkle-Root), activated as **witness
version 2**.

### Algorithms

| Algorithm | Role | Pubkey | Signature | Type |
|---|---|---|---|---|
| **ML-DSA-44** (Dilithium) | Primary | 1312 bytes | 2420 bytes | Lattice-based |
| **SLH-DSA-SHAKE-128s** (SPHINCS+) | Backup | 32 bytes | 7856 bytes | Hash-based |

BTX keeps ML-DSA-44 as the active primary algorithm today. Falcon-512 is not
enabled yet, but this branch reserves P2MR soft-fork slots for a future Falcon
activation path once implementations, audits, and operational tooling are
mature enough to ship safely.

### P2MR Design

P2MR uses a **hybrid two-leaf Merkle tree**:

- **Primary leaf**: `<1312-byte-pubkey> OP_CHECKSIG_MLDSA` — lattice-based
  ML-DSA-44 signature for everyday transactions.
- **Backup leaf**: `<32-byte-pubkey> OP_CHECKSIG_SLHDSA` — stateless
  hash-based SLH-DSA signature for key-compromise recovery.

The witness program is a 32-byte Merkle root: `OP_2 <merkle-root>`. Addresses
use Bech32m encoding with witness version 2, giving the prefix `btx1z...`.

### Script Opcodes

| Opcode | Function |
|---|---|
| `OP_CHECKSIG_MLDSA` | Verify ML-DSA-44 signature against P2MR sighash |
| `OP_CHECKSIG_SLHDSA` | Verify SLH-DSA-SHAKE-128s signature against P2MR sighash |
| `OP_CHECKSIGADD_MLDSA` | Accumulate ML-DSA signature result for threshold multisig |
| `OP_CHECKSIGADD_SLHDSA` | Accumulate SLH-DSA signature result for threshold multisig |
| `OP_CHECKTEMPLATEVERIFY` | Enforce CTV template hash in P2MR leaves |
| `OP_CHECKSIGFROMSTACK` | Verify externally provided message signatures in P2MR leaves |

Reserved for future P2MR soft forks and intentionally left inactive today:

| Reserved Opcode | Current Meaning |
|---|---|
| `OP_CHECKSIG_FALCON` | P2MR `OP_SUCCESS` reservation for future Falcon checksig |
| `OP_CHECKSIGADD_FALCON` | P2MR `OP_SUCCESS` reservation for future Falcon multisig |
| `OP_CHECKSIGFROMSTACK_FALCON` | P2MR `OP_SUCCESS` reservation for future Falcon CSFS/oracle paths |

### Wallet Integration

- **Descriptor format**: `mr(<mldsa-key>,pk_slh(<slhdsa-key>))`, plus CTV/CSFS
  leaf forms `ctv(...)`, `ctv_pk(...)`, `csfs(...)`, and `csfs_pk(...)`
- **Multisig descriptors**: `mr(multi_pq(...))` and `mr(sortedmulti_pq(...))`
- **Timelocked multisig descriptors**: `mr(cltv_multi_pq(...))`,
  `mr(csv_multi_pq(...))`, `mr(ctv_multi_pq(...))`, plus sorted variants
- **Miniscript integration**: P2MR context supports PQ key and threshold fragments
- **HD derivation**: Purpose `87h` for P2MR descriptors
- **Relay policy**: P2MR-only enforcement with watch-only guardrails

For the full PQ specification and tutorials, see:
- [doc/btx-pqc-spec.md](doc/btx-pqc-spec.md)
- [doc/btx-pq-multisig-spec.md](doc/btx-pq-multisig-spec.md)
- [doc/btx-pq-multisig-tutorial.md](doc/btx-pq-multisig-tutorial.md)
- [doc/btx-key-management-guide.md](doc/btx-key-management-guide.md)
- [doc/falcon-softfork-readiness-analysis-2026-03-29.md](doc/falcon-softfork-readiness-analysis-2026-03-29.md)

---

## Shielded Pool

BTX includes a **shielded transaction pool** active from genesis on all
networks. Shielded transactions hide sender, receiver, and amount using
lattice-based zero-knowledge proofs, while coinbase rewards are automatically
moved into the shielded pool by default.

### Production Status

As of `2026-03-23`, the production reset-chain launch architecture is:

- `DIRECT_SMILE` as the default direct `z_sendmany` backend,
- default direct ring size `8`, configurable up to `32` on the current wire
  surface via `-shieldedringsize`,
- wallet-built transparent deposit (`z_shieldcoinbase` and compatible
  coinbase-only `z_shieldfunds` sweeps after `61000`),
  fully shielded direct send, note merge, and mixed shielded-to-transparent
  unshield all running on the `v2_send` transaction family,
- shared-ring `BATCH_SMILE` ingress on the live bridge-in path,
- full account-leaf payloads committed in registry state so future spend
  reconstruction comes from authenticated consensus data,
- lean consumed-leaf transaction witnesses on wire
  (`leaf_index + account_leaf_commitment + sibling_path`),
- egress, rebalance, and settlement flows aligned with the same shielded state
  model,
- legacy MatRiCT and receipt-backed ingress retained only as non-launch
  residual tooling.

The hard-fork launch protocol is final for this chain. Larger recursive CT
anonymity sets are not part of that protocol and are explicitly rejected by
prover and verifier instead of falling back to the old prototype multi-level CT
branch.

Current measured launch-surface figures on the pre-`61000` baseline surface are:

- headline mixed-L1 throughput at a `50/50` block-space split between
  direct `1x2 v2_send` and a canonical transparent `1-in/2-out` P2MR send:
  `3,263 tx/block`, about `36.26 TPS` at `90 s`
  (`199` shielded + `3,064` transparent)
- proofless deposit `v2_send` (prefork compatibility only; not part of the
  post-`61000` direct-send readiness surface): `19,172` bytes, `221 ms`
  sample build, `1,251 tx/block` (`13.90 TPS` at `90 s`)
- live wallet `1x2 v2_send`: `60,218` bytes, `22.71 s` sample wallet first-prove,
  `398 tx/block` at the 24 MB serialized cap.
- canonical redesign-report `1x2 v2_send`: `60,110` bytes,
  `51,099` proof bytes, `10.20 s` build, `304.26 ms` verify,
  `399 tx/block`.
- `2x2 v2_send`: `70,272` bytes, `61,091` proof bytes, `7.29 s` build,
  `481.09 ms` verify, `341 tx/block`.
- `2x4 v2_send`: `101,918` bytes, `84,111` proof bytes, `5.09 s` build,
  `538.55 ms` verify, `235 tx/block`.
- mixed unshield `v2_send` (prefork compatibility only; post-`61000` unshield
  moves to bridge/egress): `44,330` bytes, `10.88 s` sample build,
  `541 tx/block` (`6.01 TPS`)
- Smile ingress `63 leaves / 8 spends / 8 proof shards / 1 reserve`:
  `312,364` bytes, `281,622` proof bytes, `109.86 s` build,
  `5.69 s` verify, `76 tx/block`
  (`4,788` represented ingress leaves / block at the proven launch ceiling).
- `32-output v2_egress`: `470,168` bytes, `433` proof bytes,
  `463.14 ms` full pipeline, `9.99 ms` verify, `51 tx/block`
  (`1,632` represented outputs / block).
- representative rebalance / settlement capacity from the live netting report:
  - `32x95`: rebalance `38,073` bytes / `6,880` proof bytes /
    `2.63 ms` build / `0.36 ms` validate / `630 tx/block`
  - `64x99`: rebalance `75,753` bytes / `13,760` proof bytes /
    `6.22 ms` build / `0.63 ms` validate / `316 tx/block`
  - settlement anchors remain `433` proof bytes and scale to `2,400 tx/block`
    by shielded verify units

These are the current measured launch-surface figures for the reset-chain
Smile-default protocol. For the current architecture, readiness report, and
benchmark details, see
[doc/btx-shielded-production-status-2026-03-20.md](doc/btx-shielded-production-status-2026-03-20.md).
For the completed genesis-reset launch checklist, see
[doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md](doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md).
For the post-launch proof-size / TPS optimization workstream built on that
baseline, see
[doc/btx-smile-v2-optimization-tracker-2026-03-21.md](doc/btx-smile-v2-optimization-tracker-2026-03-21.md)
and
[doc/btx-postlaunch-optimization-roadmap.md](doc/btx-postlaunch-optimization-roadmap.md).
For the shielded hardening fork at `61000`, audit closeout, and remaining
security roadmap, see [doc/security/README.md](doc/security/README.md).
For the transaction-family migration and mixed send benchmark details, see
[doc/btx-smile-v2-transaction-family-transition-2026-03-23.md](doc/btx-smile-v2-transaction-family-transition-2026-03-23.md).
The mixed headline assumes a `24 MB` serialized block cap, `90 s` target block
time, `12 MB` reserved for direct `1x2 v2_send` at `60,218` bytes, and
`12 MB` reserved for a measured transparent `witness_v2_p2mr` send at
`3,916` bytes.

The shielded pool is built on lattice-based confidential transaction protocols
providing:

- **Confidential amounts**: Pedersen-style commitments hide transaction values
- **Ring signatures**: Each spend references a ring of decoy commitments,
  hiding the true input among decoys
- **Range proofs**: Prove output values are non-negative without revealing them
- **Balance proofs**: Cryptographic guarantee that inputs equal outputs plus fees
- **Nullifier-based double-spend prevention**: Each note produces a unique
  nullifier; the global nullifier set prevents replay

### Transaction Types

| Type | Description |
|---|---|
| **Shield** (transparent -> shielded) | Prefork compatibility deposit on proofless `v2_send`; post-`61000` general public-flow `V2_SEND` is retired, with mature-coinbase compatibility retained for miner shielding |
| **Unshield** (shielded -> transparent) | Prefork compatibility unshield on mixed `v2_send`; post-`61000` transparent settlement moves to explicit bridge/egress surfaces |
| **Fully shielded** (shielded -> shielded) | Transfer within the pool on post-fork `DIRECT_SMILE` `v2_send` |

### Auto-Shield Coinbase

When enabled (default: **on**), the wallet automatically shields mature
coinbase outputs into the shielded pool on each new block.

```bash
# Disable auto-shielding (opt-out)
btxd -autoshieldcoinbase=0

# Manual shielding
btx-cli z_shieldcoinbase
```

### Shielded RPCs

| RPC | Description |
|---|---|
| `z_getnewaddress` | Generate a new shielded address |
| `z_listaddresses` | List all shielded addresses in the wallet |
| `z_getbalance` | Shielded balance with optional minimum confirmations |
| `z_gettotalbalance` | Combined transparent + shielded balance |
| `z_listunspent` | List unspent shielded notes |
| `z_sendmany` | Send to shielded recipients and, before `61000`, optionally transparent recipients |
| `z_shieldcoinbase` | Shield mature coinbase outputs into the pool |
| `z_shieldfunds` | Shield transparent UTXOs with automatic chunking; after `61000`, limited to mature coinbase compatibility sweeps |
| `z_mergenotes` | Consolidate many small notes into one |
| `z_viewtransaction` | Decode shielded transaction details (with viewing keys) |
| `z_exportviewingkey` | Export KEM viewing key for auditors |
| `z_importviewingkey` | Import viewing key for watch-only monitoring |

### Selective Disclosure (View Grants)

Transactions can include **CViewGrant** entries that encrypt viewing keys to
designated auditors using ML-KEM. This allows selective transparency for
compliance or audit workflows without compromising privacy for other
participants. Up to 8 view grants per transaction.

For detailed setup and operations, see
[doc/btx-shielded-pool-guide.md](doc/btx-shielded-pool-guide.md).

---

## Dandelion++ Transaction Relay

BTX implements **Dandelion++** (BIP 156), a privacy-enhancing protocol for
transaction relay that prevents adversaries from linking transactions to their
originating IP addresses.

### How It Works

1. **Stem phase**: The originating node sends the transaction to one randomly
   chosen peer. That peer forwards it to one more peer, creating a random walk
   (~10 hops expected).

2. **Fluff phase**: After stem relaying, a node probabilistically (10% per hop)
   transitions the transaction to standard diffusion relay, making it appear to
   originate from the fluff point.

| Parameter | Value |
|---|---|
| Activation Height | Block 250 000 |
| Service Flag | `NODE_DANDELION` (bit 30) |
| Epoch Interval | ~600 s |
| Stem Probability | 90% per hop |
| Relay Destinations | 2 outbound peers per epoch |
| Embargo Timer | Exponential, mean 39 s |

```bash
# Disable Dandelion++ (opt-out, default: enabled)
btxd -dandelion=0
```

For the full protocol specification, see
[doc/dandelion-pp-implementation-spec-v2.md](doc/dandelion-pp-implementation-spec-v2.md).

---

## CTV + CSFS Covenants

P2MR includes covenant and oracle primitives:

- **CTV (`OP_CHECKTEMPLATEVERIFY`)**: Template-constrained spends for vaults
  and payment trees.
- **CSFS (`OP_CHECKSIGFROMSTACK`)**: Message-based oracle signatures (ML-DSA-44
  or SLH-DSA-128s) with optional spender CHECKSIG.
- **DoS hardening**: Explicit validation-weight charging for ML-DSA, SLH-DSA,
  and CSFS; 10,000-byte consensus caps for P2MR script elements.

L2 profile: Supported constructions include CTV vaults/payment trees and CSFS
delegation closes. `SIGHASH_ANYPREVOUT` (APO) is not implemented.

---

## Building from Source

### Requirements

- **C++ compiler**: GCC 11.1+ or Clang 16.0+
- **CMake**: 3.22+
- **Boost**: 1.73.0+
- **libevent**: 2.1.8+
- **Python**: 3.10+ (for functional tests)

Optional: SQLite 3.7.17+ (descriptor wallets), Qt 5.11+/6.2+ (GUI),
ZeroMQ 4.0+ (notifications).

### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config \
  libboost-dev libevent-dev libsqlite3-dev python3 python3-zmq

cmake -B build
cmake --build build -j$(nproc)
```

### macOS

```bash
brew install cmake boost libevent sqlite pkg-config

cmake -B build
cmake --build build -j$(sysctl -n hw.logicalcpu)
```

### Convenience Script

```bash
scripts/build_btx.sh build-btx
```

### Windows 11 Quickstart

Use the BTX Windows wrapper for a native Windows 11 build:

```powershell
powershell -ExecutionPolicy Bypass -File .\contrib\devtools\build-btx-windows.ps1 `
  -InstallDependencies
```

That wrapper bootstraps a short-path standalone `vcpkg`, builds a
wallet-enabled headless node, and runs a regtest smoke test. See
[doc/btx-windows-11-compile-handbook.md](doc/btx-windows-11-compile-handbook.md)
for the step-by-step handbook and
[doc/build-windows-msvc.md](doc/build-windows-msvc.md) for the full Windows
build walkthrough.

For native CLI release assembly without Guix, see
`scripts/release/cut_local_release.py` together with
[doc/btx-github-release-automation.md](doc/btx-github-release-automation.md).

If you only need the bundled precompiled CLI archives from this snapshot, use
the files in `contrib/prebuilt/releases/`.

### Build Options

| Option | Default | Description |
|---|---|---|
| `BUILD_DAEMON` | ON | Build `btxd` |
| `BUILD_CLI` | ON | Build `btx-cli` |
| `BUILD_GUI` | OFF | Build `btx-qt` (requires Qt) |
| `BUILD_WALLET_TOOL` | auto | Build `btx-wallet` |
| `BUILD_TESTS` | ON | Build unit test suite |
| `BUILD_BENCH` | OFF | Build benchmark binary |
| `ENABLE_WALLET` | ON | Enable wallet support |
| `WITH_SQLITE` | auto | SQLite wallet backend |

### Platform-Specific Guides

- [Linux/Unix](doc/build-unix.md)
- [macOS](doc/build-osx.md)
- [Windows (MinGW)](doc/build-windows.md)
- [Windows (MSVC)](doc/build-windows-msvc.md)
- [Windows 11 Step-by-Step Handbook](doc/btx-windows-11-compile-handbook.md)
- [FreeBSD](doc/build-freebsd.md)

---

## Running a Node

### Fast-Start Validating Nodes

BTX releases are designed to support a fast-start validating-node workflow for
binary users: install a precompiled archive, load the matching rollback
snapshot, and begin using wallet, mining, and service RPCs before a full
historical sync finishes.

The shortest operator path is:

```bash
export GH_TOKEN="$(<github.key)"  # only needed for private GitHub releases

python3 contrib/faststart/btx-agent-setup.py \
  --repo btxchain/btx-node \
  --release-tag v29.2-btx1 \
  --preset service \
  --datadir="$HOME/.btx"
```

That installer consumes the published `btx-release-manifest.json`, selects the
correct platform archive, verifies the advertised assets, and can immediately
chain into the assumeutxo bootstrap flow. Use `--preset miner` for a pruned,
mining-oriented setup, or `--preset service` for an RPC-oriented node that is
ready to issue `easy` / `normal` / `hard` / `idle` MatMul service challenges
through `listmatmulservicechallengeprofiles`,
`getmatmulservicechallengeplan`, and
`issuematmulservicechallengeprofile`. The planner and profile RPCs now return
`issue_defaults` / `profile_issue_defaults` so agents can round-trip directly
into `getmatmulservicechallenge` or `issuematmulservicechallengeprofile`
without re-deriving difficulty math by hand. Service operators can also watch
`getdifficultyhealth.service_challenge_registry` for shared-registry health,
run `solvematmulservicechallenge` with explicit `time_budget_ms` /
`solver_threads` limits for background clients, and use the stateless final
flag on `verifymatmulserviceproof` / `verifymatmulserviceproofs` when they need
pure verification without local registry lookups. In `--json` mode, the
installer now keeps bootstrap progress on stderr and returns a machine-readable
summary that includes the installed `btxd` / `btx-cli` paths, the generated
fast-start config, and miner-preset handoff commands for
`contrib/mining/start-live-mining.sh`. For private GitHub releases, export one
of `BTX_GITHUB_TOKEN`, `GITHUB_TOKEN`, or `GH_TOKEN` first so the installer can
authenticate the release-asset downloads.

For the full operator flow, see
[doc/btx-download-and-go.md](doc/btx-download-and-go.md),
[doc/assumeutxo.md](doc/assumeutxo.md), and
[contrib/faststart/README.md](contrib/faststart/README.md).

### Starting the Daemon

```bash
# Foreground
./build/bin/btxd

# Background daemon
./build/bin/btxd -daemon

# Testnet
./build/bin/btxd -testnet -daemon

# Regtest (local testing)
./build/bin/btxd -regtest -daemon
```

### Configuration

Create `~/.btx/btx.conf`:

```ini
server=1
listen=1
port=19335

rpcuser=btxrpc
rpcpassword=your_secure_password
rpcport=19334

dbcache=4096
maxmempool=300

# Fast node (recommended):
prune=4096
# Archival node:
# prune=0

# Bootstrap peers
minimumchainwork=0
dnsseed=1
fixedseeds=1
addnode=node.btx.tools:19335
addnode=146.190.179.86:19335
addnode=164.90.246.229:19335
```

Or generate a profile automatically:

```bash
# Fast node (recommended default)
./contrib/devtools/gen-btx-node-conf.sh fast > ~/.btx/btx.conf

# Archival node
./contrib/devtools/gen-btx-node-conf.sh archival > ~/.btx/btx.conf
```

### Checking Status

```bash
btx-cli getblockchaininfo     # Chain state, sync progress
btx-cli getpeerinfo           # Connected peers
btx-cli getmininginfo         # Mining parameters
btx-cli getmempoolinfo        # Memory pool status
```

### Data Directory

| OS | Default Path |
|---|---|
| Linux | `~/.btx/` |
| macOS | `~/Library/Application Support/BTX/` |
| Windows | `%APPDATA%\BTX\` |

---

## Wallet Operations

### Creating a Wallet

```bash
# Create a new descriptor wallet
btx-cli createwallet "mywallet"
```

Descriptor wallets are required. Default address type is `p2mr`
(`btx1z...`).

### Receiving and Sending

```bash
# Get a new receiving address
btx-cli -rpcwallet=mywallet getnewaddress
# Returns: btx1z...

# Check balance
btx-cli -rpcwallet=mywallet getbalance

# Send BTX
btx-cli -rpcwallet=mywallet sendtoaddress "btx1z..." 1.5

# Shielded balance
btx-cli -rpcwallet=mywallet z_gettotalbalance

# Send to shielded address
btx-cli -rpcwallet=mywallet z_sendmany '[{"address":"btxs1...","amount":1.0}]'
```

### Backup

```bash
# Verify integrity before taking a production backup
btx-cli -rpcwallet=mywallet z_verifywalletintegrity

# Backup wallet file
btx-cli -rpcwallet=mywallet backupwallet "/path/to/backup.dat"

# Preferred: full encrypted bundle archive
btx-cli -rpcwallet=mywallet \
  -stdinwalletpassphrase \
  -stdinbundlepassphrase \
  backupwalletbundlearchive "/path/to/mywallet.bundle.btx"

# Restore from archive
btx-cli -stdinbundlepassphrase \
  restorewalletbundlearchive "restored" "/path/to/mywallet.bundle.btx"
```

### Wallet Encryption

```bash
btx-cli -rpcwallet=mywallet encryptwallet "your_passphrase"
btx-cli -rpcwallet=mywallet walletpassphrase "your_passphrase" 60
btx-cli -rpcwallet=mywallet walletlock
```

For BTX-native treasury, multisig, timelocked recovery, backup, restore, and
AI-safe operating guidance, see
[doc/btx-key-management-guide.md](doc/btx-key-management-guide.md).

## Key Management

BTX's recommended operational model is:

- descriptor wallets only
- P2MR receive/change descriptors
- watch-only coordinators for planning and accounting
- isolated signer wallets or external signers for authorization
- bundle archive backups plus restore drills

Use these docs together:

- [doc/btx-key-management-guide.md](doc/btx-key-management-guide.md)
- [doc/btx-pq-multisig-tutorial.md](doc/btx-pq-multisig-tutorial.md)
- [doc/managing-wallets.md](doc/managing-wallets.md)
- [doc/btx-shielded-pool-guide.md](doc/btx-shielded-pool-guide.md)
- [doc/external-signer.md](doc/external-signer.md)

---

## Shielded Transfer Builder

BTX includes a deterministic operator tool for multisig-to-shielded transfer
bundles at:

- `contrib/shielded_transfer_builder.py`

The builder exposes four explicit phases:

1. `plan`
2. `simulate`
3. `execute`
4. `release`

It is intended for large or operationally sensitive transfers where operators
want:

- a canonical JSON bundle containing the exact unsigned PSBT plan
- deterministic destination ordering and transaction ordering
- authoritative fee convergence through `z_fundpsbt`
- exact finalized mempool preflight before broadcast
- controlled input locking during review and execution

After the post-`61000` privacy fork, `z_fundpsbt` remains suitable for
mature-coinbase compatibility deposits but not for arbitrary transparent
ingress; general transparent deposits should use the bridge-ingress surface.

Example:

```bash
python3 contrib/shielded_transfer_builder.py plan \
  --datadir=/path/to/datadir \
  --chain=main \
  --rpcwallet=signer-1 \
  --signer-wallet=signer-1 \
  --signer-wallet=signer-2 \
  --signer-wallet=signer-3 \
  --destination=btxs1...=1000.00000000 \
  --destination=btxs1...=500.00000000 \
  --bundle=/tmp/transfer-bundle.json
```

The builder reports and consumes the following fee-analysis fields from the
daemon:

- `fee_authoritative`
- `required_mempool_fee`
- `estimated_vsize`
- `estimated_sigop_cost`

For the full operator workflow, lock behavior, auth/config lookup order, and
artifact model, see
[doc/shielded-transfer-builder.md](doc/shielded-transfer-builder.md).

---

## Mining

### Overview

BTX uses MatMul PoW for mining. The built-in solver is available through RPC
for regtest/testnet mining. For production mainnet mining, use
`getblocktemplate` / `submitblock`.

### Regtest Mining (Testing)

```bash
./build/bin/btxd -regtest -daemon
./build/bin/btx-cli -regtest createwallet "miner"
ADDR=$(./build/bin/btx-cli -regtest -rpcwallet=miner getnewaddress)
./build/bin/btx-cli -regtest generatetoaddress 10 "$ADDR"
./build/bin/btx-cli -regtest -rpcwallet=miner getbalance
# -> 200.00000000 (10 blocks x 20 BTX)
```

### Production Mining (getblocktemplate)

```bash
./build/bin/btx-cli getblocktemplate '{"rules": ["segwit"]}'
```

The template includes MatMul-specific fields (`matmul_dim`, `seed_a`,
`seed_b`, `target`). External miners should:

1. Fetch the template via `getblocktemplate`
2. Generate matrices A, B from `seed_a`, `seed_b`
3. Iterate nonces, applying noise and computing the MatMul transcript
4. When the transcript hash meets the target, submit via `submitblock`

### Mining Best Practices

- Keep the node healthy and near tip before mining. `getmininginfo` exposes a
  `chain_guard` section that reports peer count, near-tip peers, and whether
  mining should be paused.
- The chain guard stays conservative around recently active lagging peers, but
  it discounts long-idle stale peers so a few dead outbound connections do not
  pause otherwise healthy mining sessions.
- For normal operation, avoid `connect=`-only peer islands. Prefer normal peer
  discovery plus optional `addnode=` hints so the node can recover from stale
  peer sets on its own.
- If you use the bundled solo-mining helpers, keep enough automatic peer
  capacity available for discovery; the helper restart path now uses
  `-maxconnections=32` by default instead of a tiny connection budget.
- Back up the mining reward wallet together with its descriptors, not just the
  wallet database file.
- Prefer `btxd` / `btx-cli` in scripts and service files.
- If you intentionally drive local solo mining through `generatetoaddress`,
  use a health-aware supervisor instead of a blind shell loop so the miner can
  react to repeated RPC failures or prolonged `chain_guard` pauses.
- For actual idle-time mining, give that supervisor an explicit local idleness
  probe via `--should-mine-command='...'` so chain health alone is not treated
  as permission to keep mining while the machine is busy.

Portable helper scripts for that workflow live in
[`contrib/mining`](contrib/mining):

```bash
# Start a supervised solo-mining loop
contrib/mining/start-live-mining.sh \
  --datadir="$HOME/.btx" \
  --wallet=miner \
  --should-mine-command='/usr/local/bin/btx-should-mine-now' \
  --address-file=/path/to/miner-address.txt

# Back up the mining wallet + descriptors
contrib/mining/backup-wallet.sh \
  --datadir="$HOME/.btx" \
  --wallet=miner
```

### Mining RPCs

| Command | Description |
|---|---|
| `getmininginfo` | Current mining state, difficulty, algorithm |
| `getblocktemplate` | Block template for external mining |
| `submitblock` | Submit a solved block |
| `generatetoaddress` | Mine N blocks (regtest/testnet) |
| `getnetworkhashps` | Estimated network hash rate |

### Genesis Block Generator

```bash
./build/bin/btx-genesis --timestamp "BTX genesis" --max-tries 200000 --backend cpu
./build/bin/btx-genesis --timestamp "BTX genesis" --max-tries 200000 --backend metal
```

Backend selection: `BTX_MATMUL_BACKEND` (`cpu|metal|mlx|cuda`).

---

## Running Tests

### Unit Tests

```bash
ctest --test-dir build
./build/bin/test_btx --log_level=warning
./build/bin/test_btx --run_test=matmul_tests
```

### Functional Tests

```bash
build/test/functional/test_runner.py
build/test/functional/test_runner.py --jobs=4
build/test/functional/test_runner.py wallet_basic.py
```

### BTX-Specific Test Gates

```bash
# Consensus rules verification
scripts/test_btx_consensus.sh build-btx

# Full parallel gate (unit + functional + BTX scripts)
scripts/test_btx_parallel.sh build-btx

# Dual-node P2P connectivity check
scripts/m12_dual_node_p2p_readiness.sh --build-dir build-btx

# Single-node lifecycle smoke
scripts/m15_single_node_wallet_lifecycle.sh \
  --build-dir build-btx \
  --artifact /tmp/btx-m15-single-node.json \
  --node-label mac-host
```

### Full CI Matrix (Local)

```bash
scripts/ci/run_local_mac_matrix.sh all
```

---

## RPC Interface

BTX exposes a JSON-RPC interface compatible with Bitcoin Core. Connect using
`btx-cli` or any Bitcoin RPC client library.

| Category | Description |
|---|---|
| Blockchain | Block queries, chain state, UTXO info |
| Mining | Block templates, generation, submission |
| Wallet | Address management, sending, receiving, backup |
| Shielded | z_sendmany, z_shieldcoinbase, z_getbalance, viewing keys |
| Network | Peer management, banning, network info |
| Raw Transactions | Transaction creation, signing, decoding |

### ZeroMQ Notifications

```bash
btxd -zmqpubhashtx=tcp://127.0.0.1:28332 \
     -zmqpubhashblock=tcp://127.0.0.1:28332
```

---

## Network Configuration

### Networks

| Network | P2P Port | Chain ID | Purpose |
|---|---|---|---|
| Mainnet | 19335 | `main` | Production network |
| Testnet | 29335 | `test` | Public test network |
| Testnet4 | 48333 | `testnet4` | Updated test network |
| Signet | 38333 | `signet` | Custom-challenge test network |
| Regtest | 18444 | `regtest` | Local development and testing |

### DNS Seeds (Mainnet)

```
node.btx.tools
```

Current fixed public fallback peers compiled into `chainparamsseeds.h`:

```
146.190.179.86:19335
164.90.246.229:19335
```

### Custom Regtest / Devnet Identity

```bash
./build/bin/btxd -regtest \
  -regtestmsgstart=0a0b0c0d \
  -regtestport=19444 \
  -regtestgenesisntime=1700001234 \
  -regtestgenesisnonce=42 \
  -regtestgenesisbits=2070ffff \
  -regtestgenesisversion=4
```

All nodes in a devnet must use the same override tuple.

---

## Architecture

### Source Layout

```
src/
  matmul/               MatMul PoW implementation
    matmul_pow.h/cpp      Solve and verify functions
    field.h/cpp           Finite field arithmetic (F_{2^31 - 1})
    matrix.h/cpp          Matrix operations
    noise.h/cpp           Low-rank noise generation
    transcript.h/cpp      Canonical transcript and compression
  shielded/             Shielded pool core
    bundle.h/cpp          Shielded transaction bundles
    note.h/cpp            Note commitment and nullifier
    validation.h/cpp      Shielded proof verification
    ringct/               MatRiCT direct-spend fallback / failover proof system
    smile2/               SMILE v2 proving stack and launch-hardening work
    v2_bundle.h/cpp       Shielded v2 bundle implementation
    v2_ingress.h/cpp      Shielded v2 ingress proofs
    v2_egress.h/cpp       Shielded v2 egress proofs
    v2_proof.h/cpp        Shielded v2 proof verification
    bridge.h/cpp          Bridge operator helpers
  dandelion.h/cpp       Dandelion++ privacy relay
  libbitcoinpqc/        Post-quantum crypto library (ML-DSA + SLH-DSA)
  pqkey.h/cpp           PQ key generation, signing, verification
  script/pqm.h/cpp      P2MR Merkle hashing, proofs, script building
  consensus/params.h    Consensus parameters (MatMul, ASERT, P2MR, monetary)
  kernel/chainparams.cpp  Network-specific chain parameters
  primitives/block.h    Block header (extended for MatMul fields)
  pow.cpp/h             PoW verification and solving entry points
  validation.cpp        Block and transaction validation
  node/miner.cpp        Block template assembly
  wallet/
    shielded_wallet.h/cpp   Shielded key management, note scanning
    shielded_rpc.cpp        z_* RPC implementations
test/
  functional/           Python functional tests
  fuzz/                 Fuzz testing
scripts/
  build_btx.sh          Convenience build script
  test_btx_consensus.sh Consensus test gate
  test_btx_parallel.sh  Parallel test gate
doc/
  btx-matmul-pow-spec.md    MatMul PoW specification
  btx-pqc-spec.md           Post-quantum script profile
  btx-shielded-pool-guide.md Shielded pool operations guide
  btx-mining-ops.md          Mining operations runbook
```

### Key Differences from Bitcoin

1. **PoW**: MatMul PoW replaces SHA-256d. Block headers carry `nNonce64`,
   `matmul_digest`, `matmul_dim`, `seed_a`, `seed_b`.
2. **Post-quantum signatures**: Witness v2 P2MR outputs with ML-DSA-44 and
   SLH-DSA via `OP_CHECKSIG_MLDSA` / `OP_CHECKSIG_SLHDSA`.
3. **Shielded pool**: Lattice-based confidential transactions active from
   genesis. Coinbase auto-shield, z_* RPCs, ML-KEM note encryption.
4. **Block time**: 90 s (vs. Bitcoin's 600 s).
5. **Difficulty**: ASERT per-block adjustment from block 0.
6. **Data limits**: BIP 110-style constraints restrict OP_RETURN to 83 bytes
   and scriptPubKey to 34 bytes, preventing inscription-style data.
7. **Halving**: Every 525 000 blocks with 20 BTX initial reward (same 21M cap).
8. **Address format**: HRP `btx`; P2MR `btx1z...`; shielded `btxs1...`.
9. **Dandelion++ relay**: Stem-then-fluff privacy relay (BIP 156) from block
   250 000.

### Upstream Reference

BTX was forked from Bitcoin Knots v29.2:
[Bitcoin Knots](https://github.com/bitcoinknots/bitcoin)

---

## Using BTX As A Service Primitive

The RPC surface also supports:

- Difficulty and challenge introspection for external products
- Useful-work rate limiting
- Spam prevention and abuse pricing
- AI endpoint admission control
- Layered "proof of AI" architectures where BTX gates access and a separate
  verifiable inference layer proves model execution

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines, coding
style, and the PR review process.

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Run `scripts/test_btx_parallel.sh build-btx` to verify
5. Submit a pull request

---

## License

Released under the [MIT License](COPYING).

Copyright (c) 2009-2025 The Bitcoin Core developers
Copyright (c) 2026 The BTX developers
