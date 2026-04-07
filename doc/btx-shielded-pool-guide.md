# BTX Shielded Pool — Operations Guide

This document covers the design, setup, and operational use of BTX's shielded
transaction pool for node operators, wallet users, and application developers.

For the current production architecture, verified benchmark numbers, and the
current readiness assessment, start with
[doc/btx-shielded-production-status-2026-03-20.md](btx-shielded-production-status-2026-03-20.md).
The older capacity analysis document is now historical context only.

## Overview

BTX's shielded pool provides **confidential transactions** where sender,
receiver, and amount are hidden from public view. It is active from genesis
(block 0) on all networks and is the **default destination for mining
rewards** via auto-shield coinbase.

The shielded pool sits alongside BTX's transparent P2MR (post-quantum) layer.
Users can freely move value between the transparent and shielded pools using
shield/unshield operations.

### Current Production Backend

As of `2026-03-24`, the reset-chain production surface is Smile-only and
account-registry-backed:

- direct SMILE wallet spends are live for the shipped anonymity-set surface
  (`anon_set <= 32`, `rec_levels == 1`);
- the launch wallet default ring size is `8`, and operators can already raise
  the configured ring size anywhere in the supported `8..32` range with
  `-shieldedringsize` without changing the transaction family or wire format;
- proofless transparent-to-shielded wallet deposit, direct shielded send,
  note merge, and mixed shielded-to-transparent unshield now all build on
  `v2_send`;
- shared-ring `BATCH_SMILE` ingress, egress, settlement, and rebalance are
  all live and verified on `main`;
- full account-leaf payloads are committed in registry state, and future spend
  recovery comes from authenticated consensus state rather than inline output
  accounts;
- direct send and ingress consumed spends use lean tx-wire registry witnesses
  while full nodes recover the committed payload locally;
- bridge statements / commitments now already carry versioned aggregate
  settlement commitments plus proof-envelope `extension_digest`, so later
  settlement-side soft forks can tighten many-user action, DA, and recovery
  semantics without first adding a new outer settlement object;
- larger recursive CT anonymity sets are intentionally unsupported on the
  reset-chain protocol and are rejected explicitly rather than left as latent
  prototype behavior;
- MatRiCT and receipt-backed ingress remain in tree only as non-launch tooling,
  not as production backends.

Use
[doc/btx-shielded-production-status-2026-03-20.md](btx-shielded-production-status-2026-03-20.md)
for the canonical production numbers and
[doc/btx-smile-v2-genesis-readiness-tracker-2026-03-20.md](btx-smile-v2-genesis-readiness-tracker-2026-03-20.md)
for the reset-chain launch checklist.

Current measured launch-surface figures are:

- headline mixed-L1 throughput at a `50/50` block-space split between direct
  `1x2 v2_send` and canonical transparent `1-in/2-out witness_v2_p2mr`:
  `3,263 tx/block`, about `36.26 TPS`
- proofless deposit `v2_send`: `19,172` bytes, `221 ms` sample build,
  `1,251 tx/block`
- live wallet `1x2 v2_send`: `60,218` bytes, `22.71 s` sample wallet first-prove,
  `398 tx/block`
- canonical redesign-report `1x2 v2_send`: `60,110` bytes,
  `51,099` proof bytes, `10.20 s` build, `304.26 ms` verify
- `2x2 v2_send`: `70,272` bytes, `61,091` proof bytes, `7.29 s` build,
  `481.09 ms` verify.
- `2x4 v2_send`: `101,918` bytes, `84,111` proof bytes, `5.09 s` build,
  `538.55 ms` verify.
- mixed unshield `v2_send`: `44,330` bytes, `10.88 s` sample build,
  `541 tx/block`.
- Smile ingress `63 leaves / 8 spends / 8 proof shards / 1 reserve`:
  `312,364` bytes, `281,622` proof bytes, `109.86 s` build,
  `5.69 s` verify.
- `32-output v2_egress`: `470,168` bytes, `433` proof bytes,
  `463.14 ms` full pipeline, `9.99 ms` verify.

### Why Shielded by Default?

1. **Privacy as baseline**: Mining rewards automatically enter the shielded
   pool, establishing a privacy-first norm from the first block.
2. **Fungibility**: Shielded coins cannot be distinguished by history, which
   improves fungibility across the network.
3. **Post-quantum confidentiality**: Note encryption uses ML-KEM
   (CRYSTALS-Kyber), providing quantum-resistant key encapsulation. Direct
   shielded spends use lattice-based SMILE proofs on the shipped launch
   surface.
4. **Selective transparency**: View grants allow voluntary disclosure to
   auditors, regulators, or compliance officers without breaking privacy for
   other participants.

---

## Architecture

### Transaction Flow

```
                    ┌──────────────────┐
   Mining Reward    │  Transparent     │
   ─────────────────▶  UTXO Pool      │
                    │  (P2MR outputs)  │
                    └────────┬─────────┘
                             │
              shield         │          unshield
              (coinbase-     │          (explicit bridge /
               compatible    │           egress settlement)
               z_shield*)    │
                             │
                    ┌────────▼─────────┐
   Auto-Shield      │  Shielded Pool   │
   Coinbase ────────▶  (Notes)         │
                    │  btxs1...        │
                    └──────────────────┘
                             │
              z_sendmany     │   Fully shielded transfer
              (btxs1→btxs1)  │   value_balance = 0
                             ▼
```

### Core Components

| Component | File | Purpose |
|---|---|---|
| Shielded Note | `src/shielded/note.h` | Unit of value in the pool; commits value + recipient |
| Note Encryption | `src/shielded/note_encryption.h` | ML-KEM encrypted note payloads |
| Shielded Bundle | `src/shielded/bundle.h` | Transaction-attached shielded data |
| Merkle Tree | `src/shielded/merkle_tree.h` | Global commitment tree for anchoring spends |
| Nullifier | `src/shielded/nullifier.h` | Double-spend prevention set |
| Turnstile | `src/shielded/turnstile.h` | Pool balance integrity enforcement |
| SMILE v2 Proof | `src/shielded/smile2/ct_proof.h` | Default direct-spend proof system on the reset-chain launch surface |
| MatRiCT Proof | `src/shielded/ringct/matrict.h` | Failover backend retained in tree |
| Ring Signature | `src/shielded/ringct/ring_signature.h` | Sender anonymity among decoys |
| Range Proof | `src/shielded/ringct/range_proof.h` | Non-negative amount proof |
| Balance Proof | `src/shielded/ringct/balance_proof.h` | Conservation of value proof |
| Shielded Wallet | `src/wallet/shielded_wallet.h` | Key management, scanning, spending |
| Shielded RPCs | `src/wallet/shielded_rpc.cpp` | z_* command implementations |

### Production Proof Systems

BTX currently uses more than one shielded proving path:

- **Direct wallet spends**: `DIRECT_SMILE` is the default path on the audited
  single-round launch surface.
- **Unshield**: supported and covered by the functional wallet/bridge tests on
  `main`.
- **Ingress / egress / bridge-native batching**: dedicated `v2_ingress`,
  `v2_egress`, rebalance, and settlement structures with future-proofed
  aggregate-settlement commitments already on the wire.
- **MatRiCT**: retained as failover tooling rather than the default direct
  spend backend.

For direct wallet spends, the shipped launch surface binds:

- **membership**: ownership of one note within the shared ring,
- **confidential transfer**: value conservation and output commitment binding,
- **committed public accounts**: canonical SMILE public-account recovery from
  authenticated registry state plus lean spent-leaf witnesses,
- **nullifier/serial linkage**: deterministic spend-identity binding on the
  active direct-send surface.

Measured proof footprints on the current launch surface are:

- `1x2`: `60,110` bytes serialized, `51,099` proof-payload bytes
- `2x2`: `70,272` bytes serialized, `61,091` proof-payload bytes
- `2x4`: `101,918` bytes serialized, `84,111` proof-payload bytes

The historical `1.5 MB` direct-spend proof cap still exists in code
(`MAX_SHIELDED_PROOF_BYTES`), but the current measured SMILE witness payloads
are well below that ceiling.

For current wallet-produced measurements and actual fit-per-block analysis, use
the production-status document linked above.

### Note Commitment Scheme

```
inner = SHA256("BTX_Note_Inner_V1"   || LE64(value) || pk_hash)
cm    = SHA256("BTX_Note_Commit_V1"  || inner || rho || rcm)
nf    = SHA256("BTX_Note_Nullifier_V1" || spending_key || rho || cm)
```

- `pk_hash`: SHA256 of the recipient's full PQ public key
- `rho`: Unique random nonce per note
- `rcm`: Commitment randomness (blinding factor)
- `nf`: Deterministic nullifier derived from spending key + note identity

### Consensus Limits

| Limit | Value |
|---|---|
| Max shielded inputs/tx | 16 |
| Max shielded outputs/tx | 16 |
| Max view grants/tx | 8 |
| Max proof bytes/bundle | 1.5 MB |
| Max shielded tx size | 2 MB (`nMaxShieldedTxSize`) |
| Default wallet ring size | 8 (`RING_SIZE`, configurable with `-shieldedringsize`) |
| Supported ring-size range | 8..32 (`nMaxShieldedRingSize`) |
| Merkle tree depth | 32 (2^32 note capacity) |
| Max note memo | 512 bytes |
| Anchor lookback depth | 100 blocks |
| Activation height | 0 (all networks) |

---

## Setup

### Node Configuration

The shielded pool is enabled by default. Nodes advertise `NODE_SHIELDED`
(service flag bit 8) and will relay shielded transactions to peers that
also support it.

No special configuration is needed. The relevant defaults are:

```ini
# bitcoin.conf (legacy filename used by btxd) — shielded defaults (all implicit)
# autoshieldcoinbase=1     # Auto-shield mature coinbase (default: on)
# shieldedringsize=8       # Default direct ring size (supported range: 8..32)
# NODE_SHIELDED is always advertised
```

### Wallet Setup

```bash
# Start the node
btxd -daemon

# Create a descriptor wallet (required for shielded operations)
btx-cli createwallet "mywallet"

# Generate a shielded address
btx-cli -rpcwallet=mywallet z_getnewaddress
# Returns: btxs1...

# List all shielded addresses
btx-cli -rpcwallet=mywallet z_listaddresses
```

A shielded address encodes:
- **Version byte** (0x00)
- **Algorithm byte** (0x00 = ML-DSA)
- **Spending key hash** (SHA256 of ML-DSA public key)
- **KEM key hash** (SHA256 of ML-KEM public key)
- **Full KEM public key** (800 bytes, for encryption by senders)

---

## Operations

### Checking Balances

```bash
# Transparent balance only (standard)
btx-cli -rpcwallet=mywallet getbalance

# Shielded balance only (for shielded notes, always use z_getbalance)
btx-cli -rpcwallet=mywallet z_getbalance
btx-cli -rpcwallet=mywallet z_getbalance 6  # min 6 confirmations
# Returns an object with spendable `balance`, `note_count`, optional
# `watchonly_balance`, and combined `total_balance`

# Combined transparent + shielded
btx-cli -rpcwallet=mywallet z_gettotalbalance
# Returns spendable totals plus optional watch-only fields when present
```

### Bridge / L2 Settlement RPCs

BTX now exposes a dedicated bridge wallet RPC surface for the on-chain
settlement layer that external L2 operators can target:

- `bridge_planin` builds a canonical bridge-in plan, including the bridge
  script tree, bridge address, CTV hash, shielded bundle, and optional
  operator view grants.
- `bridge_planout` builds a canonical bridge-out plan, including the payout
  output, bridge address, CTV hash, and canonical CSFS attestation payload.
- `bridge_buildshieldtx` builds the bridge-in settlement PSBT that moves a
  funded bridge output into the shielded pool.
- `bridge_buildunshieldtx` builds the attested bridge-out settlement PSBT that
  pays a transparent recipient.
- `bridge_buildrefund` builds the timeout refund PSBT for either bridge plan
  kind once the refund lock height is eligible.
- `bridge_decodeattestation` decodes canonical bridge attestation bytes and
  returns the network/domain-bound message fields plus the CSFS hash.

Example flow:

```bash
# Build a bridge-in plan from a funded transparent bridge output into the shielded pool
btx-cli -rpcwallet=mywallet bridge_planin "<operator_pq_pubkey>" "<refund_pq_pubkey>" 5 \
  '{"bridge_id":"<32-byte hex>","operation_id":"<32-byte hex>","refund_lock_height":720,"recipient":"btxs1..."}'

# Build the settlement PSBT once the plan's bridge address has been funded
btx-cli -rpcwallet=mywallet bridge_buildshieldtx "<plan_hex>" "<funding_txid>" 0 5.0001
```

### Shielding Funds (Transparent → Shielded)

There are three transparent-to-shielded entry surfaces, but only two remain
wallet-local after the post-`61000` privacy fork:

#### 1. Auto-Shield Coinbase (Default)

Mining rewards are automatically shielded when mature. This happens
transparently on each new block with no user action required. After the
post-`61000` privacy fork, this remains the supported wallet-compatible
transparent deposit path for mining rewards.

```bash
# Disable auto-shielding if needed
btxd -autoshieldcoinbase=0
```

Auto-shield batches up to 50 coinbase UTXOs per operation with a default
fee of 0.0001 BTX.

#### 2. Manual Coinbase Shielding

This RPC remains supported after the post-`61000` privacy fork.

```bash
# Shield all mature coinbase outputs
btx-cli -rpcwallet=mywallet z_shieldcoinbase

# Shield to a specific address with custom fee
btx-cli -rpcwallet=mywallet z_shieldcoinbase "btxs1..." 0.0002

# Limit to 10 coinbase inputs
btx-cli -rpcwallet=mywallet z_shieldcoinbase "" 0.0001 10
```

#### 3. Shield Wallet-Compatible Transparent Funds

```bash
# Shield 5 BTX from compatible transparent UTXOs
btx-cli -rpcwallet=mywallet z_shieldfunds 5.0

# Shield to a specific shielded address
btx-cli -rpcwallet=mywallet z_shieldfunds 5.0 "btxs1..."

# Preview the daemon's chunking plan first
btx-cli -rpcwallet=mywallet z_planshieldfunds 25.0 "btxs1..."
```

`z_shieldfunds` now applies a conservative local batching policy for large
transparent UTXO sets. Before `61000` it sweeps general transparent wallet
funds `largest-first`. After `61000` it is limited to mature coinbase
compatibility inputs and reports `coinbase-largest-first` in the returned
policy object. General postfork transparent deposits should use the explicit
bridge-ingress flow instead. The returned RPC object includes:

- `txids`: all broadcast shielding transaction ids
- `chunk_count`: number of chunks committed
- `chunks`: per-chunk gross value, fee, shielded amount, input count, and weight
- `policy`: the exact batch policy used for the request

For fee math, stuck-transaction recovery, and application-integration guidance,
see [btx-shielded-sweep-best-practices.md](btx-shielded-sweep-best-practices.md).


### Sending Shielded Funds

```bash
# Send from shielded pool to a shielded address
btx-cli -rpcwallet=mywallet z_sendmany \
  '[{"address":"btxs1...","amount":1.5}]'

# Specify custom fee
btx-cli -rpcwallet=mywallet z_sendmany \
  '[{"address":"btxs1...","amount":1.0}]' 0.0002
```

Before `61000`, `z_sendmany` can also construct mixed direct sends that pay a
transparent address. After `61000`, transparent settlement moves to the
explicit bridge / egress flow.

### Unshielding Funds (Shielded → Transparent)

Before `61000`, funds can move back to a transparent P2MR address by using
`z_sendmany` with a transparent destination. After `61000`, use the bridge /
egress settlement surface instead.

```bash
# Unshield 2 BTX to a transparent address
btx-cli -rpcwallet=mywallet z_sendmany \
  '[{"address":"btx1z...","amount":2.0}]'
```

### Note Consolidation

Over time, receiving many small shielded payments creates many small notes.
Consolidate them to reduce future transaction sizes:

```bash
# Merge up to 10 notes into one
btx-cli -rpcwallet=mywallet z_mergenotes

# Merge up to 16 notes
btx-cli -rpcwallet=mywallet z_mergenotes 16
```

### Listing Notes and Transactions

```bash
# List unspent shielded notes
btx-cli -rpcwallet=mywallet z_listunspent

# List notes with minimum confirmations
btx-cli -rpcwallet=mywallet z_listunspent 6

# List received amounts for a shielded address
btx-cli -rpcwallet=mywallet z_listreceivedbyaddress

# View decoded details of a shielded transaction
btx-cli -rpcwallet=mywallet z_viewtransaction "txid"
```

### Ring Diversity

Shielded spends require a **ring of 16 decoy commitments** from the global
note commitment tree. On a new chain (e.g., regtest), the pool must accumulate
at least 16 committed notes before shielded spends can succeed.

In production, this happens naturally as mining rewards are auto-shielded. On
regtest for testing, seed the pool first:

```bash
# Mine blocks to get mature coinbase
btx-cli -regtest generatetoaddress 200 "$ADDR"

# Shield several small amounts to build the commitment set
for i in $(seq 1 18); do
  btx-cli -regtest -rpcwallet=mywallet z_shieldfunds 0.5
  btx-cli -regtest generatetoaddress 1 "$ADDR"
done

# Now shielded spends will have sufficient ring diversity
```

### Sweep (Emergency Migration)

The `sweeptoself` RPC consolidates all transparent UTXOs into a single new
P2MR address. This is useful for emergency key migration or PQ algorithm
preference transitions:

```bash
# Sweep all transparent UTXOs to a new address
btx-cli -rpcwallet=mywallet sweeptoself

# Sweep with SLH-DSA preference (backup key algorithm)
btx-cli -named -rpcwallet=mywallet sweeptoself \
  options='{"preferred_pq_algo":"slh_dsa_128s"}'
```

---

## Selective Disclosure (View Grants)

BTX supports **selective disclosure** through CViewGrant entries in shielded
transactions. This allows a sender to encrypt viewing information to a
designated third party (auditor, regulator, compliance officer) without
revealing the transaction to the public.

### How It Works

1. The auditor generates an ML-KEM keypair and shares their public key
2. The sender's wallet includes a CViewGrant in the transaction, encrypting
   the note viewing key to the auditor's ML-KEM public key
3. The auditor decrypts the grant using their ML-KEM secret key to see the
   transaction details (amounts, memo, etc.)

Up to 8 view grants per transaction.

### Exporting and Importing Viewing Keys

```bash
# Export a viewing key for an address you own
btx-cli -rpcwallet=mywallet z_exportviewingkey "btxs1..."
# Returns the KEM secret key bytes

# Import a viewing key for watch-only monitoring
btx-cli -rpcwallet=mywallet z_importviewingkey "<kem_sk>" "<kem_pk>" "btxs1..."
```

After importing a viewing key, the wallet will scan all blocks for notes
encrypted to that key. The wallet cannot spend these notes (no spending
key) but can track balances and transaction history.

### Validating Addresses

```bash
btx-cli z_validateaddress "btxs1..."
# Returns: {"isvalid": true, "address": "btxs1...", "type": "shielded", ...}
```

---

## Security Model

### Threat Model

| Threat | Mitigation |
|---|---|
| Amount leakage | Pedersen commitments + range proofs hide values |
| Sender identification | Ring signatures with decoy inputs |
| Receiver identification | ML-KEM encrypted notes; only recipient can decrypt |
| Double spend | Global nullifier set; each note can only be spent once |
| Pool balance manipulation | Turnstile invariant: pool balance always in [0, MAX_MONEY] |
| Quantum attack on encryption | ML-KEM (CRYSTALS-Kyber) for note encryption |
| Quantum attack on proofs | Lattice-based MatRiCT+ ring signatures |
| Viewing key compromise | View-only access; cannot spend funds |
| Malformed viewing key import | Strict validation rejects invalid key material |

### Nullifier Double-Spend Prevention

Every shielded note has a unique nullifier derived from:
```
nf = SHA256("BTX_Note_Nullifier_V1" || spending_key || rho || cm)
```

The node maintains a persistent nullifier set. When a shielded spend is
included in a block, the nullifier is added to the set. Any future
transaction attempting to reuse that nullifier is rejected at consensus.

### Turnstile Balance Invariant

The `ShieldedPoolBalance` tracks total value in the shielded pool:
- `value_balance < 0` → value enters pool (shield)
- `value_balance > 0` → value leaves pool (unshield)
- Pool balance must remain in `[0, MAX_MONEY]` at all times

This prevents inflation/deflation attacks on the shielded pool.

---

## Network Relay

### Service Flag

All BTX nodes advertise `NODE_SHIELDED` (bit 8) by default. This flag is:
- Required for peers to relay shielded transaction bundles
- Part of the DNS seed filter (`SeedsServiceFlags`)
- Checked before sending shielded data to peers

### Rate Limiting

Shielded transaction relay uses token-bucket rate limiting to prevent DoS:
- Shielded relay tokens (transaction bundles)
- Shielded data tokens (proof data)
- Shielded data request tokens (proof requests)

Nodes that exceed rate limits are temporarily deprioritized, not banned.

### Shielded Data Cache

Recently verified shielded bundle data is cached to avoid redundant proof
verification. The cache is keyed by block hash and bounded in size.

---

## Development and Testing

### Unit Tests

```bash
# Run shielded-specific unit tests
./build/bin/test_btx --run_test=note_encryption_tests
./build/bin/test_btx --run_test=ring_selection_tests
./build/bin/test_btx --run_test=shielded_hardening_tests
./build/bin/test_btx --run_test=shielded_wallet_address_tests
./build/bin/test_btx --run_test=btx_launch_readiness
```

### Functional Tests

```bash
# Shielded wallet tests
build/test/functional/test_runner.py wallet_shielded_viewingkey_rescan.py
build/test/functional/test_runner.py wallet_multisig_descriptor_psbt.py
```

### Live Regtest Validation

```bash
# Full load stress test with shielded operations
python3 scripts/live_regtest_load_stress.py

# Real-world validation scenario
python3 scripts/live_regtest_realworld_validation.py
```

### Benchmarks

```bash
# ML-KEM encryption/decryption benchmarks
./build/bin/bench_btx --filter="MLKEMEncrypt|MLKEMDecrypt"
```

---

## Configuration Reference

| Flag | Default | Description |
|---|---|---|
| `-autoshieldcoinbase` | `1` | Auto-shield mature coinbase outputs |
| `NODE_SHIELDED` | always on | Advertise shielded relay support |
| `nShieldedPoolActivationHeight` | `0` | Block height where shielded pool activates |
| `MAX_SHIELDED_SPENDS_PER_TX` | `16` | Max shielded inputs per transaction |
| `MAX_SHIELDED_OUTPUTS_PER_TX` | `16` | Max shielded outputs per transaction |
| `MAX_VIEW_GRANTS_PER_TX` | `8` | Max view grants per transaction |
| `SHIELDED_ANCHOR_DEPTH` | `100` | Max anchor lookback for spends |
| `MAX_SHIELDED_MEMO_SIZE` | `512` | Max memo bytes per note |

---

## Glossary

| Term | Definition |
|---|---|
| **Shielded note** | A unit of value in the shielded pool, committed via SHA256 |
| **Nullifier** | Deterministic identifier revealed when spending a note; prevents double-spend |
| **Commitment** | Cryptographic binding to a note's value without revealing it |
| **Ring signature** | Proof of spending authority using decoy commitments for anonymity |
| **Range proof** | Zero-knowledge proof that a committed value is non-negative |
| **Turnstile** | Balance enforcement ensuring shielded pool integrity |
| **View grant** | ML-KEM encrypted viewing key for selective disclosure |
| **MatRiCT+** | Lattice-based ring confidential transaction protocol |
| **ML-KEM** | Module-Lattice Key Encapsulation Mechanism (CRYSTALS-Kyber, FIPS 203) |
| **Shield** | Move value from transparent to shielded pool |
| **Unshield** | Move value from shielded to transparent pool |
| **Anchor** | Merkle tree root that validates a spend's ring membership |
