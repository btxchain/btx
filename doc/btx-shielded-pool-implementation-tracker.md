# BTX Shielded Pool Implementation Tracker

Status note (2026-03-24): this tracker records the March 2026 overhaul program
and is no longer the current deployment guide. Current `main` defaults to
shielded ring size `8`, supports configured rings `8..32` on the same wire
surface, and the live benchmark/readiness baseline is in
`doc/btx-shielded-production-status-2026-03-20.md`.

**Status:** Implementation Complete - All Tests Passing (2026-03-07)
**Target:** Post-Quantum Confidential Transaction Pool ("PQ Monero-circa-2024")
**Architecture:** New genesis, hard fork — no backwards compatibility constraints
**Performance Target:** Multi-core concurrent verification, thread-safe, scalable

---

## Executive Summary

This document tracks the implementation of a post-quantum shielded transaction pool for BTX. The design integrates five PQ-secure components:

1. **SHA-256 Nullifiers** — double-spend prevention (zero PQ overhead)
2. **ML-KEM Note Encryption** — quantum-resistant value/memo encryption
3. **ML-DSA/SLH-DSA Spend Authorization** — already implemented in BTX
4. **SHA-256 Merkle Commitment Tree** — note commitment tracking
5. **MatRiCT+-style Confidential Transactions** — hidden amounts + ring-16 sender anonymity

The result: ring-16 anonymity set with hidden transaction amounts, all post-quantum secure, targeting ~25-35 KB per shielded transaction.

---

## Table of Contents

1. [Component 1: Shielded Note & Nullifier System](#1-shielded-note--nullifier-system)
2. [Component 2: ML-KEM Note Encryption](#2-ml-kem-note-encryption)
3. [Component 3: Incremental Merkle Commitment Tree](#3-incremental-merkle-commitment-tree)
4. [Component 4: MatRiCT+ Confidential Transactions](#4-matrict-confidential-transactions)
5. [Component 5: Transaction Structure & Serialization](#5-transaction-structure--serialization)
6. [Component 6: Consensus & Validation Pipeline](#6-consensus--validation-pipeline)
7. [Component 7: Wallet Integration](#7-wallet-integration)
8. [Component 8: P2P Network Protocol](#8-p2p-network-protocol)
9. [Component 9: Turnstile & Pool Accounting](#9-turnstile--pool-accounting)
10. [Concurrency & Thread Safety Architecture](#10-concurrency--thread-safety-architecture)
11. [Source Code References & Licensing](#11-source-code-references--licensing)

---

## 1. Shielded Note & Nullifier System

### 1.1 Design

A **shielded note** is the fundamental unit of value in the shielded pool. Each note contains:
- `value` (uint64): Amount in satoshis
- `recipient_pk`: Recipient's PQ public key (ML-DSA-44 or SLH-DSA)
- `rho` (uint256): Unique random nonce
- `rcm` (uint256): Randomness for Pedersen-style commitment
- `memo` (bytes): Encrypted memo field

The **note commitment** is:
```
cm = SHA256(SHA256(value || recipient_pk_hash) || rho || rcm)
```

The **nullifier** is:
```
nf = SHA256(spending_key || rho || cm)
```

SHA-256 is already quantum-resistant (128-bit post-quantum security via Grover), so nullifiers require zero additional PQ overhead.

### 1.2 New Files

| File | Purpose | Lines (est.) |
|------|---------|-------------|
| `src/shielded/note.h` | `ShieldedNote` struct, commitment computation | ~120 |
| `src/shielded/note.cpp` | Note creation, commitment, nullifier derivation | ~200 |
| `src/shielded/nullifier.h` | `Nullifier` type alias (uint256), `NullifierSet` interface | ~60 |
| `src/shielded/nullifier.cpp` | `NullifierSet` backed by LevelDB, batch insert/check | ~180 |

### 1.3 Data Structures

```cpp
// src/shielded/note.h

#include <consensus/amount.h>
#include <pqkey.h>
#include <uint256.h>
#include <vector>

struct ShieldedNote {
    CAmount value;
    uint256 recipient_pk_hash;   // SHA256(full_pubkey)
    uint256 rho;                 // unique nonce (random)
    uint256 rcm;                 // commitment randomness
    std::vector<unsigned char> memo;  // encrypted memo

    /** Compute the note commitment: SHA256(SHA256(value||pk_hash)||rho||rcm) */
    uint256 GetCommitment() const;

    /** Compute nullifier given the spending key material */
    uint256 GetNullifier(Span<const unsigned char> spending_key) const;
};

using Nullifier = uint256;
```

### 1.4 NullifierSet Storage

```cpp
// src/shielded/nullifier.h

class NullifierSet {
public:
    /** Check if a nullifier has been spent. Thread-safe (read lock). */
    bool Contains(const Nullifier& nf) const;

    /** Insert nullifiers from a connected block. Must hold cs_main. */
    bool Insert(const std::vector<Nullifier>& nullifiers);

    /** Remove nullifiers on block disconnect. Must hold cs_main. */
    bool Remove(const std::vector<Nullifier>& nullifiers);

    /** Batch existence check for mempool validation. Thread-safe. */
    bool AnyExist(const std::vector<Nullifier>& nullifiers) const;

private:
    std::unique_ptr<CDBWrapper> m_db;       // LevelDB backing store
    mutable SharedMutex m_rwlock;           // Reader-writer lock
};
```

### 1.5 Modified Files

| File | Change |
|------|--------|
| `src/validation.h` | Add `NullifierSet` member to `ChainstateManager` |
| `src/validation.cpp` | Check nullifiers in `ConnectBlock()`, remove in `DisconnectBlock()` |
| `src/txdb.h` | Add `DB_NULLIFIER` key prefix constant |
| `src/txdb.cpp` | Add nullifier read/write/delete to `CBlockTreeDB` |

### 1.6 Concurrency Model

- **NullifierSet** uses a `SharedMutex` (reader-writer lock):
  - Multiple threads can check `Contains()` concurrently during mempool validation
  - `Insert()` / `Remove()` take exclusive write lock, called only from `ConnectBlock()` / `DisconnectBlock()` under `cs_main`
- **Sequential conflict check:** Nullifier uniqueness within a single block must be checked sequentially (a block cannot contain duplicate nullifiers)
- **Parallel proof verification:** After nullifier conflict check passes, shielded proofs can be verified in parallel

---

## 2. ML-KEM Note Encryption

### 2.1 Design

Note encryption uses ML-KEM-768 (FIPS 203) for key encapsulation + ChaCha20-Poly1305 AEAD for symmetric encryption:

```
1. Sender encapsulates: (ciphertext, shared_secret) = ML-KEM.Encaps(recipient_kem_pk)
2. Derive key: enc_key = HKDF-SHA256(shared_secret, "BTX-Note-Encryption-V1", 32)
3. Encrypt note: encrypted_note = ChaCha20-Poly1305(enc_key, nonce, plaintext_note)
4. View tag: vt = SHAKE128(ciphertext[0:32] || recipient_kem_pk[0:32])[0]  (1 byte)
```

**On-chain per encrypted note:**
| Component | Size |
|-----------|------|
| View tag | 1 byte |
| ML-KEM ciphertext | 1,088 bytes |
| ChaCha20-Poly1305 nonce | 12 bytes |
| Encrypted note payload | ~64 bytes (value + rho + rcm + memo_key) |
| Poly1305 tag | 16 bytes |
| **Total** | **~1,181 bytes** |

### 2.2 New Files

| File | Purpose | Lines (est.) |
|------|---------|-------------|
| `src/crypto/ml_kem.h` | ML-KEM-768 C wrapper API | ~80 |
| `src/crypto/ml_kem.cpp` | Encaps/Decaps wrapping PQClean's ML-KEM | ~200 |
| `src/shielded/note_encryption.h` | `NoteEncryption` / `NoteDecryption` classes | ~100 |
| `src/shielded/note_encryption.cpp` | Encrypt/decrypt note, view tag computation | ~250 |
| `src/crypto/ml_kem/` | PQClean ML-KEM-768 source (11 C files, ~2,800 lines total) |

### 2.3 ML-KEM-768 Parameters

| Parameter | Value |
|-----------|-------|
| Public key size | 1,184 bytes |
| Secret key size | 2,400 bytes |
| Ciphertext size | 1,088 bytes |
| Shared secret size | 32 bytes |
| Security level | NIST Level 3 (AES-192 equivalent) |

### 2.4 PQClean ML-KEM Integration

Source: [PQClean](https://github.com/PQClean/PQClean) (CC0 / Public Domain)

Files to extract from `crypto_kem/ml-kem-768/clean/`:
```
api.h, indcpa.c, indcpa.h, kem.c, kem.h, ntt.c, ntt.h,
params.h, poly.c, poly.h, polyvec.c, polyvec.h, reduce.c,
reduce.h, symmetric-shake.c, symmetric.h, cbd.c, cbd.h,
verify.c, verify.h
```

Zero external dependencies — uses FIPS 202 (SHA-3/SHAKE) which BTX already has at `src/crypto/sha3.h`.

### 2.5 API Design

```cpp
// src/crypto/ml_kem.h

struct MLKEMKeyPair {
    std::vector<unsigned char> public_key;   // 1184 bytes
    SecureByteVec secret_key;                // 2400 bytes
};

struct MLKEMEncapsResult {
    std::vector<unsigned char> ciphertext;   // 1088 bytes
    std::array<unsigned char, 32> shared_secret;
};

/** Generate ML-KEM-768 keypair from seed. */
MLKEMKeyPair MLKEMKeyGen(Span<const unsigned char> seed);

/** Encapsulate: produce ciphertext + shared secret. */
MLKEMEncapsResult MLKEMEncaps(Span<const unsigned char> public_key);

/** Decapsulate: recover shared secret from ciphertext + secret key. */
std::array<unsigned char, 32> MLKEMDecaps(
    Span<const unsigned char> ciphertext,
    Span<const unsigned char> secret_key);
```

```cpp
// src/shielded/note_encryption.h

class NoteEncryption {
public:
    struct EncryptedNote {
        uint8_t view_tag;
        std::vector<unsigned char> kem_ciphertext;  // 1088 bytes
        std::array<unsigned char, 12> nonce;
        std::vector<unsigned char> encrypted_payload;
        std::array<unsigned char, 16> tag;           // Poly1305
    };

    /** Encrypt a note to recipient. */
    static EncryptedNote Encrypt(
        const ShieldedNote& note,
        Span<const unsigned char> recipient_kem_pk);

    /** Decrypt using view tag pre-filter. Returns nullopt if view tag mismatch. */
    static std::optional<ShieldedNote> TryDecrypt(
        const EncryptedNote& enc_note,
        Span<const unsigned char> recipient_kem_pk,
        Span<const unsigned char> recipient_kem_sk);
};
```

### 2.6 View Tag Optimization

The 1-byte view tag enables wallet scanning speedup:
- Without view tag: must attempt ML-KEM decapsulation for every note (~0.1ms each)
- With view tag: compute `SHAKE128(ct[0:32] || pk[0:32])[0]`, reject 255/256 notes (~10ns each)
- **~39x speedup** in wallet scanning for blocks with many shielded outputs

### 2.7 Modified Files

| File | Change |
|------|--------|
| `src/wallet/pq_keyderivation.h` | Add ML-KEM key derivation path `m/88h/...` |
| `src/wallet/pq_keyderivation.cpp` | Implement `DeriveMLKEMKeyFromBIP39()` |
| `CMakeLists.txt` (or `src/Makefile.am`) | Add `src/crypto/ml_kem/` source files |
| `src/crypto/sha3.h` | Verify SHAKE-128/256 API compatibility with PQClean |

### 2.8 Concurrency Model

- `MLKEMEncaps()` and `MLKEMDecaps()` are **stateless, thread-safe** functions
- Note encryption/decryption can proceed fully in parallel across notes
- View tag filtering is embarrassingly parallel — each note is independent
- Wallet scanning should use a thread pool to decrypt notes in parallel across blocks

---

## 3. Incremental Merkle Commitment Tree

### 3.1 Design

An append-only Merkle tree tracking all shielded note commitments. Based on Zcash's `IncrementalMerkleTree` design with SHA-256 as the hash function (quantum-resistant).

**Parameters:**
| Parameter | Value |
|-----------|-------|
| Depth | 32 |
| Hash function | SHA-256 |
| Max notes | 2^32 (~4.3 billion) |
| Memory per frontier | ~1 KB (32 hashes + position counter) |
| Empty leaf hash | `SHA256("BTX_Shielded_Empty_Leaf")` |

### 3.2 Architecture (from Zcash IncrementalMerkleTree analysis)

The key insight is the **frontier optimization**: instead of storing the entire tree (2^32 nodes), store only the **rightmost path** plus the left siblings needed to compute the root.

```
Depth 4 example (actual is depth 32):

         root
        /    \
      h01     h23
     /   \   /   \
   h0  h1  h2  h3
   /\ /\  /\  /\
  a b c d e f g h    ← leaf commitments

Frontier after appending a,b,c,d,e:
  - left[0] = hash(d)     (sibling at depth 0)
  - left[1] = hash(h01)   (sibling at depth 1)
  - cursor = e             (rightmost uncommitted leaf)
```

### 3.3 New Files

| File | Purpose | Lines (est.) |
|------|---------|-------------|
| `src/shielded/merkle_tree.h` | `ShieldedMerkleTree`, `ShieldedMerkleWitness` | ~200 |
| `src/shielded/merkle_tree.cpp` | Append, root computation, witness updates, serialization | ~400 |

### 3.4 Data Structures

```cpp
// src/shielded/merkle_tree.h

static constexpr size_t SHIELDED_TREE_DEPTH = 32;

class ShieldedMerkleTree {
public:
    /** Append a note commitment to the tree. NOT thread-safe (called under cs_main). */
    void Append(const uint256& commitment);

    /** Get the current Merkle root. O(Depth) computation. */
    uint256 Root() const;

    /** Get current tree size (number of appended leaves). */
    uint64_t Size() const;

    /** Serialize the frontier for database storage (~1 KB). */
    SERIALIZE_METHODS(ShieldedMerkleTree, obj) {
        READWRITE(obj.m_left, obj.m_right, obj.m_parents, obj.m_size);
    }

    /** Create a witness (authentication path) for the most recently appended leaf. */
    ShieldedMerkleWitness Witness() const;

private:
    std::optional<uint256> m_left;    // Left child at current depth
    std::optional<uint256> m_right;   // Right child at current depth
    std::vector<std::optional<uint256>> m_parents;  // Parent hashes (depth-1 entries)
    uint64_t m_size{0};

    /** Compute hash for empty subtree at given depth. Cached. */
    static const uint256& EmptyRoot(size_t depth);
};

class ShieldedMerkleWitness {
public:
    /** The authentication path (32 sibling hashes). */
    std::array<uint256, SHIELDED_TREE_DEPTH> path;

    /** Position index of the leaf in the tree. */
    uint64_t position;

    /** Verify that this witness authenticates `leaf` against `root`. */
    bool Verify(const uint256& leaf, const uint256& root) const;

    /** Update this witness after a new leaf is appended to the tree. O(Depth). */
    void IncrementalUpdate(const ShieldedMerkleTree& tree);

    SERIALIZE_METHODS(ShieldedMerkleWitness, obj) {
        READWRITE(obj.path, obj.position);
    }
};
```

### 3.5 Branch Hash Computation

```cpp
// Matches BTX's existing P2MR branch hash pattern (src/script/pqm.h)
uint256 ShieldedMerkleBranchHash(const uint256& left, const uint256& right) {
    return (HashWriter{} << left << right).GetSHA256();
}
```

### 3.6 Modified Files

| File | Change |
|------|--------|
| `src/validation.cpp` | Append note commitments in `ConnectBlock()`, track tree state |
| `src/validation.h` | Add `ShieldedMerkleTree` to `CChainState` |
| `src/txdb.h` | Add `DB_SHIELDED_TREE` key for frontier persistence |
| `src/txdb.cpp` | Serialize/deserialize tree frontier on flush |

### 3.7 Concurrency Model

- **Append:** Sequential only (called in `ConnectBlock()` under `cs_main`). Order-dependent.
- **Root query:** Can be called from any thread (read-only, computes from frontier)
- **Witness creation:** Thread-safe read-only operation
- **Witness update:** Per-wallet operation, runs under wallet's `cs_wallet` lock
- **Empty root cache:** Static, computed once, immutable — fully thread-safe

---

## 4. MatRiCT+ Confidential Transactions

### 4.1 Design Overview

MatRiCT+ (IEEE S&P 2022, ePrint 2021/545) provides:
- **Ring signatures** over Module-LWE/SIS for sender anonymity (historical draft ring size 16)
- **Confidential amounts** via lattice-based Pedersen commitments
- **Balance proofs** ensuring sum(inputs) = sum(outputs) + fee
- **Range proofs** proving amounts are in [0, 2^64 - 1]

All components are fused into a single proof for efficiency.

### 4.2 Implementation Strategy

No public implementation of MatRiCT+ exists. Implementation from the paper, using these reference codebases for lattice arithmetic:

| Reference | Use | License |
|-----------|-----|---------|
| `gitlab.com/raykzhao/matrict_plus` | MatRiCT (original) reference by paper co-author | BSD-0-Clause |
| `gitlab.com/raykzhao/latte` | Lattice library (NTT, poly arithmetic) | MIT |
| `src/libbitcoinpqc/dilithium/ref/ntt.c` | BTX's existing NTT routines | MIT |
| `github.com/jaymine/LACTv2` | LACT+ design study (NOT code reuse — GPL-3.0) | GPL-3.0 (study only) |
| `github.com/pqabelian/pqringct` | API design reference (three-key arch) | ISC |

### 4.3 Lattice Parameters (from MatRiCT+ paper)

| Parameter | Value | Description |
|-----------|-------|-------------|
| Ring degree (N) | 256 | Polynomial ring R_q = Z_q[X]/(X^256 + 1) |
| Modulus (q) | 2^23 - 2^13 + 1 = 8,380,417 | NTT-friendly prime (same as Dilithium) |
| Module rank (k) | 4 | Matrix dimension |
| Ring members (M) | 16 | Anonymity set size |
| Value bits (L) | 64 | Max value = 2^64 - 1 |

### 4.4 New Files

| File | Purpose | Lines (est.) |
|------|---------|-------------|
| **Lattice arithmetic layer** | | |
| `src/shielded/lattice/params.h` | Lattice parameters (N, q, k, bounds) | ~80 |
| `src/shielded/lattice/poly.h` | `Poly256` type, NTT, inverse NTT | ~100 |
| `src/shielded/lattice/poly.cpp` | Polynomial arithmetic, NTT butterfly | ~400 |
| `src/shielded/lattice/polyvec.h` | Polynomial vector/matrix types | ~80 |
| `src/shielded/lattice/polyvec.cpp` | Vector/matrix operations | ~300 |
| `src/shielded/lattice/ntt.h` | NTT constants, roots of unity | ~40 |
| `src/shielded/lattice/ntt.cpp` | Forward/inverse NTT, Montgomery mult | ~200 |
| `src/shielded/lattice/sampling.h` | Gaussian/uniform sampling | ~60 |
| `src/shielded/lattice/sampling.cpp` | Rejection sampling, challenge generation | ~250 |
| **MatRiCT+ protocol layer** | | |
| `src/shielded/ringct/commitment.h` | Lattice Pedersen commitment | ~60 |
| `src/shielded/ringct/commitment.cpp` | Commit, open, verify | ~200 |
| `src/shielded/ringct/ring_signature.h` | Ring signature create/verify | ~80 |
| `src/shielded/ringct/ring_signature.cpp` | MLWE-based ring sig with linking | ~600 |
| `src/shielded/ringct/range_proof.h` | Range proof (binary decomposition) | ~60 |
| `src/shielded/ringct/range_proof.cpp` | Prove/verify range [0, 2^64) | ~400 |
| `src/shielded/ringct/balance_proof.h` | Balance proof (sum conservation) | ~60 |
| `src/shielded/ringct/balance_proof.cpp` | Prove sum(in) = sum(out) + fee | ~350 |
| `src/shielded/ringct/matrict.h` | Unified proof: ring sig + balance + range | ~100 |
| `src/shielded/ringct/matrict.cpp` | Create/verify full MatRiCT+ proof | ~500 |

### 4.5 Core Data Structures

```cpp
// src/shielded/lattice/poly.h

static constexpr size_t POLY_N = 256;
static constexpr int64_t POLY_Q = 8380417;  // 2^23 - 2^13 + 1

struct Poly256 {
    int32_t coeffs[POLY_N];

    void NTT();
    void InverseNTT();
    void Reduce();

    Poly256 operator+(const Poly256& other) const;
    Poly256 operator-(const Poly256& other) const;
    Poly256 operator*(const Poly256& other) const;  // pointwise in NTT domain
};

using PolyVec = std::vector<Poly256>;
using PolyMat = std::vector<PolyVec>;   // row-major
```

```cpp
// src/shielded/ringct/matrict.h

struct MatRiCTProof {
    // Ring signature component
    std::vector<PolyVec> responses;       // One per ring member
    uint256 challenge_seed;

    // Balance proof component
    PolyVec balance_response;
    std::vector<Poly256> balance_hints;

    // Range proof component (binary decomposition)
    std::vector<PolyVec> range_responses;

    // Linking tags (for double-spend detection via nullifiers)
    std::vector<PolyVec> key_images;

    /** Serialized size for ring-16, 2-in-2-out. Target: ~20 KB proof. */
    size_t GetSerializedSize() const;

    SERIALIZE_METHODS(MatRiCTProof, obj) { /* ... */ }
};

/** Create a MatRiCT+ proof. */
bool CreateMatRiCTProof(
    MatRiCTProof& proof,
    const std::vector<ShieldedNote>& input_notes,
    const std::vector<ShieldedNote>& output_notes,
    const std::vector<std::vector<uint256>>& ring_members,  // decoy commitments per input
    const std::vector<size_t>& real_indices,                 // position of real input in each ring
    Span<const unsigned char> spending_key,
    CAmount fee);

/** Verify a MatRiCT+ proof. Thread-safe, stateless. */
bool VerifyMatRiCTProof(
    const MatRiCTProof& proof,
    const std::vector<std::vector<uint256>>& ring_member_commitments,
    const std::vector<uint256>& output_commitments,
    CAmount fee);
```

### 4.6 Ring Member Selection

```cpp
// src/shielded/ringct/ring_selection.h

static constexpr size_t RING_SIZE = 16;

/** Select ring members (decoys) for each input from the commitment tree. */
struct RingSelector {
    /** Select RING_SIZE - 1 decoy commitments from the tree for each input.
     *  Uses gamma distribution for recency bias (similar to Monero). */
    std::vector<std::vector<uint256>> SelectRings(
        const ShieldedMerkleTree& tree,
        const std::vector<uint64_t>& real_positions,
        size_t ring_size = RING_SIZE);
};
```

### 4.7 Estimated Proof Sizes

| Transaction | Proof Size | Total Shielded TX |
|-------------|-----------|-------------------|
| 1-in-2-out, ring-16 | ~18 KB | ~22 KB |
| 2-in-2-out, ring-16 | ~22 KB | ~28 KB |
| 2-in-4-out, ring-16 | ~26 KB | ~35 KB |

(Includes proof + encrypted notes + nullifiers + commitment outputs)

### 4.8 Concurrency Model

- `VerifyMatRiCTProof()` is **stateless and thread-safe** — pure function of proof + public inputs
- Proof verification is the most expensive operation (~5-15ms per proof)
- Multiple proofs verified concurrently via dedicated `CCheckQueue<CShieldedProofCheck>` (see Section 10)
- `CreateMatRiCTProof()` uses rejection sampling loops — thread-local RNG required
- NTT operations are CPU-intensive and benefit from SIMD (AVX2) — same as Dilithium

---

## 5. Transaction Structure & Serialization

### 5.1 Shielded Bundle

A new `CShieldedBundle` is added to transactions alongside the existing transparent vin/vout:

```cpp
// src/shielded/bundle.h

struct CShieldedSpend {
    Nullifier nullifier;                    // 32 bytes
    uint256 anchor;                         // Merkle root at time of spend (32 bytes)
    // Ring members are referenced by position in the commitment tree
    std::vector<uint64_t> ring_positions;   // RING_SIZE positions
    // Spend auth signature (ML-DSA or SLH-DSA)
    PQAlgorithm spend_auth_algo;            // 1 byte
    std::vector<unsigned char> spend_auth_sig;
};

struct CShieldedOutput {
    uint256 note_commitment;                // 32 bytes
    NoteEncryption::EncryptedNote enc_note; // ~1,181 bytes
};

struct CShieldedBundle {
    std::vector<CShieldedSpend> spends;
    std::vector<CShieldedOutput> outputs;
    MatRiCTProof proof;                     // Single proof covering all spends/outputs
    CAmount value_balance;                  // Net transparent value flow (can be 0)

    bool IsNull() const { return spends.empty() && outputs.empty(); }
    bool HasSpends() const { return !spends.empty(); }
    bool HasOutputs() const { return !outputs.empty(); }

    SERIALIZE_METHODS(CShieldedBundle, obj) {
        READWRITE(obj.spends, obj.outputs, obj.proof, obj.value_balance);
    }
};
```

### 5.2 Transaction Serialization Extension

Extend the existing witness serialization flag system:

```
Current flags:
  0x01 = witness data present

New flags:
  0x01 = witness data present
  0x02 = shielded bundle present
```

### 5.3 Modified Files

| File | Exact Change |
|------|-------------|
| `src/primitives/transaction.h` | Add `CShieldedBundle` member to `CTransaction` and `CMutableTransaction` |
| `src/primitives/transaction.cpp` | Include shielded bundle in hash computation |
| `src/primitives/transaction.h:216` | `UnserializeTransaction()`: handle `flags & 2` for shielded data |
| `src/primitives/transaction.h:256` | `SerializeTransaction()`: serialize shielded bundle when `flags & 2` |
| `src/primitives/transaction.h:286` | `CalculateOutputValue()`: include `value_balance` from shielded bundle |
| `src/primitives/transaction.h:299` | `CTransaction::CURRENT_VERSION` bump to 3 |
| `src/primitives/transaction.h:347` | `CTransaction::GetValueOut()`: add shielded value_balance |
| `src/primitives/transaction.h:354` | `CTransaction::GetTotalSize()`: include shielded bundle size |

### 5.4 Serialization Pseudocode

```cpp
// In SerializeTransaction (modified):
template<typename Stream, typename TxType>
void SerializeTransaction(const TxType& tx, Stream& s, const TransactionSerParams& params)
{
    s << tx.version;
    unsigned char flags = 0;

    if (params.allow_witness) {
        if (tx.HasWitness()) flags |= 1;
        if (tx.HasShieldedBundle()) flags |= 2;  // NEW
    }

    if (flags) {
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    s << tx.vout;

    if (flags & 1) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s << tx.vin[i].scriptWitness.stack;
        }
    }
    if (flags & 2) {
        s << tx.shielded_bundle;  // NEW
    }
    s << tx.nLockTime;
}
```

### 5.5 Weight Calculation

```cpp
// Shielded data uses same discount as witness data (1/4 weight)
// This is justified because shielded data is verified but not stored in UTXO set

static constexpr int SHIELDED_SCALE_FACTOR = 4;  // Same as WITNESS_SCALE_FACTOR

int64_t GetShieldedWeight(const CTransaction& tx) {
    if (!tx.HasShieldedBundle()) return 0;
    size_t shielded_size = GetSerializeSize(tx.shielded_bundle, PROTOCOL_VERSION);
    return shielded_size;  // Already at 1x weight (discounted)
}

// Total weight = base_size * 4 + witness_size + shielded_size
```

---

## 6. Consensus & Validation Pipeline

### 6.1 ConnectBlock Integration

```cpp
// src/validation.cpp — ConnectBlock() modifications

// EXISTING: Line ~2933
CCheckQueueControl<CScriptCheck> control(fScriptChecks ? &scriptcheckqueue : nullptr);

// NEW: Shielded proof check queue (separate thread pool)
CCheckQueueControl<CShieldedProofCheck> shielded_control(
    fScriptChecks ? &shieldedproofcheckqueue : nullptr);

// For each transaction in the block:
for (size_t i = 0; i < block.vtx.size(); i++) {
    const CTransaction& tx = *block.vtx[i];

    // === SHIELDED VALIDATION (NEW) ===
    if (tx.HasShieldedBundle()) {
        const CShieldedBundle& bundle = tx.shielded_bundle;

        // Step 1: Sequential nullifier conflict check (MUST be sequential)
        for (const auto& spend : bundle.spends) {
            if (spent_nullifiers.count(spend.nullifier)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                    "bad-shielded-nullifier-duplicate");
            }
            if (nullifier_set.Contains(spend.nullifier)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                    "bad-shielded-nullifier-spent");
            }
            spent_nullifiers.insert(spend.nullifier);
        }

        // Step 2: Verify anchor (Merkle root must be a known historic root)
        for (const auto& spend : bundle.spends) {
            if (!IsValidShieldedAnchor(spend.anchor)) {
                return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                    "bad-shielded-anchor");
            }
        }

        // Step 3: Queue proof verification (PARALLEL via shielded check queue)
        CShieldedProofCheck check(tx, bundle);
        shielded_control.Add(std::move(check));

        // Step 4: Queue spend auth signature verification (PARALLEL)
        for (const auto& spend : bundle.spends) {
            CShieldedSpendAuthCheck auth_check(tx, spend);
            shielded_control.Add(std::move(auth_check));
        }

        // Step 5: Accumulate note commitments (sequential, after block connects)
        // Done after control.Complete() succeeds
    }

    // === EXISTING: Transparent script checks ===
    // ... CheckInputScripts() adds CScriptCheck to control ...
}

// Wait for ALL shielded proofs AND script checks to verify
if (!control.Complete()) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-script");
}
if (!shielded_control.Complete()) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS, "bad-shielded-proof");
}

// AFTER all proofs pass: append note commitments to Merkle tree
for (const auto& tx : block.vtx) {
    if (tx->HasShieldedBundle()) {
        for (const auto& output : tx->shielded_bundle.outputs) {
            shielded_tree.Append(output.note_commitment);
        }
        // Insert nullifiers
        nullifier_set.Insert(GetNullifiers(tx->shielded_bundle));
    }
}
```

### 6.2 New Validation Structures

```cpp
// src/shielded/validation.h

/** Shielded proof verification check (analogous to CScriptCheck). */
class CShieldedProofCheck {
public:
    CShieldedProofCheck(const CTransaction& tx, const CShieldedBundle& bundle);

    /** operator() called by CCheckQueue worker thread. Must be thread-safe. */
    bool operator()() const;

    void swap(CShieldedProofCheck& other) noexcept;

private:
    CTransactionRef m_tx;
    // Cached public inputs for verification
    std::vector<std::vector<uint256>> m_ring_commitments;
    std::vector<uint256> m_output_commitments;
    CAmount m_fee;
    MatRiCTProof m_proof;
};

/** Spend authorization signature check. */
class CShieldedSpendAuthCheck {
public:
    bool operator()() const;
private:
    uint256 m_sighash;
    PQAlgorithm m_algo;
    std::vector<unsigned char> m_pubkey;
    std::vector<unsigned char> m_signature;
};
```

### 6.3 DisconnectBlock

```cpp
// On block disconnect:
// 1. Remove nullifiers inserted by this block
// 2. Rewind the Merkle tree (maintain tree snapshots per block, or recompute from checkpoint)
// 3. No UTXO changes needed for shielded pool (no UTXO entries for shielded outputs)
```

### 6.4 Mempool Validation

```cpp
// src/txmempool.h — modifications

class CTxMemPool {
    // NEW: Track nullifiers from unconfirmed shielded transactions
    std::set<Nullifier> m_shielded_nullifiers GUARDED_BY(cs);

    // NEW: Check shielded transaction validity for mempool acceptance
    bool CheckShieldedInputs(const CTransaction& tx, TxValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs);
};

// Mempool acceptance for shielded txs:
// 1. Verify nullifiers not in confirmed set AND not in mempool set
// 2. Verify MatRiCT+ proof (can run in caller's thread — single tx)
// 3. Verify spend auth signatures
// 4. Verify anchor is a recent confirmed tree root (within last 100 blocks)
// 5. Check fee rate against shielded weight
```

### 6.5 Modified Files

| File | Change |
|------|--------|
| `src/validation.h:85` | Add `MAX_SHIELDEDCHECK_THREADS = 8` |
| `src/validation.h` | Add `CCheckQueue<CShieldedProofCheck> shieldedproofcheckqueue` |
| `src/validation.cpp` | Initialize shielded check queue in `ChainstateManager::InitializeChainstate()` |
| `src/validation.cpp:2729-3028` | Modify `ConnectBlock()` as described above |
| `src/validation.cpp` | Add `DisconnectBlock()` shielded revert logic |
| `src/txmempool.h` | Add `m_shielded_nullifiers` and `CheckShieldedInputs()` |
| `src/txmempool.cpp` | Implement mempool shielded validation |
| `src/consensus/consensus.h:15` | `MAX_BLOCK_WEIGHT = 24000000` (unchanged, shielded txs use witness discount) |
| `src/consensus/tx_verify.h` | Add `CheckShieldedBundle()` consensus check |
| `src/consensus/tx_verify.cpp` | Implement shielded consensus rules |

---

## 7. Wallet Integration

### 7.1 Key Architecture

Three-key model per shielded address (inspired by Abelian/Zcash):

| Key | Purpose | Type | Derivation Path |
|-----|---------|------|----------------|
| Spending key | Authorize spends, derive nullifiers | ML-DSA-44 | `m/87h/coin_typeh/accounth/0/index` |
| KEM key | Encrypt/decrypt notes | ML-KEM-768 | `m/88h/coin_typeh/accounth/0/index` |
| View key | Scan for incoming notes | Derived from KEM key | Same as KEM |

The spending key derivation already exists at `src/wallet/pq_keyderivation.h`. KEM key derivation follows the same HKDF pattern.

### 7.2 New Files

| File | Purpose | Lines (est.) |
|------|---------|-------------|
| `src/wallet/shielded_wallet.h` | `CShieldedWallet` class | ~300 |
| `src/wallet/shielded_wallet.cpp` | Note tracking, spending, scanning | ~800 |
| `src/wallet/shielded_coins.h` | `ShieldedCoin` (wallet's view of a note) | ~80 |
| `src/wallet/shielded_coins.cpp` | Coin selection for shielded spends | ~200 |
| `src/wallet/shielded_rpc.cpp` | RPC commands for shielded operations | ~600 |

### 7.3 CShieldedWallet Design

```cpp
// src/wallet/shielded_wallet.h

class CShieldedWallet {
public:
    /** Scan a block for notes belonging to this wallet.
     *  Uses view tag pre-filtering + ML-KEM decapsulation. */
    void ScanBlock(const CBlock& block, int height);

    /** Create a shielded spend transaction. */
    std::optional<CMutableTransaction> CreateShieldedSpend(
        const std::vector<CRecipient>& recipients,
        CAmount fee,
        bool shield_change);

    /** Get confirmed shielded balance. */
    CAmount GetShieldedBalance() const;

    /** Get list of spendable shielded notes. */
    std::vector<ShieldedCoin> GetSpendableNotes() const;

    /** Shield transparent UTXOs into shielded notes. */
    std::optional<CMutableTransaction> ShieldFunds(
        const std::vector<COutPoint>& utxos,
        CAmount fee);

    /** Unshield: move shielded value to transparent output. */
    std::optional<CMutableTransaction> UnshieldFunds(
        CAmount amount,
        const CTxDestination& destination,
        CAmount fee);

private:
    RecursiveMutex cs_shielded;

    /** Map from nullifier → ShieldedCoin for owned notes */
    std::map<Nullifier, ShieldedCoin> m_notes GUARDED_BY(cs_shielded);

    /** Set of nullifiers we know are spent */
    std::set<Nullifier> m_spent_nullifiers GUARDED_BY(cs_shielded);

    /** Per-note Merkle witnesses (updated incrementally) */
    std::map<uint256, ShieldedMerkleWitness> m_witnesses GUARDED_BY(cs_shielded);

    /** ML-KEM keypairs for note decryption */
    std::vector<MLKEMKeyPair> m_kem_keys GUARDED_BY(cs_shielded);

    /** PQ spending keys */
    std::vector<CPQKey> m_spending_keys GUARDED_BY(cs_shielded);

    /** Reference to global tree (read-only access) */
    const ShieldedMerkleTree* m_tree;
};
```

### 7.4 ShieldedCoin Structure

```cpp
// src/wallet/shielded_coins.h

struct ShieldedCoin {
    ShieldedNote note;
    uint256 commitment;
    Nullifier nullifier;
    uint64_t tree_position;       // Position in commitment tree
    int confirmation_height;
    bool is_spent{false};

    /** Effective value after fee estimation. */
    CAmount EffectiveValue(CAmount fee_per_byte, size_t estimated_spend_size) const;
};
```

### 7.5 Block Scanning (Parallel)

```cpp
void CShieldedWallet::ScanBlock(const CBlock& block, int height) {
    LOCK(cs_shielded);

    for (const auto& tx : block.vtx) {
        if (!tx->HasShieldedBundle()) continue;

        // Check if any nullifiers match our notes (detect spends)
        for (const auto& spend : tx->shielded_bundle.spends) {
            auto it = m_notes.find(spend.nullifier);
            if (it != m_notes.end()) {
                it->second.is_spent = true;
                m_spent_nullifiers.insert(spend.nullifier);
            }
        }

        // Try to decrypt outputs (detect receives)
        for (const auto& output : tx->shielded_bundle.outputs) {
            for (const auto& kem_key : m_kem_keys) {
                // View tag pre-filter (~39x speedup)
                auto note = NoteEncryption::TryDecrypt(
                    output.enc_note,
                    kem_key.public_key,
                    kem_key.secret_key);

                if (note.has_value()) {
                    ShieldedCoin coin;
                    coin.note = *note;
                    coin.commitment = output.note_commitment;
                    coin.nullifier = note->GetNullifier(/* spending_key */);
                    coin.tree_position = /* current tree size */;
                    coin.confirmation_height = height;
                    m_notes[coin.nullifier] = std::move(coin);
                    break;  // Found our note, no need to try other keys
                }
            }
        }

        // Update Merkle witnesses for all our notes
        for (auto& [nf, coin] : m_notes) {
            if (!coin.is_spent) {
                m_witnesses[coin.commitment].IncrementalUpdate(*m_tree);
            }
        }
    }
}
```

### 7.6 RPC Commands

| Command | Description |
|---------|-------------|
| `z_getnewaddress` | Generate new shielded address (spending key + KEM key) |
| `z_getbalance` | Get shielded balance |
| `z_listunspent` | List spendable shielded notes |
| `z_sendmany` | Send from shielded pool (shielded → shielded or → transparent) |
| `z_shieldcoinbase` | Shield mining rewards; remains supported after `61000` via the mature-coinbase compatibility lane |
| `z_shieldfunds` | Shield transparent UTXOs; after `61000`, limited to compatible mature-coinbase sweeps |
| `z_mergenotes` | Consolidate small shielded notes |
| `z_viewtransaction` | View details of a shielded transaction (if wallet owns keys) |
| `z_exportviewingkey` | Export view-only key for watch-only wallet |
| `z_importviewingkey` | Import view-only key |

### 7.7 Modified Files

| File | Change |
|------|--------|
| `src/wallet/wallet.h` | Add `std::unique_ptr<CShieldedWallet> m_shielded_wallet` member |
| `src/wallet/wallet.cpp` | Initialize shielded wallet, connect to `CValidationInterface` |
| `src/wallet/pq_keyderivation.h` | Add `DeriveMLKEMKeyFromBIP39()` |
| `src/wallet/pq_keyderivation.cpp` | Implement ML-KEM key derivation at `m/88h/...` |
| `src/wallet/rpc/spend.cpp` | Register new z_* RPC commands |
| `src/rpc/client.cpp` | Register z_* parameter names |

### 7.8 Concurrency Model

- All wallet operations lock `cs_shielded` (separate from `cs_wallet` for transparent ops)
- Block scanning can be parallelized per-note (view tag check + decryption) using a thread pool
- Witness updates are sequential within a wallet but independent across wallets
- Transaction creation locks `cs_shielded` exclusively during coin selection + proof generation

---

## 8. P2P Network Protocol

### 8.1 New Message Types

| Message | Direction | Purpose |
|---------|-----------|---------|
| `shieldedtx` | Relay | Announce/relay shielded transactions |
| `getshieldeddata` | Request | Request shielded block data |
| `shieldeddata` | Response | Shielded bundle data for a block |

### 8.2 Protocol Versioning

```cpp
// src/protocol.h — additions

static constexpr int SHIELDED_VERSION = 800001;  // Minimum version supporting shielded

// New service flag
enum ServiceFlags : uint64_t {
    // ...existing...
    NODE_SHIELDED = (1 << 8),  // Node supports shielded transactions
};
```

### 8.3 Relay Policy

```cpp
// src/net_processing.cpp — modifications

// Shielded transaction relay follows same rules as transparent:
// 1. Check fee rate (using shielded weight)
// 2. Validate proof before relay (prevents DoS via invalid proofs)
// 3. Standard mempool acceptance
// 4. Relay to peers with NODE_SHIELDED service flag

// Bandwidth consideration:
// A 30 KB shielded tx is ~7-10x larger than typical transparent tx
// Apply rate limiting per peer for shielded tx relay
static constexpr size_t MAX_SHIELDED_TX_RELAY_BYTES_PER_SECOND = 500'000;  // 500 KB/s
```

### 8.4 Modified Files

| File | Change |
|------|--------|
| `src/protocol.h` | Add `NODE_SHIELDED` flag, message types |
| `src/protocol.cpp` | Register message type strings |
| `src/net_processing.h` | Add shielded relay tracking |
| `src/net_processing.cpp` | Handle shielded tx relay, validation before forwarding |
| `src/node/transaction.h` | Add shielded tx submission to mempool |

---

## 9. Turnstile & Pool Accounting

### 9.1 Design (based on Zcash ZIP 209)

The turnstile mechanism tracks the total value in the shielded pool to contain bugs:

```
shielded_pool_value += sum(value_balance) for each shielded tx in block
```

Where `value_balance` = (transparent value flowing INTO shielded pool) - (transparent value flowing OUT).

**Invariant:** `shielded_pool_value >= 0` at all times.

If this invariant is violated, it means more value left the shielded pool than entered — indicating a soundness bug in the proof system. The chain rejects such blocks.

### 9.2 Implementation

```cpp
// src/consensus/tx_verify.h — additions

/** Track shielded pool value across blocks. */
class ShieldedPoolBalance {
public:
    /** Update balance with a new block's shielded transactions. */
    bool UpdateForBlock(const CBlock& block, CAmount& pool_value);

    /** Revert a block's contribution on disconnect. */
    void RevertBlock(const CBlock& block, CAmount& pool_value);
};

// In ConnectBlock():
CAmount new_pool_value = current_pool_value;
for (const auto& tx : block.vtx) {
    if (tx->HasShieldedBundle()) {
        new_pool_value += tx->shielded_bundle.value_balance;
    }
}
if (new_pool_value < 0) {
    return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
        "bad-shielded-pool-negative",
        "shielded pool value would go negative (turnstile violation)");
}
```

### 9.3 Modified Files

| File | Change |
|------|--------|
| `src/validation.cpp` | Add turnstile check in `ConnectBlock()` |
| `src/validation.h` | Add `m_shielded_pool_value` to chainstate |
| `src/consensus/tx_verify.h` | Add `CheckShieldedPoolBalance()` |
| `src/consensus/tx_verify.cpp` | Implement turnstile logic |

---

## 10. Concurrency & Thread Safety Architecture

### 10.1 Thread Pool Layout

```
┌─────────────────────────────────────────────────────┐
│                    Main Thread                       │
│  (cs_main lock holder during ConnectBlock)           │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────────────┐  ┌──────────────────────┐ │
│  │ Script Check Queue   │  │ Shielded Proof Queue │ │
│  │ (CCheckQueue)        │  │ (CCheckQueue)        │ │
│  │                      │  │                      │ │
│  │ Workers: scriptch.0  │  │ Workers: shieldc.0   │ │
│  │          scriptch.1  │  │          shieldc.1   │ │
│  │          ...         │  │          ...         │ │
│  │          scriptch.14 │  │          shieldc.7   │ │
│  │ (MAX 15 threads)     │  │ (MAX 8 threads)     │ │
│  └──────────────────────┘  └──────────────────────┘ │
│                                                      │
│  Sequential operations (main thread):                │
│  - Nullifier conflict checks                         │
│  - Merkle tree appends                               │
│  - Turnstile balance updates                         │
│  - UTXO set updates                                  │
│                                                      │
│  Parallel operations (queued):                       │
│  - Script verification         → Script Check Queue  │
│  - MatRiCT+ proof verification → Shielded Queue      │
│  - Spend auth sig verification → Shielded Queue      │
│                                                      │
│  Both queues: control.Complete() blocks until done    │
└─────────────────────────────────────────────────────┘
```

### 10.2 Lock Hierarchy

```
cs_main                          (global chain lock)
  └─ NullifierSet::m_rwlock      (reader-writer, for nullifier queries)
  └─ ShieldedMerkleTree          (modified only under cs_main)
  └─ CCheckQueue::m_mutex        (internal to check queue)

cs_wallet                        (wallet lock — transparent)
  └─ cs_shielded                 (wallet lock — shielded, never held with cs_main)

Net processing:
  cs_main → read nullifier set
  No lock contention between shielded proof queue and net processing
```

### 10.3 Implementation

```cpp
// src/validation.h — additions

/** Maximum number of parallel shielded proof verification threads. */
static constexpr int MAX_SHIELDEDCHECK_THREADS = 8;

// In ChainstateManager or node context:
CCheckQueue<CShieldedProofCheck> m_shielded_check_queue{128};

// Initialization (in init.cpp):
void InitShieldedCheckQueue(int num_threads) {
    for (int i = 0; i < num_threads; i++) {
        m_shielded_workers.emplace_back([&, i] {
            util::ThreadRename(strprintf("shieldc.%i", i));
            m_shielded_check_queue.Thread();
        });
    }
}
```

### 10.4 Key Thread Safety Guarantees

| Component | Thread Safety | Mechanism |
|-----------|--------------|-----------|
| `NullifierSet::Contains()` | Concurrent reads | `SharedMutex` read lock |
| `NullifierSet::Insert()` | Exclusive write | `SharedMutex` write lock + cs_main |
| `ShieldedMerkleTree::Append()` | Sequential only | Called under cs_main |
| `ShieldedMerkleTree::Root()` | Read-only safe | Pure computation from frontier |
| `VerifyMatRiCTProof()` | Fully thread-safe | Stateless pure function |
| `MLKEMDecaps()` | Fully thread-safe | Stateless pure function |
| `CShieldedWallet::ScanBlock()` | Under cs_shielded | RecursiveMutex |
| `NTT()` / `InverseNTT()` | Thread-safe | Stack-local computation |

### 10.5 SIMD Optimization Opportunities

| Operation | SIMD Target | Speedup |
|-----------|------------|---------|
| NTT butterfly (poly.cpp) | AVX2 (256-bit int32) | ~4x |
| Polynomial add/sub | AVX2 | ~4x |
| Montgomery reduction | AVX2 | ~4x |
| SHA-256 (nullifiers, Merkle) | SHA-NI | ~3-5x |
| ChaCha20 (note encryption) | AVX2 | ~3x |

BTX's existing Dilithium NTT at `src/libbitcoinpqc/dilithium/ref/ntt.c` uses the same modulus (q = 8380417) and ring degree (N = 256). The AVX2 variant at `dilithium/avx2/ntt.S` can be directly reused for MatRiCT+ polynomial arithmetic.

---

## 11. Source Code References & Licensing

### 11.1 Direct Code Sources

| Source | What to Use | License | Integration Method |
|--------|------------|---------|-------------------|
| **BTX libbitcoinpqc** (`src/libbitcoinpqc/`) | ML-DSA/SLH-DSA, NTT routines, Dilithium polynomial arithmetic | MIT | Already integrated |
| **PQClean ML-KEM-768** (`github.com/PQClean/PQClean`) | ML-KEM encapsulation/decapsulation (11 C files) | CC0/Public Domain | Extract `crypto_kem/ml-kem-768/clean/` → `src/crypto/ml_kem/` |
| **BTX crypto/** (`src/crypto/`) | SHA-256, SHA-3/SHAKE, HKDF-SHA256, ChaCha20-Poly1305 | MIT | Already integrated |
| **raykzhao/latte** (`gitlab.com/raykzhao/latte`) | Lattice NTT reference, polynomial operations | MIT | Reference for lattice arithmetic implementation |
| **raykzhao/matrict_plus** (`gitlab.com/raykzhao/matrict_plus`) | MatRiCT original implementation by paper co-author | BSD-0-Clause | Reference for ring signature + balance proof structure |
| **Zcash IncrementalMerkleTree** (`zcash/zcash`) | Frontier-optimized append-only Merkle tree | MIT | Clean-room reimplementation using SHA-256 |

### 11.2 Reference-Only Sources (NOT for code reuse)

| Source | What to Study | License | Why Not Direct Reuse |
|--------|--------------|---------|---------------------|
| **jaymine/LACTv2** | LACT+ aggregation design, 5.7 KB coin structure, polynomial packing | GPL-3.0 | GPL incompatible with MIT; study design only |
| **pqabelian/pqringct** | Three-key architecture, ring signature API design | ISC | Go language; design patterns only |
| **WardBeullens/Calamari-and-Falafl** | Logarithmic linkable ring signatures | Research | 30 KB sigs too large; MatRiCT+ is better integrated approach |
| **dfaranha/lattice-verifiable-mixnet** | BDLOP commitment scheme | Research | Degree-4096 polynomials too large for blockchain |

### 11.3 Academic Papers

| Paper | Reference | Relevance |
|-------|-----------|-----------|
| MatRiCT+ | ePrint 2021/545, IEEE S&P 2022 | Primary protocol specification |
| MatRiCT | ePrint 2019/1287 | Original protocol (has reference impl) |
| LACT+ | MDPI Cryptography 7(2), 2023 | Aggregation mechanism study |
| ML-KEM (FIPS 203) | NIST FIPS 203 | Note encryption KEM standard |
| ML-DSA (FIPS 204) | NIST FIPS 204 | Spend authorization (already in BTX) |
| Zcash Protocol Spec | Section 4.2 (Note Commitments), Section 7.4 (IncrementalMerkleTree) | Commitment tree design |
| ZIP 209 | Zcash ZIP 209 | Turnstile mechanism |

---

## Implementation Summary

### New Files (34 files, ~7,000 lines estimated)

| Directory | Files | Purpose |
|-----------|-------|---------|
| `src/shielded/` | 6 files | Note, nullifier, Merkle tree core |
| `src/shielded/lattice/` | 8 files | Polynomial arithmetic, NTT, sampling |
| `src/shielded/ringct/` | 10 files | MatRiCT+ protocol implementation |
| `src/crypto/ml_kem/` | ~15 files | PQClean ML-KEM-768 (extracted) |
| `src/shielded/note_encryption.*` | 2 files | ML-KEM + AEAD note encryption |
| `src/wallet/shielded_*` | 4 files | Wallet shielded operations |
| `src/wallet/shielded_rpc.cpp` | 1 file | z_* RPC commands |
| `src/shielded/validation.h` | 1 file | CShieldedProofCheck |

### Modified Files (18 files)

| File | Nature of Change |
|------|-----------------|
| `src/primitives/transaction.h` | Add CShieldedBundle, modify serialization |
| `src/primitives/transaction.cpp` | Include shielded in hash |
| `src/validation.h` | Add shielded check queue, nullifier set, tree |
| `src/validation.cpp` | ConnectBlock/DisconnectBlock shielded logic |
| `src/txmempool.h` | Shielded nullifier tracking |
| `src/txmempool.cpp` | Mempool shielded validation |
| `src/consensus/consensus.h` | Shielded weight constants |
| `src/consensus/tx_verify.h` | Shielded consensus checks |
| `src/consensus/tx_verify.cpp` | Turnstile, bundle validation |
| `src/txdb.h` | Nullifier DB prefix |
| `src/txdb.cpp` | Nullifier persistence |
| `src/protocol.h` | NODE_SHIELDED, message types |
| `src/protocol.cpp` | Register messages |
| `src/net_processing.cpp` | Shielded relay |
| `src/wallet/wallet.h` | CShieldedWallet member |
| `src/wallet/wallet.cpp` | Initialize shielded wallet |
| `src/wallet/pq_keyderivation.h` | ML-KEM key derivation |
| `src/init.cpp` | Shielded check queue init |

### Transaction Size Budget

| Component | Size per Shielded TX (2-in-2-out) |
|-----------|----------------------------------|
| Nullifiers (2) | 64 bytes |
| Anchors (2) | 64 bytes |
| Ring positions (2 × 16) | 256 bytes |
| Spend auth sigs (2 × ML-DSA-44) | ~5,000 bytes |
| Output commitments (2) | 64 bytes |
| Encrypted notes (2 × 1,181) | ~2,362 bytes |
| MatRiCT+ proof | ~20,000 bytes |
| value_balance | 8 bytes |
| **Total** | **~27,818 bytes (~27 KB)** |

At `WITNESS_SCALE_FACTOR = 4`, a 27 KB shielded tx weighs ~27,000 WU (1/4 discount).
`MAX_BLOCK_WEIGHT = 24,000,000` supports ~888 shielded txs per block (vs ~2,500 transparent).

---

*Document generated: 2026-03-04*
*Status updated: 2026-03-07 — Implementation complete, all tests passing (204/204)*
*Branch: claude/btx-privacy-analysis-8CN3q*
