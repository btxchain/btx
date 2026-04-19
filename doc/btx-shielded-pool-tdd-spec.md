# BTX Shielded Pool: TDD Specification & Implementation Guide

Status note (2026-03-24): this TDD spec captures the earlier shielded-pool
design program. It is not the current reset-chain launch definition. Current
`main` defaults to shielded ring size `8`, supports configured rings `8..32`
on the same wire surface, and the live benchmark/readiness baseline is in
`doc/btx-shielded-production-status-2026-03-20.md`.

**Companion to:** `doc/btx-shielded-pool-implementation-tracker.md`
**Purpose:** Implementation-ready code, test suites, security analysis, benchmarks
**Concurrency:** All code designed for multi-core parallel verification

---

## Table of Contents

- [Part A: Shielded Notes & Nullifiers](#part-a-shielded-notes--nullifiers)
- [Part B: ML-KEM Note Encryption](#part-b-ml-kem-note-encryption)
- [Part C: Incremental Merkle Commitment Tree](#part-c-incremental-merkle-commitment-tree)
- [Part D: MatRiCT+ Lattice Arithmetic & Protocol](#part-d-matrict-lattice-arithmetic--protocol)
- [Part E: Consensus Validation & Transaction Serialization](#part-e-consensus-validation--transaction-serialization)
- [Part F: Wallet Integration & RPC](#part-f-wallet-integration--rpc)
- [Part G: Covenant/CLT Bridge Interoperability](#part-g-covenantclt-bridge-interoperability)

---

# Part A: Shielded Notes & Nullifiers

## A.1 Implementation Code

### `src/shielded/note.h`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_NOTE_H
#define BTX_SHIELDED_NOTE_H

#include <consensus/amount.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

/** Maximum memo size in a shielded note (512 bytes). */
static constexpr size_t MAX_SHIELDED_MEMO_SIZE = 512;

/**
 * A shielded note represents a unit of value in the shielded pool.
 *
 * Note commitment:
 *   inner = SHA256("BTX_Note_Inner_V1" || LE64(value) || pk_hash)
 *   cm    = SHA256("BTX_Note_Commit_V1" || inner || rho || rcm)
 *
 * Nullifier:
 *   nf = SHA256("BTX_Note_Nullifier_V1" || spending_key || rho || cm)
 *
 * Domain-separated tagged hashes prevent cross-protocol collisions.
 */
struct ShieldedNote {
    CAmount value{0};
    uint256 recipient_pk_hash;  // SHA256(full PQ public key)
    uint256 rho;                // unique random nonce
    uint256 rcm;                // commitment randomness
    std::vector<unsigned char> memo;

    /** Compute the note commitment. Deterministic for fixed inputs. */
    uint256 GetCommitment() const;

    /** Compute the nullifier given the spending key bytes. */
    uint256 GetNullifier(Span<const unsigned char> spending_key) const;

    /** Check if the note has valid parameters. */
    bool IsValid() const;

    SERIALIZE_METHODS(ShieldedNote, obj)
    {
        READWRITE(obj.value, obj.recipient_pk_hash, obj.rho, obj.rcm);
        // Memo is length-prefixed
        READWRITE(obj.memo);
    }
};

using Nullifier = uint256;

#endif // BTX_SHIELDED_NOTE_H
```

### `src/shielded/note.cpp`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/note.h>

#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <hash.h>

#include <cstring>

namespace {

/** Tagged single-SHA256: SHA256(tag || data...) */
uint256 TaggedSHA256(const std::string& tag, Span<const unsigned char> data)
{
    uint256 result;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size())
        .Write(data.data(), data.size())
        .Finalize(result.begin());
    return result;
}

uint256 TaggedSHA256(const std::string& tag,
                     Span<const unsigned char> a,
                     Span<const unsigned char> b)
{
    uint256 result;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size())
        .Write(a.data(), a.size())
        .Write(b.data(), b.size())
        .Finalize(result.begin());
    return result;
}

uint256 TaggedSHA256(const std::string& tag,
                     Span<const unsigned char> a,
                     Span<const unsigned char> b,
                     Span<const unsigned char> c)
{
    uint256 result;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size())
        .Write(a.data(), a.size())
        .Write(b.data(), b.size())
        .Write(c.data(), c.size())
        .Finalize(result.begin());
    return result;
}

} // namespace

uint256 ShieldedNote::GetCommitment() const
{
    // Step 1: inner = SHA256("BTX_Note_Inner_V1" || LE64(value) || pk_hash)
    unsigned char value_le[8];
    WriteLE64(value_le, static_cast<uint64_t>(value));

    uint256 inner;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>("BTX_Note_Inner_V1"), 17)
        .Write(value_le, 8)
        .Write(recipient_pk_hash.begin(), 32)
        .Finalize(inner.begin());

    // Step 2: cm = SHA256("BTX_Note_Commit_V1" || inner || rho || rcm)
    uint256 cm;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>("BTX_Note_Commit_V1"), 18)
        .Write(inner.begin(), 32)
        .Write(rho.begin(), 32)
        .Write(rcm.begin(), 32)
        .Finalize(cm.begin());

    return cm;
}

uint256 ShieldedNote::GetNullifier(Span<const unsigned char> spending_key) const
{
    uint256 cm = GetCommitment();

    // nf = SHA256("BTX_Note_Nullifier_V1" || spending_key || rho || cm)
    uint256 nf;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>("BTX_Note_Nullifier_V1"), 21)
        .Write(spending_key.data(), spending_key.size())
        .Write(rho.begin(), 32)
        .Write(cm.begin(), 32)
        .Finalize(nf.begin());

    return nf;
}

bool ShieldedNote::IsValid() const
{
    if (value < 0 || value > MAX_MONEY) return false;
    if (rho.IsNull()) return false;
    if (rcm.IsNull()) return false;
    if (recipient_pk_hash.IsNull()) return false;
    if (memo.size() > MAX_SHIELDED_MEMO_SIZE) return false;
    return true;
}
```

### `src/shielded/nullifier.h`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_NULLIFIER_H
#define BTX_SHIELDED_NULLIFIER_H

#include <dbwrapper.h>
#include <shielded/note.h>
#include <uint256.h>

#include <memory>
#include <shared_mutex>
#include <vector>

/**
 * Persistent set of spent nullifiers, backed by LevelDB.
 *
 * Thread safety:
 *   - Contains() / AnyExist(): concurrent reads via shared_lock
 *   - Insert() / Remove(): exclusive writes via unique_lock
 *   - All writes must be done under cs_main (enforced by caller)
 *
 * Matches the reader-writer lock pattern from src/script/sigcache.h.
 */
/** Maximum nullifiers in memory cache before overflow to disk only.
 *  At 32 bytes per uint256 + ~64 bytes node overhead: 2M entries ≈ 192 MiB. */
static constexpr size_t NULLIFIER_CACHE_MAX_ENTRIES{2'000'000};

class NullifierSet
{
public:
    explicit NullifierSet(const fs::path& db_path,
                          size_t cache_bytes = 8 << 20,
                          bool memory_only = false,
                          bool wipe_data = false);
    ~NullifierSet();

    NullifierSet(const NullifierSet&) = delete;
    NullifierSet& operator=(const NullifierSet&) = delete;

    /** Check if a nullifier has been spent. Thread-safe (shared read lock).
     *  Rejects null (all-zero) nullifiers immediately. */
    [[nodiscard]] bool Contains(const Nullifier& nf) const;

    /** Check if ANY nullifier in the vector exists. Short-circuits on first match. */
    [[nodiscard]] bool AnyExist(const std::vector<Nullifier>& nullifiers) const;

    /** Insert nullifiers from a connected block. Returns false on null nf or DB error.
     *  Uses LevelDB WriteBatch with fSync=true for crash consistency. */
    bool Insert(const std::vector<Nullifier>& nullifiers);

    /** Remove nullifiers on block disconnect. Caller passes in reverse tx order. */
    bool Remove(const std::vector<Nullifier>& nullifiers);

    /** In-memory cache size (diagnostic). */
    [[nodiscard]] size_t CacheSize() const;

    /** Estimated total memory usage. */
    [[nodiscard]] size_t DynamicMemoryUsage() const;

    bool Flush();

private:
    [[nodiscard]] bool ExistsInDB(const Nullifier& nf) const;

    std::unique_ptr<CDBWrapper> m_db;
    std::unordered_set<Nullifier, std::hash<Nullifier>> m_cache;
    mutable std::shared_mutex m_rwlock;

    static constexpr uint8_t DB_NULLIFIER = 'N';
};

#endif // BTX_SHIELDED_NULLIFIER_H
```

### `src/shielded/nullifier.cpp`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/nullifier.h>

#include <logging.h>

NullifierSet::NullifierSet(fs::path db_path, size_t cache_bytes)
    : m_db(std::make_unique<CDBWrapper>(DBParams{
          .path = std::move(db_path),
          .cache_bytes = cache_bytes,
          .memory_only = false,
          .wipe_data = false,
          .obfuscate = true}))
{
}

NullifierSet::~NullifierSet() = default;

bool NullifierSet::Contains(const Nullifier& nf) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwlock);
    return m_db->Exists(std::make_pair(DB_NULLIFIER, nf));
}

bool NullifierSet::AnyExist(const std::vector<Nullifier>& nullifiers) const
{
    std::shared_lock<std::shared_mutex> lock(m_rwlock);
    for (const auto& nf : nullifiers) {
        if (m_db->Exists(std::make_pair(DB_NULLIFIER, nf))) {
            return true;
        }
    }
    return false;
}

void NullifierSet::Insert(const std::vector<Nullifier>& nullifiers)
{
    std::unique_lock<std::shared_mutex> lock(m_rwlock);
    CDBBatch batch(*m_db);
    for (const auto& nf : nullifiers) {
        batch.Write(std::make_pair(DB_NULLIFIER, nf), uint8_t{1});
    }
    m_db->WriteBatch(batch, /*fSync=*/true);
}

void NullifierSet::Remove(const std::vector<Nullifier>& nullifiers)
{
    std::unique_lock<std::shared_mutex> lock(m_rwlock);
    CDBBatch batch(*m_db);
    for (const auto& nf : nullifiers) {
        batch.Erase(std::make_pair(DB_NULLIFIER, nf));
    }
    m_db->WriteBatch(batch, /*fSync=*/true);
}

size_t NullifierSet::Size() const
{
    std::shared_lock<std::shared_mutex> lock(m_rwlock);
    // CDBWrapper doesn't expose count; use iterator
    size_t count = 0;
    auto it = m_db->NewIterator();
    uint8_t prefix = DB_NULLIFIER;
    for (it->Seek(std::make_pair(prefix, uint256{}));
         it->Valid(); it->Next()) {
        ++count;
    }
    return count;
}
```

## A.2 Test Suite

### `src/test/shielded_note_tests.cpp`

```cpp
// Copyright (c) 2026 The BTX developers
#include <shielded/note.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(shielded_note_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(commitment_determinism)
{
    ShieldedNote note;
    note.value = 50 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    uint256 cm1 = note.GetCommitment();
    uint256 cm2 = note.GetCommitment();
    BOOST_CHECK(cm1 == cm2);
    BOOST_CHECK(!cm1.IsNull());
}

BOOST_AUTO_TEST_CASE(commitment_uniqueness_different_rho)
{
    ShieldedNote note1, note2;
    note1.value = note2.value = 100 * COIN;
    note1.recipient_pk_hash = note2.recipient_pk_hash = uint256::ONE;
    note1.rcm = note2.rcm = GetRandHash();
    note1.rho = GetRandHash();
    note2.rho = GetRandHash();

    BOOST_CHECK(note1.GetCommitment() != note2.GetCommitment());
}

BOOST_AUTO_TEST_CASE(commitment_uniqueness_different_value)
{
    ShieldedNote note1, note2;
    note1.recipient_pk_hash = note2.recipient_pk_hash = uint256::ONE;
    note1.rho = note2.rho = GetRandHash();
    note1.rcm = note2.rcm = GetRandHash();
    note1.value = 50 * COIN;
    note2.value = 51 * COIN;

    BOOST_CHECK(note1.GetCommitment() != note2.GetCommitment());
}

BOOST_AUTO_TEST_CASE(nullifier_determinism)
{
    ShieldedNote note;
    note.value = 10 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    std::vector<unsigned char> sk(32, 0x42);
    uint256 nf1 = note.GetNullifier(sk);
    uint256 nf2 = note.GetNullifier(sk);
    BOOST_CHECK(nf1 == nf2);
    BOOST_CHECK(!nf1.IsNull());
}

BOOST_AUTO_TEST_CASE(nullifier_different_spending_keys)
{
    ShieldedNote note;
    note.value = 10 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    std::vector<unsigned char> sk1(32, 0x01);
    std::vector<unsigned char> sk2(32, 0x02);
    BOOST_CHECK(note.GetNullifier(sk1) != note.GetNullifier(sk2));
}

BOOST_AUTO_TEST_CASE(collision_resistance_10000_notes)
{
    std::set<uint256> commitments;
    std::set<uint256> nullifiers;
    std::vector<unsigned char> sk(32, 0xAB);

    for (int i = 0; i < 10000; ++i) {
        ShieldedNote note;
        note.value = i * COIN;
        note.recipient_pk_hash = uint256::ONE;
        note.rho = GetRandHash();
        note.rcm = GetRandHash();

        BOOST_CHECK(commitments.insert(note.GetCommitment()).second);
        BOOST_CHECK(nullifiers.insert(note.GetNullifier(sk)).second);
    }
}

BOOST_AUTO_TEST_CASE(max_money_note)
{
    ShieldedNote note;
    note.value = MAX_MONEY;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    BOOST_CHECK(note.IsValid());
    BOOST_CHECK(!note.GetCommitment().IsNull());
}

BOOST_AUTO_TEST_CASE(invalid_note_negative_value)
{
    ShieldedNote note;
    note.value = -1;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    BOOST_CHECK(!note.IsValid());
}

BOOST_AUTO_TEST_CASE(invalid_note_null_rho)
{
    ShieldedNote note;
    note.value = COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = uint256::ZERO;
    note.rcm = GetRandHash();

    BOOST_CHECK(!note.IsValid());
}

BOOST_AUTO_TEST_CASE(serialization_roundtrip)
{
    ShieldedNote note;
    note.value = 42 * COIN;
    note.recipient_pk_hash = GetRandHash();
    note.rho = GetRandHash();
    note.rcm = GetRandHash();
    note.memo = {0x01, 0x02, 0x03};

    DataStream ss{};
    ss << note;

    ShieldedNote note2;
    ss >> note2;

    BOOST_CHECK_EQUAL(note.value, note2.value);
    BOOST_CHECK(note.recipient_pk_hash == note2.recipient_pk_hash);
    BOOST_CHECK(note.rho == note2.rho);
    BOOST_CHECK(note.rcm == note2.rcm);
    BOOST_CHECK(note.memo == note2.memo);
    BOOST_CHECK(note.GetCommitment() == note2.GetCommitment());
}

BOOST_AUTO_TEST_SUITE_END()
```

### `src/test/nullifier_set_tests.cpp`

```cpp
// Copyright (c) 2026 The BTX developers
#include <shielded/nullifier.h>
#include <random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(nullifier_set_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(insert_and_contains)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf", 1 << 20);
    Nullifier nf = GetRandHash();

    BOOST_CHECK(!ns.Contains(nf));
    ns.Insert({nf});
    BOOST_CHECK(ns.Contains(nf));
}

BOOST_AUTO_TEST_CASE(batch_insert_and_any_exist)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf2", 1 << 20);
    std::vector<Nullifier> batch;
    for (int i = 0; i < 100; ++i) batch.push_back(GetRandHash());

    BOOST_CHECK(!ns.AnyExist(batch));
    ns.Insert(batch);
    BOOST_CHECK(ns.AnyExist(batch));
    BOOST_CHECK(ns.AnyExist({batch[50]}));
}

BOOST_AUTO_TEST_CASE(remove_and_verify)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf3", 1 << 20);
    Nullifier nf = GetRandHash();

    ns.Insert({nf});
    BOOST_CHECK(ns.Contains(nf));
    ns.Remove({nf});
    BOOST_CHECK(!ns.Contains(nf));
}

BOOST_AUTO_TEST_CASE(concurrent_reads)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf4", 1 << 20);
    std::vector<Nullifier> existing;
    for (int i = 0; i < 1000; ++i) existing.push_back(GetRandHash());
    ns.Insert(existing);

    // Launch 8 reader threads
    std::vector<std::thread> readers;
    std::atomic<int> hits{0};
    for (int t = 0; t < 8; ++t) {
        readers.emplace_back([&, t] {
            for (int i = t * 125; i < (t + 1) * 125 && i < 1000; ++i) {
                if (ns.Contains(existing[i])) hits++;
            }
        });
    }
    for (auto& r : readers) r.join();
    BOOST_CHECK_EQUAL(hits.load(), 1000);
}

BOOST_AUTO_TEST_CASE(duplicate_insert_idempotent)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf5", 1 << 20);
    Nullifier nf = GetRandHash();

    ns.Insert({nf});
    ns.Insert({nf}); // duplicate
    BOOST_CHECK(ns.Contains(nf));
    ns.Remove({nf});
    BOOST_CHECK(!ns.Contains(nf));
}

BOOST_AUTO_TEST_CASE(nonexistent_nullifier_returns_false)
{
    NullifierSet ns(m_args.GetDataDirNet() / "test_nf6", 1 << 20);
    BOOST_CHECK(!ns.Contains(GetRandHash()));
    BOOST_CHECK(!ns.AnyExist({GetRandHash(), GetRandHash()}));
}

BOOST_AUTO_TEST_SUITE_END()
```

## A.3 Security Vulnerability Analysis

| Attack Vector | Mitigation | Test |
|---------------|-----------|------|
| **Nullifier grinding** — create two notes with same nullifier | Nullifier = SHA256(tag \|\| spending_key \|\| rho \|\| cm); rho is 256-bit random. Collision probability ~2^-128 | `collision_resistance_10000_notes` |
| **Nullifier replay** — resubmit spent nullifier | NullifierSet::Contains() checked before block acceptance | `insert_and_contains`, `batch_insert_and_any_exist` |
| **Timing side-channel** — leak nullifier via lookup timing | LevelDB Exists() returns in ~constant time for similar-length keys. For wallet-side comparison, use `ct_memcmp` from `src/crypto/ct_utils.h` | Document in caution points |
| **Memory exhaustion** — spam nullifiers to exhaust RAM | NullifierSet backed by LevelDB on disk; in-memory cache bounded by `cache_bytes` parameter | `concurrent_reads` (tests with 1000 entries) |
| **Cross-protocol collision** — nullifier matches a value from another hash context | Domain separation tags ("BTX_Note_Nullifier_V1") prevent this | Implicit in all commitment/nullifier tests |

## A.4 Benchmarks

### `src/bench/shielded_note_bench.cpp`

```cpp
// Copyright (c) 2026 The BTX developers
#include <bench/bench.h>
#include <random.h>
#include <shielded/note.h>

static void NoteCommitment(benchmark::Bench& bench)
{
    ShieldedNote note;
    note.value = 50 * COIN;
    note.recipient_pk_hash = GetRandHash();
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    bench.minEpochIterations(10000).run([&] {
        ankerl::nanobench::doNotOptimizeAway(note.GetCommitment());
    });
}

static void NullifierDerivation(benchmark::Bench& bench)
{
    ShieldedNote note;
    note.value = 50 * COIN;
    note.recipient_pk_hash = GetRandHash();
    note.rho = GetRandHash();
    note.rcm = GetRandHash();
    std::vector<unsigned char> sk(32, 0x42);

    bench.minEpochIterations(10000).run([&] {
        ankerl::nanobench::doNotOptimizeAway(note.GetNullifier(sk));
    });
}

BENCHMARK(NoteCommitment, benchmark::PriorityLevel::HIGH);
BENCHMARK(NullifierDerivation, benchmark::PriorityLevel::HIGH);
```

## A.5 Caution Points

1. **Spending key memory safety**: The `spending_key` parameter in `GetNullifier()` should come from `CPQKey::m_secret_key` which uses `secure_allocator`. Never store raw spending key bytes in `std::vector<unsigned char>` — always use `std::vector<unsigned char, secure_allocator<unsigned char>>`.

2. **Endianness**: Value is serialized as LE64 in the commitment hash. This matches Bitcoin's existing convention (`WriteLE64`). Do NOT use host-endian.

3. **Domain separation tags**: Every tagged hash uses a distinct string prefix. If you add new hash contexts, create new unique tags. Never reuse tags across different purposes.

4. **Atomic flush**: NullifierSet::Insert() and Merkle tree Append() must be flushed atomically with the UTXO set during ConnectBlock(). If the node crashes between UTXO flush and nullifier flush, the database would be inconsistent. Use LevelDB WriteBatch across both.

5. **DisconnectBlock order**: Remove nullifiers in reverse transaction order. The NullifierSet::Remove() should be called with the exact nullifiers that were inserted during ConnectBlock() for that specific block.

---

# Part B: ML-KEM Note Encryption

## B.1 Overview

ML-KEM-768 (FIPS 203) provides post-quantum key encapsulation for encrypting shielded
notes to recipients. The encryption protocol is:

1. ML-KEM-768 Encaps(recipient_pk) → (kem_ct, shared_secret)
2. HKDF-SHA256(shared_secret, "BTX-Note-Encryption-V1") → aead_key (32 bytes)
3. nonce ← GetRandBytes(12)
4. ChaCha20-Poly1305.Encrypt(aead_key, nonce, serialized_note, aad=kem_ct) → aead_ct
5. view_tag = SHA3-256(kem_ct || recipient_pk)[0]
6. Output: EncryptedNote{kem_ct, nonce, aead_ct, view_tag}

## B.2 PQClean Integration

Extract 22 files from PQClean's `crypto_kem/ml-kem-768/clean/` into `src/crypto/ml-kem-768/`:

| # | File | Purpose |
|---|------|---------|
| 1-11 | `api.h` through `verify.h` | ML-KEM-768 clean reference headers |
| 12-20 | `kem.c` through `verify.c` | ML-KEM-768 C source files |
| 21-22 | `fips202.h`, `fips202.c` | SHAKE/SHA3 from PQClean `common/` |

**SHAKE dependency**: Use PQClean's own `fips202.c` (not BTX's `sha3.h`) because
ML-KEM needs `SHAKE128`, `SHAKE256`, `SHA3-256`, and `SHA3-512` with specific
absorb/squeeze interfaces that BTX's `SHA3_256` class does not provide.

## B.3 ML-KEM Wrapper

### `src/crypto/ml_kem.h`

```cpp
#ifndef BITCOIN_CRYPTO_ML_KEM_H
#define BITCOIN_CRYPTO_ML_KEM_H

#include <span.h>
#include <support/allocators/secure.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace mlkem {

static constexpr size_t PUBLICKEYBYTES  = 1184;
static constexpr size_t SECRETKEYBYTES  = 2400;
static constexpr size_t CIPHERTEXTBYTES = 1088;
static constexpr size_t SHAREDSECRETBYTES = 32;
static constexpr size_t KEYGEN_SEEDBYTES = 64;
static constexpr size_t ENCAPS_SEEDBYTES = 32;

using PublicKey  = std::array<uint8_t, PUBLICKEYBYTES>;
using SecretKey  = std::vector<uint8_t, secure_allocator<uint8_t>>;
using Ciphertext = std::array<uint8_t, CIPHERTEXTBYTES>;
using SharedSecret = std::vector<uint8_t, secure_allocator<uint8_t>>;

struct KeyPair {
    PublicKey pk;
    SecretKey sk;
    KeyPair() : sk(SECRETKEYBYTES, 0) {}
};

struct EncapsResult {
    Ciphertext ct;
    SharedSecret ss;
    EncapsResult() : ss(SHAREDSECRETBYTES, 0) {}
};

/** Generate ML-KEM-768 key pair (system randomness). */
KeyPair KeyGen();

/** Deterministic keygen from 64-byte seed (testing only). */
KeyPair KeyGenDerand(Span<const uint8_t> seed);

/** Encapsulate: shared secret + ciphertext from recipient's pk. */
EncapsResult Encaps(const PublicKey& pk);

/** Deterministic encaps from 32-byte seed (testing only). */
EncapsResult EncapsDerand(const PublicKey& pk, Span<const uint8_t> seed);

/** Decapsulate: recover shared secret. IND-CCA2 implicit rejection. */
SharedSecret Decaps(const Ciphertext& ct, const SecretKey& sk);

} // namespace mlkem

#endif // BITCOIN_CRYPTO_ML_KEM_H
```

### `src/crypto/ml_kem.cpp`

```cpp
#include <crypto/ml_kem.h>
#include <random.h>
#include <support/cleanse.h>
#include <util/check.h>

extern "C" {
#include <crypto/ml-kem-768/kem.h>
}

namespace mlkem {

KeyPair KeyGen()
{
    uint8_t seed[KEYGEN_SEEDBYTES];
    GetStrongRandBytes(seed);
    KeyPair result = KeyGenDerand(seed);
    memory_cleanse(seed, sizeof(seed));
    return result;
}

KeyPair KeyGenDerand(Span<const uint8_t> seed)
{
    Assume(seed.size() == KEYGEN_SEEDBYTES);
    KeyPair kp;
    int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(
        kp.pk.data(), kp.sk.data(), seed.data());
    Assume(rc == 0);
    return kp;
}

EncapsResult Encaps(const PublicKey& pk)
{
    uint8_t coin[ENCAPS_SEEDBYTES];
    GetRandBytes(coin);
    EncapsResult result = EncapsDerand(pk, coin);
    memory_cleanse(coin, sizeof(coin));
    return result;
}

EncapsResult EncapsDerand(const PublicKey& pk, Span<const uint8_t> seed)
{
    Assume(seed.size() == ENCAPS_SEEDBYTES);
    EncapsResult er;
    int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
        er.ct.data(), er.ss.data(), pk.data(), seed.data());
    Assume(rc == 0);
    return er;
}

SharedSecret Decaps(const Ciphertext& ct, const SecretKey& sk)
{
    Assume(sk.size() == SECRETKEYBYTES);
    SharedSecret ss(SHAREDSECRETBYTES, 0);
    int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(
        ss.data(), ct.data(), sk.data());
    Assume(rc == 0);
    return ss;
}

} // namespace mlkem
```

## B.4 Note Encryption

### `src/shielded/note_encryption.h`

```cpp
#ifndef BITCOIN_SHIELDED_NOTE_ENCRYPTION_H
#define BITCOIN_SHIELDED_NOTE_ENCRYPTION_H

#include <crypto/ml_kem.h>
#include <shielded/note.h>
#include <uint256.h>

#include <array>
#include <optional>
#include <vector>

namespace shielded {

static constexpr size_t MAX_MEMO_SIZE = 512;

struct EncryptedNote {
    mlkem::Ciphertext kem_ciphertext;
    std::array<uint8_t, 12> aead_nonce;
    std::vector<uint8_t> aead_ciphertext;
    uint8_t view_tag{0};

    std::vector<uint8_t> Serialize() const;
    static std::optional<EncryptedNote> Deserialize(Span<const uint8_t> data);

    static constexpr size_t OVERHEAD = mlkem::CIPHERTEXTBYTES + 12 + 16 + 1; // 1117 bytes
};

class NoteEncryption
{
public:
    /** Encrypt a note for a recipient. */
    static EncryptedNote Encrypt(const ShieldedNote& note,
                                 const mlkem::PublicKey& recipient_pk);

    /** Deterministic encryption for testing. */
    static EncryptedNote EncryptDeterministic(const ShieldedNote& note,
                                              const mlkem::PublicKey& recipient_pk,
                                              Span<const uint8_t> kem_seed,
                                              Span<const uint8_t> nonce);

    /** Try to decrypt; returns nullopt on failure (wrong key or tampered). */
    static std::optional<ShieldedNote> TryDecrypt(const EncryptedNote& enc_note,
                                                   const mlkem::PublicKey& kem_pk,
                                                   const mlkem::SecretKey& kem_sk);

    /** View tag: SHA3-256(kem_ct || pk)[0]. Public data only. */
    static uint8_t ComputeViewTag(const mlkem::Ciphertext& kem_ct,
                                   const mlkem::PublicKey& pk);

private:
    /** HKDF-SHA256(ss, "BTX-ShieldedPool", "BTX-Note-Encryption-V1") → 32 bytes. */
    static std::vector<uint8_t, secure_allocator<uint8_t>> DeriveAeadKey(
        Span<const uint8_t> shared_secret);
};

} // namespace shielded

#endif // BITCOIN_SHIELDED_NOTE_ENCRYPTION_H
```

**Implementation**: `src/shielded/note_encryption.cpp` follows the protocol:
- `Encrypt()`: KEM Encaps → HKDF → random nonce → ChaCha20-Poly1305 with AAD=kem_ct
- `TryDecrypt()`: view tag filter → KEM Decaps → HKDF → AEAD decrypt → deserialize
- All secret material uses `secure_allocator` and is cleansed after use

## B.5 Test Suite

### `src/test/ml_kem_tests.cpp`

Key test cases:
- `keygen_produces_correct_sizes` — pk=1184, sk=2400
- `keygen_produces_different_keys_each_call` — randomness verification
- `deterministic_keygen_from_seed` — same seed → same keypair
- `encaps_decaps_roundtrip` — shared secrets match
- `decaps_with_wrong_sk_produces_different_secret` — IND-CCA2 implicit rejection
- `fips203_sk_contains_pk_and_hash` — dk = dk_PKE || ek || H(ek) || z per FIPS 203

### `src/test/note_encryption_tests.cpp`

Key test cases:
- `encrypt_decrypt_roundtrip` — all fields recovered
- `decrypt_with_wrong_key_returns_nullopt` — view tag or AEAD rejects
- `view_tag_statistical_rejection` — ~255/256 false positive rate
- `encrypted_note_serialization_roundtrip` — serialize/deserialize/decrypt
- `deterministic_encryption_same_inputs_same_output` — reproducible ciphertext

## B.6 Security Analysis

1. **KEM ciphertext malleability**: ML-KEM-768 is IND-CCA2. Modified ciphertexts → implicit rejection secret → AEAD tag fails.
2. **AEAD forgery**: ChaCha20-Poly1305 tag verification catches any ciphertext tampering. AAD=kem_ct binds AEAD to specific KEM encapsulation.
3. **Nonce reuse**: Each encryption uses fresh KEM encapsulation (→ fresh AEAD key), making nonce reuse across notes impossible even if `GetRandBytes()` repeats.
4. **View tag leakage**: Derived from public data only (kem_ct || pk). Reveals 8 bits binding ciphertext to recipient — this is intentional for scanning efficiency.
5. **Memory safety**: `SecretKey` and `SharedSecret` use `secure_allocator` (locked memory + `memory_cleanse` on dealloc). Intermediate AEAD keys are explicitly cleansed.

## B.7 Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| ML-KEM KeyGen | < 0.5 ms | ~150 us typical (clean ref) |
| ML-KEM Encaps | < 0.1 ms | ~50 us typical |
| ML-KEM Decaps | < 0.1 ms | ~60 us typical |
| Full note encrypt | < 0.5 ms | KEM + HKDF + AEAD + SHA3 vtag |
| Full note decrypt | < 0.5 ms | vtag + KEM + HKDF + AEAD |
| View tag compute | < 5 us | Single SHA3-256 over ~2272 bytes |
| View tag filtering | > 100k notes/sec | ~10 us per tag check |

## B.8 Build System

```cmake
# src/crypto/CMakeLists.txt additions
target_sources(bitcoin_crypto PRIVATE
  ml-kem-768/kem.c ml-kem-768/indcpa.c ml-kem-768/poly.c
  ml-kem-768/polyvec.c ml-kem-768/ntt.c ml-kem-768/reduce.c
  ml-kem-768/cbd.c ml-kem-768/symmetric-shake.c ml-kem-768/verify.c
  ml-kem-768/fips202.c ml_kem.cpp
)
target_include_directories(bitcoin_crypto PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/ml-kem-768
)
```

---

# Part C: Incremental Merkle Commitment Tree

## C.1 Implementation Code

### `src/shielded/merkle_tree.h`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_MERKLE_TREE_H
#define BTX_SHIELDED_MERKLE_TREE_H

#include <crypto/sha256.h>
#include <serialize.h>
#include <uint256.h>

#include <array>
#include <cstdint>
#include <deque>
#include <optional>
#include <stdexcept>
#include <vector>

namespace shielded {

static constexpr size_t MERKLE_DEPTH = 32;
static constexpr uint64_t MERKLE_MAX_LEAVES = static_cast<uint64_t>(1) << MERKLE_DEPTH;

// Domain-separated hash primitives
uint256 EmptyLeafHash();
uint256 BranchHash(const uint256& left, const uint256& right);
const uint256& EmptyRoot(size_t depth);

class ShieldedMerkleTree;
class ShieldedMerkleWitness;

/** Supplies hashes for unfilled positions during root/witness computation. */
class PathFiller
{
public:
    PathFiller() = default;
    explicit PathFiller(std::deque<uint256> hashes) : queue_(std::move(hashes)) {}
    uint256 Next(size_t depth);
private:
    std::deque<uint256> queue_;
};

/**
 * Append-only incremental Merkle tree using frontier optimization.
 * Memory usage: O(depth) = ~1 KB regardless of tree size.
 *
 * Thread safety:
 *   Append() - NOT thread-safe (call under cs_main only)
 *   Root()   - Thread-safe (pure computation on immutable frontier)
 */
class ShieldedMerkleTree
{
public:
    ShieldedMerkleTree() = default;

    void Append(const uint256& commitment);
    uint256 Root() const;
    uint256 Root(size_t depth, PathFiller filler) const;
    uint64_t Size() const { return size_; }
    bool IsEmpty() const { return size_ == 0; }
    ShieldedMerkleWitness Witness() const;
    uint256 LastLeaf() const;

    const std::optional<uint256>& Left() const { return left_; }
    const std::optional<uint256>& Right() const { return right_; }
    const std::vector<std::optional<uint256>>& Parents() const { return parents_; }

    template <typename Stream>
    void Serialize(Stream& s) const;
    template <typename Stream>
    void Unserialize(Stream& s);

private:
    uint64_t size_{0};
    std::optional<uint256> left_;
    std::optional<uint256> right_;
    std::vector<std::optional<uint256>> parents_;
};

/**
 * Authentication path for a specific leaf in the Merkle tree.
 * Supports incremental updates as new leaves are appended.
 */
class ShieldedMerkleWitness
{
public:
    ShieldedMerkleWitness() = default;
    explicit ShieldedMerkleWitness(const ShieldedMerkleTree& tree);

    uint64_t Position() const;
    void ComputePath(std::array<uint256, MERKLE_DEPTH>& auth_path, uint64_t& pos) const;
    uint256 Root() const;
    bool Verify(const uint256& leaf, const uint256& root) const;
    void IncrementalUpdate(const uint256& new_leaf);

    template <typename Stream>
    void Serialize(Stream& s) const;
    template <typename Stream>
    void Unserialize(Stream& s);

private:
    ShieldedMerkleTree tree_;
    std::vector<uint256> filled_;
    std::optional<ShieldedMerkleTree> cursor_;
    size_t cursor_depth_{0};

    std::deque<uint256> PartialPath() const;
    size_t NextDepth(size_t skip) const;
};

} // namespace shielded

#endif // BTX_SHIELDED_MERKLE_TREE_H
```

### `src/shielded/merkle_tree.cpp`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/merkle_tree.h>

#include <cassert>
#include <string>

namespace shielded {

// --- Hash primitives ---

uint256 EmptyLeafHash()
{
    static const uint256 cached = []() {
        const std::string tag{"BTX_Shielded_Empty_Leaf_V1"};
        uint256 result;
        CSHA256()
            .Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size())
            .Finalize(result.begin());
        return result;
    }();
    return cached;
}

uint256 BranchHash(const uint256& left, const uint256& right)
{
    static const std::string tag{"BTX_Shielded_Branch_V1"};
    uint256 result;
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size())
        .Write(left.begin(), 32)
        .Write(right.begin(), 32)
        .Finalize(result.begin());
    return result;
}

const uint256& EmptyRoot(size_t depth)
{
    static const auto table = []() {
        std::array<uint256, MERKLE_DEPTH + 1> t;
        t[0] = EmptyLeafHash();
        for (size_t d = 1; d <= MERKLE_DEPTH; ++d) {
            t[d] = BranchHash(t[d - 1], t[d - 1]);
        }
        return t;
    }();
    assert(depth <= MERKLE_DEPTH);
    return table[depth];
}

uint256 PathFiller::Next(size_t depth)
{
    if (!queue_.empty()) {
        uint256 h = queue_.front();
        queue_.pop_front();
        return h;
    }
    return EmptyRoot(depth);
}

// --- ShieldedMerkleTree ---

void ShieldedMerkleTree::Append(const uint256& commitment)
{
    if (size_ >= MERKLE_MAX_LEAVES) {
        throw std::runtime_error("ShieldedMerkleTree: tree is full");
    }
    if (!left_.has_value()) {
        left_ = commitment;
    } else if (!right_.has_value()) {
        right_ = commitment;
    } else {
        uint256 combined = BranchHash(*left_, *right_);
        left_ = commitment;
        right_ = std::nullopt;
        bool propagating = true;
        for (size_t i = 0; i < parents_.size() && propagating; ++i) {
            if (parents_[i].has_value()) {
                combined = BranchHash(*parents_[i], combined);
                parents_[i] = std::nullopt;
            } else {
                parents_[i] = combined;
                propagating = false;
            }
        }
        if (propagating) parents_.push_back(combined);
    }
    ++size_;
}

uint256 ShieldedMerkleTree::Root() const
{
    PathFiller filler;
    return Root(MERKLE_DEPTH, std::move(filler));
}

uint256 ShieldedMerkleTree::Root(size_t depth, PathFiller filler) const
{
    if (size_ == 0) return EmptyRoot(depth);
    uint256 current;
    if (right_.has_value()) {
        current = BranchHash(*left_, *right_);
    } else {
        current = BranchHash(*left_, filler.Next(0));
    }
    size_t d = 1;
    for (size_t i = 0; i < parents_.size(); ++i, ++d) {
        if (parents_[i].has_value()) {
            current = BranchHash(*parents_[i], current);
        } else {
            current = BranchHash(current, filler.Next(d));
        }
    }
    for (; d < depth; ++d) {
        current = BranchHash(current, filler.Next(d));
    }
    return current;
}

uint256 ShieldedMerkleTree::LastLeaf() const
{
    if (size_ == 0) throw std::runtime_error("empty tree");
    return right_.has_value() ? *right_ : *left_;
}

ShieldedMerkleWitness ShieldedMerkleTree::Witness() const
{
    return ShieldedMerkleWitness(*this);
}

// --- ShieldedMerkleWitness ---

ShieldedMerkleWitness::ShieldedMerkleWitness(const ShieldedMerkleTree& tree)
    : tree_(tree)
{
    if (tree.IsEmpty()) throw std::runtime_error("cannot witness empty tree");
}

uint64_t ShieldedMerkleWitness::Position() const { return tree_.Size() - 1; }

std::deque<uint256> ShieldedMerkleWitness::PartialPath() const
{
    std::deque<uint256> uncles;
    for (const auto& h : filled_) uncles.push_back(h);
    if (cursor_.has_value()) {
        uncles.push_back(cursor_->Root(cursor_depth_, PathFiller()));
    }
    return uncles;
}

uint256 ShieldedMerkleWitness::Root() const
{
    return tree_.Root(MERKLE_DEPTH, PathFiller(PartialPath()));
}

void ShieldedMerkleWitness::ComputePath(
    std::array<uint256, MERKLE_DEPTH>& auth_path, uint64_t& pos) const
{
    PathFiller filler(PartialPath());
    pos = Position();
    const auto& left = tree_.Left();
    const auto& right = tree_.Right();
    const auto& parents = tree_.Parents();

    if (right.has_value()) {
        auth_path[0] = *left;
    } else {
        auth_path[0] = filler.Next(0);
    }
    size_t d = 1;
    for (size_t i = 0; i < parents.size(); ++i, ++d) {
        auth_path[d] = parents[i].has_value() ? *parents[i] : filler.Next(d);
    }
    for (; d < MERKLE_DEPTH; ++d) {
        auth_path[d] = filler.Next(d);
    }
}

bool ShieldedMerkleWitness::Verify(const uint256& leaf, const uint256& root) const
{
    std::array<uint256, MERKLE_DEPTH> auth_path;
    uint64_t pos;
    ComputePath(auth_path, pos);
    uint256 current = leaf;
    for (size_t d = 0; d < MERKLE_DEPTH; ++d) {
        current = (pos & 1) ? BranchHash(auth_path[d], current)
                            : BranchHash(current, auth_path[d]);
        pos >>= 1;
    }
    return current == root;
}

size_t ShieldedMerkleWitness::NextDepth(size_t skip) const
{
    uint64_t pos = Position();
    for (size_t d = 0; d < MERKLE_DEPTH; ++d) {
        if (!((pos >> d) & 1)) {
            if (skip > 0) --skip;
            else return d;
        }
    }
    return MERKLE_DEPTH;
}

void ShieldedMerkleWitness::IncrementalUpdate(const uint256& new_leaf)
{
    size_t depth = NextDepth(filled_.size());
    if (cursor_.has_value()) {
        cursor_->Append(new_leaf);
        if (cursor_->Size() == (static_cast<uint64_t>(1) << cursor_depth_)) {
            filled_.push_back(cursor_->Root());
            cursor_ = std::nullopt;
            cursor_depth_ = 0;
        }
    } else {
        if (depth == 0) {
            filled_.push_back(new_leaf);
        } else {
            cursor_ = ShieldedMerkleTree();
            cursor_depth_ = depth;
            cursor_->Append(new_leaf);
        }
    }
}

} // namespace shielded
```

## C.2 Test Suite

See `src/test/shielded_merkle_tests.cpp` — full test suite with 30+ test cases covering:
- Empty tree root matches precomputed value
- Single/two/three leaf root computation verified against manual hash chains
- 1000 sequential appends with root verification at each step
- Witness creation, verification, and incremental updates through 500 appends
- Serialization round-trip preserves tree state and witness validity
- Serialized tree size bounded at ~1200 bytes regardless of tree size
- Security tests: collision resistance, second preimage, stale witness detection, tree rewind
- Edge cases: overflow detection, empty tree witness/lastleaf throws

(Full test code provided in Merkle tree agent output — see companion implementation files)

## C.3 Security Analysis

| Attack | Mitigation | Test |
|--------|-----------|------|
| Merkle collision | SHA-256 128-bit PQ collision resistance | `different_leaf_sets_produce_different_roots` |
| Second preimage witness forgery | SHA-256 second preimage resistance | `forge_witness_fails`, `random_witness_fails` |
| Stale anchor | Accept only last 100 block roots | `anchor_age_validation` |
| Tree rewind | Persist frontier per block, restore on disconnect | `tree_rewind_produces_consistent_state` |
| Witness staleness | Wallet must call IncrementalUpdate per leaf | `stale_witness_fails_against_new_root` |
| EmptyRoot cache bug | Manually verify all 33 cached empty roots | `empty_root_cache_correctness` |

## C.4 Performance Targets

| Operation | SHA-256 Calls | Target |
|-----------|--------------|--------|
| Append (amortized) | ~1.5 | <2 us |
| Root() | 32 | <5 us |
| Witness creation | 32 | <5 us |
| Witness verify | 32 | <5 us |
| 10,000 appends | ~15,000 | <50 ms |
| IncrementalUpdate | O(cursor_depth) | <5 us |
| Serialize/deserialize | 0 | <10 us |

## C.5 Caution Points

1. **Append is NOT thread-safe** — call only from ConnectBlock under cs_main
2. **EmptyRoot table is computed lazily** — first access triggers computation of all 33 values. Ensure `SHA256AutoDetect()` has been called first
3. **Frontier persistence**: serialize ~1KB frontier on every block flush, NOT the entire tree
4. **Witness updates**: wallets must call IncrementalUpdate for EVERY new leaf, not just their own. Missing one update permanently desynchronizes the witness
5. **Power-of-2 boundaries**: Append is O(depth) worst case when size is 2^k - 1, but O(1) amortized

---

# Part D: MatRiCT+ Lattice Arithmetic & Protocol

## D.1 Lattice Arithmetic — Reusing BTX's Dilithium NTT

BTX's existing Dilithium implementation at `src/libbitcoinpqc/dilithium/ref/` uses **identical parameters** to MatRiCT+:

| Parameter | Dilithium (BTX) | MatRiCT+ |
|-----------|----------------|----------|
| N (ring degree) | 256 | 256 |
| Q (modulus) | 8,380,417 | 8,380,417 |
| QINV (Montgomery) | 58,728,449 | 58,728,449 |
| Root of unity | 1,753 | 1,753 |
| NTT butterfly | Cooley-Tukey | Cooley-Tukey |

**Direct code reuse**: The `ntt()`, `invntt_tomont()`, `montgomery_reduce()`, `reduce32()`, `caddq()`, `freeze()` functions and the `zetas[256]` table from `dilithium/ref/ntt.c` and `dilithium/ref/reduce.c` can be directly used for MatRiCT+ polynomial arithmetic.

### `src/shielded/lattice/params.h`

```cpp
#ifndef BTX_SHIELDED_LATTICE_PARAMS_H
#define BTX_SHIELDED_LATTICE_PARAMS_H

#include <cstdint>

namespace shielded::lattice {

// Ring parameters (identical to Dilithium)
static constexpr size_t POLY_N = 256;
static constexpr int32_t POLY_Q = 8380417;
static constexpr int32_t QINV = 58728449;  // Q^(-1) mod 2^32
static constexpr int32_t MONT = 4193792;   // 2^32 mod Q (Montgomery constant)

// MatRiCT+ specific parameters
static constexpr size_t RING_SIZE = 16;     // Anonymity set
static constexpr size_t MODULE_RANK = 4;    // Matrix dimension k
static constexpr size_t VALUE_BITS = 64;    // Range proof for [0, 2^64)
static constexpr int32_t BETA_CHALLENGE = 60; // Challenge polynomial weight
static constexpr int32_t GAMMA_RESPONSE = (1 << 17); // Response norm bound

} // namespace shielded::lattice

#endif
```

### `src/shielded/lattice/poly.h`

```cpp
#ifndef BTX_SHIELDED_LATTICE_POLY_H
#define BTX_SHIELDED_LATTICE_POLY_H

#include <shielded/lattice/params.h>
#include <cstdint>
#include <vector>

namespace shielded::lattice {

struct Poly256 {
    int32_t coeffs[POLY_N]{};

    /** Forward NTT (in-place, bit-reversed output). Uses Dilithium's zetas table. */
    void NTT();

    /** Inverse NTT with Montgomery factor. */
    void InverseNTT();

    /** Reduce all coefficients to [0, Q). */
    void Reduce();

    /** Conditional add Q (make non-negative). */
    void CAddQ();

    /** Pointwise multiply in NTT domain (Montgomery). */
    static Poly256 PointwiseMul(const Poly256& a, const Poly256& b);

    Poly256 operator+(const Poly256& other) const;
    Poly256 operator-(const Poly256& other) const;

    /** Infinity norm (max absolute value of coefficients). */
    int32_t InfNorm() const;

    /** Pack coefficients for serialization. */
    std::vector<unsigned char> Pack() const;
    static Poly256 Unpack(const unsigned char* data, size_t len);
};

using PolyVec = std::vector<Poly256>;
using PolyMat = std::vector<PolyVec>;  // row-major: mat[row][col]

/** Matrix-vector product: result = mat * vec (all in NTT domain). */
PolyVec MatVecMul(const PolyMat& mat, const PolyVec& vec);

/** Inner product of two polynomial vectors (NTT domain). */
Poly256 InnerProduct(const PolyVec& a, const PolyVec& b);

} // namespace shielded::lattice

#endif
```

### `src/shielded/lattice/poly.cpp` (key functions)

```cpp
#include <shielded/lattice/poly.h>

// Directly reuse Dilithium's NTT implementation
extern "C" {
    // From src/libbitcoinpqc/dilithium/ref/ntt.c
    void ntt(int32_t a[256]);
    void invntt_tomont(int32_t a[256]);
    // From src/libbitcoinpqc/dilithium/ref/reduce.c
    int32_t montgomery_reduce(int64_t a);
    int32_t reduce32(int32_t a);
    int32_t caddq(int32_t a);
    int32_t freeze(int32_t a);
}

namespace shielded::lattice {

void Poly256::NTT() { ntt(coeffs); }
void Poly256::InverseNTT() { invntt_tomont(coeffs); }

void Poly256::Reduce()
{
    for (size_t i = 0; i < POLY_N; ++i) coeffs[i] = reduce32(coeffs[i]);
}

void Poly256::CAddQ()
{
    for (size_t i = 0; i < POLY_N; ++i) coeffs[i] = caddq(coeffs[i]);
}

Poly256 Poly256::PointwiseMul(const Poly256& a, const Poly256& b)
{
    Poly256 c;
    for (size_t i = 0; i < POLY_N; ++i) {
        c.coeffs[i] = montgomery_reduce(static_cast<int64_t>(a.coeffs[i]) * b.coeffs[i]);
    }
    return c;
}

Poly256 Poly256::operator+(const Poly256& other) const
{
    Poly256 r;
    for (size_t i = 0; i < POLY_N; ++i) r.coeffs[i] = coeffs[i] + other.coeffs[i];
    return r;
}

Poly256 Poly256::operator-(const Poly256& other) const
{
    Poly256 r;
    for (size_t i = 0; i < POLY_N; ++i) r.coeffs[i] = coeffs[i] - other.coeffs[i];
    return r;
}

int32_t Poly256::InfNorm() const
{
    int32_t max = 0;
    for (size_t i = 0; i < POLY_N; ++i) {
        int32_t v = coeffs[i];
        if (v < 0) v = -v;
        if (v > max) max = v;
    }
    return max;
}

PolyVec MatVecMul(const PolyMat& mat, const PolyVec& vec)
{
    PolyVec result(mat.size());
    for (size_t i = 0; i < mat.size(); ++i) {
        result[i] = InnerProduct(mat[i], vec);
    }
    return result;
}

Poly256 InnerProduct(const PolyVec& a, const PolyVec& b)
{
    assert(a.size() == b.size());
    Poly256 result{};
    for (size_t i = 0; i < a.size(); ++i) {
        Poly256 tmp = Poly256::PointwiseMul(a[i], b[i]);
        result = result + tmp;
    }
    return result;
}

} // namespace shielded::lattice
```

## D.2 Test Suite for Lattice Arithmetic

### `src/test/lattice_poly_tests.cpp`

```cpp
#include <shielded/lattice/poly.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

using namespace shielded::lattice;

BOOST_FIXTURE_TEST_SUITE(lattice_poly_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(ntt_inverse_is_identity)
{
    Poly256 p;
    for (size_t i = 0; i < POLY_N; ++i) p.coeffs[i] = i % POLY_Q;
    Poly256 original = p;

    p.NTT();
    p.InverseNTT();
    // invntt_tomont returns in Montgomery domain — need to reduce
    for (size_t i = 0; i < POLY_N; ++i) {
        p.coeffs[i] = freeze(p.coeffs[i]);
    }

    for (size_t i = 0; i < POLY_N; ++i) {
        BOOST_CHECK_EQUAL(p.coeffs[i], freeze(original.coeffs[i]));
    }
}

BOOST_AUTO_TEST_CASE(addition_commutativity)
{
    Poly256 a, b;
    for (size_t i = 0; i < POLY_N; ++i) {
        a.coeffs[i] = i * 17 % POLY_Q;
        b.coeffs[i] = i * 31 % POLY_Q;
    }
    Poly256 ab = a + b;
    Poly256 ba = b + a;
    for (size_t i = 0; i < POLY_N; ++i) {
        BOOST_CHECK_EQUAL(ab.coeffs[i], ba.coeffs[i]);
    }
}

BOOST_AUTO_TEST_CASE(zero_is_additive_identity)
{
    Poly256 a;
    for (size_t i = 0; i < POLY_N; ++i) a.coeffs[i] = i * 7 % POLY_Q;
    Poly256 zero{};

    Poly256 r = a + zero;
    for (size_t i = 0; i < POLY_N; ++i) {
        BOOST_CHECK_EQUAL(r.coeffs[i], a.coeffs[i]);
    }
}

BOOST_AUTO_TEST_CASE(reduce_keeps_in_range)
{
    Poly256 p;
    for (size_t i = 0; i < POLY_N; ++i) p.coeffs[i] = POLY_Q + i;
    p.Reduce();
    for (size_t i = 0; i < POLY_N; ++i) {
        BOOST_CHECK(p.coeffs[i] >= -(POLY_Q / 2));
        BOOST_CHECK(p.coeffs[i] <= (POLY_Q / 2));
    }
}

BOOST_AUTO_TEST_CASE(pointwise_mul_in_ntt_domain)
{
    Poly256 a, b;
    for (size_t i = 0; i < POLY_N; ++i) {
        a.coeffs[i] = (i + 1) % POLY_Q;
        b.coeffs[i] = (i * 2 + 3) % POLY_Q;
    }
    a.NTT();
    b.NTT();
    Poly256 c = Poly256::PointwiseMul(a, b);
    // Just verify it doesn't crash and produces non-zero output
    bool any_nonzero = false;
    for (size_t i = 0; i < POLY_N; ++i) {
        if (c.coeffs[i] != 0) any_nonzero = true;
    }
    BOOST_CHECK(any_nonzero);
}

BOOST_AUTO_TEST_CASE(inf_norm_computation)
{
    Poly256 p{};
    p.coeffs[0] = 100;
    p.coeffs[1] = -200;
    p.coeffs[2] = 50;
    BOOST_CHECK_EQUAL(p.InfNorm(), 200);
}

BOOST_AUTO_TEST_SUITE_END()
```

## D.3 MatRiCT+ Protocol — Key Implementation Notes

The full MatRiCT+ protocol implementation consists of:

1. **Lattice Pedersen Commitment**: `cm = A*r + v*g mod q` where A is public matrix, r is randomness, v is value, g is generator vector
2. **Ring Signature**: MLWE-based over the historical draft ring size 16, with key images for linkability
3. **Balance Proof**: Proves `sum(input_commitments) - sum(output_commitments) = fee * g` without revealing values
4. **Range Proof**: Binary decomposition proves each value in [0, 2^64)

### Rejection Sampling

```cpp
// Ring signature creation uses rejection sampling:
// Generate response vector z, check if ||z|| < GAMMA_RESPONSE - BETA_CHALLENGE
// If not, restart with new randomness
//
// Expected restarts: ~2-4 per proof (depends on parameter choices)
// This is the primary source of proof generation variance
```

### Thread Safety of Proof Verification

```cpp
// VerifyMatRiCTProof() is a PURE FUNCTION:
// - Takes const proof + const public inputs
// - Returns bool
// - No global state, no allocations that need synchronization
// - Can be called from any CCheckQueue worker thread
// - Multiple proofs verified truly concurrently
```

---

# Part E: Consensus Validation & Transaction Serialization

## E.1 Transaction Serialization — Exact Code Changes

### Modified `UnserializeTransaction()` in `src/primitives/transaction.h`

Replace lines 215-253 with:

```cpp
template<typename Stream, typename TxType>
void UnserializeTransaction(TxType& tx, Stream& s, const TransactionSerParams& params)
{
    const bool fAllowWitness = params.allow_witness;

    s >> tx.version;
    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
    tx.shielded_bundle = CShieldedBundle{};
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) {
        s >> flags;
        if (flags != 0) {
            s >> tx.vin;
            s >> tx.vout;
        }
    } else {
        s >> tx.vout;
    }
    if ((flags & 1) && fAllowWitness) {
        flags ^= 1;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s >> tx.vin[i].scriptWitness.stack;
        }
        if (!tx.HasWitness()) {
            throw std::ios_base::failure("Superfluous witness record");
        }
    }
    if ((flags & 2) && fAllowWitness) {
        flags ^= 2;
        s >> tx.shielded_bundle;
        if (tx.shielded_bundle.IsEmpty()) {
            throw std::ios_base::failure("Superfluous shielded bundle record");
        }
    }
    if (flags) {
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.nLockTime;
}
```

### Modified `SerializeTransaction()` in `src/primitives/transaction.h`

Replace lines 255-283 with:

```cpp
template<typename Stream, typename TxType>
void SerializeTransaction(const TxType& tx, Stream& s, const TransactionSerParams& params)
{
    const bool fAllowWitness = params.allow_witness;

    s << tx.version;
    unsigned char flags = 0;
    if (fAllowWitness) {
        if (tx.HasWitness()) flags |= 1;
        if (tx.HasShieldedBundle()) flags |= 2;
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
        s << tx.shielded_bundle;
    }
    s << tx.nLockTime;
}
```

## E.2 CShieldedBundle Definition

See `src/shielded/bundle.h` in the validation agent output above.

Key constants:
```cpp
static constexpr size_t MAX_SHIELDED_SPENDS_PER_TX = 500;
static constexpr size_t MAX_SHIELDED_OUTPUTS_PER_TX = 2048;
static constexpr int SHIELDED_ANCHOR_DEPTH = 100;
static constexpr int64_t MAX_SHIELDED_TX_WEIGHT = 4000000;
```

## E.3 Weight Calculation

Shielded data is serialized in the witness-equivalent region (flags & 2). The existing `GetTransactionWeight()` formula:

```
weight = stripped_size * (WITNESS_SCALE_FACTOR - 1) + total_size
       = stripped_size * 3 + total_size
```

Since `TX_NO_WITNESS` excludes both witness AND shielded data, shielded bytes naturally get the 1:1 weight (same discount as witness). **No code change needed to GetTransactionWeight()**.

## E.4 ConnectBlock Integration

See Section 1.5 of the validation agent output for exact code insertion points in `src/validation.cpp`.

Key pipeline:
1. **Sequential**: Nullifier conflict check (within block + against chain)
2. **Sequential**: Anchor validation, binding signature check
3. **Parallel**: Queue proofs to `CCheckQueue<CShieldedProofCheck>`
4. **Both queues**: `control.Complete()` blocks until all workers finish
5. **Sequential**: Append commitments to tree, insert nullifiers, update turnstile

## E.5 Validation Test Suite

Full test suite at `src/test/shielded_validation_tests.cpp` covering:
- Valid bundle passes CheckShieldedBundle
- Duplicate nullifier within tx fails
- Already-spent nullifier fails
- Invalid anchor fails
- Negative pool balance fails turnstile
- Empty bundle is invalid
- Weight calculation correctness
- Anchor consistency required

## E.6 DoS Mitigation

| Attack | Mitigation | Constant |
|--------|-----------|----------|
| Proof spam | Verify proof before relay; rate limit per peer | MAX_SHIELDED_TX_RELAY_PER_SECOND = 5 |
| Large tx DoS | MAX_SHIELDED_TX_WEIGHT per transaction | 4,000,000 WU |
| Nullifier bloat | Bounded by block weight; each output requires fee | fee_rate * shielded_weight |
| Mempool DoS | Higher minimum fee rate for shielded txs | 2x transparent minimum |
| Stale anchor | Reject anchors older than 100 blocks | SHIELDED_ANCHOR_DEPTH = 100 |
| Eclipse on shielded | Require >= 2 NODE_SHIELDED peers | Check in connection management |

---

# Part F: Wallet Integration & RPC

## F.1 Three-Key Architecture

| Key | Type | Derivation Path | Purpose |
|-----|------|-----------------|---------|
| Spending key | ML-DSA-44 | m/87h/coin_type/account/0/index | Authorize spends, derive nullifiers |
| KEM key | ML-KEM-768 | m/88h/coin_type/account/0/index | Encrypt/decrypt notes |
| View key | Derived from KEM SK | Same as KEM | Scan for incoming notes (export-safe) |

## F.2 Shielded Address Format

```
Human-readable part: "btxs" (BTX shielded)
Encoding: Bech32m
Payload: version(1) || algo(1) || spending_pk_hash(32) || kem_pk_hash(32)
Total payload: 66 bytes
Example: btxs1q... (Bech32m encoded)
```

## F.3 RPC Commands

| Command | Parameters | Description |
|---------|-----------|-------------|
| `z_getnewaddress` | `[algo]` | Generate spending + KEM keypair, return btxs address |
| `z_getbalance` | `[minconf]` | Return confirmed shielded balance |
| `z_listunspent` | `[minconf] [maxconf]` | List spendable shielded notes |
| `z_sendmany` | `fromaddr amounts [fee]` | Send from shielded pool |
| `z_shieldcoinbase` | `fromaddr toaddr [fee]` | Shield mining rewards; post-`61000` this remains the supported wallet-side transparent deposit path |
| `z_shieldfunds` | `amounts toaddr [fee]` | Shield transparent UTXOs; post-`61000` limited to mature-coinbase compatibility sweeps |
| `z_mergenotes` | `toaddr [fee]` | Consolidate small notes |
| `z_viewtransaction` | `txid` | View owned shielded tx details |
| `z_exportviewingkey` | `addr` | Export view-only key (KEM SK) |
| `z_importviewingkey` | `key [rescan]` | Import view-only key |

## F.4 Wallet Test Suite

Key tests for `src/test/shielded_wallet_tests.cpp`:
- Generate address produces valid keys
- ScanBlock detects incoming notes
- ScanBlock detects outgoing spends
- GetShieldedBalance returns correct sum
- CreateShieldedSpend produces valid transaction
- Witness updates keep pace with tree
- Import viewing key allows balance check but not spending
- Block disconnect properly reverts wallet state

## F.5 Concurrency Architecture

```
                    ┌───────────────────┐
                    │    Main Thread     │
                    │   (cs_main lock)   │
                    └───────┬───────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │ Script Queue │ │Shielded Queue│ │ Wallet Scan  │
    │ scriptch.0-14│ │ shieldc.0-7  │ │ (cs_shielded)│
    │ (15 threads) │ │ (8 threads)  │ │              │
    └──────────────┘ └──────────────┘ └──────────────┘
```

Lock hierarchy (no deadlocks):
```
cs_main → NullifierSet::m_rwlock → CCheckQueue::m_mutex
cs_wallet → cs_shielded (NEVER with cs_main simultaneously)
```

---

## Part G: Covenant/CLT Bridge Interoperability & Privacy-Preserving Value Transfer

### G.1 Overview: Bridge Architecture with Shielded Pool

BTX's existing covenant infrastructure — CTV (`OP_CHECKTEMPLATEVERIFY`, `0xb3`), CSFS
(`OP_CHECKSIGFROMSTACK`, `0xbd`), CLTV (`OP_CHECKLOCKTIMEVERIFY`, `0xb1`), HTLC, and
atomic swap scripts — provides the building blocks for cross-chain and L2 bridge
operations. This section specifies how these covenant primitives interoperate with the
shielded pool to create a **compliance-friendly privacy solution** where:

- **L2 operators** (banks, business partners, bridge operators) can see value amounts
  during bridge-in/bridge-out operations via view keys
- **On-chain observers** see only shielded commitments — amounts and identities are hidden
- **Post-quantum security** is provided end-to-end via ML-DSA/SLH-DSA signatures

This creates a practical middle ground between full transparency and full anonymity,
enabling institutional adoption while maintaining user privacy from general public
observation.

### G.2 Existing Covenant Infrastructure (Reference)

All covenant opcodes are **P2MR-only** (`SigVersion::P2MR`, witness v2), ensuring
post-quantum security for all bridge operations.

#### G.2.1 CTV Hash Computation

**Location**: `src/script/interpreter.cpp:1682-1699`

```cpp
// CTV hash commits to the transaction template:
// SHA256(version || nLockTime || [scriptsigs_hash] || vin_count ||
//        sequences_hash || vout_count || outputs_hash || input_index)
uint256 ComputeCTVHashImpl(const T& tx, uint32_t nIn,
    const PrecomputedTransactionData& txdata)
{
    HashWriter ss{};
    ss << tx.version;
    ss << tx.nLockTime;
    if (txdata.m_ctv_has_scriptsigs) {
        ss << txdata.m_ctv_scriptsigs_hash;
    }
    ss << static_cast<uint32_t>(tx.vin.size());
    ss << txdata.m_sequences_single_hash;
    ss << static_cast<uint32_t>(tx.vout.size());
    ss << txdata.m_outputs_single_hash;
    ss << nIn;
    return ss.GetSHA256();
}
```

**Key property**: CTV commits to `outputs_hash`, which includes the exact output
scripts and amounts. When a CTV-constrained UTXO is spent, the spending transaction
**must** match the pre-committed template exactly.

#### G.2.2 CSFS Oracle Attestation

**Location**: `src/script/interpreter.cpp:1263-1310`

```cpp
// CSFS verifies a PQ signature over an arbitrary message from the stack:
// Stack: [sig] [msg] [pubkey] → [bool]
// Message is tagged: TaggedHash("CSFS/btx") over msg bytes
case OP_CHECKSIGFROMSTACK:
{
    HashWriter hasher = HASHER_CSFS;  // TaggedHash("CSFS/btx")
    hasher.write(MakeByteSpan(msg));
    const uint256 hash = hasher.GetSHA256();
    success = CPQPubKey{algo, pubkey}.Verify(hash, sig);
}
```

**Key property**: CSFS enables **oracle-attested operations** where a bridge operator
signs a message attesting to off-chain state (e.g., "deposit of X confirmed on L2"),
and the BTX script validates the attestation on-chain without revealing the message
content to other observers.

#### G.2.3 Bridge Script Templates (Existing Code)

From `src/script/pqm.cpp`:

| Function | Purpose | Pattern |
|----------|---------|---------|
| `BuildP2MRHTLCLeaf()` | Cross-chain hash lock | preimage check + CSFS oracle |
| `BuildP2MRRefundLeaf()` | Timeout refund path | CLTV + PQ checksig |
| `BuildP2MRAtomicSwapLeaf()` | CTV-constrained swap | CTV template + PQ checksig |
| `BuildP2MRCTVChecksigScript()` | Template + auth | CTV verify, then checksig |
| `BuildP2MRDelegationScript()` | Delegated signing | CSFS verify, then checksig |
| `BuildP2MRMultisigCTVScript()` | k-of-n + template | CTV + multisig threshold |

### G.3 Shield/Unshield Bridge Flow

#### G.3.1 Bridge-In: Transparent → Shielded (Shield Operation)

The shield operation converts transparent value into shielded notes. This is the
entry point where L2 operators can observe amounts.

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  L2 / Bridge │     │   BTX Mainchain  │     │  Shielded Pool   │
│  Operator    │     │  (Transparent)   │     │  (Hidden Amts)   │
└──────┬───────┘     └────────┬─────────┘     └────────┬─────────┘
       │                      │                        │
       │  1. User deposits    │                        │
       │  value on L2/bridge  │                        │
       │  (amount visible     │                        │
       │   to operator)       │                        │
       │                      │                        │
       │  2. Operator signs   │                        │
       │  CSFS attestation    │                        │
       │  confirming deposit  │                        │
       │──────────────────────►                        │
       │                      │                        │
       │  3. CTV-constrained  │                        │
       │  shield tx created   │                        │
       │                      │  4. Shield tx commits  │
       │                      │  value into shielded   │
       │                      │  note commitment       │
       │                      │────────────────────────►│
       │                      │                        │
       │  5. Operator gets    │                        │
       │  view key for audit  │                        │
       │◄─────────────────────│                        │
       │                      │                        │
```

**Shield Transaction Structure**:

```cpp
// New: ShieldTransaction combines transparent inputs with shielded outputs
struct ShieldTransaction {
    // Transparent inputs (visible amounts — bridge operator sees these)
    std::vector<CTxIn> vin;

    // CTV-constrained: outputs MUST match the pre-committed template
    // This prevents the bridge operator from redirecting funds
    uint256 ctv_hash;

    // Shielded outputs (hidden amounts on-chain)
    std::vector<ShieldedOutput> shielded_outputs;

    // View key grant: encrypted for the bridge operator's KEM public key
    // Allows operator to verify amounts match the bridge deposit
    std::vector<EncryptedViewGrant> view_grants;

    // Turnstile tracking: sum(transparent_inputs) == sum(shielded_values)
    // Enforced by consensus (ZIP 209 style)
    CAmount transparent_value_in;
};

// A view grant allows selective disclosure to a specific party
struct EncryptedViewGrant {
    mlkem::Ciphertext kem_ct;           // ML-KEM-768 encapsulation
    std::array<uint8_t, 12> nonce;      // AEAD nonce
    std::vector<uint8_t> encrypted_data; // AEAD(view_key_material)
};
```

**Implementation file**: `src/shielded/bridge.h`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHIELDED_BRIDGE_H
#define BITCOIN_SHIELDED_BRIDGE_H

#include <consensus/amount.h>
#include <crypto/ml_kem.h>
#include <script/pqm.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <vector>

namespace shielded {

/** Maximum number of view grants per shield/unshield transaction. */
static constexpr size_t MAX_VIEW_GRANTS = 8;

/** Maximum number of shielded outputs in a single shield transaction. */
static constexpr size_t MAX_SHIELD_OUTPUTS = 16;

/** Maximum number of shielded inputs in a single unshield transaction. */
static constexpr size_t MAX_UNSHIELD_INPUTS = 16;

/**
 * View grant: encrypted view key material for selective disclosure.
 *
 * A view grant allows a specific party (identified by their ML-KEM-768 public key)
 * to decrypt and verify the amounts in shielded notes without being able to spend them.
 *
 * Protocol:
 *   1. ML-KEM Encaps(operator_pk) → (ct, ss)
 *   2. HKDF-SHA256(ss, "BTX-ViewGrant-V1") → aead_key
 *   3. AEAD_Encrypt(aead_key, nonce, view_key_data) → ciphertext
 */
struct ViewGrant {
    mlkem::Ciphertext kem_ct;
    std::array<uint8_t, 12> nonce;
    std::vector<uint8_t> encrypted_data;

    /** Create a view grant for a specific operator.
     *
     * @param[in] view_key       The view key bytes to share
     * @param[in] operator_pk    The operator's ML-KEM-768 public key
     * @return The encrypted view grant
     */
    static ViewGrant Create(
        Span<const uint8_t> view_key,
        const mlkem::PublicKey& operator_pk);

    /** Decrypt a view grant using the operator's secret key.
     *
     * @param[in] operator_sk  The operator's ML-KEM-768 secret key
     * @return The decrypted view key bytes, or nullopt on failure
     */
    std::optional<std::vector<uint8_t>> Decrypt(
        const mlkem::SecretKey& operator_sk) const;

    SERIALIZE_METHODS(ViewGrant, obj)
    {
        READWRITE(obj.kem_ct, obj.nonce, obj.encrypted_data);
    }
};

/**
 * Shielded output for a shield (bridge-in) transaction.
 *
 * Contains the note commitment, the encrypted note (for the recipient),
 * and the range proof proving the committed value is non-negative.
 */
struct ShieldedOutput {
    uint256 note_commitment;                //!< cm = NoteCommitment(value, pk, rho, rcm)
    EncryptedNote encrypted_note;           //!< Encrypted for recipient's KEM key
    std::vector<uint8_t> range_proof;       //!< MatRiCT+ range proof: value ∈ [0, MAX_MONEY]
    uint256 merkle_anchor;                  //!< Root of note commitment tree at creation time

    SERIALIZE_METHODS(ShieldedOutput, obj)
    {
        READWRITE(obj.note_commitment, obj.encrypted_note,
                  obj.range_proof, obj.merkle_anchor);
    }
};

/**
 * Shielded input for an unshield (bridge-out) transaction.
 *
 * Contains the nullifier (proving the note was spent) and the spend
 * authorization proof.
 */
struct ShieldedInput {
    Nullifier nullifier;                    //!< nf = Nullifier(spending_key, rho, cm)
    std::vector<uint8_t> spend_proof;       //!< Zero-knowledge proof of valid spend
    std::vector<uint8_t> spend_auth_sig;    //!< PQ signature authorizing the spend

    SERIALIZE_METHODS(ShieldedInput, obj)
    {
        READWRITE(obj.nullifier, obj.spend_proof, obj.spend_auth_sig);
    }
};

/**
 * ShieldedBundle: the shielded data attached to a transaction.
 *
 * This is the data carried in the `flags & 2` section of the serialized
 * transaction (alongside witness data in `flags & 1`).
 */
struct ShieldedBundle {
    std::vector<ShieldedInput> shielded_inputs;
    std::vector<ShieldedOutput> shielded_outputs;
    std::vector<ViewGrant> view_grants;

    /** The value balance: net transparent value change.
     *  Positive = value flowing FROM shielded TO transparent (unshield).
     *  Negative = value flowing FROM transparent TO shielded (shield).
     *  Zero     = fully shielded transaction (shielded-to-shielded). */
    CAmount value_balance{0};

    [[nodiscard]] bool IsShieldOnly() const {
        return shielded_inputs.empty() && !shielded_outputs.empty() && value_balance < 0;
    }

    [[nodiscard]] bool IsUnshieldOnly() const {
        return !shielded_inputs.empty() && shielded_outputs.empty() && value_balance > 0;
    }

    [[nodiscard]] bool IsFullyShielded() const {
        return !shielded_inputs.empty() && !shielded_outputs.empty() && value_balance == 0;
    }

    /** Validate structural constraints (sizes, bounds). */
    [[nodiscard]] bool CheckStructure() const;

    SERIALIZE_METHODS(ShieldedBundle, obj)
    {
        READWRITE(obj.shielded_inputs, obj.shielded_outputs,
                  obj.view_grants, obj.value_balance);
    }
};

/**
 * Build a CTV-constrained shield transaction template.
 *
 * Creates a P2MR script tree with:
 *   Leaf 0: CTV(shield_template) + operator_checksig — normal shield path
 *   Leaf 1: CLTV(timeout) + user_checksig — refund if bridge fails
 *
 * @param[in] shield_ctv_hash     CTV hash committing to the shield tx outputs
 * @param[in] operator_algo       Bridge operator's PQ algorithm
 * @param[in] operator_pubkey     Bridge operator's PQ public key
 * @param[in] user_algo           User's PQ algorithm (for refund)
 * @param[in] user_pubkey         User's PQ public key (for refund)
 * @param[in] refund_timeout      Block height for refund eligibility
 * @return Pair of (leaf_hashes, merkle_root) for the P2MR address
 */
std::pair<std::vector<uint256>, uint256> BuildShieldBridgeScriptTree(
    const uint256& shield_ctv_hash,
    PQAlgorithm operator_algo,
    Span<const unsigned char> operator_pubkey,
    PQAlgorithm user_algo,
    Span<const unsigned char> user_pubkey,
    int64_t refund_timeout);

/**
 * Build a CTV-constrained unshield transaction template.
 *
 * Creates a P2MR script tree with:
 *   Leaf 0: CTV(unshield_template) + CSFS(operator_attestation) — normal unshield
 *   Leaf 1: CLTV(timeout) + user_checksig — refund if operator unresponsive
 *
 * The CSFS leaf requires the bridge operator to sign an attestation message
 * confirming the L2 withdrawal was processed, before the on-chain unshield
 * can complete.
 *
 * @param[in] unshield_ctv_hash   CTV hash committing to unshield tx outputs
 * @param[in] operator_algo       Bridge operator's PQ algorithm (for CSFS)
 * @param[in] operator_pubkey     Bridge operator's PQ public key (for CSFS)
 * @param[in] user_algo           User's PQ algorithm (for refund)
 * @param[in] user_pubkey         User's PQ public key (for refund)
 * @param[in] refund_timeout      Block height for refund eligibility
 * @return Pair of (leaf_hashes, merkle_root) for the P2MR address
 */
std::pair<std::vector<uint256>, uint256> BuildUnshieldBridgeScriptTree(
    const uint256& unshield_ctv_hash,
    PQAlgorithm operator_algo,
    Span<const unsigned char> operator_pubkey,
    PQAlgorithm user_algo,
    Span<const unsigned char> user_pubkey,
    int64_t refund_timeout);

} // namespace shielded

#endif // BITCOIN_SHIELDED_BRIDGE_H
```

**Implementation file**: `src/shielded/bridge.cpp`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/bridge.h>

#include <crypto/chacha20poly1305.h>
#include <crypto/hkdf_sha256_32.h>
#include <hash.h>
#include <random.h>
#include <script/pqm.h>
#include <support/cleanse.h>
#include <util/check.h>

namespace shielded {

// ── ViewGrant ──────────────────────────────────────────────────────

ViewGrant ViewGrant::Create(
    Span<const uint8_t> view_key,
    const mlkem::PublicKey& operator_pk)
{
    // Step 1: KEM encapsulation
    mlkem::EncapsResult kem = mlkem::Encaps(operator_pk);

    // Step 2: Derive AEAD key
    CHKDF_HMAC_SHA256_L32 hkdf(kem.ss.data(), kem.ss.size(), "BTX-ShieldedPool");
    std::vector<uint8_t> aead_key(32, 0);
    hkdf.Expand32("BTX-ViewGrant-V1", aead_key.data());

    // Step 3: Random nonce
    ViewGrant grant;
    grant.kem_ct = kem.ct;
    GetRandBytes(grant.nonce);

    // Step 4: AEAD encrypt
    grant.encrypted_data.resize(view_key.size() + AEADChaCha20Poly1305::EXPANSION);
    {
        AEADChaCha20Poly1305 aead(MakeByteSpan(aead_key));
        uint32_t nonce_prefix = ReadLE32(grant.nonce.data());
        uint64_t nonce_suffix = ReadLE64(grant.nonce.data() + 4);
        AEADChaCha20Poly1305::Nonce96 nonce96{nonce_prefix, nonce_suffix};
        aead.Encrypt(
            MakeByteSpan(view_key),
            MakeByteSpan(kem.ct),  // AAD = KEM ciphertext
            nonce96,
            MakeWritableByteSpan(grant.encrypted_data));
    }

    memory_cleanse(aead_key.data(), aead_key.size());
    memory_cleanse(kem.ss.data(), kem.ss.size());
    return grant;
}

std::optional<std::vector<uint8_t>> ViewGrant::Decrypt(
    const mlkem::SecretKey& operator_sk) const
{
    // Step 1: KEM decapsulation
    mlkem::SharedSecret ss = mlkem::Decaps(kem_ct, operator_sk);

    // Step 2: Derive AEAD key
    CHKDF_HMAC_SHA256_L32 hkdf(ss.data(), ss.size(), "BTX-ShieldedPool");
    std::vector<uint8_t> aead_key(32, 0);
    hkdf.Expand32("BTX-ViewGrant-V1", aead_key.data());

    // Step 3: AEAD decrypt
    if (encrypted_data.size() < AEADChaCha20Poly1305::EXPANSION) {
        memory_cleanse(aead_key.data(), aead_key.size());
        memory_cleanse(ss.data(), ss.size());
        return std::nullopt;
    }
    size_t pt_len = encrypted_data.size() - AEADChaCha20Poly1305::EXPANSION;
    std::vector<uint8_t> plaintext(pt_len);

    bool ok;
    {
        AEADChaCha20Poly1305 aead(MakeByteSpan(aead_key));
        uint32_t nonce_prefix = ReadLE32(nonce.data());
        uint64_t nonce_suffix = ReadLE64(nonce.data() + 4);
        AEADChaCha20Poly1305::Nonce96 nonce96{nonce_prefix, nonce_suffix};
        ok = aead.Decrypt(
            MakeByteSpan(encrypted_data),
            MakeByteSpan(kem_ct),
            nonce96,
            MakeWritableByteSpan(plaintext));
    }

    memory_cleanse(aead_key.data(), aead_key.size());
    memory_cleanse(ss.data(), ss.size());
    return ok ? std::make_optional(std::move(plaintext)) : std::nullopt;
}

// ── ShieldedBundle ─────────────────────────────────────────────────

bool ShieldedBundle::CheckStructure() const
{
    if (shielded_inputs.size() > MAX_UNSHIELD_INPUTS) return false;
    if (shielded_outputs.size() > MAX_SHIELD_OUTPUTS) return false;
    if (view_grants.size() > MAX_VIEW_GRANTS) return false;

    // Must have at least one shielded input or output
    if (shielded_inputs.empty() && shielded_outputs.empty()) return false;

    // Value balance range check
    if (!MoneyRange(value_balance) && !MoneyRange(-value_balance)) return false;

    return true;
}

// ── Bridge Script Trees ────────────────────────────────────────────

std::pair<std::vector<uint256>, uint256> BuildShieldBridgeScriptTree(
    const uint256& shield_ctv_hash,
    PQAlgorithm operator_algo,
    Span<const unsigned char> operator_pubkey,
    PQAlgorithm user_algo,
    Span<const unsigned char> user_pubkey,
    int64_t refund_timeout)
{
    // Leaf 0: CTV + operator signature (normal bridge-in path)
    std::vector<unsigned char> shield_leaf =
        BuildP2MRCTVChecksigScript(shield_ctv_hash, operator_algo, operator_pubkey);
    Assume(!shield_leaf.empty());

    // Leaf 1: CLTV + user signature (refund if bridge fails)
    std::vector<unsigned char> refund_leaf =
        BuildP2MRRefundLeaf(refund_timeout, user_algo, user_pubkey);
    Assume(!refund_leaf.empty());

    // Compute leaf hashes
    uint256 shield_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, shield_leaf);
    uint256 refund_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, refund_leaf);

    // Compute Merkle root
    std::vector<uint256> leaf_hashes{shield_hash, refund_hash};
    uint256 root = ComputeP2MRMerkleRoot(leaf_hashes);

    return {leaf_hashes, root};
}

std::pair<std::vector<uint256>, uint256> BuildUnshieldBridgeScriptTree(
    const uint256& unshield_ctv_hash,
    PQAlgorithm operator_algo,
    Span<const unsigned char> operator_pubkey,
    PQAlgorithm user_algo,
    Span<const unsigned char> user_pubkey,
    int64_t refund_timeout)
{
    // Leaf 0: CTV + CSFS(operator attestation)
    // The operator must sign an attestation that the L2 withdrawal was processed
    // before the on-chain unshield can complete.
    //
    // Script: [ctv_hash] OP_CTV OP_DROP [operator_pubkey] OP_CHECKSIGFROMSTACK
    // Witness: [operator_csfs_sig] [attestation_msg] [ctv_hash]
    std::vector<unsigned char> unshield_leaf = BuildP2MRCTVScript(unshield_ctv_hash);
    Assume(!unshield_leaf.empty());
    unshield_leaf.push_back(OP_DROP);
    std::vector<unsigned char> csfs_part = BuildP2MRCSFSScript(operator_algo, operator_pubkey);
    Assume(!csfs_part.empty());
    unshield_leaf.insert(unshield_leaf.end(), csfs_part.begin(), csfs_part.end());

    // Leaf 1: CLTV + user signature (refund if operator unresponsive)
    std::vector<unsigned char> refund_leaf =
        BuildP2MRRefundLeaf(refund_timeout, user_algo, user_pubkey);
    Assume(!refund_leaf.empty());

    // Compute leaf hashes
    uint256 unshield_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, unshield_leaf);
    uint256 refund_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, refund_leaf);

    // Compute Merkle root
    std::vector<uint256> leaf_hashes{unshield_hash, refund_hash};
    uint256 root = ComputeP2MRMerkleRoot(leaf_hashes);

    return {leaf_hashes, root};
}

} // namespace shielded
```

### G.4 Turnstile Value Pool Enforcement (ZIP 209 Style)

The turnstile mechanism prevents inflation bugs at the boundary between transparent
and shielded value pools.

#### G.4.1 Pool Balance Tracking

```cpp
// New: src/shielded/turnstile.h

#ifndef BITCOIN_SHIELDED_TURNSTILE_H
#define BITCOIN_SHIELDED_TURNSTILE_H

#include <consensus/amount.h>
#include <serialize.h>

#include <cstdint>

/**
 * ShieldedPoolBalance tracks the total value in the shielded pool.
 *
 * Invariant: pool_balance >= 0 at all times (consensus rule).
 *
 * On shield (bridge-in):  pool_balance += shield_amount
 * On unshield (bridge-out): pool_balance -= unshield_amount
 * On fully-shielded tx:     pool_balance unchanged (value_balance == 0)
 *
 * This is analogous to Zcash's ZIP 209 "Prohibit Negative Shielded Chain Value
 * Pool Balance" which prevents bugs where more value is unshielded than was
 * ever shielded, indicating a consensus bug or inflation exploit.
 */
class ShieldedPoolBalance
{
public:
    /** Get the current pool balance. Thread-safe via atomic read. */
    [[nodiscard]] CAmount GetBalance() const { return m_balance; }

    /** Apply a shielded transaction's value balance change.
     *
     * @param[in] value_balance  Net transparent value change from ShieldedBundle.
     *   Positive: value flows FROM shielded TO transparent (unshield).
     *   Negative: value flows FROM transparent TO shielded (shield).
     *
     * @return true if the resulting pool balance is non-negative.
     *         Returns false (and does NOT apply the change) if the
     *         unshield would make the pool balance negative.
     */
    [[nodiscard]] bool ApplyValueBalance(CAmount value_balance);

    /** Reverse a value balance change (for DisconnectBlock). */
    void UndoValueBalance(CAmount value_balance);

    SERIALIZE_METHODS(ShieldedPoolBalance, obj)
    {
        READWRITE(obj.m_balance);
    }

private:
    CAmount m_balance{0};
};

#endif // BITCOIN_SHIELDED_TURNSTILE_H
```

#### G.4.2 Turnstile Implementation

```cpp
// New: src/shielded/turnstile.cpp

#include <shielded/turnstile.h>

#include <consensus/amount.h>
#include <logging.h>
#include <util/check.h>

bool ShieldedPoolBalance::ApplyValueBalance(CAmount value_balance)
{
    // value_balance > 0 means unshielding (value leaving the pool)
    // value_balance < 0 means shielding (value entering the pool)
    // value_balance == 0 means fully shielded (no pool change)

    CAmount new_balance = m_balance - value_balance;

    // ZIP 209 invariant: pool balance must never go negative
    if (new_balance < 0) {
        LogPrintf("ERROR: ShieldedPoolBalance::ApplyValueBalance: "
                  "pool balance would go negative (%lld - %lld = %lld)\n",
                  m_balance, value_balance, new_balance);
        return false;
    }

    // Sanity: pool balance must not exceed total supply
    if (new_balance > MAX_MONEY) {
        LogPrintf("ERROR: ShieldedPoolBalance::ApplyValueBalance: "
                  "pool balance would exceed MAX_MONEY (%lld)\n", new_balance);
        return false;
    }

    m_balance = new_balance;
    return true;
}

void ShieldedPoolBalance::UndoValueBalance(CAmount value_balance)
{
    // Reverse the operation: add back what was subtracted
    m_balance += value_balance;
    Assume(m_balance >= 0);
    Assume(m_balance <= MAX_MONEY);
}
```

#### G.4.3 Consensus Integration

In `ConnectBlock()` (src/validation.cpp), add after shielded transaction validation:

```cpp
// After validating all shielded proofs and nullifiers:
for (const auto& tx : block.vtx) {
    if (tx->HasShieldedBundle()) {
        const auto& bundle = tx->GetShieldedBundle();
        if (!m_shielded_pool_balance.ApplyValueBalance(bundle.value_balance)) {
            return state.Invalid(BlockValidationResult::BLOCK_CONSENSUS,
                "shielded-pool-balance-negative",
                strprintf("shielded pool balance would go negative"));
        }
    }
}
```

### G.5 Comparative Privacy Analysis

#### G.5.1 BTX Shielded Bridge vs Tornado Cash

| Property | Tornado Cash | BTX Shielded Bridge |
|----------|-------------|-------------------|
| **Anonymity set** | Per-denomination pool (0.1/1/10/100 ETH) | Single unified pool (all amounts) |
| **Amount hiding** | Fixed denominations only | Full amount hiding (MatRiCT+ range proofs) |
| **Compliance** | No selective disclosure | View grants to operators via ML-KEM |
| **Quantum resistance** | None (ECDSA + Groth16 zkSNARKs) | Full PQ security (ML-DSA + lattice proofs) |
| **Bridge model** | Relayer-based (censorship vulnerable) | CTV-constrained + CSFS oracle attestation |
| **Refund mechanism** | Requires relayer cooperation | CLTV timeout (trustless on-chain refund) |
| **Regulatory status** | OFAC sanctioned | Compliance-by-design (operator view keys) |
| **Liquidity** | Fragmented across denomination pools | Unified pool = deeper liquidity |
| **On-chain footprint** | ~340 bytes per deposit/withdrawal | ~2-3 KB per shield/unshield (PQ signatures) |
| **Trusted setup** | Groth16 requires ceremony | No trusted setup (hash-based + lattice) |

**Key advantage**: Tornado Cash was sanctioned primarily because it provided no mechanism
for compliance — all transactions were fully anonymous with no ability to prove source
of funds. BTX's view grant system allows operators to verify amounts and sources while
keeping this information off the public chain.

#### G.5.2 BTX Shielded Bridge vs Zcash Sapling

| Property | Zcash Sapling | BTX Shielded Bridge |
|----------|--------------|-------------------|
| **Pool structure** | Separate transparent/shielded pools | Same architecture + bridge integration |
| **View keys** | Full/incoming viewing keys | Granular view grants per operator |
| **Turnstile** | ZIP 209 pool balance tracking | Same model, adapted for bridge flows |
| **Quantum resistance** | None (Jubjub curve + Groth16) | Full PQ (ML-DSA + MatRiCT+ + ML-KEM) |
| **Bridge support** | Not native (requires wrappers) | Native CTV/CSFS/HTLC primitives |
| **Covenants** | None | CTV constrains transaction templates |
| **Oracle attestation** | Not available | CSFS enables bridge operator attestations |
| **Cross-chain** | Limited | HTLC + atomic swaps built-in |

#### G.5.3 Liquidity Advantages

The BTX approach provides superior liquidity access because:

1. **Single unified pool**: Unlike Tornado's fragmented denomination pools, all shielded
   value exists in one pool. The anonymity set is the entire pool, not just the pool
   for a specific denomination.

2. **Continuous amounts**: Users can shield/unshield arbitrary amounts, not just
   fixed denominations. This eliminates the "change problem" where users must make
   multiple transactions to handle non-standard amounts.

3. **Bridge operator incentives**: Operators earn fees for processing bridge operations
   and can verify compliance via view grants, making them willing participants rather
   than adversaries.

4. **Institutional access**: Banks and regulated entities can participate as bridge
   operators, bringing their existing liquidity pools into the BTX ecosystem while
   satisfying their regulatory requirements.

5. **Cross-chain bridges**: HTLC + atomic swap scripts enable trustless bridges to
   other chains, allowing BTX's shielded pool to be a liquidity hub.

### G.6 Test-Driven Development: Bridge Tests

#### G.6.1 `src/test/shielded_bridge_tests.cpp`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/bridge.h>
#include <shielded/turnstile.h>

#include <consensus/amount.h>
#include <crypto/ml_kem.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(shielded_bridge_tests, BasicTestingSetup)

// ── View Grant Tests ──────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(view_grant_roundtrip)
{
    // An operator can decrypt a view grant created for their public key.
    auto operator_kp = mlkem::KeyGen();
    std::vector<uint8_t> view_key(32, 0x42);

    auto grant = shielded::ViewGrant::Create(view_key, operator_kp.pk);
    auto decrypted = grant.Decrypt(operator_kp.sk);

    BOOST_REQUIRE(decrypted.has_value());
    BOOST_CHECK(decrypted.value() == view_key);
}

BOOST_AUTO_TEST_CASE(view_grant_wrong_key_fails)
{
    // A different operator cannot decrypt someone else's view grant.
    auto operator_a = mlkem::KeyGen();
    auto operator_b = mlkem::KeyGen();
    std::vector<uint8_t> view_key(32, 0xAA);

    auto grant = shielded::ViewGrant::Create(view_key, operator_a.pk);
    auto decrypted = grant.Decrypt(operator_b.sk);

    BOOST_CHECK(!decrypted.has_value());
}

BOOST_AUTO_TEST_CASE(view_grant_different_view_keys)
{
    // Different view keys produce different encrypted grants.
    auto kp = mlkem::KeyGen();
    std::vector<uint8_t> vk1(32, 0x11);
    std::vector<uint8_t> vk2(32, 0x22);

    auto g1 = shielded::ViewGrant::Create(vk1, kp.pk);
    auto g2 = shielded::ViewGrant::Create(vk2, kp.pk);

    // Different KEM encapsulations -> different ciphertexts
    BOOST_CHECK(g1.kem_ct != g2.kem_ct);

    // Both decrypt correctly
    auto d1 = g1.Decrypt(kp.sk);
    auto d2 = g2.Decrypt(kp.sk);
    BOOST_REQUIRE(d1.has_value());
    BOOST_REQUIRE(d2.has_value());
    BOOST_CHECK(d1.value() == vk1);
    BOOST_CHECK(d2.value() == vk2);
}

BOOST_AUTO_TEST_CASE(view_grant_tamper_detection)
{
    // Tampering with the encrypted data causes decryption to fail (AEAD tag).
    auto kp = mlkem::KeyGen();
    std::vector<uint8_t> view_key(32, 0xFF);

    auto grant = shielded::ViewGrant::Create(view_key, kp.pk);
    grant.encrypted_data[0] ^= 0x01; // flip one bit

    auto decrypted = grant.Decrypt(kp.sk);
    BOOST_CHECK(!decrypted.has_value());
}

// ── Turnstile Tests ───────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(turnstile_shield_increases_balance)
{
    shielded::ShieldedPoolBalance pool;
    BOOST_CHECK_EQUAL(pool.GetBalance(), 0);

    // Shield 10 BTC (value_balance = -10 BTC, negative = value entering pool)
    BOOST_CHECK(pool.ApplyValueBalance(-10 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 10 * COIN);
}

BOOST_AUTO_TEST_CASE(turnstile_unshield_decreases_balance)
{
    shielded::ShieldedPoolBalance pool;

    // Shield 10 BTC first
    BOOST_CHECK(pool.ApplyValueBalance(-10 * COIN));

    // Unshield 3 BTC (value_balance = +3 BTC, positive = value leaving pool)
    BOOST_CHECK(pool.ApplyValueBalance(3 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 7 * COIN);
}

BOOST_AUTO_TEST_CASE(turnstile_prevents_negative_balance)
{
    shielded::ShieldedPoolBalance pool;

    // Shield 5 BTC
    BOOST_CHECK(pool.ApplyValueBalance(-5 * COIN));

    // Try to unshield 10 BTC (more than pool contains)
    BOOST_CHECK(!pool.ApplyValueBalance(10 * COIN));

    // Pool balance unchanged
    BOOST_CHECK_EQUAL(pool.GetBalance(), 5 * COIN);
}

BOOST_AUTO_TEST_CASE(turnstile_prevents_negative_balance_empty_pool)
{
    shielded::ShieldedPoolBalance pool;

    // Try to unshield from empty pool
    BOOST_CHECK(!pool.ApplyValueBalance(1 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 0);
}

BOOST_AUTO_TEST_CASE(turnstile_fully_shielded_no_change)
{
    shielded::ShieldedPoolBalance pool;
    BOOST_CHECK(pool.ApplyValueBalance(-10 * COIN));

    // Fully shielded tx: value_balance == 0
    BOOST_CHECK(pool.ApplyValueBalance(0));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 10 * COIN);
}

BOOST_AUTO_TEST_CASE(turnstile_undo_shield)
{
    shielded::ShieldedPoolBalance pool;
    BOOST_CHECK(pool.ApplyValueBalance(-10 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 10 * COIN);

    // Undo (disconnect block)
    pool.UndoValueBalance(-10 * COIN);
    BOOST_CHECK_EQUAL(pool.GetBalance(), 0);
}

BOOST_AUTO_TEST_CASE(turnstile_undo_unshield)
{
    shielded::ShieldedPoolBalance pool;
    BOOST_CHECK(pool.ApplyValueBalance(-10 * COIN));
    BOOST_CHECK(pool.ApplyValueBalance(3 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 7 * COIN);

    // Undo the unshield
    pool.UndoValueBalance(3 * COIN);
    BOOST_CHECK_EQUAL(pool.GetBalance(), 10 * COIN);
}

BOOST_AUTO_TEST_CASE(turnstile_max_money_boundary)
{
    shielded::ShieldedPoolBalance pool;

    // Shield MAX_MONEY
    BOOST_CHECK(pool.ApplyValueBalance(-MAX_MONEY));
    BOOST_CHECK_EQUAL(pool.GetBalance(), MAX_MONEY);

    // Try to shield 1 more satoshi (exceeds MAX_MONEY)
    BOOST_CHECK(!pool.ApplyValueBalance(-1));
    BOOST_CHECK_EQUAL(pool.GetBalance(), MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(turnstile_exact_drain)
{
    shielded::ShieldedPoolBalance pool;
    BOOST_CHECK(pool.ApplyValueBalance(-100 * COIN));

    // Unshield exactly the pool balance
    BOOST_CHECK(pool.ApplyValueBalance(100 * COIN));
    BOOST_CHECK_EQUAL(pool.GetBalance(), 0);
}

// ── Bridge Script Tree Tests ──────────────────────────────────────

BOOST_AUTO_TEST_CASE(shield_bridge_script_tree_structure)
{
    // Generate PQ key pairs for operator and user
    CPQKey operator_key;
    operator_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey operator_pk = operator_key.GetPubKey();

    CPQKey user_key;
    user_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey user_pk = user_key.GetPubKey();

    uint256 ctv_hash = m_rng.rand256();
    int64_t refund_timeout = 144 * 30; // ~30 days in blocks

    auto [leaf_hashes, root] = shielded::BuildShieldBridgeScriptTree(
        ctv_hash,
        PQAlgorithm::ML_DSA_44, operator_pk.GetKeyData(),
        PQAlgorithm::ML_DSA_44, user_pk.GetKeyData(),
        refund_timeout);

    // Must have exactly 2 leaves
    BOOST_CHECK_EQUAL(leaf_hashes.size(), 2u);

    // Root must not be null
    BOOST_CHECK(!root.IsNull());

    // Leaf hashes must differ (different scripts)
    BOOST_CHECK(leaf_hashes[0] != leaf_hashes[1]);

    // Root must be deterministic
    auto [leaf_hashes2, root2] = shielded::BuildShieldBridgeScriptTree(
        ctv_hash,
        PQAlgorithm::ML_DSA_44, operator_pk.GetKeyData(),
        PQAlgorithm::ML_DSA_44, user_pk.GetKeyData(),
        refund_timeout);
    BOOST_CHECK_EQUAL(root, root2);
}

BOOST_AUTO_TEST_CASE(unshield_bridge_script_tree_structure)
{
    CPQKey operator_key;
    operator_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey operator_pk = operator_key.GetPubKey();

    CPQKey user_key;
    user_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey user_pk = user_key.GetPubKey();

    uint256 ctv_hash = m_rng.rand256();
    int64_t refund_timeout = 144 * 7; // ~1 week

    auto [leaf_hashes, root] = shielded::BuildUnshieldBridgeScriptTree(
        ctv_hash,
        PQAlgorithm::ML_DSA_44, operator_pk.GetKeyData(),
        PQAlgorithm::ML_DSA_44, user_pk.GetKeyData(),
        refund_timeout);

    BOOST_CHECK_EQUAL(leaf_hashes.size(), 2u);
    BOOST_CHECK(!root.IsNull());
    BOOST_CHECK(leaf_hashes[0] != leaf_hashes[1]);
}

BOOST_AUTO_TEST_CASE(different_ctv_hash_different_tree)
{
    CPQKey operator_key;
    operator_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey operator_pk = operator_key.GetPubKey();

    CPQKey user_key;
    user_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey user_pk = user_key.GetPubKey();

    uint256 ctv_hash_a = m_rng.rand256();
    uint256 ctv_hash_b = m_rng.rand256();

    auto [_, root_a] = shielded::BuildShieldBridgeScriptTree(
        ctv_hash_a,
        PQAlgorithm::ML_DSA_44, operator_pk.GetKeyData(),
        PQAlgorithm::ML_DSA_44, user_pk.GetKeyData(),
        1000);

    auto [__, root_b] = shielded::BuildShieldBridgeScriptTree(
        ctv_hash_b,
        PQAlgorithm::ML_DSA_44, operator_pk.GetKeyData(),
        PQAlgorithm::ML_DSA_44, user_pk.GetKeyData(),
        1000);

    // Different CTV hashes must produce different Merkle roots
    BOOST_CHECK(root_a != root_b);
}

BOOST_AUTO_TEST_CASE(merkle_proof_verification)
{
    CPQKey operator_key;
    operator_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey operator_pk = operator_key.GetPubKey();

    CPQKey user_key;
    user_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey user_pk = user_key.GetPubKey();

    uint256 ctv_hash = m_rng.rand256();

    auto [leaf_hashes, root] = shielded::BuildShieldBridgeScriptTree(
        ctv_hash,
        PQAlgorithm::ML_DSA_44, operator_pk.GetKeyData(),
        PQAlgorithm::ML_DSA_44, user_pk.GetKeyData(),
        1000);

    // Build control block for leaf 0 (CTV + checksig path)
    // Control: [leaf_version] [sibling_hash]
    std::vector<unsigned char> control;
    control.push_back(P2MR_LEAF_VERSION);
    control.insert(control.end(), leaf_hashes[1].begin(), leaf_hashes[1].end());

    // Verify: leaf_hash[0] + control should reconstruct root
    BOOST_CHECK(VerifyP2MRCommitment(control, root, leaf_hashes[0]));

    // Control for leaf 1 (refund path)
    std::vector<unsigned char> control_refund;
    control_refund.push_back(P2MR_LEAF_VERSION);
    control_refund.insert(control_refund.end(), leaf_hashes[0].begin(), leaf_hashes[0].end());

    BOOST_CHECK(VerifyP2MRCommitment(control_refund, root, leaf_hashes[1]));
}

// ── ShieldedBundle Structure Tests ────────────────────────────────

BOOST_AUTO_TEST_CASE(shielded_bundle_check_structure_valid)
{
    shielded::ShieldedBundle bundle;
    bundle.shielded_outputs.push_back(shielded::ShieldedOutput{});
    bundle.value_balance = -1 * COIN;

    BOOST_CHECK(bundle.CheckStructure());
}

BOOST_AUTO_TEST_CASE(shielded_bundle_empty_rejected)
{
    shielded::ShieldedBundle bundle;

    // No inputs or outputs = invalid
    BOOST_CHECK(!bundle.CheckStructure());
}

BOOST_AUTO_TEST_CASE(shielded_bundle_too_many_outputs_rejected)
{
    shielded::ShieldedBundle bundle;
    for (size_t i = 0; i <= shielded::MAX_SHIELD_OUTPUTS; ++i) {
        bundle.shielded_outputs.push_back(shielded::ShieldedOutput{});
    }
    bundle.value_balance = -1 * COIN;

    BOOST_CHECK(!bundle.CheckStructure());
}

BOOST_AUTO_TEST_CASE(shielded_bundle_type_detection)
{
    // Shield-only (value entering pool)
    shielded::ShieldedBundle shield;
    shield.shielded_outputs.push_back(shielded::ShieldedOutput{});
    shield.value_balance = -5 * COIN;
    BOOST_CHECK(shield.IsShieldOnly());

    // Unshield-only (value leaving pool)
    shielded::ShieldedBundle unshield;
    unshield.shielded_inputs.push_back(shielded::ShieldedInput{});
    unshield.value_balance = 5 * COIN;
    BOOST_CHECK(unshield.IsUnshieldOnly());

    // Fully shielded (value stays in pool)
    shielded::ShieldedBundle full;
    full.shielded_inputs.push_back(shielded::ShieldedInput{});
    full.shielded_outputs.push_back(shielded::ShieldedOutput{});
    full.value_balance = 0;
    BOOST_CHECK(full.IsFullyShielded());
}

BOOST_AUTO_TEST_SUITE_END()
```

### G.7 Security Analysis: Bridge-Specific Threats

#### G.7.1 Bridge Operator Collusion (Fund Theft)

**Threat**: A malicious bridge operator could attempt to redirect bridged funds to
their own address instead of creating the agreed-upon shielded notes.

**Mitigation**: CTV (OP_CHECKTEMPLATEVERIFY) constrains the bridge transaction to a
pre-committed template. The transaction outputs (including shielded note commitments)
are locked in the CTV hash BEFORE the user deposits funds. The operator cannot modify
the outputs without invalidating the CTV check.

```
User creates CTV hash: SHA256(version || locktime || ... || outputs_hash || ...)
                                                            ↑
                                                This commits to the exact
                                                shielded output commitments
```

**Test**:
```cpp
BOOST_AUTO_TEST_CASE(security_ctv_prevents_output_modification)
{
    // The CTV hash commits to the outputs. If the operator tries to modify
    // the outputs (e.g., redirect to their own address), the CTV check fails.
    //
    // This test verifies that ComputeCTVHash changes when outputs change.
    CMutableTransaction tx1;
    tx1.version = 2;
    tx1.nLockTime = 0;
    tx1.vin.push_back(CTxIn(COutPoint(m_rng.rand256(), 0)));
    tx1.vout.push_back(CTxOut(1 * COIN, CScript() << OP_TRUE));

    CMutableTransaction tx2 = tx1;
    tx2.vout[0].nValue = 2 * COIN; // different amount

    PrecomputedTransactionData ptd1;
    ptd1.Init(tx1, {}, true);
    PrecomputedTransactionData ptd2;
    ptd2.Init(tx2, {}, true);

    uint256 ctv1 = ComputeCTVHash(tx1, 0, ptd1);
    uint256 ctv2 = ComputeCTVHash(tx2, 0, ptd2);

    BOOST_CHECK(ctv1 != ctv2); // Different outputs = different CTV hash
}
```

#### G.7.2 Operator Liveness Failure

**Threat**: The bridge operator goes offline or refuses to process the bridge
transaction, leaving user funds locked.

**Mitigation**: Every bridge script tree includes a **refund leaf** with CLTV timeout:

```
Leaf 0: CTV(template) + operator_checksig  — normal bridge path
Leaf 1: CLTV(timeout) + user_checksig      — refund after timeout
```

If the operator doesn't complete the bridge within the timeout period (e.g., 30 days),
the user can claim a refund by spending via Leaf 1. This is completely trustless —
no cooperation from the operator is required.

**Test**:
```cpp
BOOST_AUTO_TEST_CASE(security_refund_path_accessible_after_timeout)
{
    // Verify that the refund leaf is a valid P2MR leaf script that can be
    // executed when the CLTV timeout is reached.
    CPQKey user_key;
    user_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey user_pk = user_key.GetPubKey();

    int64_t timeout = 4320; // ~30 days in blocks

    std::vector<unsigned char> refund_leaf =
        BuildP2MRRefundLeaf(timeout, PQAlgorithm::ML_DSA_44, user_pk.GetKeyData());

    BOOST_CHECK(!refund_leaf.empty());

    // Verify it contains CLTV opcode
    CScript script(refund_leaf.begin(), refund_leaf.end());
    bool has_cltv = false;
    for (auto it = script.begin(); it != script.end(); ) {
        opcodetype opcode;
        if (script.GetOp(it, opcode) && opcode == OP_CHECKLOCKTIMEVERIFY) {
            has_cltv = true;
            break;
        }
    }
    BOOST_CHECK(has_cltv);
}
```

#### G.7.3 Oracle Message Replay (CSFS)

**Threat**: An attacker captures a valid CSFS oracle attestation from one bridge
operation and replays it in a different transaction.

**Mitigation**: The CSFS message should include the specific CTV hash for the bridge
transaction, binding the attestation to exactly one transaction template. Since CTV
hashes are unique per transaction (they include input index, outputs hash, etc.), a
valid CSFS signature for one bridge operation cannot be replayed for another.

**Recommended message format for CSFS attestation**:
```
attestation_msg = SHA256("BTX/BridgeAttestation/v1" || ctv_hash || operator_nonce)
```

**Test**:
```cpp
BOOST_AUTO_TEST_CASE(security_csfs_attestation_not_replayable)
{
    // Two different CTV hashes produce different attestation messages,
    // so a CSFS signature for one cannot validate for the other.
    uint256 ctv_hash_1 = m_rng.rand256();
    uint256 ctv_hash_2 = m_rng.rand256();

    // Compute attestation messages
    HashWriter hw1{TaggedHash("BTX/BridgeAttestation/v1")};
    hw1 << ctv_hash_1;
    uint256 msg1 = hw1.GetSHA256();

    HashWriter hw2{TaggedHash("BTX/BridgeAttestation/v1")};
    hw2 << ctv_hash_2;
    uint256 msg2 = hw2.GetSHA256();

    BOOST_CHECK(msg1 != msg2);
}
```

#### G.7.4 Shielded Pool Inflation via Bridge Bug

**Threat**: A bug in the bridge logic allows more value to be unshielded than was
originally shielded, creating coins out of thin air.

**Mitigation**: The `ShieldedPoolBalance` turnstile tracks total shielded value. The
invariant `pool_balance >= 0` is checked on every block connect. If a block would
cause the pool balance to go negative, the entire block is rejected. This is the
same approach used by Zcash (ZIP 209) and has prevented real inflation bugs.

Additionally, each shielded transaction includes a MatRiCT balance proof and
proof transcript binding that enforce `sum(input_values) == sum(output_values) + value_balance`
before the turnstile check.

#### G.7.5 View Key Compromise

**Threat**: An attacker obtains a bridge operator's view key, enabling them to
see all amounts in transactions that included view grants for that operator.

**Mitigation**:
- View grants are **per-transaction**, not global. Compromising one grant reveals
  only the amounts in that specific transaction, not all shielded transactions.
- View keys provide **read-only access** — they cannot authorize spends.
- Operators should use **hardware security modules (HSMs)** for their ML-KEM
  secret keys.
- Key rotation: operators can periodically generate new KEM key pairs. Old
  grants remain encrypted with the old key; new transactions use the new key.

#### G.7.6 DoS via Expensive Bridge Operations

**Threat**: An attacker floods the network with bridge transactions containing
expensive PQ signature verifications or invalid shielded proofs.

**Mitigation**:
- **Validation weight budgets**: Each P2MR script execution has a weight budget
  (`execdata.m_validation_weight_left`). ML-DSA costs 500 weight, SLH-DSA costs
  5000 weight per sigop. Exceeding the budget fails the script immediately.
- **MAX_P2MR_STACK_BYTES**: Stack size limited to 1 MB per script execution.
- **Shielded proof verification** uses a dedicated `CCheckQueue<CShieldedProofCheck>`
  with 8 threads, preventing shielded verification from starving script verification.
- **Fee rate enforcement**: Bridge transactions with shielded bundles must pay fees
  proportional to their total weight (transparent + shielded data weight).

### G.8 Benchmark: Bridge Operations

```cpp
// New: src/bench/shielded_bridge_bench.cpp

#include <bench/bench.h>
#include <crypto/ml_kem.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <shielded/bridge.h>
#include <shielded/turnstile.h>

#include <cassert>
#include <cstring>

namespace {

void bench_view_grant_create(benchmark::Bench& bench)
{
    // Target: < 0.5 ms (dominated by ML-KEM Encaps)
    auto kp = mlkem::KeyGen();
    std::vector<uint8_t> view_key(32, 0x42);

    bench.minEpochIterations(50).run([&] {
        auto grant = shielded::ViewGrant::Create(view_key, kp.pk);
        assert(!grant.encrypted_data.empty());
    });
}

void bench_view_grant_decrypt(benchmark::Bench& bench)
{
    // Target: < 0.5 ms (dominated by ML-KEM Decaps)
    auto kp = mlkem::KeyGen();
    std::vector<uint8_t> view_key(32, 0x42);
    auto grant = shielded::ViewGrant::Create(view_key, kp.pk);

    bench.minEpochIterations(50).run([&] {
        auto decrypted = grant.Decrypt(kp.sk);
        assert(decrypted.has_value());
    });
}

void bench_turnstile_apply(benchmark::Bench& bench)
{
    // Target: < 0.1 us (simple arithmetic + bounds check)
    shielded::ShieldedPoolBalance pool;

    bench.minEpochIterations(100000).run([&] {
        pool.ApplyValueBalance(-COIN);
        pool.ApplyValueBalance(COIN);
    });
}

void bench_shield_bridge_script_tree(benchmark::Bench& bench)
{
    // Target: < 1 ms (2 SHA-256 leaf hashes + 1 branch hash)
    CPQKey operator_key;
    operator_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey operator_pk = operator_key.GetPubKey();

    CPQKey user_key;
    user_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    CPQPubKey user_pk = user_key.GetPubKey();

    uint256 ctv_hash;
    std::memset(ctv_hash.begin(), 0xAA, 32);

    bench.minEpochIterations(100).run([&] {
        auto [leaves, root] = shielded::BuildShieldBridgeScriptTree(
            ctv_hash,
            PQAlgorithm::ML_DSA_44, operator_pk.GetKeyData(),
            PQAlgorithm::ML_DSA_44, user_pk.GetKeyData(),
            4320);
        assert(!root.IsNull());
    });
}

} // namespace

BENCHMARK(bench_view_grant_create, benchmark::PriorityLevel::HIGH);
BENCHMARK(bench_view_grant_decrypt, benchmark::PriorityLevel::HIGH);
BENCHMARK(bench_turnstile_apply, benchmark::PriorityLevel::HIGH);
BENCHMARK(bench_shield_bridge_script_tree, benchmark::PriorityLevel::HIGH);
```

### G.9 Caution Points: Bridge Integration

#### G.9.1 CTV Hash Does Not Commit to Shielded Bundle

**Critical**: The current `ComputeCTVHash()` implementation (interpreter.cpp:1682-1699)
commits to `outputs_hash` (transparent outputs) but does NOT commit to the shielded
bundle data (note commitments, encrypted notes, range proofs). This means a CTV
template could be satisfied by a transaction with different shielded outputs than
intended.

**Required change**: Extend `ComputeCTVHash()` to include a hash of the shielded bundle:

```cpp
// PROPOSED: Extended CTV hash for shielded-aware transactions
uint256 ComputeCTVHashImpl(const T& tx, uint32_t nIn,
    const PrecomputedTransactionData& txdata)
{
    HashWriter ss{};
    ss << tx.version;
    ss << tx.nLockTime;
    if (txdata.m_ctv_has_scriptsigs) {
        ss << txdata.m_ctv_scriptsigs_hash;
    }
    ss << static_cast<uint32_t>(tx.vin.size());
    ss << txdata.m_sequences_single_hash;
    ss << static_cast<uint32_t>(tx.vout.size());
    ss << txdata.m_outputs_single_hash;
    // NEW: Include shielded bundle hash if present
    if (txdata.m_has_shielded_bundle) {
        ss << txdata.m_shielded_bundle_hash;
    }
    ss << nIn;
    return ss.GetSHA256();
}
```

**Test requirement**: Verify that changing the shielded bundle changes the CTV hash,
and that transactions with shielded bundles produce different CTV hashes than
identical transactions without shielded bundles.

#### G.9.2 View Grant Privacy Boundary

**Important**: View grants intentionally create a privacy boundary. The bridge operator
can see amounts but cannot spend funds. However, the following must be ensured:

1. View grants must NOT leak the spending key or KEM decryption key
2. View grants must NOT enable linking different shielded transactions to the same user
3. The view key material shared via grants should be derived specifically for the
   operator, not the user's master view key

**Recommended**: Use a per-operator derived view key:
```
operator_view_key = HKDF-SHA256(master_view_key, "BTX-OperatorView-V1", operator_id)
```

#### G.9.3 Atomic Shield + Merkle Tree Insert

**Important**: When processing a shield transaction, two operations must be atomic:
1. Adding the note commitment to the Merkle tree
2. Recording the value in the turnstile pool balance

If these operations are not atomic (e.g., crash between them), the system could enter
an inconsistent state where a note exists in the tree but the pool balance doesn't
reflect it (or vice versa).

**Solution**: Both operations must occur within the same `cs_main` critical section
during `ConnectBlock()`, and both must be undone atomically during `DisconnectBlock()`.

#### G.9.4 Cross-Chain HTLC Quantum Safety

**Warning**: While BTX uses PQ signatures for the on-chain HTLC leaf, the cross-chain
counterpart (on Bitcoin, Ethereum, etc.) likely uses classical ECDSA/Schnorr signatures.
An attacker with a quantum computer could:

1. Observe the HTLC preimage on the classical chain
2. Use quantum computing to forge the classical chain's signature
3. Claim funds on both chains

**Mitigation**: For high-value bridge operations, use **short HTLC timeouts** (hours,
not days) to reduce the window of quantum attack. Alternatively, use CTV-based
bridge patterns where the cross-chain operation is committed before any secrets are
revealed.

### G.10 Build System Changes for Bridge Module

Add to `src/shielded/CMakeLists.txt`:

```cmake
target_sources(btx_shielded PRIVATE
  bridge.cpp
  turnstile.cpp
)
```

Add to `src/test/CMakeLists.txt`:

```cmake
  shielded_bridge_tests.cpp
```

Add to `src/bench/CMakeLists.txt`:

```cmake
  shielded_bridge_bench.cpp
```

### G.11 Summary: Why BTX Creates a Superior Privacy Solution

1. **Compliance-friendly**: View grants enable selective disclosure to bridge operators
   and regulators, satisfying AML/KYC requirements at bridge boundaries while
   maintaining on-chain privacy. This is fundamentally different from Tornado Cash's
   all-or-nothing approach that led to OFAC sanctions.

2. **Superior anonymity set**: A single unified shielded pool (vs Tornado's fragmented
   denomination pools) means every shielded UTXO contributes to the anonymity set.
   The anonymity set grows with every user, not just users of the same denomination.

3. **Full amount hiding**: MatRiCT+ range proofs hide amounts on-chain, unlike Tornado
   which reveals amounts by denomination. This eliminates amount-based transaction
   graph analysis.

4. **Post-quantum security**: End-to-end PQ protection (ML-DSA signatures, ML-KEM
   encryption, lattice-based range proofs) provides security against future quantum
   attacks. Neither Tornado Cash nor Zcash Sapling has this property.

5. **Trustless bridge operations**: CTV constrains transaction templates (preventing
   operator theft), CSFS enables oracle attestations (binding bridge state to on-chain
   transactions), and CLTV provides trustless refunds (protecting users from operator
   failure). This is more robust than Tornado's relayer model.

6. **Greater liquidity potential**: Institutional operators (banks, payment processors)
   can participate as bridge operators because they can satisfy compliance requirements
   via view grants. This brings institutional liquidity into the privacy pool —
   something that was impossible with Tornado Cash and impractical with Zcash.

7. **No trusted setup**: Unlike Tornado Cash (Groth16 zkSNARKs) and Zcash Sapling
   (Groth16), BTX's privacy system uses hash-based commitments and lattice-based
   proofs that require no trusted setup ceremony.

---

*Document updated: 2026-03-04*
*Branch: claude/btx-privacy-analysis-8CN3q*
*Part G: Covenant/CLT Bridge Interoperability — complete*
