# BTX Shielded Pool: Wallet Integration, RPC Commands, and Concurrency Architecture

**Status:** Implementation-Ready Specification
**Target Files:** `src/wallet/shielded_wallet.*`, `src/wallet/shielded_coins.*`, `src/wallet/shielded_rpc.cpp`, `src/wallet/pq_keyderivation.h` additions, `src/init.cpp` modifications
**Dependencies:** Components 1-6 from btx-shielded-pool-implementation-tracker.md

---

## 1. Complete Implementation Code

### 1.1 `src/wallet/shielded_wallet.h`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_SHIELDED_WALLET_H
#define BITCOIN_WALLET_SHIELDED_WALLET_H

#include <consensus/amount.h>
#include <crypto/ml_kem.h>
#include <pqkey.h>
#include <shielded/merkle_tree.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <shielded/bundle.h>
#include <sync.h>
#include <uint256.h>
#include <validationinterface.h>
#include <wallet/shielded_coins.h>

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <vector>

class CBlock;
class CBlockIndex;
class CTransaction;
struct CMutableTransaction;

namespace wallet {

class CWallet;

// ---------------------------------------------------------------------------
// Shielded key material
// ---------------------------------------------------------------------------

/** A complete shielded address keypair: spending key + KEM key + derived view key. */
struct ShieldedKeySet
{
    //! ML-DSA-44 spending key — authorizes spends, derives nullifiers.
    //! Stored in secure_allocator-backed memory via CPQKey::m_secret_key.
    CPQKey spending_key;

    //! ML-KEM-768 keypair — encrypts/decrypts notes.
    MLKEMKeyPair kem_key;

    //! SHA-256 hash of the spending public key (used in note commitments).
    uint256 spending_pk_hash;

    //! SHA-256 hash of the KEM public key (used in shielded address).
    uint256 kem_pk_hash;

    //! Derivation metadata.
    uint32_t account{0};
    uint32_t index{0};

    //! Whether this key set has full spending authority (false = view-only).
    bool has_spending_key{true};
};

// ---------------------------------------------------------------------------
// Shielded address
// ---------------------------------------------------------------------------

/** A BTX shielded address encodes the spending public key hash and KEM
 *  public key hash.  Format: btxs1<version><algo><pk_hash><kem_pk_hash>.
 *  See Section 6 for full encoding specification. */
struct ShieldedAddress
{
    uint8_t version{0x00};
    uint8_t algo_byte{0x00};  // 0x00 = ML-DSA-44 + ML-KEM-768
    uint256 pk_hash;
    uint256 kem_pk_hash;

    std::string Encode() const;
    static std::optional<ShieldedAddress> Decode(const std::string& addr);
    bool IsValid() const;

    friend bool operator==(const ShieldedAddress& a, const ShieldedAddress& b) {
        return a.version == b.version && a.algo_byte == b.algo_byte &&
               a.pk_hash == b.pk_hash && a.kem_pk_hash == b.kem_pk_hash;
    }
    friend bool operator<(const ShieldedAddress& a, const ShieldedAddress& b) {
        if (a.pk_hash != b.pk_hash) return a.pk_hash < b.pk_hash;
        return a.kem_pk_hash < b.kem_pk_hash;
    }
};

// ---------------------------------------------------------------------------
// CShieldedWallet — manages shielded keys, notes, scanning, and spending
// ---------------------------------------------------------------------------

class CShieldedWallet : public CValidationInterface
{
public:
    explicit CShieldedWallet(CWallet& parent_wallet,
                             const shielded::ShieldedMerkleTree* global_tree);
    ~CShieldedWallet();

    // Disallow copy
    CShieldedWallet(const CShieldedWallet&) = delete;
    CShieldedWallet& operator=(const CShieldedWallet&) = delete;

    // -----------------------------------------------------------------
    // Key management
    // -----------------------------------------------------------------

    /** Generate a new shielded address (spending + KEM key pair).
     *  Keys are derived deterministically from the wallet's master seed
     *  at paths m/87h/coin_type/account/0/index (spending)
     *  and m/88h/coin_type/account/0/index (KEM). */
    ShieldedAddress GenerateNewAddress(uint32_t account = 0)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Import a view-only key (KEM secret key only, no spending key).
     *  Allows balance checking and scanning but not spending. */
    bool ImportViewingKey(const std::vector<unsigned char>& kem_sk,
                          const std::vector<unsigned char>& kem_pk,
                          const uint256& spending_pk_hash)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Export the viewing key (KEM secret key) for a given address.
     *  Returns nullopt if the address is not owned by this wallet. */
    std::optional<std::vector<unsigned char>> ExportViewingKey(
        const ShieldedAddress& addr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return all shielded addresses owned by this wallet. */
    std::vector<ShieldedAddress> GetAddresses() const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Check whether we have the spending key for an address. */
    bool HaveSpendingKey(const ShieldedAddress& addr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    // -----------------------------------------------------------------
    // Block scanning
    // -----------------------------------------------------------------

    /** Scan a single block for notes belonging to this wallet.
     *
     *  For each shielded transaction in the block:
     *  1. Check spend nullifiers against our note set (detect outgoing).
     *  2. For each encrypted output, apply view tag pre-filter (1 byte check,
     *     rejects 255/256 notes at ~10ns each).
     *  3. On view tag match, attempt ML-KEM decapsulation + AEAD decryption.
     *  4. On successful decryption, register the note and create a witness.
     *  5. Incrementally update all existing witnesses for new commitments.
     *
     *  Steps 1-3 are embarrassingly parallel per-output and per-key.
     *  Step 5 is sequential (order-dependent within the wallet). */
    void ScanBlock(const CBlock& block, int height)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Undo a block: re-mark spent notes as unspent, remove notes
     *  received in the disconnected block, rewind witnesses. */
    void UndoBlock(const CBlock& block, int height)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Full rescan from genesis (or a given start height).
     *  Called after importing a viewing key. */
    void Rescan(int start_height = 0)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    // -----------------------------------------------------------------
    // Balance and note queries
    // -----------------------------------------------------------------

    /** Return total confirmed shielded balance (sum of unspent notes
     *  with >= min_depth confirmations). */
    CAmount GetShieldedBalance(int min_depth = 1) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return all spendable (unspent, confirmed, has spending key) notes. */
    std::vector<ShieldedCoin> GetSpendableNotes(int min_depth = 1) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return all unspent notes (including view-only). */
    std::vector<ShieldedCoin> GetUnspentNotes(int min_depth = 0) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    // -----------------------------------------------------------------
    // Transaction creation
    // -----------------------------------------------------------------

    /** Create a shielded-to-shielded or shielded-to-transparent spend.
     *
     *  @param[in] shielded_recipients  Shielded destination + amount pairs.
     *  @param[in] transparent_recipients  Transparent destination + amount pairs
     *             (for unshielding).
     *  @param[in] fee  Transaction fee in satoshis.
     *  @return Signed mutable transaction, or nullopt on failure. */
    std::optional<CMutableTransaction> CreateShieldedSpend(
        const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
        const std::vector<std::pair<CTxDestination, CAmount>>& transparent_recipients,
        CAmount fee)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Shield transparent UTXOs into a shielded note to ourselves.
     *
     *  @param[in] utxos  Transparent outpoints to spend.
     *  @param[in] fee    Transaction fee.
     *  @param[in] dest   Optional destination address; defaults to our own. */
    std::optional<CMutableTransaction> ShieldFunds(
        const std::vector<COutPoint>& utxos,
        CAmount fee,
        std::optional<ShieldedAddress> dest = std::nullopt)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Unshield: move shielded value to a transparent output.
     *
     *  @param[in] amount       Amount to unshield.
     *  @param[in] destination  Transparent address.
     *  @param[in] fee          Transaction fee. */
    std::optional<CMutableTransaction> UnshieldFunds(
        CAmount amount,
        const CTxDestination& destination,
        CAmount fee)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Consolidate small notes into fewer larger notes.
     *  Reduces ongoing witness update overhead. Returns number of notes merged.
     *
     *  @param[in] max_notes    Maximum number of notes to merge per tx.
     *  @param[in] fee          Transaction fee. */
    std::optional<CMutableTransaction> MergeNotes(
        size_t max_notes,
        CAmount fee)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    // -----------------------------------------------------------------
    // CValidationInterface callbacks
    // -----------------------------------------------------------------

    void BlockConnected(ChainstateRole role,
                        const std::shared_ptr<const CBlock>& block,
                        const CBlockIndex* pindex) override;

    void BlockDisconnected(const std::shared_ptr<const CBlock>& block,
                           const CBlockIndex* pindex) override;

    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx,
                                   uint64_t mempool_sequence) override;

    // -----------------------------------------------------------------
    // Lock
    // -----------------------------------------------------------------

    /** Shielded wallet lock.  Separate from CWallet::cs_wallet to avoid
     *  contention between transparent and shielded operations.
     *  LOCK ORDERING: cs_wallet must be acquired BEFORE cs_shielded if both
     *  are needed.  cs_shielded must NEVER be held while acquiring cs_main. */
    mutable RecursiveMutex cs_shielded;

private:
    //! Reference to parent wallet (for transparent UTXO access, master seed).
    CWallet& m_parent_wallet;

    //! Reference to the global commitment tree (read-only from wallet's POV).
    const shielded::ShieldedMerkleTree* m_global_tree;

    //! All shielded key sets, indexed by address.
    std::map<ShieldedAddress, ShieldedKeySet> m_key_sets
        GUARDED_BY(cs_shielded);

    //! Map from nullifier to ShieldedCoin for all owned notes.
    std::map<uint256, ShieldedCoin> m_notes
        GUARDED_BY(cs_shielded);

    //! Set of nullifiers that have been spent (confirmed on-chain).
    std::set<uint256> m_spent_nullifiers
        GUARDED_BY(cs_shielded);

    //! Per-note Merkle witnesses, keyed by note commitment.
    std::map<uint256, shielded::ShieldedMerkleWitness> m_witnesses
        GUARDED_BY(cs_shielded);

    //! Next derivation index for key generation.
    uint32_t m_next_spending_index GUARDED_BY(cs_shielded) {0};
    uint32_t m_next_kem_index GUARDED_BY(cs_shielded) {0};

    //! Last scanned block height.
    int m_last_scanned_height GUARDED_BY(cs_shielded) {-1};

    //! Last scanned block hash.
    uint256 m_last_scanned_hash GUARDED_BY(cs_shielded);

    //! Pending mempool notes (not yet confirmed).
    std::map<uint256, ShieldedCoin> m_mempool_notes
        GUARDED_BY(cs_shielded);

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /** Try to decrypt a single encrypted note with all our KEM keys.
     *  Returns the decrypted note and matching key set on success. */
    std::optional<std::pair<ShieldedNote, const ShieldedKeySet*>>
    TryDecryptNote(const NoteEncryption::EncryptedNote& enc_note) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Update all witnesses for an appended commitment. */
    void UpdateWitnesses(const uint256& new_commitment)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Prune witnesses for spent notes. */
    void PruneSpentWitnesses()
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Select notes for spending using BnB or knapsack. */
    std::vector<ShieldedCoin> SelectNotes(CAmount target, CAmount fee) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Get the wallet's master seed bytes (unlocks from parent). */
    std::vector<unsigned char> GetMasterSeed() const;

    /** Get current chain tip height from parent wallet. */
    int GetChainTipHeight() const;
};

} // namespace wallet

#endif // BITCOIN_WALLET_SHIELDED_WALLET_H
```

### 1.2 `src/wallet/shielded_wallet.cpp`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/shielded_wallet.h>

#include <bech32.h>
#include <crypto/hkdf_sha256_32.h>
#include <crypto/ml_kem.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key_io.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <shielded/bundle.h>
#include <shielded/merkle_tree.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <util/strencodings.h>
#include <wallet/pq_keyderivation.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <cassert>

namespace wallet {

// =========================================================================
// ShieldedAddress encode/decode  (see Section 6 for full specification)
// =========================================================================

static constexpr const char* SHIELDED_HRP = "btxs";

std::string ShieldedAddress::Encode() const
{
    // Payload: version_byte(1) || algo_byte(1) || pk_hash(32) || kem_pk_hash(32) = 66 bytes
    std::vector<unsigned char> payload;
    payload.reserve(66);
    payload.push_back(version);
    payload.push_back(algo_byte);
    payload.insert(payload.end(), pk_hash.begin(), pk_hash.end());
    payload.insert(payload.end(), kem_pk_hash.begin(), kem_pk_hash.end());

    // Convert 8-bit groups to 5-bit groups for Bech32m
    std::vector<uint8_t> data;
    data.reserve(1 + (payload.size() * 8 + 4) / 5);
    ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); },
                            payload.begin(), payload.end());
    return bech32::Encode(bech32::Encoding::BECH32M, SHIELDED_HRP, data);
}

std::optional<ShieldedAddress> ShieldedAddress::Decode(const std::string& addr)
{
    // Shielded addresses are longer than standard bech32 — use a generous limit.
    // 66 payload bytes * 8/5 = ~106 data chars + hrp(4) + separator(1) + checksum(6) < 120
    auto dec = bech32::Decode(addr, bech32::CharLimit{120});
    if (dec.encoding != bech32::Encoding::BECH32M) return std::nullopt;
    if (dec.hrp != SHIELDED_HRP) return std::nullopt;

    // Convert 5-bit back to 8-bit
    std::vector<unsigned char> payload;
    if (!ConvertBits<5, 8, false>([&](unsigned char c) { payload.push_back(c); },
                                  dec.data.begin(), dec.data.end())) {
        return std::nullopt;
    }

    // Expected payload: version(1) + algo(1) + pk_hash(32) + kem_pk_hash(32) = 66
    if (payload.size() != 66) return std::nullopt;

    ShieldedAddress sa;
    sa.version = payload[0];
    sa.algo_byte = payload[1];
    if (sa.version != 0x00) return std::nullopt;          // Only v0 supported
    if (sa.algo_byte != 0x00) return std::nullopt;        // Only algo 0 (ML-DSA + ML-KEM)
    std::copy(payload.begin() + 2, payload.begin() + 34, sa.pk_hash.begin());
    std::copy(payload.begin() + 34, payload.begin() + 66, sa.kem_pk_hash.begin());
    return sa;
}

bool ShieldedAddress::IsValid() const
{
    return version == 0x00 && algo_byte == 0x00 &&
           !pk_hash.IsNull() && !kem_pk_hash.IsNull();
}

// =========================================================================
// CShieldedWallet — construction / destruction
// =========================================================================

CShieldedWallet::CShieldedWallet(CWallet& parent_wallet,
                                 const shielded::ShieldedMerkleTree* global_tree)
    : m_parent_wallet(parent_wallet),
      m_global_tree(global_tree)
{
}

CShieldedWallet::~CShieldedWallet() = default;

// =========================================================================
// Key management
// =========================================================================

ShieldedAddress CShieldedWallet::GenerateNewAddress(uint32_t account)
{
    AssertLockHeld(cs_shielded);

    // Obtain master seed from the parent wallet.
    std::vector<unsigned char> master_seed = GetMasterSeed();
    if (master_seed.empty()) {
        throw std::runtime_error("CShieldedWallet::GenerateNewAddress: no master seed available");
    }

    // Determine coin_type: mainnet = 0, testnet = 1 (matches BIP44 convention).
    const uint32_t coin_type = m_parent_wallet.chain().getParams().IsTestChain() ? 1 : 0;

    // Derive spending key at m/87h/coin_type/account/0/index
    uint32_t spending_index = m_next_spending_index;
    auto spending_key_opt = DerivePQKeyFromBIP39(
        master_seed, PQAlgorithm::ML_DSA_44,
        coin_type, account, /*change=*/0, spending_index);
    if (!spending_key_opt) {
        throw std::runtime_error("CShieldedWallet::GenerateNewAddress: spending key derivation failed");
    }

    // Derive KEM key at m/88h/coin_type/account/0/index
    uint32_t kem_index = m_next_kem_index;
    auto kem_seed = DeriveMLKEMSeedFromBIP39(
        master_seed, coin_type, account, /*change=*/0, kem_index);
    MLKEMKeyPair kem_key = MLKEMKeyGen(kem_seed);

    // Compute public key hashes
    uint256 spending_pk_hash;
    {
        auto pk_data = spending_key_opt->GetPubKey();
        CSHA256().Write(pk_data.data(), pk_data.size()).Finalize(spending_pk_hash.begin());
    }
    uint256 kem_pk_hash;
    {
        CSHA256().Write(kem_key.public_key.data(), kem_key.public_key.size())
            .Finalize(kem_pk_hash.begin());
    }

    // Build the key set
    ShieldedKeySet keyset;
    keyset.spending_key = std::move(*spending_key_opt);
    keyset.kem_key = std::move(kem_key);
    keyset.spending_pk_hash = spending_pk_hash;
    keyset.kem_pk_hash = kem_pk_hash;
    keyset.account = account;
    keyset.index = spending_index;
    keyset.has_spending_key = true;

    // Build the address
    ShieldedAddress addr;
    addr.version = 0x00;
    addr.algo_byte = 0x00;
    addr.pk_hash = spending_pk_hash;
    addr.kem_pk_hash = kem_pk_hash;

    // Store and advance indices
    m_key_sets[addr] = std::move(keyset);
    m_next_spending_index = spending_index + 1;
    m_next_kem_index = kem_index + 1;

    LogPrintf("CShieldedWallet: generated shielded address index=%u\n", spending_index);
    return addr;
}

bool CShieldedWallet::ImportViewingKey(
    const std::vector<unsigned char>& kem_sk,
    const std::vector<unsigned char>& kem_pk,
    const uint256& spending_pk_hash)
{
    AssertLockHeld(cs_shielded);

    if (kem_sk.size() != MLKEM768_SECRET_KEY_SIZE ||
        kem_pk.size() != MLKEM768_PUBLIC_KEY_SIZE) {
        return false;
    }

    uint256 kem_pk_hash;
    CSHA256().Write(kem_pk.data(), kem_pk.size()).Finalize(kem_pk_hash.begin());

    ShieldedKeySet keyset;
    // No spending key — view-only.
    keyset.has_spending_key = false;
    keyset.spending_pk_hash = spending_pk_hash;
    keyset.kem_pk_hash = kem_pk_hash;
    keyset.kem_key.public_key.assign(kem_pk.begin(), kem_pk.end());
    keyset.kem_key.secret_key.assign(kem_sk.begin(), kem_sk.end());

    ShieldedAddress addr;
    addr.version = 0x00;
    addr.algo_byte = 0x00;
    addr.pk_hash = spending_pk_hash;
    addr.kem_pk_hash = kem_pk_hash;

    m_key_sets[addr] = std::move(keyset);
    LogPrintf("CShieldedWallet: imported viewing key for %s\n", addr.Encode());
    return true;
}

std::optional<std::vector<unsigned char>> CShieldedWallet::ExportViewingKey(
    const ShieldedAddress& addr) const
{
    AssertLockHeld(cs_shielded);
    auto it = m_key_sets.find(addr);
    if (it == m_key_sets.end()) return std::nullopt;
    // The viewing key IS the KEM secret key.
    return std::vector<unsigned char>(it->second.kem_key.secret_key.begin(),
                                     it->second.kem_key.secret_key.end());
}

std::vector<ShieldedAddress> CShieldedWallet::GetAddresses() const
{
    AssertLockHeld(cs_shielded);
    std::vector<ShieldedAddress> result;
    result.reserve(m_key_sets.size());
    for (const auto& [addr, _] : m_key_sets) {
        result.push_back(addr);
    }
    return result;
}

bool CShieldedWallet::HaveSpendingKey(const ShieldedAddress& addr) const
{
    AssertLockHeld(cs_shielded);
    auto it = m_key_sets.find(addr);
    return it != m_key_sets.end() && it->second.has_spending_key;
}

// =========================================================================
// Block scanning
// =========================================================================

void CShieldedWallet::ScanBlock(const CBlock& block, int height)
{
    AssertLockHeld(cs_shielded);

    for (const auto& tx : block.vtx) {
        if (!tx->HasShieldedBundle()) continue;
        const auto& bundle = tx->shielded_bundle;

        // --- Phase 1: Detect outgoing spends (nullifier match) ---
        for (const auto& spend : bundle.spends) {
            auto it = m_notes.find(spend.nullifier);
            if (it != m_notes.end() && !it->second.is_spent) {
                it->second.is_spent = true;
                it->second.spent_height = height;
                m_spent_nullifiers.insert(spend.nullifier);
                LogPrintf("CShieldedWallet: note spent nf=%s height=%d\n",
                          spend.nullifier.GetHex().substr(0, 16), height);
            }
        }

        // --- Phase 2: Detect incoming notes (view tag + decryption) ---
        // This is embarrassingly parallel per output * per key.
        // In a production build with >100 outputs, dispatch to a thread pool.
        for (size_t out_idx = 0; out_idx < bundle.outputs.size(); ++out_idx) {
            const auto& output = bundle.outputs[out_idx];
            auto result = TryDecryptNote(output.enc_note);

            if (result.has_value()) {
                auto& [note, keyset] = *result;
                ShieldedCoin coin;
                coin.note = std::move(note);
                coin.commitment = output.note_commitment;
                coin.nullifier = coin.note.GetNullifier(
                    keyset->spending_key.GetPubKey());
                coin.tree_position = m_global_tree->Size() - bundle.outputs.size() + out_idx;
                coin.confirmation_height = height;
                coin.is_spent = false;
                coin.is_mine_spend = keyset->has_spending_key;
                coin.block_hash = block.GetHash();

                // Create witness for this note
                // The global tree already has this commitment appended by consensus.
                // We reconstruct the witness from the tree state.
                m_witnesses[coin.commitment] = m_global_tree->Witness();

                m_notes[coin.nullifier] = std::move(coin);
                LogPrintf("CShieldedWallet: received shielded note value=%lld height=%d\n",
                          coin.note.value, height);
            }
        }

        // --- Phase 3: Incrementally update all existing witnesses ---
        // Must be done sequentially — each update depends on the tree state
        // AFTER the previous commitment was appended.
        for (const auto& output : bundle.outputs) {
            UpdateWitnesses(output.note_commitment);
        }
    }

    // Prune witnesses for confirmed spent notes (no longer needed).
    PruneSpentWitnesses();

    m_last_scanned_height = height;
    m_last_scanned_hash = block.GetHash();
}

void CShieldedWallet::UndoBlock(const CBlock& block, int height)
{
    AssertLockHeld(cs_shielded);

    // Process transactions in reverse order
    for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
        const auto& tx = *it;
        if (!tx->HasShieldedBundle()) continue;
        const auto& bundle = tx->shielded_bundle;

        // Un-receive: remove notes that were received in this block
        for (const auto& output : bundle.outputs) {
            // Find any note with this commitment and this height
            for (auto note_it = m_notes.begin(); note_it != m_notes.end(); ) {
                if (note_it->second.commitment == output.note_commitment &&
                    note_it->second.confirmation_height == height) {
                    m_witnesses.erase(note_it->second.commitment);
                    note_it = m_notes.erase(note_it);
                } else {
                    ++note_it;
                }
            }
        }

        // Un-spend: mark notes that were spent in this block as unspent
        for (const auto& spend : bundle.spends) {
            auto note_it = m_notes.find(spend.nullifier);
            if (note_it != m_notes.end() && note_it->second.spent_height == height) {
                note_it->second.is_spent = false;
                note_it->second.spent_height = -1;
                m_spent_nullifiers.erase(spend.nullifier);
            }
        }
    }

    if (m_last_scanned_height == height) {
        m_last_scanned_height = height - 1;
    }
}

void CShieldedWallet::Rescan(int start_height)
{
    AssertLockHeld(cs_shielded);
    // Clear all notes and witnesses — rescan from scratch.
    m_notes.clear();
    m_spent_nullifiers.clear();
    m_witnesses.clear();
    m_mempool_notes.clear();
    m_last_scanned_height = start_height - 1;

    // The actual block fetching is orchestrated by the parent wallet's rescan
    // infrastructure, which calls ScanBlock() for each block in sequence.
    LogPrintf("CShieldedWallet: initiating rescan from height %d\n", start_height);
}

// =========================================================================
// Balance and note queries
// =========================================================================

CAmount CShieldedWallet::GetShieldedBalance(int min_depth) const
{
    AssertLockHeld(cs_shielded);
    int tip_height = GetChainTipHeight();
    CAmount balance = 0;
    for (const auto& [nf, coin] : m_notes) {
        if (coin.is_spent) continue;
        int depth = tip_height - coin.confirmation_height + 1;
        if (depth >= min_depth) {
            balance += coin.note.value;
        }
    }
    return balance;
}

std::vector<ShieldedCoin> CShieldedWallet::GetSpendableNotes(int min_depth) const
{
    AssertLockHeld(cs_shielded);
    int tip_height = GetChainTipHeight();
    std::vector<ShieldedCoin> result;
    for (const auto& [nf, coin] : m_notes) {
        if (coin.is_spent) continue;
        if (!coin.is_mine_spend) continue;  // View-only notes not spendable
        int depth = tip_height - coin.confirmation_height + 1;
        if (depth >= min_depth) {
            result.push_back(coin);
        }
    }
    return result;
}

std::vector<ShieldedCoin> CShieldedWallet::GetUnspentNotes(int min_depth) const
{
    AssertLockHeld(cs_shielded);
    int tip_height = GetChainTipHeight();
    std::vector<ShieldedCoin> result;
    for (const auto& [nf, coin] : m_notes) {
        if (coin.is_spent) continue;
        int depth = tip_height - coin.confirmation_height + 1;
        if (depth >= min_depth) {
            result.push_back(coin);
        }
    }
    return result;
}

// =========================================================================
// Transaction creation
// =========================================================================

std::optional<CMutableTransaction> CShieldedWallet::CreateShieldedSpend(
    const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
    const std::vector<std::pair<CTxDestination, CAmount>>& transparent_recipients,
    CAmount fee)
{
    AssertLockHeld(cs_shielded);

    // 1. Calculate total output value
    CAmount total_shielded_out = 0;
    for (const auto& [addr, amount] : shielded_recipients) {
        if (amount <= 0) return std::nullopt;
        total_shielded_out += amount;
    }
    CAmount total_transparent_out = 0;
    for (const auto& [dest, amount] : transparent_recipients) {
        if (amount <= 0) return std::nullopt;
        total_transparent_out += amount;
    }
    CAmount total_needed = total_shielded_out + total_transparent_out + fee;

    // 2. Select notes (coin selection)
    auto selected = SelectNotes(total_needed, fee);
    if (selected.empty()) {
        LogPrintf("CShieldedWallet::CreateShieldedSpend: insufficient shielded funds\n");
        return std::nullopt;
    }
    CAmount total_input = 0;
    for (const auto& coin : selected) {
        total_input += coin.note.value;
    }

    // 3. Calculate change
    CAmount change = total_input - total_needed;
    assert(change >= 0);

    // 4. Build the shielded bundle
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    CShieldedBundle bundle;

    // 4a. Build spends
    for (const auto& coin : selected) {
        CShieldedSpend spend;
        spend.nullifier = coin.nullifier;
        spend.anchor = m_global_tree->Root();

        // Look up the witness for this note
        auto wit_it = m_witnesses.find(coin.commitment);
        if (wit_it == m_witnesses.end()) {
            LogPrintf("CShieldedWallet::CreateShieldedSpend: missing witness\n");
            return std::nullopt;
        }

        // Ring member selection: pick RING_SIZE-1 decoys from the commitment tree
        // The real note's position is included at a random index.
        spend.ring_positions = SelectRingMembers(coin.tree_position, RING_SIZE);

        // Sign with spending key
        // Find the key set that owns this note
        const ShieldedKeySet* keyset = nullptr;
        for (const auto& [addr, ks] : m_key_sets) {
            if (ks.spending_pk_hash == coin.note.recipient_pk_hash) {
                keyset = &ks;
                break;
            }
        }
        if (!keyset || !keyset->has_spending_key) {
            LogPrintf("CShieldedWallet::CreateShieldedSpend: no spending key\n");
            return std::nullopt;
        }

        // Compute spend authorization signature over the transaction sighash
        uint256 sighash; // Filled after bundle is assembled
        spend.spend_auth_algo = keyset->spending_key.GetAlgorithm();
        // Signature is deferred until after proof generation (see below)

        bundle.spends.push_back(std::move(spend));
    }

    // 4b. Build shielded outputs
    for (const auto& [addr, amount] : shielded_recipients) {
        CShieldedOutput output;
        ShieldedNote note;
        note.value = amount;
        note.recipient_pk_hash = addr.pk_hash;
        note.rho = GetRandHash();  // Fresh random nonce
        note.rcm = GetRandHash();  // Fresh commitment randomness

        output.note_commitment = note.GetCommitment();

        // Look up the full KEM public key for the recipient
        // (In a real implementation, the sender needs the full KEM pk,
        //  which is transmitted out-of-band or resolved from the address book.)
        auto kem_pk = ResolveKEMPublicKey(addr);
        output.enc_note = NoteEncryption::Encrypt(note, kem_pk);

        bundle.outputs.push_back(std::move(output));
    }

    // 4c. Add change output (ALWAYS use a fresh shielded note for change)
    if (change > 0) {
        // Generate a fresh address for change to avoid linkability
        ShieldedAddress change_addr = GenerateNewAddress();
        CShieldedOutput change_output;
        ShieldedNote change_note;
        change_note.value = change;
        change_note.recipient_pk_hash = change_addr.pk_hash;
        change_note.rho = GetRandHash();
        change_note.rcm = GetRandHash();

        change_output.note_commitment = change_note.GetCommitment();
        auto change_kem_pk = ResolveKEMPublicKey(change_addr);
        change_output.enc_note = NoteEncryption::Encrypt(change_note, change_kem_pk);

        bundle.outputs.push_back(std::move(change_output));
    }

    // 4d. Build transparent outputs (for unshielding)
    for (const auto& [dest, amount] : transparent_recipients) {
        CTxOut txout;
        txout.nValue = amount;
        txout.scriptPubKey = GetScriptForDestination(dest);
        mtx.vout.push_back(std::move(txout));
    }

    // 4e. Set value_balance = net flow from shielded to transparent
    // Positive value_balance means value flows OUT of the shielded pool.
    bundle.value_balance = total_transparent_out;

    // 5. Generate MatRiCT+ proof covering all spends and outputs
    // This proves: sum(inputs) = sum(outputs) + fee + value_balance
    // AND that all input values are non-negative (range proof).
    bundle.proof = GenerateMatRiCTProof(selected, bundle.spends,
                                        bundle.outputs, fee,
                                        bundle.value_balance);

    // 6. Sign spend authorizations
    mtx.shielded_bundle = std::move(bundle);
    uint256 sighash = ComputeShieldedSighash(mtx);
    for (size_t i = 0; i < mtx.shielded_bundle.spends.size(); ++i) {
        auto& spend = mtx.shielded_bundle.spends[i];
        const ShieldedKeySet* keyset = nullptr;
        for (const auto& [addr, ks] : m_key_sets) {
            if (ks.spending_pk_hash == selected[i].note.recipient_pk_hash) {
                keyset = &ks;
                break;
            }
        }
        std::vector<unsigned char> sig;
        if (!keyset->spending_key.Sign(sighash, sig)) {
            return std::nullopt;
        }
        spend.spend_auth_sig = std::move(sig);
    }

    return mtx;
}

std::optional<CMutableTransaction> CShieldedWallet::ShieldFunds(
    const std::vector<COutPoint>& utxos,
    CAmount fee,
    std::optional<ShieldedAddress> dest)
{
    AssertLockHeld(cs_shielded);

    // If no destination specified, shield to our own first address,
    // or generate a new one.
    ShieldedAddress shield_dest;
    if (dest.has_value()) {
        shield_dest = *dest;
    } else {
        auto addrs = GetAddresses();
        if (addrs.empty()) {
            shield_dest = GenerateNewAddress();
        } else {
            // Use a fresh address for privacy.
            shield_dest = GenerateNewAddress();
        }
    }

    // Build a transaction with transparent inputs and one shielded output.
    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;

    // Add transparent inputs
    CAmount total_in = 0;
    {
        LOCK(m_parent_wallet.cs_wallet);
        for (const auto& outpoint : utxos) {
            const CWalletTx* wtx = m_parent_wallet.GetWalletTx(outpoint.hash);
            if (!wtx) return std::nullopt;
            total_in += wtx->tx->vout[outpoint.n].nValue;
            mtx.vin.emplace_back(outpoint);
        }
    }

    CAmount shield_amount = total_in - fee;
    if (shield_amount <= 0) return std::nullopt;

    // Build shielded output
    CShieldedBundle bundle;
    CShieldedOutput output;
    ShieldedNote note;
    note.value = shield_amount;
    note.recipient_pk_hash = shield_dest.pk_hash;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();
    output.note_commitment = note.GetCommitment();

    auto kem_pk = ResolveKEMPublicKey(shield_dest);
    output.enc_note = NoteEncryption::Encrypt(note, kem_pk);
    bundle.outputs.push_back(std::move(output));

    // value_balance is negative: value flows INTO the shielded pool
    bundle.value_balance = -shield_amount;

    // Proof covers: transparent inputs fund the shielded output
    bundle.proof = GenerateMatRiCTProof({}, {}, bundle.outputs, fee, bundle.value_balance);

    mtx.shielded_bundle = std::move(bundle);

    // Sign transparent inputs via parent wallet
    {
        LOCK(m_parent_wallet.cs_wallet);
        if (!m_parent_wallet.SignTransaction(mtx)) {
            return std::nullopt;
        }
    }

    return mtx;
}

std::optional<CMutableTransaction> CShieldedWallet::UnshieldFunds(
    CAmount amount,
    const CTxDestination& destination,
    CAmount fee)
{
    AssertLockHeld(cs_shielded);

    // Use CreateShieldedSpend with a transparent recipient
    return CreateShieldedSpend(
        /*shielded_recipients=*/{},
        /*transparent_recipients=*/{{destination, amount}},
        fee);
}

std::optional<CMutableTransaction> CShieldedWallet::MergeNotes(
    size_t max_notes,
    CAmount fee)
{
    AssertLockHeld(cs_shielded);

    auto spendable = GetSpendableNotes(/*min_depth=*/1);
    if (spendable.size() <= 1) return std::nullopt;

    // Sort by value ascending — merge the smallest notes first
    std::sort(spendable.begin(), spendable.end(),
              [](const ShieldedCoin& a, const ShieldedCoin& b) {
                  return a.note.value < b.note.value;
              });

    size_t merge_count = std::min(max_notes, spendable.size());
    CAmount total = 0;
    std::vector<ShieldedCoin> to_merge;
    for (size_t i = 0; i < merge_count; ++i) {
        to_merge.push_back(spendable[i]);
        total += spendable[i].note.value;
    }

    CAmount merged_value = total - fee;
    if (merged_value <= 0) return std::nullopt;

    // Send the merged value back to ourselves
    ShieldedAddress self_addr = GenerateNewAddress();
    return CreateShieldedSpend(
        /*shielded_recipients=*/{{self_addr, merged_value}},
        /*transparent_recipients=*/{},
        fee);
}

// =========================================================================
// CValidationInterface callbacks
// =========================================================================

void CShieldedWallet::BlockConnected(
    ChainstateRole role,
    const std::shared_ptr<const CBlock>& block,
    const CBlockIndex* pindex)
{
    // Only process active chainstate blocks.
    if (role == ChainstateRole::BACKGROUND) return;

    LOCK(cs_shielded);
    ScanBlock(*block, pindex->nHeight);
}

void CShieldedWallet::BlockDisconnected(
    const std::shared_ptr<const CBlock>& block,
    const CBlockIndex* pindex)
{
    LOCK(cs_shielded);
    UndoBlock(*block, pindex->nHeight);
}

void CShieldedWallet::TransactionAddedToMempool(
    const NewMempoolTransactionInfo& tx_info,
    uint64_t mempool_sequence)
{
    LOCK(cs_shielded);
    const auto& tx = tx_info.info.m_tx;
    if (!tx->HasShieldedBundle()) return;

    // Attempt to decrypt mempool notes (for immediate UI feedback).
    const auto& bundle = tx->shielded_bundle;
    for (const auto& output : bundle.outputs) {
        auto result = TryDecryptNote(output.enc_note);
        if (result.has_value()) {
            auto& [note, keyset] = *result;
            ShieldedCoin coin;
            coin.note = std::move(note);
            coin.commitment = output.note_commitment;
            coin.nullifier = coin.note.GetNullifier(keyset->spending_key.GetPubKey());
            coin.confirmation_height = -1;  // Unconfirmed
            coin.is_spent = false;
            coin.is_mine_spend = keyset->has_spending_key;
            m_mempool_notes[coin.nullifier] = std::move(coin);
        }
    }
}

// =========================================================================
// Internal helpers
// =========================================================================

std::optional<std::pair<ShieldedNote, const ShieldedKeySet*>>
CShieldedWallet::TryDecryptNote(const NoteEncryption::EncryptedNote& enc_note) const
{
    AssertLockHeld(cs_shielded);
    for (const auto& [addr, keyset] : m_key_sets) {
        // View tag pre-filter: ~10ns, rejects 255/256 non-matching notes
        auto note = NoteEncryption::TryDecrypt(
            enc_note,
            keyset.kem_key.public_key,
            keyset.kem_key.secret_key);

        if (note.has_value()) {
            return std::make_pair(std::move(*note), &keyset);
        }
    }
    return std::nullopt;
}

void CShieldedWallet::UpdateWitnesses(const uint256& new_commitment)
{
    AssertLockHeld(cs_shielded);
    for (auto& [cm, witness] : m_witnesses) {
        witness.IncrementalUpdate(*m_global_tree);
    }
}

void CShieldedWallet::PruneSpentWitnesses()
{
    AssertLockHeld(cs_shielded);
    for (auto it = m_witnesses.begin(); it != m_witnesses.end(); ) {
        // Check if the note with this commitment is spent
        bool is_spent = false;
        for (const auto& [nf, coin] : m_notes) {
            if (coin.commitment == it->first && coin.is_spent) {
                is_spent = true;
                break;
            }
        }
        if (is_spent) {
            it = m_witnesses.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<ShieldedCoin> CShieldedWallet::SelectNotes(
    CAmount target, CAmount fee) const
{
    AssertLockHeld(cs_shielded);
    // Delegate to shielded coin selection (see shielded_coins.cpp).
    auto spendable = GetSpendableNotes(/*min_depth=*/1);
    return ShieldedCoinSelection(spendable, target, fee);
}

std::vector<unsigned char> CShieldedWallet::GetMasterSeed() const
{
    LOCK(m_parent_wallet.cs_wallet);
    // Access the wallet's master seed via the existing key derivation infrastructure.
    // The exact mechanism depends on whether it's a descriptor wallet (HD seed)
    // or legacy wallet.  We extract the raw seed bytes.
    auto spk_man = m_parent_wallet.GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false);
    if (!spk_man) return {};
    // In descriptor wallet, the HD seed is accessible through the key provider.
    CExtKey master_key;
    if (!spk_man->GetMasterExtKey(master_key)) return {};
    return std::vector<unsigned char>(master_key.key.begin(), master_key.key.end());
}

int CShieldedWallet::GetChainTipHeight() const
{
    LOCK(m_parent_wallet.cs_wallet);
    return m_parent_wallet.GetLastBlockHeight();
}

} // namespace wallet
```

### 1.3 `src/wallet/shielded_coins.h` and `src/wallet/shielded_coins.cpp`

#### `src/wallet/shielded_coins.h`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_SHIELDED_COINS_H
#define BITCOIN_WALLET_SHIELDED_COINS_H

#include <consensus/amount.h>
#include <shielded/note.h>
#include <uint256.h>

#include <vector>

namespace wallet {

/** Size estimate for a single shielded spend input in a transaction.
 *  Nullifier(32) + anchor(32) + ring_positions(16*8=128) +
 *  spend_auth_sig(~2420 for ML-DSA-44) + algo_byte(1) = ~2613 bytes */
static constexpr size_t SHIELDED_SPEND_INPUT_SIZE = 2613;

/** Size estimate for a single shielded output in a transaction.
 *  commitment(32) + encrypted_note(~1181) = ~1213 bytes */
static constexpr size_t SHIELDED_OUTPUT_SIZE = 1213;

/** A wallet's view of a shielded note (spendable UTXO equivalent). */
struct ShieldedCoin
{
    //! The decrypted note (value, recipient, rho, rcm).
    ShieldedNote note;

    //! The note commitment (leaf in the Merkle tree).
    uint256 commitment;

    //! The nullifier (derived from spending key + note).
    uint256 nullifier;

    //! Position of this commitment in the global Merkle tree.
    uint64_t tree_position{0};

    //! Block height at which this note was confirmed (-1 if unconfirmed).
    int confirmation_height{-1};

    //! Block height at which this note was spent (-1 if unspent).
    int spent_height{-1};

    //! Whether this note has been spent.
    bool is_spent{false};

    //! Whether we have the spending key (false = view-only).
    bool is_mine_spend{false};

    //! Block hash where this note was confirmed.
    uint256 block_hash;

    /** Effective value: note value minus estimated spend cost.
     *  Used by coin selection to account for the marginal cost of
     *  including this note as an input. */
    CAmount EffectiveValue(CAmount fee_per_weight) const
    {
        // Each shielded spend adds ~SHIELDED_SPEND_INPUT_SIZE bytes.
        // At witness discount (1/4), weight = SHIELDED_SPEND_INPUT_SIZE.
        CAmount spend_cost = fee_per_weight * SHIELDED_SPEND_INPUT_SIZE;
        return note.value - spend_cost;
    }

    /** Return the number of confirmations given the current tip height. */
    int GetDepth(int tip_height) const
    {
        if (confirmation_height < 0) return 0;
        return tip_height - confirmation_height + 1;
    }
};

// ---------------------------------------------------------------------------
// Coin selection for shielded spends
// ---------------------------------------------------------------------------

/** Branch-and-Bound coin selection adapted for shielded notes.
 *
 *  Attempts exact-match selection (no change output needed) within a
 *  tolerance of `cost_of_change`.  Falls back to knapsack if BnB fails.
 *
 *  @param[in] available     Available notes, must be sorted by EffectiveValue descending.
 *  @param[in] target        Target amount (outputs + fee).
 *  @param[in] fee_per_weight  Fee rate for estimating spend costs.
 *  @return Selected notes, or empty vector on failure. */
std::vector<ShieldedCoin> ShieldedCoinSelection(
    const std::vector<ShieldedCoin>& available,
    CAmount target,
    CAmount fee_per_weight);

/** Knapsack solver fallback.  Selects notes that exceed the target by the
 *  smallest margin. */
std::vector<ShieldedCoin> ShieldedKnapsackSolver(
    const std::vector<ShieldedCoin>& available,
    CAmount target);

/** Identify notes that should be consolidated.
 *  Returns notes whose individual value is below `dust_threshold`. */
std::vector<ShieldedCoin> GetDustNotes(
    const std::vector<ShieldedCoin>& notes,
    CAmount dust_threshold);

} // namespace wallet

#endif // BITCOIN_WALLET_SHIELDED_COINS_H
```

#### `src/wallet/shielded_coins.cpp`

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/shielded_coins.h>

#include <algorithm>
#include <numeric>
#include <random.h>

namespace wallet {

// ---------------------------------------------------------------------------
// Branch-and-Bound (BnB) for shielded notes
// ---------------------------------------------------------------------------

/** Maximum number of BnB iterations before giving up. */
static constexpr int BNB_MAX_ITERATIONS = 100000;

/** Cost of adding a change output (shielded output size * fee rate).
 *  Used as the BnB tolerance window. */
static CAmount CostOfChange(CAmount fee_per_weight)
{
    return fee_per_weight * SHIELDED_OUTPUT_SIZE;
}

namespace {

bool BnBSearch(const std::vector<ShieldedCoin>& available,
               CAmount target,
               CAmount cost_of_change,
               std::vector<bool>& selection,
               CAmount current_value,
               size_t depth,
               int& iterations)
{
    if (current_value > target + cost_of_change) return false;
    if (current_value >= target) return true;
    if (++iterations > BNB_MAX_ITERATIONS) return false;
    if (depth >= available.size()) return false;

    // Try including this note
    selection[depth] = true;
    if (BnBSearch(available, target, cost_of_change, selection,
                  current_value + available[depth].note.value,
                  depth + 1, iterations)) {
        return true;
    }

    // Try excluding this note
    selection[depth] = false;
    if (BnBSearch(available, target, cost_of_change, selection,
                  current_value, depth + 1, iterations)) {
        return true;
    }

    return false;
}

} // namespace

std::vector<ShieldedCoin> ShieldedCoinSelection(
    const std::vector<ShieldedCoin>& available,
    CAmount target,
    CAmount fee_per_weight)
{
    if (available.empty() || target <= 0) return {};

    // Sort by effective value descending (largest first for BnB efficiency)
    std::vector<ShieldedCoin> sorted = available;
    std::sort(sorted.begin(), sorted.end(),
              [fee_per_weight](const ShieldedCoin& a, const ShieldedCoin& b) {
                  return a.EffectiveValue(fee_per_weight) > b.EffectiveValue(fee_per_weight);
              });

    // Remove notes with non-positive effective value
    sorted.erase(
        std::remove_if(sorted.begin(), sorted.end(),
                       [fee_per_weight](const ShieldedCoin& c) {
                           return c.EffectiveValue(fee_per_weight) <= 0;
                       }),
        sorted.end());

    // Check if total available is sufficient
    CAmount total_available = std::accumulate(sorted.begin(), sorted.end(), CAmount{0},
        [](CAmount sum, const ShieldedCoin& c) { return sum + c.note.value; });
    if (total_available < target) return {};

    // Try BnB first (exact match, no change needed)
    CAmount change_cost = CostOfChange(fee_per_weight);
    std::vector<bool> selection(sorted.size(), false);
    int iterations = 0;

    if (BnBSearch(sorted, target, change_cost, selection, 0, 0, iterations)) {
        std::vector<ShieldedCoin> result;
        for (size_t i = 0; i < sorted.size(); ++i) {
            if (selection[i]) {
                result.push_back(sorted[i]);
            }
        }
        return result;
    }

    // Fall back to knapsack
    return ShieldedKnapsackSolver(sorted, target);
}

std::vector<ShieldedCoin> ShieldedKnapsackSolver(
    const std::vector<ShieldedCoin>& available,
    CAmount target)
{
    // Simple greedy: pick largest notes until target is met.
    // This is suboptimal but reliable.
    std::vector<ShieldedCoin> result;
    CAmount running = 0;

    for (const auto& coin : available) {
        if (running >= target) break;
        result.push_back(coin);
        running += coin.note.value;
    }

    if (running < target) return {};  // Insufficient funds

    // Try to find a single note that exactly covers the target
    // (avoids unnecessary change)
    for (const auto& coin : available) {
        if (coin.note.value >= target && coin.note.value < running) {
            return {coin};
        }
    }

    return result;
}

std::vector<ShieldedCoin> GetDustNotes(
    const std::vector<ShieldedCoin>& notes,
    CAmount dust_threshold)
{
    std::vector<ShieldedCoin> dust;
    for (const auto& coin : notes) {
        if (!coin.is_spent && coin.note.value < dust_threshold) {
            dust.push_back(coin);
        }
    }
    return dust;
}

} // namespace wallet
```

### 1.4 `src/wallet/pq_keyderivation.h` additions

```cpp
// === Additions to src/wallet/pq_keyderivation.h ===
// Add after the existing DerivePQKeyFromBIP39 declaration:

#include <crypto/ml_kem.h>

namespace wallet {

/** Derive a deterministic 32-byte seed for ML-KEM key generation from a
 *  wallet master seed.
 *
 *  Path semantics: m/88h/coin_type/account/change/index
 *
 *  The path uses purpose 88h (distinct from 87h used by spending keys)
 *  to ensure domain separation between ML-DSA and ML-KEM key material.
 *
 *  HKDF parameters:
 *    IKM  = master_seed
 *    Salt = "BTX-MLKEM-BIP88-HKDF-V1"
 *    Info = "m/88h" || BE32(88|0x80000000) || BE32(coin_type|0x80000000)
 *           || BE32(account|0x80000000) || BE32(change) || BE32(index)
 *           || byte(0x02)     // algorithm identifier: ML-KEM-768
 *
 *  The algorithm byte (0x02) in the Info string ensures that if the same
 *  path were ever reused for a different algorithm, the derived keys would
 *  be completely independent.  This prevents cross-algorithm key reuse. */
std::array<unsigned char, 32> DeriveMLKEMSeedFromBIP39(
    Span<const unsigned char> master_seed,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index);

/** Derive a deterministic ML-KEM-768 keypair from a wallet master seed.
 *  Internally calls DeriveMLKEMSeedFromBIP39() then MLKEMKeyGen(). */
MLKEMKeyPair DeriveMLKEMKeyFromBIP39(
    Span<const unsigned char> master_seed,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index);

} // namespace wallet
```

#### Implementation in `src/wallet/pq_keyderivation.cpp`

```cpp
// === Additions to src/wallet/pq_keyderivation.cpp ===
// Add at the end of the file, before the closing namespace brace:

namespace {
constexpr const char* MLKEM_DERIVATION_SALT = "BTX-MLKEM-BIP88-HKDF-V1";
constexpr const char* MLKEM_DERIVATION_INFO_TAG = "m/88h";
constexpr uint8_t MLKEM_ALGORITHM_BYTE = 0x02;  // ML-KEM-768
} // namespace

std::array<unsigned char, 32> DeriveMLKEMSeedFromBIP39(
    Span<const unsigned char> master_seed,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index)
{
    std::array<unsigned char, 32> seed{};
    if (master_seed.empty()) return seed;

    CHKDF_HMAC_SHA256_L32 hkdf(master_seed.data(), master_seed.size(),
                                MLKEM_DERIVATION_SALT);

    std::string info{MLKEM_DERIVATION_INFO_TAG};
    info.reserve(info.size() + (5 * sizeof(uint32_t)) + sizeof(uint8_t));

    AppendBE32(info, 88U | BIP32_HARDENED_FLAG);
    AppendBE32(info, coin_type | BIP32_HARDENED_FLAG);
    AppendBE32(info, account | BIP32_HARDENED_FLAG);
    AppendBE32(info, change);
    AppendBE32(info, index);
    info.push_back(static_cast<char>(MLKEM_ALGORITHM_BYTE));

    hkdf.Expand32(info, seed.data());
    return seed;
}

MLKEMKeyPair DeriveMLKEMKeyFromBIP39(
    Span<const unsigned char> master_seed,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index)
{
    const auto seed = DeriveMLKEMSeedFromBIP39(
        master_seed, coin_type, account, change, index);
    return MLKEMKeyGen(seed);
}
```

### 1.5 `src/wallet/shielded_rpc.cpp` — Full RPC Command Implementations

```cpp
// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <core_io.h>
#include <key_io.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <wallet/rpc/util.h>
#include <wallet/shielded_wallet.h>
#include <wallet/wallet.h>

namespace wallet {

// =========================================================================
// Helper: get CShieldedWallet from request
// =========================================================================

static CShieldedWallet& EnsureShieldedWallet(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }
    if (!pwallet->m_shielded_wallet) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            "Shielded wallet not initialized. Enable with -shielded=1");
    }
    return *pwallet->m_shielded_wallet;
}

static std::shared_ptr<CWallet> EnsureWalletForShielded(const JSONRPCRequest& request)
{
    auto pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet not found");
    }
    if (!pwallet->m_shielded_wallet) {
        throw JSONRPCError(RPC_WALLET_ERROR,
            "Shielded wallet not initialized. Enable with -shielded=1");
    }
    return pwallet;
}

// =========================================================================
// z_getnewaddress
// =========================================================================

RPCHelpMan z_getnewaddress()
{
    return RPCHelpMan{"z_getnewaddress",
        "\nReturns a new shielded (z-address) for receiving private payments.\n"
        "Generates a fresh ML-DSA-44 spending key (m/87h/...) and ML-KEM-768\n"
        "KEM key (m/88h/...) deterministically from the wallet's master seed.\n",
        {
            {"account", RPCArg::Type::NUM, RPCArg::Default{0},
             "The account number for key derivation (BIP44-style)."},
        },
        RPCResult{
            RPCResult::Type::STR, "address",
            "The new shielded address (btxs1... Bech32m encoded)"
        },
        RPCExamples{
            HelpExampleCli("z_getnewaddress", "")
            + HelpExampleCli("z_getnewaddress", "1")
            + HelpExampleRpc("z_getnewaddress", "")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pwallet = EnsureWalletForShielded(request);
        EnsureWalletIsUnlocked(*pwallet);

        uint32_t account = 0;
        if (!request.params[0].isNull()) {
            account = request.params[0].getInt<uint32_t>();
        }

        LOCK(pwallet->m_shielded_wallet->cs_shielded);
        ShieldedAddress addr = pwallet->m_shielded_wallet->GenerateNewAddress(account);
        return addr.Encode();
    },
    };
}

// =========================================================================
// z_getbalance
// =========================================================================

RPCHelpMan z_getbalance()
{
    return RPCHelpMan{"z_getbalance",
        "\nReturns the confirmed shielded balance of the wallet.\n"
        "Only includes notes with at least minconf confirmations.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1},
             "Minimum number of confirmations for notes to be counted."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_AMOUNT, "balance", "Total confirmed shielded balance"},
                {RPCResult::Type::NUM, "note_count", "Number of unspent shielded notes"},
                RESULT_LAST_PROCESSED_BLOCK,
            }
        },
        RPCExamples{
            HelpExampleCli("z_getbalance", "")
            + HelpExampleCli("z_getbalance", "6")
            + HelpExampleRpc("z_getbalance", "1")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pwallet = EnsureWalletForShielded(request);

        int min_depth = 1;
        if (!request.params[0].isNull()) {
            min_depth = request.params[0].getInt<int>();
        }

        UniValue result(UniValue::VOBJ);
        {
            LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
            CAmount balance = pwallet->m_shielded_wallet->GetShieldedBalance(min_depth);
            auto notes = pwallet->m_shielded_wallet->GetUnspentNotes(min_depth);
            result.pushKV("balance", ValueFromAmount(balance));
            result.pushKV("note_count", (int64_t)notes.size());
            AppendLastProcessedBlock(result, *pwallet);
        }
        return result;
    },
    };
}

// =========================================================================
// z_listunspent
// =========================================================================

RPCHelpMan z_listunspent()
{
    return RPCHelpMan{"z_listunspent",
        "\nReturns a list of unspent shielded notes with their amounts\n"
        "and confirmation counts.\n",
        {
            {"minconf", RPCArg::Type::NUM, RPCArg::Default{1},
             "Minimum confirmations to filter."},
            {"maxconf", RPCArg::Type::NUM, RPCArg::Default{9999999},
             "Maximum confirmations to filter."},
            {"include_watchonly", RPCArg::Type::BOOL, RPCArg::Default{false},
             "Include notes from view-only imported keys."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "nullifier", "The note's nullifier"},
                        {RPCResult::Type::STR_HEX, "commitment", "The note commitment"},
                        {RPCResult::Type::STR_AMOUNT, "amount", "The note value"},
                        {RPCResult::Type::NUM, "confirmations", "Number of confirmations"},
                        {RPCResult::Type::BOOL, "spendable", "Whether we have the spending key"},
                        {RPCResult::Type::NUM, "tree_position", "Position in commitment tree"},
                        {RPCResult::Type::STR_HEX, "block_hash", "Block containing this note"},
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("z_listunspent", "")
            + HelpExampleCli("z_listunspent", "6 9999999 true")
            + HelpExampleRpc("z_listunspent", "1, 9999999, false")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pwallet = EnsureWalletForShielded(request);

        int min_depth = 1;
        int max_depth = 9999999;
        bool include_watchonly = false;
        if (!request.params[0].isNull()) min_depth = request.params[0].getInt<int>();
        if (!request.params[1].isNull()) max_depth = request.params[1].getInt<int>();
        if (!request.params[2].isNull()) include_watchonly = request.params[2].get_bool();

        UniValue results(UniValue::VARR);
        {
            LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);
            int tip_height = pwallet->GetLastBlockHeight();
            auto notes = pwallet->m_shielded_wallet->GetUnspentNotes(0);

            for (const auto& coin : notes) {
                int depth = coin.GetDepth(tip_height);
                if (depth < min_depth || depth > max_depth) continue;
                if (!include_watchonly && !coin.is_mine_spend) continue;

                UniValue entry(UniValue::VOBJ);
                entry.pushKV("nullifier", coin.nullifier.GetHex());
                entry.pushKV("commitment", coin.commitment.GetHex());
                entry.pushKV("amount", ValueFromAmount(coin.note.value));
                entry.pushKV("confirmations", depth);
                entry.pushKV("spendable", coin.is_mine_spend);
                entry.pushKV("tree_position", (int64_t)coin.tree_position);
                entry.pushKV("block_hash", coin.block_hash.GetHex());
                results.push_back(std::move(entry));
            }
        }
        return results;
    },
    };
}

// =========================================================================
// z_sendmany
// =========================================================================

RPCHelpMan z_sendmany()
{
    return RPCHelpMan{"z_sendmany",
        "\nSend from the shielded pool to one or more shielded or transparent\n"
        "recipients. Uses coin selection to pick notes, generates MatRiCT+\n"
        "proof, and signs with ML-DSA spend authorization.\n",
        {
            {"amounts", RPCArg::Type::ARR, RPCArg::Optional::NO,
             "A JSON array of recipient objects",
                {
                    {"", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "",
                        {
                            {"address", RPCArg::Type::STR, RPCArg::Optional::NO,
                             "Shielded (btxs1...) or transparent (btx1...) address"},
                            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO,
                             "Amount in BTX"},
                        },
                    },
                },
            },
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)},
             "Transaction fee in BTX (default: 0.0001 BTX)"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction ID"},
                {RPCResult::Type::NUM, "spends", "Number of shielded spends"},
                {RPCResult::Type::NUM, "outputs", "Number of shielded outputs"},
                {RPCResult::Type::STR_AMOUNT, "fee", "Transaction fee paid"},
            }
        },
        RPCExamples{
            HelpExampleCli("z_sendmany",
                "'[{\"address\":\"btxs1...\",\"amount\":1.0}]'")
            + HelpExampleCli("z_sendmany",
                "'[{\"address\":\"btxs1...\",\"amount\":0.5},"
                "{\"address\":\"btx1...\",\"amount\":0.3}]' 0.0001")
            + HelpExampleRpc("z_sendmany",
                "\"[{\\\"address\\\":\\\"btxs1...\\\",\\\"amount\\\":1.0}]\", 0.0001")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pwallet = EnsureWalletForShielded(request);
        EnsureWalletIsUnlocked(*pwallet);

        // Parse recipients
        const UniValue& amounts = request.params[0].get_array();
        std::vector<std::pair<ShieldedAddress, CAmount>> shielded_recipients;
        std::vector<std::pair<CTxDestination, CAmount>> transparent_recipients;

        for (size_t i = 0; i < amounts.size(); ++i) {
            const UniValue& recipient = amounts[i];
            const std::string addr_str = recipient["address"].get_str();
            CAmount amount = AmountFromValue(recipient["amount"]);

            // Try as shielded address first
            auto shielded_addr = ShieldedAddress::Decode(addr_str);
            if (shielded_addr.has_value()) {
                shielded_recipients.emplace_back(*shielded_addr, amount);
                continue;
            }

            // Try as transparent address
            CTxDestination dest = DecodeDestination(addr_str);
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                    strprintf("Invalid address: %s", addr_str));
            }
            transparent_recipients.emplace_back(dest, amount);
        }

        if (shielded_recipients.empty() && transparent_recipients.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No recipients specified");
        }

        // Parse fee
        CAmount fee = 10000;  // Default 0.0001 BTX
        if (!request.params[1].isNull()) {
            fee = AmountFromValue(request.params[1]);
        }

        // Create and broadcast transaction
        std::optional<CMutableTransaction> mtx;
        {
            LOCK(pwallet->m_shielded_wallet->cs_shielded);
            mtx = pwallet->m_shielded_wallet->CreateShieldedSpend(
                shielded_recipients, transparent_recipients, fee);
        }

        if (!mtx) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                "Failed to create shielded transaction. "
                "Check balance with z_getbalance.");
        }

        // Commit the transaction
        CTransactionRef tx = MakeTransactionRef(std::move(*mtx));
        pwallet->CommitTransaction(tx, {}, /*orderForm=*/{});

        UniValue result(UniValue::VOBJ);
        result.pushKV("txid", tx->GetHash().GetHex());
        result.pushKV("spends", (int64_t)tx->shielded_bundle.spends.size());
        result.pushKV("outputs", (int64_t)tx->shielded_bundle.outputs.size());
        result.pushKV("fee", ValueFromAmount(fee));
        return result;
    },
    };
}

// =========================================================================
// z_shieldcoinbase
// =========================================================================

RPCHelpMan z_shieldcoinbase()
{
    return RPCHelpMan{"z_shieldcoinbase",
        "\nShield coinbase (mining) rewards to a shielded address.\n"
        "Selects all mature, unspent coinbase outputs and shields them.\n",
        {
            {"destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
             "Shielded destination address (btxs1...). Default: generate new."},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)},
             "Transaction fee in BTX."},
            {"limit", RPCArg::Type::NUM, RPCArg::Default{50},
             "Maximum number of coinbase UTXOs to shield per transaction."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction ID"},
                {RPCResult::Type::STR_AMOUNT, "amount", "Total amount shielded"},
                {RPCResult::Type::NUM, "shielding_inputs", "Number of coinbase UTXOs consumed"},
            }
        },
        RPCExamples{
            HelpExampleCli("z_shieldcoinbase", "")
            + HelpExampleCli("z_shieldcoinbase", "\"btxs1...\" 0.0001 50")
            + HelpExampleRpc("z_shieldcoinbase", "\"btxs1...\", 0.0001, 50")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pwallet = EnsureWalletForShielded(request);
        EnsureWalletIsUnlocked(*pwallet);

        // Parse optional destination
        std::optional<ShieldedAddress> dest;
        if (!request.params[0].isNull()) {
            auto addr = ShieldedAddress::Decode(request.params[0].get_str());
            if (!addr) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");
            }
            dest = *addr;
        }

        CAmount fee = 10000;
        if (!request.params[1].isNull()) {
            fee = AmountFromValue(request.params[1]);
        }

        int limit = 50;
        if (!request.params[2].isNull()) {
            limit = request.params[2].getInt<int>();
            if (limit <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "limit must be positive");
        }

        // Gather mature coinbase UTXOs
        std::vector<COutPoint> coinbase_utxos;
        CAmount total_amount = 0;
        {
            LOCK(pwallet->cs_wallet);
            for (const auto& [txid, wtx] : pwallet->mapWallet) {
                if (!wtx.IsCoinBase()) continue;
                if (pwallet->GetTxBlocksToMaturity(wtx) > 0) continue;
                for (uint32_t n = 0; n < wtx.tx->vout.size(); ++n) {
                    if (pwallet->IsSpent(COutPoint(txid, n))) continue;
                    coinbase_utxos.emplace_back(txid, n);
                    total_amount += wtx.tx->vout[n].nValue;
                    if ((int)coinbase_utxos.size() >= limit) break;
                }
                if ((int)coinbase_utxos.size() >= limit) break;
            }
        }

        if (coinbase_utxos.empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "No mature coinbase UTXOs available");
        }

        std::optional<CMutableTransaction> mtx;
        {
            LOCK(pwallet->m_shielded_wallet->cs_shielded);
            mtx = pwallet->m_shielded_wallet->ShieldFunds(coinbase_utxos, fee, dest);
        }

        if (!mtx) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create shielding transaction");
        }

        CTransactionRef tx = MakeTransactionRef(std::move(*mtx));
        pwallet->CommitTransaction(tx, {}, {});

        UniValue result(UniValue::VOBJ);
        result.pushKV("txid", tx->GetHash().GetHex());
        result.pushKV("amount", ValueFromAmount(total_amount - fee));
        result.pushKV("shielding_inputs", (int64_t)coinbase_utxos.size());
        return result;
    },
    };
}

// =========================================================================
// z_shieldfunds
// =========================================================================

RPCHelpMan z_shieldfunds()
{
    return RPCHelpMan{"z_shieldfunds",
        "\nShield transparent UTXOs into a shielded note.\n"
        "Selects UTXOs using the wallet's transparent coin selection.\n",
        {
            {"amount", RPCArg::Type::AMOUNT, RPCArg::Optional::NO,
             "Amount to shield in BTX."},
            {"destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED,
             "Shielded destination address (btxs1...). Default: generate new."},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)},
             "Transaction fee in BTX."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction ID"},
                {RPCResult::Type::STR_AMOUNT, "amount", "Amount shielded"},
                {RPCResult::Type::NUM, "transparent_inputs", "Number of transparent inputs consumed"},
            }
        },
        RPCExamples{
            HelpExampleCli("z_shieldfunds", "1.0")
            + HelpExampleCli("z_shieldfunds", "1.0 \"btxs1...\"")
            + HelpExampleRpc("z_shieldfunds", "1.0")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pwallet = EnsureWalletForShielded(request);
        EnsureWalletIsUnlocked(*pwallet);

        CAmount amount = AmountFromValue(request.params[0]);
        if (amount <= 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "Amount must be positive");

        std::optional<ShieldedAddress> dest;
        if (!request.params[1].isNull()) {
            auto addr = ShieldedAddress::Decode(request.params[1].get_str());
            if (!addr) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");
            dest = *addr;
        }

        CAmount fee = 10000;
        if (!request.params[2].isNull()) {
            fee = AmountFromValue(request.params[2]);
        }

        // Select transparent UTXOs to cover amount + fee
        std::vector<COutPoint> utxos;
        CAmount total_selected = 0;
        {
            LOCK(pwallet->cs_wallet);
            for (const auto& [txid, wtx] : pwallet->mapWallet) {
                if (wtx.IsCoinBase() && pwallet->GetTxBlocksToMaturity(wtx) > 0) continue;
                for (uint32_t n = 0; n < wtx.tx->vout.size(); ++n) {
                    if (pwallet->IsSpent(COutPoint(txid, n))) continue;
                    utxos.emplace_back(txid, n);
                    total_selected += wtx.tx->vout[n].nValue;
                    if (total_selected >= amount + fee) break;
                }
                if (total_selected >= amount + fee) break;
            }
        }

        if (total_selected < amount + fee) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient transparent funds");
        }

        std::optional<CMutableTransaction> mtx;
        {
            LOCK(pwallet->m_shielded_wallet->cs_shielded);
            mtx = pwallet->m_shielded_wallet->ShieldFunds(utxos, fee, dest);
        }

        if (!mtx) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create shielding transaction");
        }

        CTransactionRef tx = MakeTransactionRef(std::move(*mtx));
        pwallet->CommitTransaction(tx, {}, {});

        UniValue result(UniValue::VOBJ);
        result.pushKV("txid", tx->GetHash().GetHex());
        result.pushKV("amount", ValueFromAmount(amount));
        result.pushKV("transparent_inputs", (int64_t)utxos.size());
        return result;
    },
    };
}

// =========================================================================
// z_mergenotes
// =========================================================================

RPCHelpMan z_mergenotes()
{
    return RPCHelpMan{"z_mergenotes",
        "\nConsolidate multiple small shielded notes into fewer larger ones.\n"
        "This reduces the ongoing witness update overhead (each note requires\n"
        "incremental witness updates per block) and improves spend efficiency.\n",
        {
            {"max_notes", RPCArg::Type::NUM, RPCArg::Default{10},
             "Maximum number of notes to merge per transaction."},
            {"fee", RPCArg::Type::AMOUNT, RPCArg::Default{FormatMoney(10000)},
             "Transaction fee in BTX."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction ID"},
                {RPCResult::Type::NUM, "merged_notes", "Number of notes consumed"},
                {RPCResult::Type::STR_AMOUNT, "merged_value", "Total value of merged notes"},
                {RPCResult::Type::STR_AMOUNT, "output_value", "Value of the consolidated note"},
            }
        },
        RPCExamples{
            HelpExampleCli("z_mergenotes", "")
            + HelpExampleCli("z_mergenotes", "20 0.0002")
            + HelpExampleRpc("z_mergenotes", "10, 0.0001")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pwallet = EnsureWalletForShielded(request);
        EnsureWalletIsUnlocked(*pwallet);

        size_t max_notes = 10;
        if (!request.params[0].isNull()) {
            max_notes = request.params[0].getInt<int>();
            if (max_notes < 2) throw JSONRPCError(RPC_INVALID_PARAMETER,
                "max_notes must be at least 2");
        }

        CAmount fee = 10000;
        if (!request.params[1].isNull()) {
            fee = AmountFromValue(request.params[1]);
        }

        std::optional<CMutableTransaction> mtx;
        CAmount merged_value = 0;
        size_t merged_count = 0;
        {
            LOCK(pwallet->m_shielded_wallet->cs_shielded);
            auto spendable = pwallet->m_shielded_wallet->GetSpendableNotes(1);
            if (spendable.size() < 2) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "Not enough notes to merge (need at least 2)");
            }
            merged_count = std::min(max_notes, spendable.size());
            for (size_t i = 0; i < merged_count; ++i) {
                merged_value += spendable[i].note.value;
            }
            mtx = pwallet->m_shielded_wallet->MergeNotes(max_notes, fee);
        }

        if (!mtx) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to create merge transaction");
        }

        CTransactionRef tx = MakeTransactionRef(std::move(*mtx));
        pwallet->CommitTransaction(tx, {}, {});

        UniValue result(UniValue::VOBJ);
        result.pushKV("txid", tx->GetHash().GetHex());
        result.pushKV("merged_notes", (int64_t)merged_count);
        result.pushKV("merged_value", ValueFromAmount(merged_value));
        result.pushKV("output_value", ValueFromAmount(merged_value - fee));
        return result;
    },
    };
}

// =========================================================================
// z_viewtransaction
// =========================================================================

RPCHelpMan z_viewtransaction()
{
    return RPCHelpMan{"z_viewtransaction",
        "\nGet detailed information about a shielded transaction that the\n"
        "wallet can decrypt (requires ownership of viewing or spending keys).\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The transaction ID."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "txid", "The transaction ID"},
                {RPCResult::Type::ARR, "spends", "Shielded spends we can identify",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "nullifier", "Nullifier of spent note"},
                                {RPCResult::Type::STR_AMOUNT, "amount", "Amount spent (if ours)"},
                                {RPCResult::Type::BOOL, "is_ours", "Whether this spend is from our wallet"},
                            }
                        },
                    }
                },
                {RPCResult::Type::ARR, "outputs", "Shielded outputs we can decrypt",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::STR_HEX, "commitment", "Note commitment"},
                                {RPCResult::Type::STR_AMOUNT, "amount", "Amount received"},
                                {RPCResult::Type::BOOL, "is_ours", "Whether this output is to us"},
                            }
                        },
                    }
                },
                {RPCResult::Type::STR_AMOUNT, "value_balance", "Net transparent value flow"},
            }
        },
        RPCExamples{
            HelpExampleCli("z_viewtransaction", "\"<txid>\"")
            + HelpExampleRpc("z_viewtransaction", "\"<txid>\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pwallet = EnsureWalletForShielded(request);
        uint256 txid = ParseHashV(request.params[0], "txid");

        LOCK2(pwallet->cs_wallet, pwallet->m_shielded_wallet->cs_shielded);

        const CWalletTx* wtx = pwallet->GetWalletTx(txid);
        if (!wtx || !wtx->tx->HasShieldedBundle()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                "Transaction not found or has no shielded data");
        }

        const auto& bundle = wtx->tx->shielded_bundle;
        UniValue result(UniValue::VOBJ);
        result.pushKV("txid", txid.GetHex());

        // Spends
        UniValue spends(UniValue::VARR);
        for (const auto& spend : bundle.spends) {
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("nullifier", spend.nullifier.GetHex());
            // Check if this nullifier matches one of our notes
            auto& notes = pwallet->m_shielded_wallet->m_notes;
            auto it = notes.find(spend.nullifier);
            if (it != notes.end()) {
                entry.pushKV("amount", ValueFromAmount(it->second.note.value));
                entry.pushKV("is_ours", true);
            } else {
                entry.pushKV("amount", ValueFromAmount(0));
                entry.pushKV("is_ours", false);
            }
            spends.push_back(std::move(entry));
        }
        result.pushKV("spends", std::move(spends));

        // Outputs
        UniValue outputs(UniValue::VARR);
        for (const auto& output : bundle.outputs) {
            UniValue entry(UniValue::VOBJ);
            entry.pushKV("commitment", output.note_commitment.GetHex());
            auto decrypted = pwallet->m_shielded_wallet->TryDecryptNote(output.enc_note);
            if (decrypted.has_value()) {
                entry.pushKV("amount", ValueFromAmount(decrypted->first.value));
                entry.pushKV("is_ours", true);
            } else {
                entry.pushKV("amount", ValueFromAmount(0));
                entry.pushKV("is_ours", false);
            }
            outputs.push_back(std::move(entry));
        }
        result.pushKV("outputs", std::move(outputs));
        result.pushKV("value_balance", ValueFromAmount(bundle.value_balance));

        return result;
    },
    };
}

// =========================================================================
// z_exportviewingkey
// =========================================================================

RPCHelpMan z_exportviewingkey()
{
    return RPCHelpMan{"z_exportviewingkey",
        "\nExport the viewing key for a shielded address.\n"
        "The viewing key is the ML-KEM-768 secret key, which allows\n"
        "scanning for and decrypting incoming notes but NOT spending.\n"
        "\nWARNING: Anyone with this key can see all incoming transactions\n"
        "to this address. Keep it secure.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The shielded address (btxs1...) to export."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The shielded address"},
                {RPCResult::Type::STR_HEX, "viewing_key", "The viewing key (ML-KEM secret key, hex)"},
                {RPCResult::Type::STR_HEX, "spending_pk_hash", "Hash of the spending public key"},
                {RPCResult::Type::STR_HEX, "kem_public_key", "The KEM public key (hex)"},
            }
        },
        RPCExamples{
            HelpExampleCli("z_exportviewingkey", "\"btxs1...\"")
            + HelpExampleRpc("z_exportviewingkey", "\"btxs1...\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pwallet = EnsureWalletForShielded(request);
        EnsureWalletIsUnlocked(*pwallet);

        auto addr = ShieldedAddress::Decode(request.params[0].get_str());
        if (!addr) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid shielded address");

        LOCK(pwallet->m_shielded_wallet->cs_shielded);
        auto vk = pwallet->m_shielded_wallet->ExportViewingKey(*addr);
        if (!vk) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");
        }

        auto it = pwallet->m_shielded_wallet->m_key_sets.find(*addr);

        UniValue result(UniValue::VOBJ);
        result.pushKV("address", addr->Encode());
        result.pushKV("viewing_key", HexStr(*vk));
        result.pushKV("spending_pk_hash", addr->pk_hash.GetHex());
        result.pushKV("kem_public_key", HexStr(it->second.kem_key.public_key));
        return result;
    },
    };
}

// =========================================================================
// z_importviewingkey
// =========================================================================

RPCHelpMan z_importviewingkey()
{
    return RPCHelpMan{"z_importviewingkey",
        "\nImport a shielded viewing key for watch-only scanning.\n"
        "After import, the wallet will scan existing and future blocks\n"
        "for notes encrypted to the corresponding KEM public key.\n"
        "\nThis does NOT enable spending — only balance viewing.\n",
        {
            {"viewing_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The viewing key (ML-KEM secret key) in hex."},
            {"kem_public_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The corresponding KEM public key in hex."},
            {"spending_pk_hash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "SHA-256 hash of the spending public key."},
            {"rescan", RPCArg::Type::BOOL, RPCArg::Default{true},
             "Rescan the blockchain for existing notes."},
            {"start_height", RPCArg::Type::NUM, RPCArg::Default{0},
             "Block height from which to start rescan."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR, "address", "The imported shielded address"},
                {RPCResult::Type::BOOL, "success", "Whether import succeeded"},
            }
        },
        RPCExamples{
            HelpExampleCli("z_importviewingkey",
                "\"<hex_kem_sk>\" \"<hex_kem_pk>\" \"<hex_pk_hash>\"")
            + HelpExampleRpc("z_importviewingkey",
                "\"<hex_kem_sk>\", \"<hex_kem_pk>\", \"<hex_pk_hash>\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto pwallet = EnsureWalletForShielded(request);

        auto kem_sk = ParseHex(request.params[0].get_str());
        auto kem_pk = ParseHex(request.params[1].get_str());
        uint256 spending_pk_hash = ParseHashV(request.params[2], "spending_pk_hash");

        bool rescan = true;
        int start_height = 0;
        if (!request.params[3].isNull()) rescan = request.params[3].get_bool();
        if (!request.params[4].isNull()) start_height = request.params[4].getInt<int>();

        bool ok;
        ShieldedAddress addr;
        {
            LOCK(pwallet->m_shielded_wallet->cs_shielded);
            ok = pwallet->m_shielded_wallet->ImportViewingKey(kem_sk, kem_pk, spending_pk_hash);
            if (ok) {
                auto addrs = pwallet->m_shielded_wallet->GetAddresses();
                addr = addrs.back();
                if (rescan) {
                    pwallet->m_shielded_wallet->Rescan(start_height);
                }
            }
        }

        UniValue result(UniValue::VOBJ);
        result.pushKV("address", ok ? addr.Encode() : "");
        result.pushKV("success", ok);
        return result;
    },
    };
}

// =========================================================================
// z_validateaddress
// =========================================================================

RPCHelpMan z_validateaddress()
{
    return RPCHelpMan{"z_validateaddress",
        "\nValidate a shielded address and return information about it.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The shielded address to validate (btxs1...)."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::BOOL, "isvalid", "Whether the address is valid"},
                {RPCResult::Type::STR, "address", "The address (if valid)"},
                {RPCResult::Type::NUM, "version", "Address version byte"},
                {RPCResult::Type::STR, "algorithm", "Cryptographic algorithm"},
                {RPCResult::Type::STR_HEX, "pk_hash", "Spending public key hash"},
                {RPCResult::Type::STR_HEX, "kem_pk_hash", "KEM public key hash"},
                {RPCResult::Type::BOOL, "ismine", "Whether the wallet has keys for this address"},
                {RPCResult::Type::BOOL, "iswatchonly", "Whether the wallet has view-only access"},
            }
        },
        RPCExamples{
            HelpExampleCli("z_validateaddress", "\"btxs1...\"")
            + HelpExampleRpc("z_validateaddress", "\"btxs1...\"")
        },
    [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
    {
        auto addr = ShieldedAddress::Decode(request.params[0].get_str());

        UniValue result(UniValue::VOBJ);
        if (!addr || !addr->IsValid()) {
            result.pushKV("isvalid", false);
            return result;
        }

        result.pushKV("isvalid", true);
        result.pushKV("address", addr->Encode());
        result.pushKV("version", (int)addr->version);
        result.pushKV("algorithm", "ml-dsa-44+ml-kem-768");
        result.pushKV("pk_hash", addr->pk_hash.GetHex());
        result.pushKV("kem_pk_hash", addr->kem_pk_hash.GetHex());

        // Check wallet ownership
        try {
            auto pwallet = GetWalletForJSONRPCRequest(request);
            if (pwallet && pwallet->m_shielded_wallet) {
                LOCK(pwallet->m_shielded_wallet->cs_shielded);
                bool has_spending = pwallet->m_shielded_wallet->HaveSpendingKey(*addr);
                auto vk = pwallet->m_shielded_wallet->ExportViewingKey(*addr);
                result.pushKV("ismine", has_spending);
                result.pushKV("iswatchonly", vk.has_value() && !has_spending);
            } else {
                result.pushKV("ismine", false);
                result.pushKV("iswatchonly", false);
            }
        } catch (...) {
            result.pushKV("ismine", false);
            result.pushKV("iswatchonly", false);
        }

        return result;
    },
    };
}

// =========================================================================
// RPC Registration
// =========================================================================

// Forward declarations for src/wallet/rpc/wallet.cpp
RPCHelpMan z_getnewaddress();
RPCHelpMan z_getbalance();
RPCHelpMan z_listunspent();
RPCHelpMan z_sendmany();
RPCHelpMan z_shieldcoinbase();
RPCHelpMan z_shieldfunds();
RPCHelpMan z_mergenotes();
RPCHelpMan z_viewtransaction();
RPCHelpMan z_exportviewingkey();
RPCHelpMan z_importviewingkey();
RPCHelpMan z_validateaddress();

} // namespace wallet
```

#### RPC Registration in `src/wallet/rpc/wallet.cpp`

Add these entries to the `GetWalletRPCCommands()` `commands[]` array:

```cpp
// === Additions to src/wallet/rpc/wallet.cpp ===
// Add forward declarations before GetWalletRPCCommands():

// shielded
RPCHelpMan z_getnewaddress();
RPCHelpMan z_getbalance();
RPCHelpMan z_listunspent();
RPCHelpMan z_sendmany();
RPCHelpMan z_shieldcoinbase();
RPCHelpMan z_shieldfunds();
RPCHelpMan z_mergenotes();
RPCHelpMan z_viewtransaction();
RPCHelpMan z_exportviewingkey();
RPCHelpMan z_importviewingkey();
RPCHelpMan z_validateaddress();

// Add to the commands[] array in GetWalletRPCCommands():
        {"shielded", &z_getnewaddress},
        {"shielded", &z_getbalance},
        {"shielded", &z_listunspent},
        {"shielded", &z_sendmany},
        {"shielded", &z_shieldcoinbase},
        {"shielded", &z_shieldfunds},
        {"shielded", &z_mergenotes},
        {"shielded", &z_viewtransaction},
        {"shielded", &z_exportviewingkey},
        {"shielded", &z_importviewingkey},
        {"shielded", &z_validateaddress},
```

---
