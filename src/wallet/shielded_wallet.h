// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_SHIELDED_WALLET_H
#define BITCOIN_WALLET_SHIELDED_WALLET_H

#include <addresstype.h>
#include <psbt.h>
#include <consensus/amount.h>
#include <crypto/ml_kem.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <shielded/bridge.h>
#include <shielded/merkle_tree.h>
#include <shielded/note_encryption.h>
#include <shielded/smile2/public_account.h>
#include <shielded/v2_ingress.h>
#include <sync.h>
#include <uint256.h>
#include <wallet/shielded_coins.h>

#include <array>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

class CBlock;
class CTransaction;

namespace wallet {

class CWallet;

/** Full shielded key material for one address. */
struct ShieldedKeySet
{
    CPQKey spending_key;
    mlkem::KeyPair kem_key;
    uint256 spending_pk_hash;
    uint256 kem_pk_hash;
    uint32_t account{0};
    uint32_t index{0};
    bool spending_key_loaded{false};
    bool has_spending_key{true};
};

/** BTX shielded address container (Bech32m-encoded externally). */
struct ShieldedAddress
{
    uint8_t version{0x00};
    uint8_t algo_byte{0x00};
    uint256 pk_hash;
    uint256 kem_pk_hash;
    // Optional full recipient KEM public key (required for external encrypted sends).
    std::array<uint8_t, mlkem::PUBLICKEYBYTES> kem_pk{};

    [[nodiscard]] std::string Encode() const;
    [[nodiscard]] static std::optional<ShieldedAddress> Decode(const std::string& addr);
    [[nodiscard]] bool IsValid() const;
    [[nodiscard]] bool HasKEMPublicKey() const;

    SERIALIZE_METHODS(ShieldedAddress, obj)
    {
        // Persist the compact canonical address identity. Full KEM public key
        // is restored from key material where available and may be absent for
        // legacy/imported addresses.
        READWRITE(obj.version, obj.algo_byte, obj.pk_hash, obj.kem_pk_hash);
    }

    friend bool operator==(const ShieldedAddress& a, const ShieldedAddress& b)
    {
        return a.version == b.version &&
               a.algo_byte == b.algo_byte &&
               a.pk_hash == b.pk_hash &&
               a.kem_pk_hash == b.kem_pk_hash;
    }
    friend bool operator<(const ShieldedAddress& a, const ShieldedAddress& b)
    {
        if (a.version != b.version) return a.version < b.version;
        if (a.algo_byte != b.algo_byte) return a.algo_byte < b.algo_byte;
        if (a.pk_hash != b.pk_hash) return a.pk_hash < b.pk_hash;
        return a.kem_pk_hash < b.kem_pk_hash;
    }
};

enum class ShieldedAddressLifecycleState : uint8_t {
    ACTIVE = 1,
    ROTATED = 2,
    REVOKED = 3,
};

[[nodiscard]] bool IsValidShieldedAddressLifecycleState(ShieldedAddressLifecycleState state);
[[nodiscard]] const char* GetShieldedAddressLifecycleStateName(ShieldedAddressLifecycleState state);

struct ShieldedAddressLifecycle
{
    uint8_t version{1};
    ShieldedAddressLifecycleState state{ShieldedAddressLifecycleState::ACTIVE};
    bool has_successor{false};
    ShieldedAddress successor;
    bool has_predecessor{false};
    ShieldedAddress predecessor;
    int32_t transition_height{-1};

    [[nodiscard]] bool IsValid() const;

    SERIALIZE_METHODS(ShieldedAddressLifecycle, obj)
    {
        READWRITE(obj.version);
        uint8_t state_byte{0};
        SER_WRITE(obj, state_byte = static_cast<uint8_t>(obj.state));
        READWRITE(state_byte);
        SER_READ(obj, obj.state = static_cast<ShieldedAddressLifecycleState>(state_byte));
        READWRITE(obj.has_successor);
        if (obj.has_successor) {
            READWRITE(obj.successor);
        }
        READWRITE(obj.has_predecessor);
        if (obj.has_predecessor) {
            READWRITE(obj.predecessor);
        }
        READWRITE(obj.transition_height);
    }
};

/** Cached shielded spend view row for z_viewtransaction fallback. */
struct ShieldedTxViewSpend
{
    Nullifier nullifier;
    CAmount amount{0};
    bool is_ours{false};
};

/** Cached shielded output view row for z_viewtransaction fallback. */
struct ShieldedTxViewOutput
{
    uint256 commitment;
    CAmount amount{0};
    bool is_ours{false};
};

/** Cached shielded output-chunk summary row for large-fanout reporting. */
struct ShieldedTxViewOutputChunk
{
    std::string scan_domain{"unknown"};
    uint32_t first_output_index{0};
    uint32_t output_count{0};
    uint32_t ciphertext_bytes{0};
    uint256 scan_hint_commitment;
    uint256 ciphertext_commitment;
    uint32_t owned_output_count{0};
    CAmount owned_amount{0};
};

/** Cached per-transaction shielded view for watch-only/auditor workflows. */
struct ShieldedTxView
{
    std::vector<ShieldedTxViewSpend> spends;
    std::vector<ShieldedTxViewOutput> outputs;
    std::vector<ShieldedTxViewOutputChunk> output_chunks;
    CAmount value_balance{0};
    std::string family{"legacy"};
};

struct ShieldedAddressLifecycleBuildResult
{
    CMutableTransaction tx;
    std::optional<ShieldedAddress> successor;
};

/** Deterministic direct-send selection preview for fee estimation. */
struct ShieldedSpendSelectionEstimate
{
    std::vector<ShieldedCoin> selected;
    CAmount total_needed{0};
    CAmount total_input{0};
    CAmount change{0};
    size_t shielded_output_count{0};
    size_t transparent_output_bytes{0};
};

struct ShieldedBalanceSummary
{
    CAmount spendable{0};
    CAmount recovery_only{0};
    CAmount watchonly{0};
    int64_t spendable_note_count{0};
    int64_t recovery_only_note_count{0};
    int64_t watchonly_note_count{0};
};

/** Shielded wallet state manager layered over CWallet. */
class CShieldedWallet
{
public:
    explicit CShieldedWallet(CWallet& parent_wallet);
    ~CShieldedWallet();

    CShieldedWallet(const CShieldedWallet&) = delete;
    CShieldedWallet& operator=(const CShieldedWallet&) = delete;

    /** Generate a new local shielded address and store key material. */
    [[nodiscard]] ShieldedAddress GenerateNewAddress(uint32_t account = 0)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Import view-only KEM keys for an externally controlled shielded address. */
    [[nodiscard]] bool ImportViewingKey(const std::vector<unsigned char>& kem_sk,
                                        const std::vector<unsigned char>& kem_pk,
                                        const uint256& spending_pk_hash)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Export viewing key (KEM secret key) for an owned shielded address. */
    [[nodiscard]] std::optional<std::vector<unsigned char>> ExportViewingKey(
        const ShieldedAddress& addr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return all known shielded addresses. */
    [[nodiscard]] std::vector<ShieldedAddress> GetAddresses() const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return lifecycle metadata for a local shielded address. */
    [[nodiscard]] std::optional<ShieldedAddressLifecycle> GetAddressLifecycle(
        const ShieldedAddress& addr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return the preferred active receive address, if one exists. */
    [[nodiscard]] std::optional<ShieldedAddress> GetPreferredReceiveAddress() const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return true if spending authority exists for this address. */
    [[nodiscard]] bool HaveSpendingKey(const ShieldedAddress& addr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Rotate a local receive address to a fresh successor address. */
    [[nodiscard]] std::optional<ShieldedAddress> RotateAddress(const ShieldedAddress& addr,
                                                               std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Revoke a local receive address for future sends. */
    [[nodiscard]] bool RevokeAddress(const ShieldedAddress& addr, std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Build a post-fork authenticated on-chain rotation transaction. */
    [[nodiscard]] std::optional<ShieldedAddressLifecycleBuildResult> BuildAddressRotationTransaction(
        const ShieldedAddress& addr,
        CAmount fee,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Build a post-fork authenticated on-chain revocation transaction. */
    [[nodiscard]] std::optional<ShieldedAddressLifecycleBuildResult> BuildAddressRevocationTransaction(
        const ShieldedAddress& addr,
        CAmount fee,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Persist a committed local address rotation after broadcast. */
    [[nodiscard]] bool ApplyCommittedAddressRotation(const ShieldedAddress& addr,
                                                     const ShieldedAddress& successor,
                                                     std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Persist a committed local address revocation after broadcast. */
    [[nodiscard]] bool ApplyCommittedAddressRevocation(const ShieldedAddress& addr,
                                                       std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Resolve a local lifecycle-managed destination under post-fork rules. */
    [[nodiscard]] std::optional<ShieldedAddress> ResolveLifecycleDestination(
        const ShieldedAddress& addr,
        int32_t validation_height,
        std::string* error = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Scan a connected block for shielded receives/spends. */
    void ScanBlock(const CBlock& block, int height)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Revert shielded wallet state for a disconnected block. */
    void UndoBlock(const CBlock& block, int height)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Track note visibility from mempool transactions. */
    void TransactionAddedToMempool(const CTransaction& tx)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Remove stale mempool notes when a transaction leaves the mempool. */
    void TransactionRemovedFromMempool(const CTransaction& tx)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Clear cached notes and reset scan cursor. */
    void Rescan(int start_height = 0)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return shielded balance split between spendable and watch-only notes. */
    [[nodiscard]] ShieldedBalanceSummary GetShieldedBalanceSummary(int min_depth = 1) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return confirmed spendable shielded balance. */
    [[nodiscard]] CAmount GetShieldedBalance(int min_depth = 1) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return spendable (owned + unspent) notes. */
    [[nodiscard]] std::vector<ShieldedCoin> GetSpendableNotes(int min_depth = 1) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return stranded wallet-owned notes eligible for spend-path recovery. */
    [[nodiscard]] std::vector<ShieldedCoin> GetRecoverableNotes(int min_depth = 1) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return unspent notes (including view-only). */
    [[nodiscard]] std::vector<ShieldedCoin> GetUnspentNotes(int min_depth = 0) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Estimate deterministic direct-send note selection before proof generation. */
    [[nodiscard]] std::optional<ShieldedSpendSelectionEstimate> EstimateDirectSpendSelection(
        const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
        const std::vector<std::pair<CTxDestination, CAmount>>& transparent_recipients,
        CAmount fee,
        std::string* error = nullptr,
        const std::vector<ShieldedCoin>* selected_override = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Build shielded spend transaction. */
    [[nodiscard]] std::optional<CMutableTransaction> CreateShieldedSpend(
        const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
        const std::vector<std::pair<CTxDestination, CAmount>>& transparent_recipients,
        CAmount fee,
        bool allow_transparent_fallback = true,
        std::string* error = nullptr,
        const std::vector<ShieldedCoin>* selected_override = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Recover one stranded shielded note into a fresh ordinary shielded note. */
    [[nodiscard]] std::optional<CMutableTransaction> CreateSpendPathRecovery(
        const uint256& note_commitment,
        std::optional<ShieldedAddress> destination,
        CAmount fee,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Build transparent->shielded transaction using selected transparent UTXOs.
     *  @param requested_amount  If positive, shield only this amount and return
     *         the remainder (total_in - fee - requested_amount) as a transparent
     *         change output.  When 0 (default), the entire input value minus fee
     *         is shielded. */
    [[nodiscard]] std::optional<CMutableTransaction> ShieldFunds(
        const std::vector<COutPoint>& utxos,
        CAmount fee,
        std::optional<ShieldedAddress> dest = std::nullopt,
        CAmount requested_amount = 0,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Build transparent->shielded transaction as an unsigned PSBT.
     *  Returns a PSBT with the shielded bundle embedded in the unsigned tx
     *  and UTXO witness data populated for each transparent input.
     *  @param requested_amount  If positive, shield only this amount and return
     *         the remainder as a transparent change output.  When 0 (default),
     *         the entire input value minus fee is shielded. */
    [[nodiscard]] std::optional<PartiallySignedTransaction> ShieldFundsPSBT(
        const std::vector<COutPoint>& utxos,
        CAmount fee,
        std::optional<ShieldedAddress> dest = std::nullopt,
        CAmount requested_amount = 0,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Build transparent-input fallback deposit for shielded recipients. */
    [[nodiscard]] std::optional<CMutableTransaction> CreateTransparentToShieldedSend(
        const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
        CAmount fee,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Build a deterministic receipt-backed v2 egress batch transaction. */
    [[nodiscard]] std::optional<CMutableTransaction> CreateV2EgressBatch(
        const shielded::BridgeBatchStatement& statement,
        const std::vector<shielded::BridgeProofDescriptor>& proof_descriptors,
        const shielded::BridgeProofDescriptor& imported_descriptor,
        const std::vector<shielded::BridgeProofReceipt>& proof_receipts,
        const shielded::BridgeProofReceipt& imported_receipt,
        const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
        const std::vector<uint32_t>& output_chunk_sizes,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Build a deterministic wallet-side v2 ingress batch transaction. */
    [[nodiscard]] std::optional<CMutableTransaction> CreateV2IngressBatch(
        const shielded::BridgeBatchStatement& statement,
        const std::vector<shielded::v2::V2IngressLeafInput>& ingress_leaves,
        const std::vector<std::pair<ShieldedAddress, CAmount>>& reserve_outputs,
        std::optional<shielded::v2::V2IngressSettlementWitness> settlement_witness = std::nullopt,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Build a deterministic wallet-side v2 rebalance transaction. */
    [[nodiscard]] std::optional<CMutableTransaction> CreateV2Rebalance(
        const std::vector<shielded::v2::ReserveDelta>& reserve_deltas,
        const std::vector<std::pair<ShieldedAddress, CAmount>>& reserve_outputs,
        const shielded::v2::NettingManifest& netting_manifest,
        CAmount requested_fee,
        CAmount& actual_fee_paid,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Build unshield transaction. */
    [[nodiscard]] std::optional<CMutableTransaction> UnshieldFunds(
        CAmount amount,
        const CTxDestination& destination,
        CAmount fee)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Consolidate many notes into one output. */
    [[nodiscard]] std::optional<CMutableTransaction> MergeNotes(
        size_t max_notes,
        CAmount fee,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Try decrypting an encrypted note with local viewing keys. */
    [[nodiscard]] std::optional<ShieldedNote> TryDecryptNote(
        const shielded::EncryptedNote& enc_note) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Try decrypting a shielded_v2 output payload with local viewing keys. */
    [[nodiscard]] std::optional<ShieldedNote> TryDecryptNote(
        const shielded::v2::EncryptedNotePayload& enc_note) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Lookup local note record by nullifier. */
    [[nodiscard]] std::optional<ShieldedCoin> GetCoinByNullifier(const Nullifier& nf) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    /** Resolve the exact note set spent by an in-mempool shielded wallet transaction. */
    [[nodiscard]] std::optional<std::vector<ShieldedCoin>> GetConflictSpendSelection(
        const uint256& txid,
        std::string* error = nullptr) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Lookup cached shielded transaction view for watch-only/auditor RPCs. */
    [[nodiscard]] std::optional<ShieldedTxView> GetCachedTransactionView(const uint256& txid) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return KEM public key for a local address. */
    [[nodiscard]] bool GetKEMPublicKey(const ShieldedAddress& addr, mlkem::PublicKey& out_pk) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    // R5-520: Reserve nullifiers for notes being used in an in-flight transaction.
    // Call after CreateShieldedSpend while still holding cs_shielded. The reserved
    // nullifiers will be excluded from future SelectNotes calls until released.
    void ReservePendingSpends(const std::vector<Nullifier>& nullifiers)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    void ReleasePendingSpends(const std::vector<Nullifier>& nullifiers)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Return local scan cursor height. */
    [[nodiscard]] int LastScannedHeight() const EXCLUSIVE_LOCKS_REQUIRED(cs_shielded)
    {
        return m_last_scanned_height;
    }

    /** Return true if the last rebuild was incomplete due to pruned blocks.
     *  When set, shielded balances may be underreported. */
    [[nodiscard]] bool IsScanIncomplete() const EXCLUSIVE_LOCKS_REQUIRED(cs_shielded)
    {
        return m_scan_incomplete;
    }

    /** Return true if the wallet started locked from tree-only fallback state
     *  and balances remain incomplete until the shielded state is rehydrated. */
    [[nodiscard]] bool IsLockedStateIncomplete() const EXCLUSIVE_LOCKS_REQUIRED(cs_shielded)
    {
        return m_locked_state_incomplete;
    }

    /** Return the current chain-valid shielded anchor known to the wallet. */
    [[nodiscard]] uint256 GetCurrentAnchor() const EXCLUSIVE_LOCKS_REQUIRED(cs_shielded)
    {
        return m_tree.Root();
    }

    /** Attempt to derive any missing spending keys after wallet unlock.
     *  Also reloads the full persisted state if keys/notes were lost due to
     *  a locked-wallet startup (tree-only fallback). */
    bool MaybeRehydrateSpendingKeys() EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Flush in-memory shielded state to the wallet database.
     *  Must be called before backupwallet to ensure a consistent snapshot. */
    [[nodiscard]] bool PersistState() EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    /** Verify that all shielded key material is present and derivable.
     *  Returns a diagnostic report suitable for backup validation. */
    struct KeyIntegrityReport {
        int total_keys{0};
        int spending_keys_loaded{0};
        int viewing_keys_loaded{0};
        int spending_keys_missing{0};
        bool master_seed_available{false};
        int notes_total{0};
        int notes_unspent{0};
        int tree_size{0};
        int scan_height{-1};
        bool scan_incomplete{false};
    };
    [[nodiscard]] KeyIntegrityReport VerifyKeyIntegrity() EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);

    mutable RecursiveMutex cs_shielded;

private:
    CWallet& m_parent_wallet;

    std::map<ShieldedAddress, ShieldedKeySet> m_key_sets GUARDED_BY(cs_shielded);
    std::map<ShieldedAddress, ShieldedAddressLifecycle> m_address_lifecycles GUARDED_BY(cs_shielded);
    std::map<Nullifier, ShieldedCoin> m_notes GUARDED_BY(cs_shielded);
    std::set<Nullifier> m_spent_nullifiers GUARDED_BY(cs_shielded);
    std::map<uint256, shielded::ShieldedMerkleWitness> m_witnesses GUARDED_BY(cs_shielded);
    std::map<uint256, smile2::CompactPublicAccount> m_smile_public_accounts GUARDED_BY(cs_shielded);
    std::map<uint256, uint256> m_account_leaf_commitments GUARDED_BY(cs_shielded);
    shielded::ShieldedMerkleTree m_tree GUARDED_BY(cs_shielded){
        shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
    std::map<Nullifier, ShieldedCoin> m_mempool_notes GUARDED_BY(cs_shielded);
    /** Reverse index: txid -> set of nullifiers inserted into m_mempool_notes
     *  for that transaction.  Used by TransactionRemovedFromMempool to erase
     *  the correct output-derived nullifiers (not input spend nullifiers). */
    std::map<uint256, std::set<Nullifier>> m_mempool_note_index GUARDED_BY(cs_shielded);
    /** Bounded view cache: evict oldest entries when exceeding TX_VIEW_CACHE_MAX. */
    static constexpr size_t TX_VIEW_CACHE_MAX{10000};
    std::map<uint256, ShieldedTxView> m_tx_view_cache GUARDED_BY(cs_shielded);
    // R5-520: Nullifiers of notes currently being used in in-flight (unconfirmed)
    // transactions. Prevents double-selection if multiple CreateShieldedSpend
    // calls race between lock release and mempool acceptance.
    // M4 audit fix: mutable so const member functions can clean up stale
    // pending-spend reservations without const_cast UB.
    mutable std::set<Nullifier> m_pending_spends GUARDED_BY(cs_shielded);
    std::vector<uint64_t> m_recent_ring_exclusions GUARDED_BY(cs_shielded);
    uint32_t m_next_spending_index GUARDED_BY(cs_shielded){0};
    uint32_t m_next_kem_index GUARDED_BY(cs_shielded){0};
    int m_last_scanned_height GUARDED_BY(cs_shielded){-1};
    uint256 m_last_scanned_hash GUARDED_BY(cs_shielded);
    bool m_defer_persist GUARDED_BY(cs_shielded){false};
    /** Set when a shielded chain rebuild could not complete because
     *  early blocks have been pruned.  The wallet tree and note index
     *  may be incomplete, so balances should be treated as lower bounds. */
    bool m_scan_incomplete GUARDED_BY(cs_shielded){false};
    /** Set when an encrypted wallet was loaded while locked using the
     *  tree-only fallback state and full note/key accounting is unavailable
     *  until the shielded state is rehydrated after unlock. */
    bool m_locked_state_incomplete GUARDED_BY(cs_shielded){false};

    [[nodiscard]] std::vector<unsigned char> GetMasterSeed() const;
    [[nodiscard]] int GetChainTipHeight() const;
    [[nodiscard]] const ShieldedKeySet* FindLoadedSpendingKeysetForRecipient(
        const uint256& recipient_pk_hash) const EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    [[nodiscard]] std::optional<Nullifier> ComputeOwnedNullifier(
        const ShieldedCoin& coin,
        const std::vector<unsigned char>& master_seed,
        const ShieldedKeySet& keyset) const EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    [[nodiscard]] size_t RepairOwnedNoteSpendMetadataForMap(
        std::map<Nullifier, ShieldedCoin>& note_map,
        const char* map_name,
        const std::vector<unsigned char>& master_seed) EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    [[nodiscard]] bool RepairOwnedNoteSpendMetadata(
        const std::vector<unsigned char>& master_seed) EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    void PruneStalePendingSpends() const EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    [[nodiscard]] std::vector<ShieldedCoin> GetOrdinarySpendableNotes(int min_depth) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    [[nodiscard]] std::optional<CMutableTransaction> CreateV2Send(
        const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
        const std::vector<std::pair<CTxDestination, CAmount>>& transparent_recipients,
        CAmount fee,
        std::string* error = nullptr)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    [[nodiscard]] std::optional<CMutableTransaction> CreateV2Send(
        const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
        const std::vector<std::pair<CTxDestination, CAmount>>& transparent_recipients,
        CAmount fee,
        const std::vector<ShieldedCoin>* selected_override,
        std::string* error)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    void RecordScannedOutput(const CBlock& block,
                             int height,
                             const uint256& note_commitment,
                             const shielded::EncryptedNote& enc_note,
                             const std::vector<unsigned char>& master_seed,
                             std::set<uint256>& block_commitments_seen,
                             ShieldedTxView& tx_view,
                             bool& tx_has_local_visibility)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    void RecordScannedOutput(const CBlock& block,
                             int height,
                             const shielded::v2::OutputDescription& output,
                             const std::optional<shielded::registry::AccountLeafHint>& account_leaf_hint,
                             const std::vector<unsigned char>& master_seed,
                             std::set<uint256>& block_commitments_seen,
                             ShieldedTxView& tx_view,
                             bool& tx_has_local_visibility)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    void RecordMempoolOutput(const uint256& txid,
                             const uint256& note_commitment,
                             const shielded::EncryptedNote& enc_note,
                             const std::vector<unsigned char>& master_seed,
                             ShieldedTxView& tx_view,
                             bool& tx_has_local_visibility)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    void RecordMempoolOutput(const uint256& txid,
                             const shielded::v2::OutputDescription& output,
                             const std::optional<shielded::registry::AccountLeafHint>& account_leaf_hint,
                             const std::vector<unsigned char>& master_seed,
                             ShieldedTxView& tx_view,
                             bool& tx_has_local_visibility)
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    [[nodiscard]] std::vector<ShieldedCoin> SelectNotes(CAmount target,
                                                        CAmount fee,
                                                        bool prefer_minimal_inputs = false) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    [[nodiscard]] bool NullifierReservedByAnotherMempoolTx(const Nullifier& nf,
                                                           const uint256& excluding_txid = uint256()) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    [[nodiscard]] std::optional<std::pair<ShieldedNote, const ShieldedKeySet*>> TryDecryptNoteFull(
        const shielded::EncryptedNote& enc_note) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    [[nodiscard]] std::optional<std::pair<ShieldedNote, const ShieldedKeySet*>> TryDecryptNoteFull(
        const shielded::v2::EncryptedNotePayload& enc_note) const
        EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    void UpdateWitnesses(const uint256& new_commitment) EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    void PruneSpentWitnesses() EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    void LoadPersistedState() EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    void CatchUpToChainTip() EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    /** Rebuild only the commitment position index by replaying output commitments from the chain. */
    void RebuildCommitmentIndex() EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    /** Rebuild the public SMILE-account index by replaying output metadata from the chain. */
    void RebuildSmilePublicAccountIndex() EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
    /** Rebuild in-memory shielded cache by scanning active chain from genesis. */
    void RebuildFromActiveChain() EXCLUSIVE_LOCKS_REQUIRED(cs_shielded);
};

} // namespace wallet

#endif // BITCOIN_WALLET_SHIELDED_WALLET_H
