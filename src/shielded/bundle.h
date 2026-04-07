// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_BUNDLE_H
#define BTX_SHIELDED_BUNDLE_H

#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/amount.h>
#include <crypto/ml_kem.h>
#include <serialize.h>
#include <shielded/lattice/params.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <shielded/v2_bundle.h>
#include <span.h>
#include <support/allocators/secure.h>
#include <uint256.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <optional>
#include <string>
#include <vector>

/** Maximum shielded spends per transaction. */
static constexpr size_t MAX_SHIELDED_SPENDS_PER_TX{16};

/** Maximum shielded outputs per transaction. */
static constexpr size_t MAX_SHIELDED_OUTPUTS_PER_TX{16};

/** Maximum number of selective disclosure grants per transaction. */
static constexpr size_t MAX_VIEW_GRANTS_PER_TX{8};

/** Maximum encrypted payload bytes inside one selective disclosure grant. */
static constexpr size_t MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE{512};

/** Maximum anchor lookback depth for shielded spends. */
static constexpr int SHIELDED_ANCHOR_DEPTH{100};

/** Maximum shielded transaction weight (WU). */
static constexpr int64_t MAX_SHIELDED_TX_WEIGHT{MAX_BLOCK_WEIGHT};

/** Post-fork fee quantum used to reduce shielded fee fingerprinting. */
namespace shielded {
static constexpr CAmount SHIELDED_PRIVACY_FEE_QUANTUM{1000};
} // namespace shielded

/** Upper bound for serialized MatRiCT proof bytes in one bundle.
 *  A 2-in-2-out proof with polynomial challenges is ~1.1 MB due to
 *  range proofs (~473 KB/output) and ring signatures (~100 KB/input).
 *  Set to 1.5 MB to accommodate typical transactions with headroom. */
static constexpr size_t MAX_SHIELDED_PROOF_BYTES{1536 * 1024};

/** Encrypted view key disclosure for a third-party auditor/operator. */
struct CViewGrant {
    using SecureBytes = std::vector<uint8_t, secure_allocator<uint8_t>>;

    mlkem::Ciphertext kem_ct;
    std::array<uint8_t, 12> nonce;
    std::vector<uint8_t> encrypted_data;

    [[nodiscard]] static CViewGrant Create(Span<const uint8_t> view_key,
                                           const mlkem::PublicKey& operator_pk);
    [[nodiscard]] static CViewGrant CreateDeterministic(Span<const uint8_t> view_key,
                                                        const mlkem::PublicKey& operator_pk,
                                                        Span<const uint8_t> kem_seed,
                                                        Span<const uint8_t> nonce);

    [[nodiscard]] std::optional<SecureBytes> Decrypt(
        const mlkem::SecretKey& operator_sk) const;

    SERIALIZE_METHODS(CViewGrant, obj)
    {
        READWRITE(obj.kem_ct, obj.nonce);
        if constexpr (ser_action.ForRead()) {
            uint64_t data_size{0};
            ::Unserialize(s, COMPACTSIZE(data_size));
            if (data_size > MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE) {
                throw std::ios_base::failure("CViewGrant::Unserialize oversized encrypted_data");
            }
            obj.encrypted_data.resize(data_size);
            if (data_size > 0) {
                s.read(AsWritableBytes(Span<uint8_t>{obj.encrypted_data.data(), obj.encrypted_data.size()}));
            }
        } else {
            const uint64_t data_size = obj.encrypted_data.size();
            if (data_size > MAX_VIEW_GRANT_ENCRYPTED_DATA_SIZE) {
                throw std::ios_base::failure("CViewGrant::Serialize oversized encrypted_data");
            }
            ::Serialize(s, COMPACTSIZE(data_size));
            if (data_size > 0) {
                s.write(AsBytes(Span<const uint8_t>{obj.encrypted_data.data(), obj.encrypted_data.size()}));
            }
        }
    }
};

/** Shielded output payload carried in a transaction. */
struct CShieldedOutput {
    uint256 note_commitment;
    shielded::EncryptedNote encrypted_note;
    std::vector<uint8_t> range_proof;
    uint256 merkle_anchor;

    SERIALIZE_METHODS(CShieldedOutput, obj)
    {
        READWRITE(obj.note_commitment, obj.encrypted_note);
        if constexpr (ser_action.ForRead()) {
            uint64_t legacy_range_proof_size{0};
            ::Unserialize(s, COMPACTSIZE(legacy_range_proof_size));
            if (legacy_range_proof_size != 0) {
                throw std::ios_base::failure("CShieldedOutput::Unserialize non-empty legacy range_proof");
            }
            obj.range_proof.clear();
        } else {
            if (!obj.range_proof.empty()) {
                throw std::ios_base::failure("CShieldedOutput::Serialize non-empty legacy range_proof");
            }
            const uint64_t legacy_range_proof_size{0};
            ::Serialize(s, COMPACTSIZE(legacy_range_proof_size));
        }
        READWRITE(obj.merkle_anchor);
    }
};

/** Shielded input payload carried in a transaction. */
struct CShieldedInput {
    Nullifier nullifier;
    // Absolute commitment positions in the global shielded tree (ring members).
    std::vector<uint64_t> ring_positions;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, nullifier);
        const uint64_t ring_position_count = ring_positions.size();
        if (ring_position_count > static_cast<uint64_t>(shielded::lattice::MAX_RING_SIZE)) {
            throw std::ios_base::failure("CShieldedInput::Serialize oversized ring_positions");
        }
        ::Serialize(s, COMPACTSIZE(ring_position_count));
        for (const uint64_t position : ring_positions) {
            ::Serialize(s, position);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, nullifier);
        uint64_t ring_position_count{0};
        ::Unserialize(s, COMPACTSIZE(ring_position_count));
        if (ring_position_count > static_cast<uint64_t>(shielded::lattice::MAX_RING_SIZE)) {
            throw std::ios_base::failure("CShieldedInput::Unserialize oversized ring_positions");
        }
        ring_positions.assign(ring_position_count, 0);
        for (uint64_t& position : ring_positions) {
            ::Unserialize(s, position);
        }
    }
};

/** Bundle of all shielded data attached to a transaction. */
struct CShieldedBundle {
    static constexpr uint64_t SERIALIZED_V2_BUNDLE_TAG{MAX_SHIELDED_SPENDS_PER_TX + 1};

    std::vector<CShieldedInput> shielded_inputs;
    std::vector<CShieldedOutput> shielded_outputs;
    std::vector<CViewGrant> view_grants;
    std::vector<uint8_t> proof;
    std::optional<shielded::v2::TransactionBundle> v2_bundle;

    // Positive: value leaves shielded pool (unshield). Negative: enters pool (shield).
    CAmount value_balance{0};

    [[nodiscard]] bool IsEmpty() const;
    [[nodiscard]] bool HasLegacyDirectSpendData() const;
    [[nodiscard]] bool HasV2Bundle() const { return v2_bundle.has_value(); }
    [[nodiscard]] bool HasShieldedInputs() const;
    [[nodiscard]] bool HasShieldedOutputs() const;
    [[nodiscard]] size_t GetShieldedInputCount() const;
    [[nodiscard]] size_t GetShieldedOutputCount() const;
    [[nodiscard]] size_t GetProofSize() const;
    [[nodiscard]] const shielded::v2::TransactionBundle* GetV2Bundle() const
    {
        return v2_bundle ? &*v2_bundle : nullptr;
    }
    [[nodiscard]] std::optional<shielded::v2::TransactionFamily> GetTransactionFamily() const
    {
        if (!v2_bundle) return std::nullopt;
        return shielded::v2::GetBundleSemanticFamily(*v2_bundle);
    }
    [[nodiscard]] bool IsShieldOnly() const;
    [[nodiscard]] bool IsUnshieldOnly() const;
    [[nodiscard]] bool IsFullyShielded() const;
    [[nodiscard]] bool CheckStructure() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (HasV2Bundle()) {
            if (HasLegacyDirectSpendData()) {
                throw std::ios_base::failure("CShieldedBundle::Serialize mixed legacy/v2 bundle");
            }
            const uint64_t v2_bundle_tag = SERIALIZED_V2_BUNDLE_TAG;
            ::Serialize(s, COMPACTSIZE(v2_bundle_tag));
            ::Serialize(s, *v2_bundle);
            return;
        }

        const uint64_t input_count = shielded_inputs.size();
        if (input_count > MAX_SHIELDED_SPENDS_PER_TX) {
            throw std::ios_base::failure("CShieldedBundle::Serialize oversized shielded_inputs");
        }
        ::Serialize(s, COMPACTSIZE(input_count));
        for (const CShieldedInput& input : shielded_inputs) {
            s << input;
        }

        const uint64_t output_count = shielded_outputs.size();
        if (output_count > MAX_SHIELDED_OUTPUTS_PER_TX) {
            throw std::ios_base::failure("CShieldedBundle::Serialize oversized shielded_outputs");
        }
        ::Serialize(s, COMPACTSIZE(output_count));
        for (const CShieldedOutput& output : shielded_outputs) {
            s << output;
        }

        const uint64_t grant_count = view_grants.size();
        if (grant_count > MAX_VIEW_GRANTS_PER_TX) {
            throw std::ios_base::failure("CShieldedBundle::Serialize oversized view_grants");
        }
        ::Serialize(s, COMPACTSIZE(grant_count));
        for (const CViewGrant& grant : view_grants) {
            s << grant;
        }

        const uint64_t proof_size = proof.size();
        if (proof_size > MAX_SHIELDED_PROOF_BYTES) {
            throw std::ios_base::failure("CShieldedBundle::Serialize oversized proof");
        }
        ::Serialize(s, COMPACTSIZE(proof_size));
        if (proof_size > 0) {
            s.write(AsBytes(Span<const uint8_t>{proof.data(), proof.size()}));
        }
        s << value_balance;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        shielded_inputs.clear();
        shielded_outputs.clear();
        view_grants.clear();
        proof.clear();
        v2_bundle.reset();
        value_balance = 0;

        uint64_t input_count_or_tag{0};
        ::Unserialize(s, COMPACTSIZE(input_count_or_tag));
        if (input_count_or_tag == SERIALIZED_V2_BUNDLE_TAG) {
            shielded::v2::TransactionBundle bundle;
            ::Unserialize(s, bundle);
            v2_bundle = std::move(bundle);
            return;
        }
        if (input_count_or_tag > MAX_SHIELDED_SPENDS_PER_TX) {
            throw std::ios_base::failure("CShieldedBundle::Unserialize oversized shielded_inputs");
        }
        const uint64_t input_count = input_count_or_tag;
        shielded_inputs.assign(input_count, {});
        for (CShieldedInput& input : shielded_inputs) {
            s >> input;
        }

        uint64_t output_count{0};
        ::Unserialize(s, COMPACTSIZE(output_count));
        if (output_count > MAX_SHIELDED_OUTPUTS_PER_TX) {
            throw std::ios_base::failure("CShieldedBundle::Unserialize oversized shielded_outputs");
        }
        shielded_outputs.assign(output_count, {});
        for (CShieldedOutput& output : shielded_outputs) {
            s >> output;
        }

        uint64_t grant_count{0};
        ::Unserialize(s, COMPACTSIZE(grant_count));
        if (grant_count > MAX_VIEW_GRANTS_PER_TX) {
            throw std::ios_base::failure("CShieldedBundle::Unserialize oversized view_grants");
        }
        view_grants.assign(grant_count, {});
        for (CViewGrant& grant : view_grants) {
            s >> grant;
        }

        uint64_t proof_size{0};
        ::Unserialize(s, COMPACTSIZE(proof_size));
        if (proof_size > MAX_SHIELDED_PROOF_BYTES) {
            throw std::ios_base::failure("CShieldedBundle::Unserialize oversized proof");
        }
        proof.resize(proof_size);
        if (proof_size > 0) {
            s.read(AsWritableBytes(Span<uint8_t>{proof.data(), proof.size()}));
        }
        s >> value_balance;
    }
};

[[nodiscard]] uint256 ComputeShieldedBundleCtvHash(const CShieldedBundle& bundle);
[[nodiscard]] std::vector<Nullifier> CollectShieldedNullifiers(const CShieldedBundle& bundle);
[[nodiscard]] std::vector<uint256> CollectShieldedOutputCommitments(const CShieldedBundle& bundle);
[[nodiscard]] std::vector<std::pair<uint256, smile2::CompactPublicAccount>> CollectShieldedOutputSmileAccounts(
    const CShieldedBundle& bundle);
[[nodiscard]] std::optional<std::vector<std::pair<uint256, uint256>>> CollectShieldedOutputAccountLeafEntries(
    const CShieldedBundle& bundle,
    bool use_nonced_bridge_tag = false);
[[nodiscard]] std::optional<std::vector<uint256>> CollectShieldedOutputAccountLeafCommitments(
    const CShieldedBundle& bundle,
    bool use_nonced_bridge_tag = false);
[[nodiscard]] std::vector<uint256> CollectShieldedAnchors(const CShieldedBundle& bundle);
[[nodiscard]] std::vector<uint256> CollectShieldedSettlementAnchorRefs(const CShieldedBundle& bundle);
[[nodiscard]] std::optional<CAmount> TryGetShieldedStateValueBalance(const CShieldedBundle& bundle,
                                                                     std::string& reject_reason);
[[nodiscard]] CAmount GetShieldedStateValueBalance(const CShieldedBundle& bundle);
[[nodiscard]] CAmount GetShieldedTxValueBalance(const CShieldedBundle& bundle);
namespace shielded {
[[nodiscard]] bool UseShieldedCanonicalFeeBuckets(const Consensus::Params& consensus, int32_t height);
[[nodiscard]] bool IsCanonicalShieldedFee(CAmount fee,
                                          const Consensus::Params& consensus,
                                          int32_t height);
[[nodiscard]] CAmount RoundShieldedFeeToCanonicalBucket(CAmount fee,
                                                        const Consensus::Params& consensus,
                                                        int32_t height);
} // namespace shielded

struct ShieldedResourceUsage {
    uint64_t verify_units{0};
    uint64_t scan_units{0};
    uint64_t tree_update_units{0};
};

[[nodiscard]] ShieldedResourceUsage GetShieldedResourceUsage(const CShieldedBundle& bundle);
[[nodiscard]] uint64_t GetShieldedVerifyCost(const CShieldedBundle& bundle);

#endif // BTX_SHIELDED_BUNDLE_H
