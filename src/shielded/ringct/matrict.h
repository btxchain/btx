// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_RINGCT_MATRICT_H
#define BTX_SHIELDED_RINGCT_MATRICT_H

#include <consensus/amount.h>
#include <consensus/params.h>
#include <primitives/transaction.h>
#include <shielded/note.h>
#include <shielded/ringct/balance_proof.h>
#include <shielded/ringct/range_proof.h>
#include <shielded/ringct/ring_signature.h>

#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <ios>
#include <stdexcept>
#include <vector>

namespace shielded::ringct {

static constexpr size_t MAX_MATRICT_INPUTS{MAX_SHIELDED_SPENDS_PER_TX};
static constexpr size_t MAX_MATRICT_OUTPUTS{MAX_SHIELDED_OUTPUTS_PER_TX};

/** Unified MatRiCT+ proof for one transaction bundle. */
struct MatRiCTProof {
    RingSignature ring_signature;
    BalanceProof balance_proof;
    std::vector<RangeProof> output_range_proofs;

    std::vector<Commitment> input_commitments;
    std::vector<Commitment> output_commitments;
    std::vector<uint256> output_note_commitments;

    uint256 challenge_seed;

    [[nodiscard]] size_t GetSerializedSize() const;
    [[nodiscard]] bool IsValid() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, ring_signature);
        ::Serialize(s, balance_proof);

        if (output_range_proofs.size() > MAX_MATRICT_OUTPUTS) {
            throw std::ios_base::failure("MatRiCTProof::Serialize oversized output_range_proofs");
        }
        if (input_commitments.size() > MAX_MATRICT_INPUTS) {
            throw std::ios_base::failure("MatRiCTProof::Serialize oversized input_commitments");
        }
        if (output_commitments.size() > MAX_MATRICT_OUTPUTS) {
            throw std::ios_base::failure("MatRiCTProof::Serialize oversized output_commitments");
        }
        if (output_note_commitments.size() > MAX_MATRICT_OUTPUTS) {
            throw std::ios_base::failure("MatRiCTProof::Serialize oversized output_note_commitments");
        }

        uint64_t count = output_range_proofs.size();
        ::Serialize(s, COMPACTSIZE(count));
        for (const auto& proof : output_range_proofs) {
            ::Serialize(s, proof);
        }

        count = input_commitments.size();
        ::Serialize(s, COMPACTSIZE(count));
        for (const auto& commitment : input_commitments) {
            ::Serialize(s, commitment);
        }

        count = output_commitments.size();
        ::Serialize(s, COMPACTSIZE(count));
        for (const auto& commitment : output_commitments) {
            ::Serialize(s, commitment);
        }

        count = output_note_commitments.size();
        ::Serialize(s, COMPACTSIZE(count));
        for (const auto& commitment : output_note_commitments) {
            ::Serialize(s, commitment);
        }

        ::Serialize(s, challenge_seed);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, ring_signature);
        ::Unserialize(s, balance_proof);

        uint64_t count{0};

        ::Unserialize(s, COMPACTSIZE(count));
        if (count > static_cast<uint64_t>(MAX_MATRICT_OUTPUTS)) {
            throw std::ios_base::failure("MatRiCTProof::Unserialize oversized output_range_proofs");
        }
        output_range_proofs.assign(count, RangeProof{});
        for (auto& proof : output_range_proofs) {
            ::Unserialize(s, proof);
        }

        ::Unserialize(s, COMPACTSIZE(count));
        if (count > static_cast<uint64_t>(MAX_MATRICT_INPUTS)) {
            throw std::ios_base::failure("MatRiCTProof::Unserialize oversized input_commitments");
        }
        input_commitments.assign(count, Commitment{});
        for (auto& commitment : input_commitments) {
            ::Unserialize(s, commitment);
        }

        ::Unserialize(s, COMPACTSIZE(count));
        if (count > static_cast<uint64_t>(MAX_MATRICT_OUTPUTS)) {
            throw std::ios_base::failure("MatRiCTProof::Unserialize oversized output_commitments");
        }
        output_commitments.assign(count, Commitment{});
        for (auto& commitment : output_commitments) {
            ::Unserialize(s, commitment);
        }

        ::Unserialize(s, COMPACTSIZE(count));
        if (count > static_cast<uint64_t>(MAX_MATRICT_OUTPUTS)) {
            throw std::ios_base::failure("MatRiCTProof::Unserialize oversized output_note_commitments");
        }
        output_note_commitments.assign(count, uint256{});
        for (auto& commitment : output_note_commitments) {
            ::Unserialize(s, commitment);
        }

        ::Unserialize(s, challenge_seed);

        if (output_range_proofs.size() != output_commitments.size()) {
            throw std::ios_base::failure("MatRiCTProof::Unserialize output range/commitment size mismatch");
        }
        if (output_note_commitments.size() != output_commitments.size()) {
            throw std::ios_base::failure("MatRiCTProof::Unserialize output note commitment size mismatch");
        }
        if (ring_signature.input_proofs.size() != input_commitments.size()) {
            throw std::ios_base::failure("MatRiCTProof::Unserialize ring/input commitment size mismatch");
        }
    }
};

/** Compute deterministic proof binding hash over a transaction with proof bytes stripped. */
[[nodiscard]] uint256 ComputeMatRiCTBindingHash(const CTransaction& tx);
[[nodiscard]] uint256 ComputeMatRiCTBindingHash(const CMutableTransaction& tx);
[[nodiscard]] uint256 ComputeMatRiCTBindingHash(const CTransaction& tx,
                                                const Consensus::Params& consensus,
                                                int32_t validation_height);
[[nodiscard]] uint256 ComputeMatRiCTBindingHash(const CMutableTransaction& tx,
                                                const Consensus::Params& consensus,
                                                int32_t validation_height);

/** Create a MatRiCT+ proof. */
[[nodiscard]] bool CreateMatRiCTProof(MatRiCTProof& proof,
                                      const std::vector<ShieldedNote>& input_notes,
                                      const std::vector<ShieldedNote>& output_notes,
                                      Span<const uint256> output_note_commitments,
                                      const std::vector<Nullifier>& input_nullifiers,
                                      const std::vector<std::vector<uint256>>& ring_members,
                                      const std::vector<size_t>& real_indices,
                                      Span<const unsigned char> spending_key,
                                      CAmount fee,
                                      const uint256& tx_binding_hash = uint256{},
                                      Span<const unsigned char> rng_entropy = {},
                                      bool allow_singleton_ring = false);
[[nodiscard]] bool CreateMatRiCTProof(MatRiCTProof& proof,
                                      const std::vector<ShieldedNote>& input_notes,
                                      const std::vector<ShieldedNote>& output_notes,
                                      const std::vector<Nullifier>& input_nullifiers,
                                      const std::vector<std::vector<uint256>>& ring_members,
                                      const std::vector<size_t>& real_indices,
                                      Span<const unsigned char> spending_key,
                                      CAmount fee,
                                      const uint256& tx_binding_hash = uint256{},
                                      Span<const unsigned char> rng_entropy = {},
                                      bool allow_singleton_ring = false);

/** Verify a MatRiCT+ proof. Thread-safe and stateless. */
[[nodiscard]] bool VerifyMatRiCTProof(const MatRiCTProof& proof,
                                      const std::vector<std::vector<uint256>>& ring_member_commitments,
                                      const std::vector<Nullifier>& input_nullifiers,
                                      const std::vector<uint256>& output_commitments,
                                      CAmount fee,
                                      const uint256& tx_binding_hash = uint256{},
                                      bool allow_singleton_ring = false);

} // namespace shielded::ringct

#endif // BTX_SHIELDED_RINGCT_MATRICT_H
