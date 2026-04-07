// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_RINGCT_RING_SIGNATURE_H
#define BTX_SHIELDED_RINGCT_RING_SIGNATURE_H

#include <consensus/amount.h>
#include <shielded/note.h>
#include <shielded/lattice/polyvec.h>
#include <shielded/ringct/commitment.h>

#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <limits>
#include <stdexcept>
#include <vector>

namespace shielded::ringct {

static constexpr size_t MAX_RING_SIGNATURE_INPUTS{128};

/** One ring input's per-member challenge/response material. */
struct RingInputProof {
    // Per-member responses z_j.
    std::vector<lattice::PolyVec> responses;

    // Per-member Fiat-Shamir challenge digests c_j.
    std::vector<uint256> challenges;

    [[nodiscard]] bool IsValid(size_t expected_ring_size) const;
    [[nodiscard]] size_t GetSerializedSize() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint64_t response_count = responses.size();
        ::Serialize(s, response_count);
        for (const auto& response : responses) {
            SerializePolyVecSigned24(s, response, "RingInputProof::Serialize response");
        }

        if (challenges.size() != responses.size()) {
            throw std::ios_base::failure("RingInputProof::Serialize challenge/response size mismatch");
        }
        const uint64_t challenge_count = challenges.size();
        ::Serialize(s, challenge_count);
        for (const uint256& challenge : challenges) {
            ::Serialize(s, challenge);
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint64_t response_count{0};
        ::Unserialize(s, response_count);
        if (response_count > static_cast<uint64_t>(lattice::MAX_RING_SIZE)) {
            throw std::ios_base::failure("RingInputProof::Unserialize oversized response count");
        }
        responses.assign(response_count, lattice::PolyVec(lattice::MODULE_RANK));
        for (size_t i = 0; i < response_count; ++i) {
            UnserializePolyVecSigned24(s, responses[i], "RingInputProof::Unserialize response");
        }
        uint64_t challenge_count{0};
        ::Unserialize(s, challenge_count);
        if (challenge_count != response_count || challenge_count > static_cast<uint64_t>(lattice::MAX_RING_SIZE)) {
            throw std::ios_base::failure("RingInputProof::Unserialize invalid challenge count");
        }
        challenges.resize(challenge_count);
        for (size_t i = 0; i < challenge_count; ++i) {
            ::Unserialize(s, challenges[i]);
        }
    }
};

/** Linkable MLWE-style ring signature proof object. */
struct RingSignature {
    // Per-input ring challenge/response vectors.
    std::vector<RingInputProof> input_proofs;

    // One key image per real input.
    std::vector<lattice::PolyVec> key_images;

    // Per-input per-member public-key offsets used to bind signer witnesses into ring equations.
    std::vector<std::vector<lattice::PolyVec>> member_public_key_offsets;

    // Fiat-Shamir transcript challenge.
    uint256 challenge_seed;

    [[nodiscard]] bool IsValid(size_t expected_inputs, size_t expected_ring_size) const;
    [[nodiscard]] size_t GetSerializedSize() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint64_t input_proof_count = input_proofs.size();
        if (input_proof_count > static_cast<uint64_t>(MAX_RING_SIGNATURE_INPUTS)) {
            throw std::ios_base::failure("RingSignature::Serialize oversized input_proofs count");
        }
        ::Serialize(s, COMPACTSIZE(input_proof_count));
        for (const RingInputProof& input_proof : input_proofs) {
            ::Serialize(s, input_proof);
        }
        const uint64_t key_image_count = key_images.size();
        ::Serialize(s, key_image_count);
        for (const auto& key_image : key_images) {
            SerializePolyVecModQ23(s, key_image, "RingSignature::Serialize key_image");
        }
        if (member_public_key_offsets.size() != input_proofs.size()) {
            throw std::ios_base::failure("RingSignature::Serialize member_public_key_offsets/input_proof size mismatch");
        }
        const uint64_t input_offset_count = member_public_key_offsets.size();
        ::Serialize(s, input_offset_count);
        for (const auto& input_offsets : member_public_key_offsets) {
            const uint64_t member_offset_count = input_offsets.size();
            if (member_offset_count > static_cast<uint64_t>(lattice::MAX_RING_SIZE)) {
                throw std::ios_base::failure("RingSignature::Serialize oversized member_public_key_offsets row");
            }
            ::Serialize(s, member_offset_count);
            for (const auto& offset : input_offsets) {
                SerializePolyVecModQ23(s, offset, "RingSignature::Serialize member_public_key_offset");
            }
        }
        ::Serialize(s, challenge_seed);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint64_t input_proof_count{0};
        ::Unserialize(s, COMPACTSIZE(input_proof_count));
        if (input_proof_count > static_cast<uint64_t>(MAX_RING_SIGNATURE_INPUTS)) {
            throw std::ios_base::failure("RingSignature::Unserialize oversized input_proofs count");
        }
        input_proofs.assign(input_proof_count, {});
        for (RingInputProof& input_proof : input_proofs) {
            ::Unserialize(s, input_proof);
        }
        uint64_t key_image_count{0};
        ::Unserialize(s, key_image_count);
        if (key_image_count > static_cast<uint64_t>(MAX_RING_SIGNATURE_INPUTS)) {
            throw std::ios_base::failure("RingSignature::Unserialize oversized key_image count");
        }
        key_images.assign(key_image_count, lattice::PolyVec(lattice::MODULE_RANK));
        for (size_t i = 0; i < key_image_count; ++i) {
            UnserializePolyVecModQ23(s, key_images[i], "RingSignature::Unserialize key_image");
        }
        uint64_t input_offset_count{0};
        ::Unserialize(s, input_offset_count);
        if (input_offset_count > static_cast<uint64_t>(MAX_RING_SIGNATURE_INPUTS)) {
            throw std::ios_base::failure("RingSignature::Unserialize oversized member_public_key_offsets count");
        }
        member_public_key_offsets.assign(input_offset_count, {});
        for (size_t input_idx = 0; input_idx < input_offset_count; ++input_idx) {
            uint64_t member_offset_count{0};
            ::Unserialize(s, member_offset_count);
            if (member_offset_count > static_cast<uint64_t>(lattice::MAX_RING_SIZE)) {
                throw std::ios_base::failure("RingSignature::Unserialize oversized member_public_key_offsets row");
            }
            member_public_key_offsets[input_idx].assign(member_offset_count, lattice::PolyVec(lattice::MODULE_RANK));
            for (size_t member_idx = 0; member_idx < member_offset_count; ++member_idx) {
                UnserializePolyVecModQ23(s,
                                         member_public_key_offsets[input_idx][member_idx],
                                         "RingSignature::Unserialize member_public_key_offset");
            }
        }
        ::Unserialize(s, challenge_seed);
        if (key_images.size() != input_proofs.size() ||
            member_public_key_offsets.size() != input_proofs.size()) {
            throw std::ios_base::failure("RingSignature::Unserialize vector count mismatch");
        }
        for (size_t i = 0; i < member_public_key_offsets.size(); ++i) {
            if (member_public_key_offsets[i].size() != input_proofs[i].responses.size()) {
                throw std::ios_base::failure("RingSignature::Unserialize member_public_key_offsets row mismatch");
            }
        }
    }
};

/** Build message hash over value commitments for ring signing. */
[[nodiscard]] uint256 RingSignatureMessageHash(const std::vector<Commitment>& input_commitments,
                                               const std::vector<Commitment>& output_commitments,
                                               CAmount fee,
                                               const std::vector<Nullifier>& input_nullifiers,
                                               const uint256& tx_binding_hash = uint256{});

/** Compute deterministic nullifier from one ring key image. */
[[nodiscard]] Nullifier ComputeNullifierFromKeyImage(const lattice::PolyVec& key_image);

/** Derive deterministic input secret witness from wallet spend key material and note data. */
[[nodiscard]] bool DeriveInputSecretFromNote(lattice::PolyVec& out_secret,
                                             Span<const unsigned char> spending_key,
                                             const ShieldedNote& note);

/** Derive deterministic nullifier from a secret witness and real ring-member commitment. */
[[nodiscard]] bool DeriveInputNullifierFromSecret(Nullifier& out_nullifier,
                                                  const lattice::PolyVec& input_secret,
                                                  const uint256& ring_member_commitment);

/** Derive deterministic nullifier directly from note data and ring-member commitment. */
[[nodiscard]] bool DeriveInputNullifierForNote(Nullifier& out_nullifier,
                                               Span<const unsigned char> spending_key,
                                               const ShieldedNote& note,
                                               const uint256& ring_member_commitment);

/** Verify that each input nullifier matches the corresponding ring key image. */
[[nodiscard]] bool VerifyRingSignatureNullifierBinding(const RingSignature& signature,
                                                       const std::vector<Nullifier>& input_nullifiers);

/** Create a ring signature over public ring members and message hash. */
[[nodiscard]] bool CreateRingSignature(RingSignature& signature,
                                       const std::vector<std::vector<uint256>>& ring_members,
                                       const std::vector<size_t>& real_indices,
                                       const std::vector<lattice::PolyVec>& input_secrets,
                                       const uint256& message_hash,
                                       Span<const unsigned char> rng_entropy = {},
                                       bool allow_duplicate_ring_members = false);

/** Verify a ring signature. Stateless and thread-safe. */
[[nodiscard]] bool VerifyRingSignature(const RingSignature& signature,
                                       const std::vector<std::vector<uint256>>& ring_members,
                                       const uint256& message_hash);

/** Export the finalized Fiat-Shamir transcript chunks used to derive the
 *  ring-signature challenge seed. This supports independent transcript
 *  checking without exposing verifier internals in the caller. */
[[nodiscard]] bool ExportRingSignatureTranscriptChunks(
    std::vector<std::vector<std::vector<unsigned char>>>& out_chunks,
    const RingSignature& signature,
    const std::vector<std::vector<uint256>>& ring_members,
    const uint256& message_hash);

} // namespace shielded::ringct

#endif // BTX_SHIELDED_RINGCT_RING_SIGNATURE_H
