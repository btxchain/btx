// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_RINGCT_RANGE_PROOF_H
#define BTX_SHIELDED_RINGCT_RANGE_PROOF_H

#include <shielded/lattice/params.h>
#include <shielded/ringct/commitment.h>

#include <serialize.h>
#include <uint256.h>

#include <array>
#include <limits>
#include <stdexcept>
#include <vector>

namespace shielded::ringct {

/** OR-proof that a bit commitment opens to either 0 or 1. */
struct RangeBitProof {
    uint256 c0;
    uint256 c1;
    lattice::PolyVec z0;
    lattice::PolyVec z1;

    [[nodiscard]] bool IsValid() const;
    [[nodiscard]] size_t GetSerializedSize() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        ::Serialize(s, c0);
        ::Serialize(s, c1);
        SerializePolyVecSigned24(s, z0, "RangeBitProof::Serialize z0");
        SerializePolyVecSigned24(s, z1, "RangeBitProof::Serialize z1");
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        ::Unserialize(s, c0);
        ::Unserialize(s, c1);
        UnserializePolyVecSigned24(s, z0, "RangeBitProof::Unserialize z0");
        UnserializePolyVecSigned24(s, z1, "RangeBitProof::Unserialize z1");
    }
};

/** Range proof with hidden bit decomposition and commitment relation checks. */
struct RangeProof {
    // Commitment per bit of the (hidden) value decomposition.
    std::vector<Commitment> bit_commitments;

    // OR-proof per bit: committed bit is 0 or 1.
    std::vector<RangeBitProof> bit_proofs;

    // Schnorr-style proof for value_commitment - sum(2^i * bit_commitments[i]) = Commit(0, blind_delta).
    lattice::PolyVec relation_nonce_commitment;
    lattice::PolyVec relation_response_blind;
    uint256 bit_proof_binding;
    uint256 transcript_hash;

    [[nodiscard]] bool IsValid() const;
    [[nodiscard]] size_t GetSerializedSize() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (bit_commitments.size() != lattice::VALUE_BITS || bit_proofs.size() != lattice::VALUE_BITS) {
            throw std::ios_base::failure("RangeProof::Serialize invalid bit vector sizes");
        }
        for (size_t i = 0; i < lattice::VALUE_BITS; ++i) {
            ::Serialize(s, bit_commitments[i]);
            ::Serialize(s, bit_proofs[i]);
        }
        SerializePolyVecModQ23(s, relation_nonce_commitment, "RangeProof::Serialize relation_nonce_commitment");
        SerializePolyVecModQ23(s, relation_response_blind, "RangeProof::Serialize relation_response_blind");
        ::Serialize(s, bit_proof_binding);
        ::Serialize(s, transcript_hash);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        bit_commitments.assign(lattice::VALUE_BITS, Commitment{});
        bit_proofs.assign(lattice::VALUE_BITS, RangeBitProof{});
        for (size_t i = 0; i < lattice::VALUE_BITS; ++i) {
            ::Unserialize(s, bit_commitments[i]);
            ::Unserialize(s, bit_proofs[i]);
        }
        UnserializePolyVecModQ23(s, relation_nonce_commitment, "RangeProof::Unserialize relation_nonce_commitment");
        UnserializePolyVecModQ23(s, relation_response_blind, "RangeProof::Unserialize relation_response_blind");
        ::Unserialize(s, bit_proof_binding);
        ::Unserialize(s, transcript_hash);
    }
};

/** Create range proof for an opened commitment. */
[[nodiscard]] bool CreateRangeProof(RangeProof& proof,
                                    const CommitmentOpening& opening,
                                    const Commitment& value_commitment);

/** Verify range proof against a public value commitment. */
[[nodiscard]] bool VerifyRangeProof(const RangeProof& proof,
                                    const Commitment& value_commitment);

} // namespace shielded::ringct

#endif // BTX_SHIELDED_RINGCT_RANGE_PROOF_H
