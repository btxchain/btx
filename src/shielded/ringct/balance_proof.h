// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_RINGCT_BALANCE_PROOF_H
#define BTX_SHIELDED_RINGCT_BALANCE_PROOF_H

#include <consensus/amount.h>
#include <shielded/ringct/commitment.h>

#include <serialize.h>
#include <uint256.h>

#include <vector>

namespace shielded::ringct {

/** Proof that sum(inputs) = sum(outputs) + fee under commitment relation. */
struct BalanceProof {
    // Commitment to a random nonce blind t = A*r.
    lattice::PolyVec nonce_commitment;
    // Schnorr-style response s = r + c*balance_blind.
    lattice::PolyVec response_blind;
    uint256 transcript_hash;

    [[nodiscard]] bool IsValid() const;
    [[nodiscard]] size_t GetSerializedSize() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        SerializePolyVecModQ23(s, nonce_commitment, "BalanceProof::Serialize nonce");
        SerializePolyVecModQ23(s, response_blind, "BalanceProof::Serialize response");
        ::Serialize(s, transcript_hash);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        UnserializePolyVecModQ23(s, nonce_commitment, "BalanceProof::Unserialize nonce");
        UnserializePolyVecModQ23(s, response_blind, "BalanceProof::Unserialize response");
        ::Unserialize(s, transcript_hash);
    }
};

/** Create balance proof from opened commitments. */
[[nodiscard]] bool CreateBalanceProof(BalanceProof& proof,
                                      const std::vector<CommitmentOpening>& input_openings,
                                      const std::vector<CommitmentOpening>& output_openings,
                                      CAmount fee,
                                      const uint256& tx_binding_hash = uint256{});

/** Verify balance proof against public commitments. */
[[nodiscard]] bool VerifyBalanceProof(const BalanceProof& proof,
                                      const std::vector<Commitment>& input_commitments,
                                      const std::vector<Commitment>& output_commitments,
                                      CAmount fee,
                                      const uint256& tx_binding_hash = uint256{});

} // namespace shielded::ringct

#endif // BTX_SHIELDED_RINGCT_BALANCE_PROOF_H
