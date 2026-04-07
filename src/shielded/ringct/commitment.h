// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_RINGCT_COMMITMENT_H
#define BTX_SHIELDED_RINGCT_COMMITMENT_H

#include <consensus/amount.h>
#include <shielded/lattice/polymat.h>
#include <shielded/ringct/proof_encoding.h>

#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <vector>

namespace shielded::ringct {

/** Opening witness for a lattice commitment. */
struct CommitmentOpening {
    CAmount value{0};
    lattice::PolyVec blind;

    [[nodiscard]] bool IsValid() const;

    SERIALIZE_METHODS(CommitmentOpening, obj)
    {
        READWRITE(obj.value, obj.blind);
    }
};

/** Lattice Pedersen-like commitment vector in module-R_q^k. */
struct Commitment {
    lattice::PolyVec vec;

    [[nodiscard]] bool IsValid() const;
    [[nodiscard]] size_t GetSerializedSize() const;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        SerializePolyVecModQ23(s, vec, "Commitment::Serialize");
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        UnserializePolyVecModQ23(s, vec, "Commitment::Unserialize");
    }
};

/** Commit to a value with explicit blinding vector. */
[[nodiscard]] Commitment Commit(CAmount value, const lattice::PolyVec& blind);

/** Deterministic commitment helper using seed-derived blind. */
[[nodiscard]] Commitment CommitWithSeed(CAmount value, Span<const unsigned char> seed);

/** Verify a commitment opening. */
[[nodiscard]] bool VerifyCommitment(const Commitment& commitment, const CommitmentOpening& opening);

/** Compact digest used as public commitment identifier. */
[[nodiscard]] uint256 CommitmentHash(const Commitment& commitment);

/** Add commitments component-wise (mod q). */
[[nodiscard]] Commitment CommitmentAdd(const Commitment& a, const Commitment& b);

/** Subtract commitments component-wise (mod q). */
[[nodiscard]] Commitment CommitmentSub(const Commitment& a, const Commitment& b);

/** Scale commitment by scalar (mod q). */
[[nodiscard]] Commitment CommitmentScale(const Commitment& c, int64_t scalar);

/** Public commitment for a known fee amount (zero blinding). */
[[nodiscard]] Commitment CommitmentForFee(CAmount fee);

/** Weighted sum of blind vectors (mod q). */
[[nodiscard]] lattice::PolyVec CombineBlinds(const std::vector<lattice::PolyVec>& blinds,
                                             const std::vector<int64_t>& weights);

/** Public matrix A used by commitments. */
[[nodiscard]] const lattice::PolyMat& CommitmentMatrix();

/** Public generator vector g used for value term. */
[[nodiscard]] const lattice::PolyVec& ValueGenerator();

} // namespace shielded::ringct

#endif // BTX_SHIELDED_RINGCT_COMMITMENT_H
