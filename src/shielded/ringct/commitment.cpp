// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/ringct/commitment.h>

#include <hash.h>
#include <shielded/lattice/sampling.h>

#include <array>
#include <stdexcept>

namespace shielded::ringct {
namespace {

[[nodiscard]] int64_t ModQ(int64_t value)
{
    int64_t out = value % lattice::POLY_Q;
    if (out < 0) out += lattice::POLY_Q;
    return out;
}

[[nodiscard]] lattice::PolyMat BuildCommitmentMatrix()
{
    static constexpr std::array<unsigned char, 24> MATRIX_SEED{
        'B','T','X','_','M','a','t','R','i','C','T','_','C','o','m','m','i','t','_','A','_','V','1','\0'};

    lattice::PolyMat mat(lattice::MODULE_RANK, lattice::PolyVec(lattice::MODULE_RANK));
    for (size_t row = 0; row < lattice::MODULE_RANK; ++row) {
        for (size_t col = 0; col < lattice::MODULE_RANK; ++col) {
            const uint32_t nonce = static_cast<uint32_t>(row * lattice::MODULE_RANK + col);
            mat[row][col] = lattice::ExpandUniformPoly(
                Span<const unsigned char>{MATRIX_SEED.data(), MATRIX_SEED.size()}, nonce);
        }
    }
    return mat;
}

[[nodiscard]] lattice::PolyVec BuildValueGenerator()
{
    static constexpr std::array<unsigned char, 24> GENERATOR_SEED{
        'B','T','X','_','M','a','t','R','i','C','T','_','C','o','m','m','i','t','_','G','_','V','1','\0'};

    return lattice::ExpandUniformVec(
        Span<const unsigned char>{GENERATOR_SEED.data(), GENERATOR_SEED.size()}, lattice::MODULE_RANK, 4096);
}

[[nodiscard]] lattice::PolyVec ZeroBlind()
{
    return lattice::PolyVec(lattice::MODULE_RANK);
}

} // namespace

bool CommitmentOpening::IsValid() const
{
    return lattice::IsValidPolyVec(blind);
}

bool Commitment::IsValid() const
{
    return lattice::IsValidPolyVec(vec);
}

size_t Commitment::GetSerializedSize() const
{
    return POLYVEC_MODQ23_PACKED_SIZE;
}

Commitment Commit(CAmount value, const lattice::PolyVec& blind)
{
    if (!lattice::IsValidPolyVec(blind)) {
        throw std::runtime_error("Commit: invalid blinding vector length");
    }

    lattice::PolyVec committed = lattice::MatVecMul(CommitmentMatrix(), blind);
    const lattice::PolyVec& gen = ValueGenerator();
    const int64_t value_mod = ModQ(value);

    for (size_t i = 0; i < committed.size(); ++i) {
        committed[i] = committed[i] + lattice::PolyScale(gen[i], value_mod);
        committed[i].Reduce();
        committed[i].CAddQ();
    }

    return Commitment{committed};
}

Commitment CommitWithSeed(CAmount value, Span<const unsigned char> seed)
{
    lattice::PolyVec blind = lattice::ExpandUniformVec(seed, lattice::MODULE_RANK, 8192);
    return Commit(value, blind);
}

bool VerifyCommitment(const Commitment& commitment, const CommitmentOpening& opening)
{
    if (!commitment.IsValid() || !opening.IsValid()) return false;
    const Commitment recomputed = Commit(opening.value, opening.blind);
    // SideChannel F1 fix: use constant-time comparison to prevent timing
    // side-channels that could leak information about secret blinding factors.
    return lattice::PolyVecEqualCT(recomputed.vec, commitment.vec);
}

uint256 CommitmentHash(const Commitment& commitment)
{
    HashWriter hw;
    hw << commitment;
    return hw.GetSHA256();
}

Commitment CommitmentAdd(const Commitment& a, const Commitment& b)
{
    if (!a.IsValid() || !b.IsValid()) {
        throw std::runtime_error("CommitmentAdd: invalid commitment");
    }
    return Commitment{lattice::PolyVecAdd(a.vec, b.vec)};
}

Commitment CommitmentSub(const Commitment& a, const Commitment& b)
{
    if (!a.IsValid() || !b.IsValid()) {
        throw std::runtime_error("CommitmentSub: invalid commitment");
    }
    return Commitment{lattice::PolyVecSub(a.vec, b.vec)};
}

Commitment CommitmentScale(const Commitment& c, int64_t scalar)
{
    if (!c.IsValid()) {
        throw std::runtime_error("CommitmentScale: invalid commitment");
    }
    return Commitment{lattice::PolyVecScale(c.vec, scalar)};
}

Commitment CommitmentForFee(CAmount fee)
{
    return Commit(fee, ZeroBlind());
}

lattice::PolyVec CombineBlinds(const std::vector<lattice::PolyVec>& blinds, const std::vector<int64_t>& weights)
{
    if (blinds.size() != weights.size()) {
        throw std::runtime_error("CombineBlinds: size mismatch");
    }

    lattice::PolyVec acc(lattice::MODULE_RANK);
    for (size_t i = 0; i < blinds.size(); ++i) {
        if (!lattice::IsValidPolyVec(blinds[i])) {
            throw std::runtime_error("CombineBlinds: invalid blind vector");
        }
        const lattice::PolyVec scaled = lattice::PolyVecScale(blinds[i], weights[i]);
        acc = lattice::PolyVecAdd(acc, scaled);
    }
    return acc;
}

const lattice::PolyMat& CommitmentMatrix()
{
    static const lattice::PolyMat g_matrix = BuildCommitmentMatrix();
    return g_matrix;
}

const lattice::PolyVec& ValueGenerator()
{
    static const lattice::PolyVec g_vector = BuildValueGenerator();
    return g_vector;
}

} // namespace shielded::ringct
