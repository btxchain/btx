// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/ringct/range_proof.h>

#include <arith_uint256.h>
#include <crypto/timing_safe.h>
#include <hash.h>
#include <random.h>
#include <shielded/lattice/polyvec.h>
#include <shielded/lattice/sampling.h>
#include <support/cleanse.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace shielded::ringct {
namespace {

void CleansePolyVec(lattice::PolyVec& vec)
{
    if (vec.empty()) return;
    memory_cleanse(vec.data(), vec.size() * sizeof(lattice::Poly256));
}

/** Constant-time byte-level conditional swap.
 *  Swaps the contents of a and b if do_swap is non-zero.
 *  Both buffers must be the same size. */
void CtSwapBytes(void* a, void* b, size_t len, uint8_t do_swap)
{
    auto* pa = static_cast<unsigned char*>(a);
    auto* pb = static_cast<unsigned char*>(b);
    const unsigned char mask = static_cast<unsigned char>(-static_cast<int8_t>(do_swap != 0));
    for (size_t i = 0; i < len; ++i) {
        const unsigned char diff = (pa[i] ^ pb[i]) & mask;
        pa[i] ^= diff;
        pb[i] ^= diff;
    }
}

static constexpr int32_t RESPONSE_SERIALIZATION_BOUND{(1 << 23) - 1};
// Masking bound: y sampled from [-MASKING_BOUND, MASKING_BOUND] (wide range).
static constexpr int32_t MASKING_BOUND{lattice::GAMMA_RESPONSE};
// Acceptance bound: accept z iff ||z||_inf <= gamma - beta*eta (Lyubashevsky).
static constexpr int32_t RESPONSE_NORM_BOUND{
    lattice::GAMMA_RESPONSE - lattice::BETA_CHALLENGE * lattice::SECRET_SMALL_ETA};
static constexpr int64_t BIT_CHALLENGE_BOUND{lattice::BETA_CHALLENGE};
static constexpr int MAX_REJECTION_ATTEMPTS{512};
static_assert(MASKING_BOUND <= RESPONSE_SERIALIZATION_BOUND,
              "Signed24 serialization must accommodate MASKING_BOUND");
static_assert(RESPONSE_NORM_BOUND > 0, "RESPONSE_NORM_BOUND must be positive");
static_assert(RESPONSE_NORM_BOUND < MASKING_BOUND,
              "acceptance bound must be strictly less than masking bound for rejection sampling");
static_assert(lattice::VALUE_BITS < 63, "Range proof bit-width must remain below signed CAmount width");
static_assert((uint64_t{1} << lattice::VALUE_BITS) > static_cast<uint64_t>(MAX_MONEY),
              "VALUE_BITS must cover MAX_MONEY");

[[nodiscard]] int64_t DeriveBoundedChallenge(const uint256& hash, int64_t bound)
{
    const uint64_t span = static_cast<uint64_t>(2 * bound + 1);
    const uint64_t v = ReadLE64(hash.begin()) % span;
    return static_cast<int64_t>(v) - bound;
}

[[nodiscard]] int64_t ChallengeScalarFromDigest(const uint256& digest)
{
    return DeriveBoundedChallenge(digest, BIT_CHALLENGE_BOUND);
}

[[nodiscard]] uint256 AddChallengeDigests(const uint256& a, const uint256& b)
{
    arith_uint256 sum = UintToArith256(a);
    sum += UintToArith256(b);
    return ArithToUint256(sum);
}

[[nodiscard]] uint256 SubChallengeDigests(const uint256& a, const uint256& b)
{
    arith_uint256 diff = UintToArith256(a);
    diff -= UintToArith256(b);
    return ArithToUint256(diff);
}

/** Derive a polynomial challenge from the transcript hash via SampleChallenge.
 *  This provides >200-bit soundness (sparse ternary with BETA_CHALLENGE=60
 *  non-zero coefficients), replacing the prior ~23-bit scalar mod-q challenge. */
[[nodiscard]] lattice::Poly256 ChallengeFromTranscript(const uint256& transcript_hash)
{
    return lattice::SampleChallenge(
        Span<const unsigned char>{transcript_hash.begin(), uint256::size()});
}

/** Multiply each polynomial in vec by poly in R_q using NTT. */
[[nodiscard]] lattice::PolyVec PolyVecMulPoly(const lattice::PolyVec& vec, const lattice::Poly256& poly)
{
    lattice::PolyVec vec_ntt = vec;
    for (auto& p : vec_ntt) p.NTT();
    lattice::Poly256 poly_ntt = poly;
    poly_ntt.NTT();
    lattice::PolyVec out(vec_ntt.size());
    for (size_t i = 0; i < vec_ntt.size(); ++i) {
        out[i] = lattice::Poly256::PointwiseMul(vec_ntt[i], poly_ntt);
        out[i].InverseNTT();
        out[i].Reduce();
        out[i].CAddQ();
    }
    return out;
}

[[nodiscard]] bool ValueFitsRangeBits(CAmount value)
{
    if (value < 0) return false;
    if constexpr (lattice::VALUE_BITS >= 63) {
        return true;
    } else {
        return static_cast<uint64_t>(value) < (uint64_t{1} << lattice::VALUE_BITS);
    }
}

[[nodiscard]] lattice::PolyVec ZeroBlind()
{
    return lattice::PolyVec(lattice::MODULE_RANK);
}

[[nodiscard]] Commitment ZeroCommitment()
{
    return Commitment{lattice::PolyVec(lattice::MODULE_RANK)};
}

[[nodiscard]] const Commitment& OneCommitment()
{
    static const Commitment k_one = Commit(/*value=*/1, ZeroBlind());
    return k_one;
}

// NOTE: SampleBoundedCoeff uses randrange() deliberately to preserve deterministic
// RNG progression. The timing depends on ChaCha20 output, not on secret values.
[[nodiscard]] int32_t SampleBoundedCoeff(FastRandomContext& rng, int32_t bound)
{
    if (bound <= 0) return 0;
    // R7-102: Widen to uint64_t before multiply to prevent int32 overflow.
    const uint32_t span = static_cast<uint32_t>(static_cast<uint64_t>(bound) * 2 + 1);
    return static_cast<int32_t>(rng.randrange(span)) - bound;
}

[[nodiscard]] lattice::PolyVec SampleBoundedVec(FastRandomContext& rng, int32_t bound)
{
    lattice::PolyVec out(lattice::MODULE_RANK);
    for (size_t k = 0; k < lattice::MODULE_RANK; ++k) {
        for (size_t i = 0; i < lattice::POLY_N; ++i) {
            out[k].coeffs[i] = SampleBoundedCoeff(rng, bound);
        }
    }
    return out;
}

/** Sample masking vector y from [-MASKING_BOUND, MASKING_BOUND]. */
[[nodiscard]] lattice::PolyVec SampleMaskingVec(FastRandomContext& rng)
{
    return SampleBoundedVec(rng, MASKING_BOUND);
}

/** Sample simulated response from [-RESPONSE_NORM_BOUND, RESPONSE_NORM_BOUND]. */
[[nodiscard]] lattice::PolyVec SampleSimulatedResponse(FastRandomContext& rng)
{
    return SampleBoundedVec(rng, RESPONSE_NORM_BOUND);
}

// R7-103: PolyVecScaleCentered is safe because the largest product is
// MASKING_BOUND * BIT_CHALLENGE_BOUND = 131072 * 60 = 7,864,320 which fits int32_t.
// However we add a compile-time check and keep the int64_t intermediate for safety.
static_assert(static_cast<int64_t>(MASKING_BOUND) * BIT_CHALLENGE_BOUND < std::numeric_limits<int32_t>::max(),
              "PolyVecScaleCentered: product of masking bound and challenge bound must fit int32_t");

[[nodiscard]] lattice::PolyVec PolyVecScaleCentered(const lattice::PolyVec& vec, int64_t scalar)
{
    lattice::PolyVec out(vec.size());
    for (size_t i = 0; i < vec.size(); ++i) {
        for (size_t j = 0; j < lattice::POLY_N; ++j) {
            const int64_t product = static_cast<int64_t>(vec[i].coeffs[j]) * scalar;
            out[i].coeffs[j] = static_cast<int32_t>(product);
        }
    }
    return out;
}

[[nodiscard]] lattice::PolyVec PolyVecAddCentered(const lattice::PolyVec& a, const lattice::PolyVec& b)
{
    if (a.size() != b.size()) return {};
    lattice::PolyVec out(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        for (size_t j = 0; j < lattice::POLY_N; ++j) {
            out[i].coeffs[j] = static_cast<int32_t>(static_cast<int64_t>(a[i].coeffs[j]) + b[i].coeffs[j]);
        }
    }
    return out;
}

[[nodiscard]] Commitment BranchStatement(const Commitment& bit_commitment, size_t branch)
{
    if (branch == 0) return bit_commitment;
    return CommitmentSub(bit_commitment, OneCommitment());
}

[[nodiscard]] lattice::PolyVec ComputeAnnouncement(const lattice::PolyVec& z,
                                                   int64_t challenge,
                                                   const Commitment& statement)
{
    const lattice::PolyVec lhs = lattice::MatVecMul(CommitmentMatrix(), z);
    const lattice::PolyVec rhs = lattice::PolyVecScale(statement.vec, challenge);
    return lattice::PolyVecSub(lhs, rhs);
}

[[nodiscard]] uint256 ComputeBitChallengeHash(size_t bit_index,
                                              const Commitment& bit_commitment,
                                              const Commitment& value_commitment,
                                              const lattice::PolyVec& a0,
                                              const lattice::PolyVec& a1)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RangeProof_BitChallenge_V4"};
    hw << static_cast<uint32_t>(bit_index);
    hw << bit_commitment;
    hw << value_commitment;
    hw << a0;
    hw << a1;
    return hw.GetSHA256();
}

void RunRangeProofPaddingIterations(size_t bit_index,
                                    int accepted_attempt,
                                    const Commitment& bit_commitment,
                                    const Commitment& value_commitment,
                                    const lattice::PolyVec& sim_announcement_if_bit0,
                                    const lattice::PolyVec& sim_announcement_if_bit1)
{
    if (accepted_attempt < 0 || accepted_attempt >= (MAX_REJECTION_ATTEMPTS - 1)) return;

    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RangeProof_Padding_V1"};
    hw << static_cast<uint32_t>(bit_index);
    hw << bit_commitment;
    hw << value_commitment;
    hw << accepted_attempt;
    FastRandomContext padding_rng(hw.GetSHA256());

    for (int pad = accepted_attempt + 1; pad < MAX_REJECTION_ATTEMPTS; ++pad) {
        // R7-105: Use constant-time sampling in padding to prevent timing
        // side-channel leakage of accepted_attempt via RNG-dependent rejection.
        lattice::PolyVec y = lattice::SampleBoundedVecCT(padding_rng, lattice::MODULE_RANK, MASKING_BOUND);
        if (!lattice::IsValidPolyVec(y)) {
            CleansePolyVec(y);
            continue;
        }
        const lattice::PolyVec real_announcement = lattice::MatVecMul(CommitmentMatrix(), y);

        const uint256 total_challenge_if_bit0 = ComputeBitChallengeHash(
            bit_index,
            bit_commitment,
            value_commitment,
            real_announcement,
            sim_announcement_if_bit0);
        const uint256 total_challenge_if_bit1 = ComputeBitChallengeHash(
            bit_index,
            bit_commitment,
            value_commitment,
            sim_announcement_if_bit1,
            real_announcement);

        uint256 total_challenge = total_challenge_if_bit0;
        uint256 total_challenge_alt = total_challenge_if_bit1;
        const uint8_t selector = static_cast<uint8_t>(padding_rng.rand32() & 1U);
        CtSwapBytes(total_challenge.begin(), total_challenge_alt.begin(), uint256::size(), selector);
        if (total_challenge.IsNull()) {
            CleansePolyVec(y);
            continue;
        }
        uint256 simulated_challenge = padding_rng.rand256();
        if (simulated_challenge.IsNull()) simulated_challenge = uint256::ONE;
        const uint256 real_challenge = SubChallengeDigests(total_challenge, simulated_challenge);
        if (real_challenge.IsNull()) {
            CleansePolyVec(y);
            continue;
        }

        lattice::PolyVec dummy_blind = lattice::SampleSmallVec(padding_rng, lattice::MODULE_RANK, /*eta=*/2);
        const int64_t real_challenge_scalar = ChallengeScalarFromDigest(real_challenge);
        lattice::PolyVec dummy_response = PolyVecAddCentered(
            y,
            PolyVecScaleCentered(dummy_blind, real_challenge_scalar));
        (void)lattice::IsValidPolyVec(dummy_response);
        (void)lattice::PolyVecInfNorm(dummy_response);
        CleansePolyVec(dummy_response);
        CleansePolyVec(dummy_blind);
        CleansePolyVec(y);
    }
}

[[nodiscard]] uint256 ComputeRangeProofRngSeed(const CommitmentOpening& opening,
                                               const Commitment& value_commitment)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RangeProof_RNGSeed_V1"};
    hw << opening.value;
    hw << opening.blind;
    hw << value_commitment;
    return hw.GetSHA256();
}

[[nodiscard]] lattice::PolyVec SampleNonceBlind(const uint256& rng_seed)
{
    // R7-105: Use constant-time sampling since RNG is seeded from secret opening data.
    FastRandomContext rng(rng_seed);
    return lattice::SampleBoundedVecCT(rng, lattice::MODULE_RANK, MASKING_BOUND);
}

[[nodiscard]] std::vector<int64_t> BuildPow2ScalarsModQ(size_t count)
{
    std::vector<int64_t> out(count, 0);
    if (count == 0) return out;
    out[0] = 1;
    for (size_t i = 1; i < count; ++i) {
        out[i] = (out[i - 1] * 2) % lattice::POLY_Q;
    }
    return out;
}

[[nodiscard]] const std::vector<int64_t>& Pow2ScalarsModQ()
{
    static const std::vector<int64_t> k_pow2_scalars = BuildPow2ScalarsModQ(lattice::VALUE_BITS);
    return k_pow2_scalars;
}

[[nodiscard]] Commitment WeightedBitCommitmentSum(const std::vector<Commitment>& bit_commitments,
                                                  const std::vector<int64_t>& pow2_scalars)
{
    if (bit_commitments.size() != pow2_scalars.size()) return ZeroCommitment();
    Commitment out = ZeroCommitment();
    for (size_t i = 0; i < bit_commitments.size(); ++i) {
        out = CommitmentAdd(out, CommitmentScale(bit_commitments[i], pow2_scalars[i]));
    }
    return out;
}

[[nodiscard]] uint256 ComputeRelationTranscript(const lattice::PolyVec& relation_nonce_commitment,
                                                const Commitment& value_commitment,
                                                const std::vector<Commitment>& bit_commitments,
                                                const Commitment& statement_commitment)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RangeProof_Relation_V4"};
    // R5-105: Bind static lattice parameters into transcript to prevent
    // parameter-confusion attacks across different parameter sets.
    hw << static_cast<uint32_t>(lattice::POLY_N);
    hw << static_cast<int32_t>(lattice::POLY_Q);
    hw << static_cast<uint32_t>(lattice::MODULE_RANK);
    hw << relation_nonce_commitment;
    hw << value_commitment;
    hw << bit_commitments;
    hw << statement_commitment;
    return hw.GetSHA256();
}

[[nodiscard]] uint256 ComputeBitProofBinding(const Commitment& value_commitment,
                                             const std::vector<Commitment>& bit_commitments,
                                             const std::vector<RangeBitProof>& bit_proofs)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_RangeProof_Binding_V1"};
    // R5-105: Bind static lattice parameters into transcript.
    hw << static_cast<uint32_t>(lattice::POLY_N);
    hw << static_cast<int32_t>(lattice::POLY_Q);
    hw << static_cast<uint32_t>(lattice::MODULE_RANK);
    hw << value_commitment;
    hw << bit_commitments;
    for (const auto& bit_proof : bit_proofs) {
        hw << bit_proof.c0;
        hw << bit_proof.c1;
        hw << bit_proof.z0;
        hw << bit_proof.z1;
    }
    return hw.GetSHA256();
}

} // namespace

bool RangeBitProof::IsValid() const
{
    if (!lattice::IsValidPolyVec(z0)) return false;
    if (!lattice::IsValidPolyVec(z1)) return false;
    if (lattice::PolyVecInfNorm(z0) > RESPONSE_NORM_BOUND) return false;
    if (lattice::PolyVecInfNorm(z1) > RESPONSE_NORM_BOUND) return false;
    if (c0.IsNull()) return false;
    if (c1.IsNull()) return false;
    return true;
}

size_t RangeBitProof::GetSerializedSize() const
{
    const size_t vec_size = static_cast<size_t>(lattice::MODULE_RANK) *
                            lattice::POLY_N *
                            3U;
    return (2 * uint256::size()) + (2 * vec_size);
}

bool RangeProof::IsValid() const
{
    if (bit_commitments.size() != lattice::VALUE_BITS) return false;
    if (bit_proofs.size() != lattice::VALUE_BITS) return false;
    if (!lattice::IsValidPolyVec(relation_nonce_commitment)) return false;
    if (!lattice::IsValidPolyVec(relation_response_blind)) return false;
    if (bit_proof_binding.IsNull()) return false;
    if (transcript_hash.IsNull()) return false;

    for (size_t i = 0; i < lattice::VALUE_BITS; ++i) {
        if (!bit_commitments[i].IsValid()) return false;
        if (!bit_proofs[i].IsValid()) return false;
    }
    return true;
}

size_t RangeProof::GetSerializedSize() const
{
    const size_t vec_size = POLYVEC_MODQ23_PACKED_SIZE;
    size_t total{0};
    for (const auto& c : bit_commitments) total += c.GetSerializedSize();
    for (const auto& bp : bit_proofs) total += bp.GetSerializedSize();
    total += (2 * vec_size); // relation nonce + response
    total += uint256::size(); // bit_proof_binding
    total += uint256::size(); // transcript_hash
    return total;
}

bool CreateRangeProof(RangeProof& proof,
                      const CommitmentOpening& opening,
                      const Commitment& value_commitment)
{
    if (!opening.IsValid() || !value_commitment.IsValid()) return false;
    if (opening.value < 0) return false;
    if (!ValueFitsRangeBits(opening.value)) return false;
    if (!VerifyCommitment(value_commitment, opening)) return false;

    const uint256 rng_seed = ComputeRangeProofRngSeed(opening, value_commitment);
    FastRandomContext rng(rng_seed);
    const uint64_t value = static_cast<uint64_t>(opening.value);
    const std::vector<int64_t>& pow2_scalars = Pow2ScalarsModQ();

    proof.bit_commitments.assign(lattice::VALUE_BITS, ZeroCommitment());
    proof.bit_proofs.assign(lattice::VALUE_BITS, RangeBitProof{});

    lattice::PolyVec weighted_bit_blind_sum = ZeroBlind();
    Commitment weighted_bit_commitment_sum = ZeroCommitment();
    for (size_t i = 0; i < lattice::VALUE_BITS; ++i) {
        const uint8_t bit = static_cast<uint8_t>((value >> i) & 1U);
        lattice::PolyVec bit_blind = lattice::SampleSmallVec(rng, lattice::MODULE_RANK, /*eta=*/2);
        proof.bit_commitments[i] = Commit(bit, bit_blind);

        RangeBitProof& bit_proof = proof.bit_proofs[i];

        // Compute announcements and challenges for both branches uniformly.
        // We always simulate branch-1 and prove branch-0 for the commitment,
        // then swap results based on the actual bit value at the end
        // using constant-time selection to avoid secret-dependent branching.
        uint256 simulated_challenge = rng.rand256();
        if (simulated_challenge.IsNull()) simulated_challenge = uint256::ONE;
        const int64_t simulated_challenge_scalar = ChallengeScalarFromDigest(simulated_challenge);
        const lattice::PolyVec simulated_response = SampleSimulatedResponse(rng);
        if (!lattice::IsValidPolyVec(simulated_response)) return false;

        // Compute simulated announcements for both branches
        const Commitment statement0 = BranchStatement(proof.bit_commitments[i], 0);
        const Commitment statement1 = BranchStatement(proof.bit_commitments[i], 1);
        const lattice::PolyVec sim_announcement_if_bit0 = ComputeAnnouncement(simulated_response,
                                                                               simulated_challenge_scalar,
                                                                               statement1);
        const lattice::PolyVec sim_announcement_if_bit1 = ComputeAnnouncement(simulated_response,
                                                                               simulated_challenge_scalar,
                                                                               statement0);

        bool accepted{false};
        int accepted_attempt{-1};
        for (int attempt = 0; attempt < MAX_REJECTION_ATTEMPTS; ++attempt) {
            lattice::PolyVec y = SampleMaskingVec(rng);
            if (!lattice::IsValidPolyVec(y)) {
                CleansePolyVec(y);
                continue;
            }

            const lattice::PolyVec real_announcement = lattice::MatVecMul(CommitmentMatrix(), y);

            // Compute challenge hashes for both bit=0 and bit=1 cases
            const uint256 total_challenge_if_bit0 = ComputeBitChallengeHash(i,
                proof.bit_commitments[i], value_commitment,
                real_announcement, sim_announcement_if_bit0);
            const uint256 total_challenge_if_bit1 = ComputeBitChallengeHash(i,
                proof.bit_commitments[i], value_commitment,
                sim_announcement_if_bit1, real_announcement);

            // Constant-time selection: compute total_challenge for both bit values,
            // then use ct-swap to select the correct one without branching on the secret bit.
            uint256 total_challenge = total_challenge_if_bit0;
            uint256 total_challenge_alt = total_challenge_if_bit1;
            CtSwapBytes(total_challenge.begin(), total_challenge_alt.begin(), uint256::size(), bit);
            if (total_challenge.IsNull()) continue;
            const uint256 real_challenge = SubChallengeDigests(total_challenge, simulated_challenge);
            if (real_challenge.IsNull()) continue;
            const int64_t real_challenge_scalar = ChallengeScalarFromDigest(real_challenge);

            const lattice::PolyVec real_response = PolyVecAddCentered(
                y,
                PolyVecScaleCentered(bit_blind, real_challenge_scalar));
            if (!lattice::IsValidPolyVec(real_response)) continue;
            if (lattice::PolyVecInfNorm(real_response) > RESPONSE_NORM_BOUND) continue;

            // Assign as if bit=0 (real on branch 0, simulated on branch 1),
            // then constant-time swap if bit=1.
            bit_proof.c0 = real_challenge;
            bit_proof.z0 = real_response;
            bit_proof.c1 = simulated_challenge;
            bit_proof.z1 = simulated_response;
            CtSwapBytes(bit_proof.c0.begin(), bit_proof.c1.begin(), uint256::size(), bit);
            CtSwapBytes(bit_proof.z0.data(), bit_proof.z1.data(),
                        bit_proof.z0.size() * sizeof(lattice::Poly256), bit);
            CleansePolyVec(y);
            accepted = true;
            accepted_attempt = attempt;
            break;
        }
        RunRangeProofPaddingIterations(i,
                                       accepted_attempt,
                                       proof.bit_commitments[i],
                                       value_commitment,
                                       sim_announcement_if_bit0,
                                       sim_announcement_if_bit1);
        if (!accepted) return false;

        weighted_bit_blind_sum = lattice::PolyVecAdd(
            weighted_bit_blind_sum,
            lattice::PolyVecScale(bit_blind, pow2_scalars[i]));
        weighted_bit_commitment_sum = CommitmentAdd(
            weighted_bit_commitment_sum,
            CommitmentScale(proof.bit_commitments[i], pow2_scalars[i]));

        // Cleanse per-bit blinding factor immediately after use.
        CleansePolyVec(bit_blind);
    }

    lattice::PolyVec statement_blind = lattice::PolyVecSub(opening.blind, weighted_bit_blind_sum);

    const Commitment statement = CommitmentSub(value_commitment, weighted_bit_commitment_sum);
    // SideChannel F1 fix: constant-time comparison for secret-dependent data.
    if (!lattice::PolyVecEqualCT(statement.vec, Commit(/*value=*/0, statement_blind).vec)) {
        CleansePolyVec(statement_blind);
        CleansePolyVec(weighted_bit_blind_sum);
        return false;
    }

    lattice::PolyVec nonce_blind = SampleNonceBlind(rng_seed);
    proof.relation_nonce_commitment = Commit(/*value=*/0, nonce_blind).vec;
    proof.transcript_hash = ComputeRelationTranscript(proof.relation_nonce_commitment,
                                                      value_commitment,
                                                      proof.bit_commitments,
                                                      statement);
    const lattice::Poly256 challenge = ChallengeFromTranscript(proof.transcript_hash);
    proof.relation_response_blind = lattice::PolyVecAdd(
        nonce_blind,
        PolyVecMulPoly(statement_blind, challenge));
    proof.bit_proof_binding = ComputeBitProofBinding(value_commitment, proof.bit_commitments, proof.bit_proofs);

    // Cleanse all secret blinding factor material from the stack.
    CleansePolyVec(statement_blind);
    CleansePolyVec(weighted_bit_blind_sum);
    CleansePolyVec(nonce_blind);

    return proof.IsValid();
}

bool VerifyRangeProof(const RangeProof& proof,
                      const Commitment& value_commitment)
{
    if (!proof.IsValid() || !value_commitment.IsValid()) return false;
    const std::vector<int64_t>& pow2_scalars = Pow2ScalarsModQ();
    if (!TimingSafeEqual(proof.bit_proof_binding, ComputeBitProofBinding(value_commitment,
                                                                         proof.bit_commitments,
                                                                         proof.bit_proofs))) {
        return false;
    }

    for (size_t i = 0; i < lattice::VALUE_BITS; ++i) {
        const Commitment statement0 = BranchStatement(proof.bit_commitments[i], /*branch=*/0);
        const Commitment statement1 = BranchStatement(proof.bit_commitments[i], /*branch=*/1);
        const int64_t c0_scalar = ChallengeScalarFromDigest(proof.bit_proofs[i].c0);
        const int64_t c1_scalar = ChallengeScalarFromDigest(proof.bit_proofs[i].c1);

        const lattice::PolyVec a0 = ComputeAnnouncement(proof.bit_proofs[i].z0,
                                                        c0_scalar,
                                                        statement0);
        const lattice::PolyVec a1 = ComputeAnnouncement(proof.bit_proofs[i].z1,
                                                        c1_scalar,
                                                        statement1);

        const uint256 expected = ComputeBitChallengeHash(i, proof.bit_commitments[i], value_commitment, a0, a1);
        if (!TimingSafeEqual(AddChallengeDigests(proof.bit_proofs[i].c0, proof.bit_proofs[i].c1), expected)) return false;
    }

    const Commitment weighted_bits = WeightedBitCommitmentSum(proof.bit_commitments, pow2_scalars);
    const Commitment statement = CommitmentSub(value_commitment, weighted_bits);

    const uint256 expected_transcript = ComputeRelationTranscript(proof.relation_nonce_commitment,
                                                                  value_commitment,
                                                                  proof.bit_commitments,
                                                                  statement);
    if (!TimingSafeEqual(expected_transcript, proof.transcript_hash)) return false;

    const lattice::Poly256 challenge = ChallengeFromTranscript(expected_transcript);
    const Commitment lhs = Commit(/*value=*/0, proof.relation_response_blind);
    const Commitment rhs = CommitmentAdd(Commitment{proof.relation_nonce_commitment},
                                         Commitment{PolyVecMulPoly(statement.vec, challenge)});
    return lattice::PolyVecEqualCT(lhs.vec, rhs.vec);
}

} // namespace shielded::ringct
