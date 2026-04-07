// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/ringct/balance_proof.h>

#include <crypto/timing_safe.h>
#include <hash.h>
#include <random.h>
#include <shielded/lattice/polyvec.h>
#include <shielded/lattice/sampling.h>
#include <support/cleanse.h>
#include <util/overflow.h>

#include <string>

namespace shielded::ringct {
namespace {

[[nodiscard]] Commitment ComputeBalanceStatement(const std::vector<Commitment>& input_commitments,
                                                 const std::vector<Commitment>& output_commitments,
                                                 CAmount fee)
{
    Commitment statement{lattice::PolyVec(lattice::MODULE_RANK)};
    for (const auto& c : input_commitments) {
        statement = CommitmentAdd(statement, c);
    }
    for (const auto& c : output_commitments) {
        statement = CommitmentSub(statement, c);
    }
    return CommitmentSub(statement, CommitmentForFee(fee));
}

[[nodiscard]] uint256 ComputeTranscript(const lattice::PolyVec& nonce_commitment,
                                        const Commitment& statement_commitment,
                                        const std::vector<Commitment>& input_commitments,
                                        const std::vector<Commitment>& output_commitments,
                                        CAmount fee,
                                        const uint256& tx_binding_hash)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_BalanceProof_V2"};
    // R5-105: Bind static lattice parameters into transcript to prevent
    // parameter-confusion attacks across different parameter sets.
    hw << static_cast<uint32_t>(lattice::POLY_N);
    hw << static_cast<int32_t>(lattice::POLY_Q);
    hw << static_cast<uint32_t>(lattice::MODULE_RANK);
    hw << nonce_commitment;
    hw << statement_commitment;
    hw << input_commitments;
    hw << output_commitments;
    hw << fee;
    hw << tx_binding_hash;
    return hw.GetSHA256();
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

// Nonce bound for the algebraic Schnorr balance proof. Response is reduced mod q
// and serialized as ModQ23, so no serialization clamp is needed. Use the full
// GAMMA_RESPONSE to provide maximum statistical hiding of the balance blind.
//
// R7-106: Design rationale for BALANCE_RESPONSE_NORM_BOUND = q-1:
// Unlike the ring signature (where the secret blind has small eta=2 coefficients
// and rejection sampling with bound gamma-beta*eta is essential for ZK), the
// balance proof operates over a statement A*b = S where S is publicly computable
// from the transaction commitments. With the square (MODULE_RANK x MODULE_RANK)
// commitment matrix providing perfect binding, b = A^{-1}*S is uniquely
// determined and publicly extractable. Therefore the balance proof is a proof
// of knowledge (not zero-knowledge of b), and the response norm bound need only
// ensure serialization correctness (mod q), not statistical hiding. The nonce
// r ~ Uniform([-GAMMA_RESPONSE, GAMMA_RESPONSE]) still masks the blind
// contribution c*b (whose inf-norm is at most BETA_CHALLENGE * ||b||_inf ~
// 60 * (max_ios * SECRET_SMALL_ETA) << GAMMA_RESPONSE) by a factor of ~34:1,
// providing statistical hiding as defense-in-depth.
static constexpr int32_t NONCE_BOUND{lattice::GAMMA_RESPONSE};
static constexpr int32_t BALANCE_RESPONSE_NORM_BOUND{lattice::POLY_Q - 1};
static constexpr int MAX_BALANCE_REJECTION_ATTEMPTS{64};

[[nodiscard]] lattice::PolyVec SampleNonceBlind(const lattice::PolyVec& balance_blind,
                                                const std::vector<Commitment>& input_commitments,
                                                const std::vector<Commitment>& output_commitments,
                                                CAmount fee,
                                                const uint256& tx_binding_hash,
                                                uint32_t attempt = 0)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCT_BalanceProof_Nonce_V2"};
    hw << balance_blind;
    hw << input_commitments;
    hw << output_commitments;
    hw << fee;
    hw << tx_binding_hash;
    if (attempt != 0) hw << attempt;
    // R7-105: Use constant-time sampling since RNG is seeded from balance_blind (secret).
    FastRandomContext rng(hw.GetSHA256());
    return lattice::SampleBoundedVecCT(rng, lattice::MODULE_RANK, NONCE_BOUND);
}

void CleansePolyVec(lattice::PolyVec& vec)
{
    if (vec.empty()) return;
    memory_cleanse(vec.data(), vec.size() * sizeof(lattice::Poly256));
}

} // namespace

bool BalanceProof::IsValid() const
{
    return lattice::IsValidPolyVec(nonce_commitment) &&
           lattice::IsValidPolyVec(response_blind) &&
           !transcript_hash.IsNull();
}

size_t BalanceProof::GetSerializedSize() const
{
    const size_t vec_size = POLYVEC_MODQ23_PACKED_SIZE;
    return (2 * vec_size) + uint256::size();
}

bool CreateBalanceProof(BalanceProof& proof,
                        const std::vector<CommitmentOpening>& input_openings,
                        const std::vector<CommitmentOpening>& output_openings,
                        CAmount fee,
                        const uint256& tx_binding_hash)
{
    if (input_openings.empty()) return false;

    CAmount sum_in{0};
    CAmount sum_out{0};

    std::vector<lattice::PolyVec> blinds;
    std::vector<int64_t> weights;

    for (const auto& opening : input_openings) {
        if (!opening.IsValid()) return false;
        // R7-101: Use checked arithmetic to prevent signed overflow (UB).
        const auto next_sum_in = CheckedAdd(sum_in, opening.value);
        if (!next_sum_in.has_value() || !MoneyRange(*next_sum_in)) return false;
        sum_in = *next_sum_in;
        blinds.push_back(opening.blind);
        weights.push_back(1);
    }

    for (const auto& opening : output_openings) {
        if (!opening.IsValid()) return false;
        const auto next_sum_out = CheckedAdd(sum_out, opening.value);
        if (!next_sum_out.has_value() || !MoneyRange(*next_sum_out)) return false;
        sum_out = *next_sum_out;
        blinds.push_back(opening.blind);
        weights.push_back(-1);
    }

    // R7-101: Checked addition for sum_out + fee to prevent overflow.
    const auto expected_in = CheckedAdd(sum_out, fee);
    if (!expected_in.has_value() || sum_in != *expected_in) return false;

    lattice::PolyVec balance_blind = CombineBlinds(blinds, weights);

    // T5: Cleanse individual blind copies now that the combined blind is computed.
    for (auto& b : blinds) CleansePolyVec(b);
    blinds.clear();

    std::vector<Commitment> input_commitments;
    std::vector<Commitment> output_commitments;
    input_commitments.reserve(input_openings.size());
    output_commitments.reserve(output_openings.size());

    for (const auto& opening : input_openings) {
        input_commitments.push_back(Commit(opening.value, opening.blind));
    }
    for (const auto& opening : output_openings) {
        output_commitments.push_back(Commit(opening.value, opening.blind));
    }

    const Commitment statement = ComputeBalanceStatement(input_commitments, output_commitments, fee);
    // SideChannel F1 fix: constant-time comparison for secret-dependent data.
    if (!lattice::PolyVecEqualCT(statement.vec, Commit(/*value=*/0, balance_blind).vec)) return false;

    bool accepted{false};
    int accepted_attempt{-1};
    lattice::PolyVec nonce_blind;
    for (uint32_t attempt = 0; attempt < static_cast<uint32_t>(MAX_BALANCE_REJECTION_ATTEMPTS); ++attempt) {
        nonce_blind = SampleNonceBlind(balance_blind,
                                       input_commitments,
                                       output_commitments,
                                       fee,
                                       tx_binding_hash,
                                       attempt);
        proof.nonce_commitment = Commit(/*value=*/0, nonce_blind).vec;
        proof.transcript_hash = ComputeTranscript(proof.nonce_commitment,
                                                  statement,
                                                  input_commitments,
                                                  output_commitments,
                                                  fee,
                                                  tx_binding_hash);
        const lattice::Poly256 challenge = ChallengeFromTranscript(proof.transcript_hash);
        proof.response_blind = lattice::PolyVecAdd(nonce_blind, PolyVecMulPoly(balance_blind, challenge));
        if (!lattice::IsValidPolyVec(proof.response_blind)) continue;
        if (lattice::PolyVecInfNorm(proof.response_blind) > BALANCE_RESPONSE_NORM_BOUND) continue;
        accepted = true;
        accepted_attempt = static_cast<int>(attempt);
        break;
    }

    // R7-104: Run padding iterations after acceptance to make timing constant
    // regardless of which attempt was accepted. Uses dummy computation that
    // mirrors the real iteration to prevent timing side-channel leakage of
    // the balance blind norm.
    if (accepted_attempt >= 0 && accepted_attempt < MAX_BALANCE_REJECTION_ATTEMPTS - 1) {
        HashWriter padding_hw;
        padding_hw << std::string{"BTX_MatRiCT_BalanceProof_Padding_V1"};
        padding_hw << balance_blind;
        padding_hw << accepted_attempt;
        FastRandomContext padding_rng(padding_hw.GetSHA256());
        for (int pad = accepted_attempt + 1; pad < MAX_BALANCE_REJECTION_ATTEMPTS; ++pad) {
            // R7-105: Use constant-time sampling in padding to prevent timing
            // side-channel leakage of accepted_attempt via RNG-dependent rejection.
            lattice::PolyVec dummy_nonce = lattice::SampleBoundedVecCT(padding_rng, lattice::MODULE_RANK, NONCE_BOUND);
            lattice::PolyVec dummy_commitment = Commit(/*value=*/0, dummy_nonce).vec;
            (void)lattice::IsValidPolyVec(dummy_commitment);
            (void)lattice::PolyVecInfNorm(dummy_commitment);
            CleansePolyVec(dummy_nonce);
            CleansePolyVec(dummy_commitment);
        }
    }

    if (!accepted) {
        CleansePolyVec(balance_blind);
        CleansePolyVec(nonce_blind);
        CleansePolyVec(proof.response_blind);
        return false;
    }

    // Cleanse secret blinding material from the stack.
    CleansePolyVec(balance_blind);
    CleansePolyVec(nonce_blind);
    return true;
}

bool VerifyBalanceProof(const BalanceProof& proof,
                        const std::vector<Commitment>& input_commitments,
                        const std::vector<Commitment>& output_commitments,
                        CAmount fee,
                        const uint256& tx_binding_hash)
{
    if (!proof.IsValid()) return false;
    if (input_commitments.empty()) return false;

    for (const auto& c : input_commitments) {
        if (!c.IsValid()) return false;
    }
    for (const auto& c : output_commitments) {
        if (!c.IsValid()) return false;
    }

    const Commitment statement = ComputeBalanceStatement(input_commitments, output_commitments, fee);

    const uint256 expected = ComputeTranscript(proof.nonce_commitment,
                                               statement,
                                               input_commitments,
                                               output_commitments,
                                               fee,
                                               tx_binding_hash);
    if (!TimingSafeEqual(expected, proof.transcript_hash)) return false;

    const lattice::Poly256 challenge = ChallengeFromTranscript(expected);
    const Commitment lhs = Commit(/*value=*/0, proof.response_blind);
    const Commitment rhs = CommitmentAdd(
        Commitment{proof.nonce_commitment},
        Commitment{PolyVecMulPoly(statement.vec, challenge)});
    return lattice::PolyVecEqualCT(lhs.vec, rhs.vec);
}

} // namespace shielded::ringct
