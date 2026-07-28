// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_GEMM_SUMCHECK_BINDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_GEMM_SUMCHECK_BINDING_H

// ===========================================================================
// PR-89 relation endpoint #8 — EpisodeGemmSumcheck.
//
// Binds the per-layer Thaler product-sumcheck transcript
//   { (g_k(0), g_k(1), g_k(2)) }_{k=1..log2 K},  chain-end gf = a_eval*b_eval
// (matmul_v4_rc_gkr.h RCGkrLayerClaimV7 §523-536) to the layer's execution
// obligation sumcheck_commitment (matmul_v4_rc_stage3_gemm_extract.h:582).
//
// FOUR constraint families are enforced (Thaler, Proofs-Args-and-ZK Thm 4.6):
//   (i)   chaining      g_k(0)+g_k(1) - claim_{k-1} = 0, and
//                       claim_k = g_k(r_k) via Lagrange-from-3-points;
//   (ii)  initial claim claim_0 = MLE(Y)  (pinned to the endpoint-7 Y claim);
//   (iii) terminal      claim_{log2 K} - a_eval*b_eval = 0 (Thm 3.1);
//   (iv)  challenge      r_k = FS(prefix) where THIS sub-transcript's FS is the
//         honesty        ALG_HASH sponge (absorb the per-round leaf digest, one
//                        Poseidon2 permutation per round, squeeze 3 Fp lanes).
//
// Families (i)-(iii) are additionally discharged by a genuine in-AIR quotient
// proof (AirQuotientProve/Verify over Fp3) — the same batched-FRI backend the
// scalar commitment openings use (matmul_v4_rc_stage3_relation_closure.cpp
// OpenRCStage3EndpointCommitment).  Family (iv) is the algebraic sponge; its
// full in-AIR shape is 118 degree-7 S-box identities per round.
//
// Alg fold: leaf_k = alg_hash::LeafHashRow([layer,k,g0.{c0,c1,c2},g1,g2,r_k],k)
// (VectorRootAlg leaf-i binding), Compress-folded to sumcheck_root and pinned
// to the committed sumcheck_commitment.  SHA is transport-only.
//
// Soundness floor: eps <= 2*log2 K / |Fp3| ~ 2^-185 (K<=2^20) + Poseidon-FS
// (ROM) + 2^128 tree floor  =>  2^128.  Flips NO consensus/authority gate.
// ===========================================================================

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <cstdint>
#include <string>
#include <vector>

#include <uint256.h>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3GemmSumcheckBindingVersion = 1;

/** Maximum log2(K) supported (K <= 2^20 keeps eps <= 2^-185). */
inline constexpr uint32_t kRCStage3GemmSumcheckMaxRounds = 20;

/** One Thaler product-sumcheck round: the degree-2 message and its challenge. */
struct RCStage3GemmSumcheckRound {
    gkr_field::Fp3 g0{}; // g_k(0)
    gkr_field::Fp3 g1{}; // g_k(1)
    gkr_field::Fp3 g2{}; // g_k(2)
    gkr_field::Fp3 r{};  // r_k (FS challenge)

    bool operator==(const RCStage3GemmSumcheckRound& other) const
    {
        return gkr_field::Eq(g0, other.g0) &&
               gkr_field::Eq(g1, other.g1) &&
               gkr_field::Eq(g2, other.g2) &&
               gkr_field::Eq(r, other.r);
    }
};

/** One GEMM layer's complete product-sumcheck transcript. */
struct RCStage3GemmSumcheckLayerTranscript {
    uint32_t layer_ordinal{0};
    gkr_field::Fp3 initial_claim{}; // claim_0 = MLE(Y), pinned to endpoint 7
    gkr_field::Fp3 a_eval{};        // A(r_i,r_k) opening of operand-A commitment
    gkr_field::Fp3 b_eval{};        // B(r_k,r_j) opening of operand-B commitment
    std::vector<RCStage3GemmSumcheckRound> rounds; // size == log2 K
};

struct RCStage3GemmSumcheckAlgBindingResult {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeGemmSumcheck};
    uint32_t k_log2{0};

    // Family verdicts (native re-derivation).
    bool initial_claim_ok{false};  // (ii)
    bool chaining_ok{false};       // (i)  every round
    bool terminal_ok{false};       // (iii)
    bool challenge_fs_ok{false};   // (iv) alg-hash sponge FS

    // In-AIR discharge of families (i)-(iii).
    bool air_proved{false};    // AirQuotientProve division_exact
    bool air_verified{false};  // AirQuotientVerify accepted

    // Alg fold + obligation pin.
    uint256 sumcheck_root{};
    bool fold_root_pinned{false};  // sumcheck_root == committed sumcheck_commitment

    bool binding_complete{false};  // all of the above hold, no tamper
    gkr_field::Fp3 a_eval{};
    gkr_field::Fp3 b_eval{};
    std::string note;
};

/**
 * Build an honest, fully self-consistent product-sumcheck transcript for a
 * layer with K = 2^k_log2 (forward FS construction; a_eval*b_eval is fixed to
 * the terminal claim).  Test/native-prover convenience.
 */
[[nodiscard]] RCStage3GemmSumcheckLayerTranscript
BuildRCStage3HonestGemmSumcheckLayerTranscript(uint32_t layer_ordinal,
                                               uint32_t k_log2,
                                               uint64_t seed);

/** Compute the VectorRootAlg sumcheck_root of one layer transcript. */
[[nodiscard]] uint256 ComputeRCStage3GemmSumcheckRoot(
    const RCStage3GemmSumcheckLayerTranscript& transcript);

/**
 * Verify all four families for one layer transcript, discharge (i)-(iii) with a
 * genuine in-AIR quotient proof, fold to sumcheck_root and pin it to the
 * committed obligation sumcheck_commitment.  `y_claim` is the endpoint-7 MLE(Y)
 * value the initial claim is pinned against.  binding_complete is the
 * conjunction of every check.
 */
[[nodiscard]] bool VerifyRCStage3GemmSumcheckAlgBinding(
    const RCStage3GemmSumcheckLayerTranscript& transcript,
    const gkr_field::Fp3& y_claim,
    const uint256& committed_sumcheck_commitment,
    RCStage3GemmSumcheckAlgBindingResult& out,
    std::string* why = nullptr);

/**
 * Semantic pin the openings lane wires into the endpoint-8 registry slot.
 * `semantic_relation_complete` is true iff the alg binding verified with no
 * tamper.  The lane copies these fields into RCStage3RelationEndpointCellAudit /
 * the endpoint pin; it does NOT need to re-run the AIR.
 */
struct RCStage3GemmSumcheckSemanticPin {
    RCStage3RelationEndpoint endpoint{
        RCStage3RelationEndpoint::EpisodeGemmSumcheck};
    bool semantic_relation_complete{false};
    uint256 sumcheck_root{};
    std::string note;
};

[[nodiscard]] RCStage3GemmSumcheckSemanticPin
RCStage3GemmSumcheckWireSemanticPin(
    const RCStage3GemmSumcheckAlgBindingResult& result);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_GEMM_SUMCHECK_BINDING_H
