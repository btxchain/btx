// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_CHAIN_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_CHAIN_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_exchange_permutation_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_mix_product.h>

namespace matmul::v4::rc {

inline constexpr uint16_t
    kRCStage3CoupledChainProductVersion = 1;

struct RCStage3CoupledChainProduct {
    uint16_t version{
        kRCStage3CoupledChainProductVersion};
    uint32_t bank_to_gemm_instances{0};
    uint32_t prior_extract_to_gemm_instances{0};
    uint32_t gemm_to_exchange_instances{0};
    uint32_t permutation_to_mix_instances{0};
    uint32_t mix_to_exchange_instances{0};
    uint32_t material_round_chain_instances{0};
    uint32_t mix_to_extract_instances{0};
    uint32_t exchange_to_extract_instances{0};
    uint256 bank_to_gemm_commitment{};
    uint256 prior_extract_to_gemm_commitment{};
    uint256 gemm_to_exchange_commitment{};
    uint256 permutation_to_mix_commitment{};
    uint256 mix_to_exchange_commitment{};
    uint256 material_round_chain_commitment{};
    uint256 mix_to_extract_commitment{};
    uint256 exchange_to_extract_commitment{};
    uint256 product_commitment{};
};

/**
 * Recompute all producer/consumer endpoint roots from the proof-owned vectors,
 * then equality-link:
 *   28 -> 31, 46 -> 30, 32 -> 34, 38 -> 39,
 *   41 -> 34, and shape-conditionally 41 -> 42 or 36 -> 42.
 *
 * This bounded V1 requires one bank page per barrier/lobe GEMM. It performs
 * no native GEMM, exchange, mix, Extract or bank replay.
 */
[[nodiscard]] bool ValidateRCStage3CoupledChainProduct(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& bank,
    const RCStage3CoupledGemmProduct& gemm,
    const RCStage3CoupledExchangePermutationProduct& exchange,
    const RCStage3CoupledMixProduct& mix,
    const RCStage3CoupledExtractProduct& extract,
    RCStage3CoupledChainProduct& out,
    std::string* why = nullptr);

/** Execute every producer proof before applying the exact chain equality. */
[[nodiscard]] bool VerifyRCStage3CoupledChainProduct(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& bank,
    const RCStage3CoupledGemmProduct& gemm,
    const RCStage3CoupledExchangePermutationProduct& exchange,
    const RCStage3CoupledMixProduct& mix,
    const RCStage3CoupledExtractProduct& extract,
    RCStage3CoupledChainProduct& out,
    std::string* why = nullptr);

struct RCStage3CoupledChainProductAudit {
    /** Historical cut when this seven-edge product was introduced. These are
     * not counts from CurrentRCStage3ProvenanceGraphAudit(). */
    uint32_t graph_open_edges_before{24};
    uint32_t exact_edges_closed{7};
    uint32_t graph_open_edges_after{17};
    bool bank_pages_to_gemm_b_exact{false};
    bool prior_extract_to_gemm_a_exact{false};
    bool gemm_y_to_exchange_input_exact{false};
    bool permutation_output_to_mix_input_exact{false};
    bool mix_output_to_material_round_exact{false};
    bool material_round_chain_exact{false};
    bool mix_output_to_extract_input_exact{false};
    bool material_output_to_extract_input_exact{false};
    bool actual_proof_owned_vectors_consumed{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
};

[[nodiscard]] RCStage3CoupledChainProductAudit
CurrentRCStage3CoupledChainProductAudit();

inline constexpr bool
    kRCStage3CoupledChainBoundedExactExecutable = true;
inline constexpr bool
    kRCStage3CoupledChainRecursivelyConsumed = false;

} // namespace matmul::v4::rc

#endif
