// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_INITIAL_STATE_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_INITIAL_STATE_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_gemm_product.h>

namespace matmul::v4::rc {

inline constexpr uint16_t
    kRCStage3CoupledInitialStateProductVersion = 2;

struct RCStage3CoupledInitialLobeProduct {
    uint32_t lobe{0};
    RCStage3CoupledBankHashExecution lobe_seed;
    stage3_hash_air::CounterXofManifest mantissa;
    stage3_hash_semantic::FlatBoundaryProofBundle mantissa_proof;
    stage3_hash_air::CounterXofManifest scale;
    stage3_hash_semantic::FlatBoundaryProofBundle scale_proof;
    /** Complete W-by-W expansion; GEMM A consumes its first M rows. */
    std::vector<int8_t> expanded_tile;
    RCStage3CoupledBankDequantPin dequant_pin;
    air_quotient::AirQuotientSplitRapRowsProof dequant_proof;
    uint256 receipt_commitment{};
};

struct RCStage3CoupledInitialStateProduct {
    uint16_t version{
        kRCStage3CoupledInitialStateProductVersion};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 sigma{};
    std::vector<RCStage3CoupledInitialLobeProduct> lobes;
    uint256 initial_state_endpoint_root{};
    uint256 product_commitment{};
};

[[nodiscard]] bool BuildRCStage3CoupledInitialStateProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledInitialStateProduct& out,
    std::string* why = nullptr);
[[nodiscard]] bool ProveRCStage3CoupledInitialStateProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledInitialStateProduct& out,
    std::string* why = nullptr);
[[nodiscard]] bool ValidateRCStage3CoupledInitialStateProductSchedule(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledInitialStateProduct& product,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledInitialStateProduct(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledInitialStateProduct& product,
    std::string* why = nullptr);

/** Exact barrier-zero lobe/page-slot equality, endpoint 25 -> endpoint 30. */
[[nodiscard]] bool ValidateRCStage3CoupledInitialStateGemmLink(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledInitialStateProduct& initial,
    const RCStage3CoupledGemmProduct& gemm,
    uint256& link_commitment,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledInitialStateGemmLink(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledInitialStateProduct& initial,
    const RCStage3CoupledGemmProduct& gemm,
    uint256& link_commitment,
    std::string* why = nullptr);

struct RCStage3CoupledInitialStateProductAudit {
    bool lobe_seed_sha_executable{false};
    bool mantissa_scale_xof_executable{false};
    bool dequant_executable{false};
    bool complete_initial_state_root{false};
    bool every_barrier0_gemm_a_slice_equal{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
};

[[nodiscard]] RCStage3CoupledInitialStateProductAudit
CurrentRCStage3CoupledInitialStateProductAudit();

} // namespace matmul::v4::rc

#endif
