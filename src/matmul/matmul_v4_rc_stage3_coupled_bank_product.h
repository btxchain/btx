// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_PRODUCT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_PRODUCT_H

#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_coupled_bank_stream.h>
#include <matmul/matmul_v4_rc_stage3_episode_air.h>
#include <matmul/matmul_v4_rc_stage3_hash_semantic.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3CoupledBankProductVersion = 2;

enum RCStage3CoupledBankDequantColumn : uint32_t {
    kRCStage3CoupledBankMantissa = 0,
    kRCStage3CoupledBankRepeatedScale,
    kRCStage3CoupledBankScaleBit0,
    kRCStage3CoupledBankScaleBit1,
    kRCStage3CoupledBankScaleFactor,
    kRCStage3CoupledBankOutput,
    kRCStage3CoupledBankDequantColumns,
};

struct RCStage3CoupledBankHashExecution {
    stage3_hash_air::ShaManifest manifest;
    stage3_hash_semantic::FlatBoundaryProofBundle proof;
};

struct RCStage3CoupledBankDequantPin {
    uint16_t version{kRCStage3CoupledBankProductVersion};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 sigma{};
    uint32_t page_index{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint32_t n_coeffs{0};
    /** Sole endpoint-28 producer authority: ordered row commitment to all six
     * dequant columns, including signed OUTPUT. */
    uint256 r0_row_group_root{};
    uint256 pin_commitment{};
};

struct RCStage3CoupledBankPageProduct {
    uint32_t page_index{0};
    RCStage3CoupledBankHashExecution page_seed;
    stage3_hash_air::CounterXofManifest mantissa;
    stage3_hash_semantic::FlatBoundaryProofBundle mantissa_proof;
    stage3_hash_air::CounterXofManifest scale;
    stage3_hash_semantic::FlatBoundaryProofBundle scale_proof;
    /** Exact signed page bytes, represented in two's-complement. */
    std::vector<int8_t> page_bytes;
    RCStage3CoupledBankDequantPin dequant_pin;
    air_quotient::AirQuotientSplitRapRowsProof dequant_proof;
    uint256 page_receipt_commitment{};
};

struct RCStage3CoupledBankProduct {
    uint16_t version{kRCStage3CoupledBankProductVersion};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 header_commitment{};
    uint256 sigma{};
    RCStage3CoupledBankHashExecution bank_root_seed;
    std::vector<RCStage3CoupledBankPageProduct> pages;
    uint256 seed_xof_endpoint_root{};
    uint256 pages_endpoint_root{};
    /** Exact AlgHash source-tree root consumed by endpoint 29. */
    uint256 bank_page_byte_root{};
    uint256 product_commitment{};
};

[[nodiscard]] uint256 ComputeRCStage3CoupledBankDequantPinCommitment(
    const RCStage3CoupledBankDequantPin& pin);
[[nodiscard]] uint256 ComputeRCStage3CoupledBankDequantSeed(
    const RCStage3CoupledBankDequantPin& pin);
[[nodiscard]] bool BuildRCStage3CoupledBankDequantConstraintSystem(
    const RCStage3CoupledBankDequantPin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
/** Canonical ordered bytecode for all five dequant constraints. */
[[nodiscard]] bool BuildRCStage3CoupledBankDequantProgramTable(
    const RCStage3CoupledBankDequantPin& pin,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledBankDequantProof(
    const RCStage3CoupledBankDequantPin& pin,
    const air_quotient::AirQuotientSplitRapRowsProof& proof,
    std::string* why = nullptr);

/** Bounded native prover helper. Verification never calls bank derivation. */
[[nodiscard]] bool BuildRCStage3CoupledBankProduct(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledBankProduct& out,
    std::string* why = nullptr);
/** Fill every SHA/XOF provenance proof and page dequant quotient. */
[[nodiscard]] bool ProveRCStage3CoupledBankProduct(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledBankProduct& out,
    std::string* why = nullptr);

/** Exact manifest/root validation with no native bank-page replay. */
[[nodiscard]] bool ValidateRCStage3CoupledBankProductSchedule(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& product,
    std::string* why = nullptr);
/** Execute every seed SHA, counter-XOF SHA and dequant quotient. */
[[nodiscard]] bool VerifyRCStage3CoupledBankProduct(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& product,
    std::string* why = nullptr);

/** Execute endpoints 27/28, then require endpoint 29's source-tree root to
 * be byte-for-byte identical to endpoint 28's proof-owned page stream. */
[[nodiscard]] bool VerifyRCStage3CoupledBankStreamSourceLink(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& product,
    const RCStage3CoupledBankStreamManifest& stream_manifest,
    std::string* why = nullptr);

/**
 * Exact value-level seam between endpoint 28's page-major signed-byte stream
 * and endpoint 29's flat SHA preimage. This helper proves equality only; the
 * combined verifier below additionally executes both producer proofs.
 */
[[nodiscard]] bool ValidateRCStage3CoupledBankFlatSourceEquality(
    const RCStage3CoupledBankProduct& product,
    const RCStage3CoupledBankRootManifest& flat_manifest,
    std::string* why = nullptr);

/** Execute endpoints 27/28 and the bounded endpoint-29 SHA proof, then bind
 * every endpoint-28 output byte to the corresponding endpoint-29 SHA input.
 */
[[nodiscard]] bool VerifyRCStage3CoupledBankFlatSourceLink(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBankProduct& product,
    const RCStage3CoupledBankRootExecution& flat_bank,
    std::string* why = nullptr);

struct RCStage3CoupledBankProductAudit {
    bool immutable_all_page_schedule{false};
    bool bank_seed_sha_executed{false};
    bool page_seed_sha_executed{false};
    bool mantissa_and_scale_xof_executed{false};
    bool xof_to_page_dequant_equality_executed{false};
    bool proof_owned_page_memory_root{false};
    bool endpoint29_source_root_equality_executable{false};
    bool endpoints_27_28_bounded_local_complete{false};
    bool production_streaming_complete{false};
    bool recursively_consumed{false};
    bool transitively_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3CoupledBankProductAudit
CurrentRCStage3CoupledBankProductAudit();

inline constexpr bool kRCStage3CoupledBankBoundedLocalProductExecutable =
    true;
inline constexpr bool kRCStage3CoupledBankProductionStreamingComplete =
    false;

} // namespace matmul::v4::rc

#endif
