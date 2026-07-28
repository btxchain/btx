// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EXTRACT_CHACHA_SAMPLER_CHILD_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EXTRACT_CHACHA_SAMPLER_CHILD_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::extract_chacha_sampler_child {

namespace aq = air_quotient;

inline constexpr uint16_t kVersionV1 = 1;

struct CellV1 {
    uint32_t column{0};
    uint32_t row{0};

    bool operator==(const CellV1&) const = default;
};

/**
 * Public, receipt-sized statement for one exact Extract tile.
 *
 * The raw accumulator words, ChaCha output, sampler candidates and extracted
 * bytes are not public inputs. They remain ordinary epoch-R0 cells. The
 * normalized parent must equality-consume the exported input/output cells
 * below before this child contributes to authority.
 */
struct TileStatementV1 {
    uint16_t version{kVersionV1};
    uint256 statement_commitment{};
    uint256 public_fs_seed{};
    uint256 prf_key{};
    uint32_t row{0};
    uint32_t block{0};
    uint32_t chacha_blocks{0};
    uint32_t candidate_rows{0};
    uint32_t trace_rows{0};
    uint8_t scale_e{0};
    uint256 public_boundary_statement{};
    uint256 r0_root{};
    std::array<CellV1, 32> output_cells{};
    /** Per-candidate proof-owned position and signed input bit cells. */
    std::vector<CellV1> position_cells;
    std::vector<std::array<CellV1, 64>> input_bit_cells;
    uint256 retained_node_commitment{};

    bool operator==(const TileStatementV1&) const = default;
};

struct TileProofV1 {
    uint16_t version{kVersionV1};
    TileStatementV1 statement;
    aq::AirQuotientSplitRapRowsProof quotient;
    bool native_verified{false};
    /** Set only by a future normalized parent proof, never by this child. */
    bool normalized_parent_consumed{false};
};

/**
 * Copy verifier-owned preprocessed evaluations into the committed prover
 * trace. Duplicate metadata is accepted only when it names the same values.
 */
[[nodiscard]] bool MaterializeVerifierOwnedPreprocessedV1(
    const aq::AirConstraintSystem<gkr_field::Fp3>& cs,
    std::vector<std::vector<gkr_field::Fp3>>& columns,
    std::string* why = nullptr);

/** Deterministic two-lane challenge derivation exposed for transcript audits. */
[[nodiscard]] std::array<gkr_field::Fp3, 2>
DeriveChallengePairForAuditV1(
    const TileStatementV1& statement);

[[nodiscard]] uint256 ComputeRetainedNodeCommitmentV1(
    const TileStatementV1& statement);

/**
 * Build and prove one complete local tile relation:
 *
 *  - canonical ChaCha20 block program with private final words;
 *  - literal in-proof aliases from every consumed final-word nibble to the
 *    corresponding RcSampler kappa bits;
 *  - the full RcSampler acceptance/position/LogUp/dequant relation;
 *  - literal aliases from RcSampler mix columns to the signed-int mix AIR.
 *
 * The result exports ordinary R0 cells for the 32 extracted outputs and every
 * selected signed input word. Exact all-tile aggregation and normalized
 * parent equality consumption remain external obligations.
 */
[[nodiscard]] bool ProveTileV1(
    const uint256& statement_commitment,
    const uint256& public_fs_seed,
    const uint256& prf_key,
    uint32_t row,
    uint32_t block,
    const std::array<int64_t, 32>& input,
    TileProofV1& out,
    std::string* why = nullptr);

/** Verify without receiving the private accumulator or extracted output. */
[[nodiscard]] bool VerifyTileV1(
    const TileProofV1& proof,
    std::string* why = nullptr);

inline constexpr bool kLocalTileRelationExecutableV1 = true;
inline constexpr bool kNormalizedParentConsumptionReadyV1 = false;
static_assert(kLocalTileRelationExecutableV1);
static_assert(!kNormalizedParentConsumptionReadyV1);

} // namespace matmul::v4::rc::extract_chacha_sampler_child

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EXTRACT_CHACHA_SAMPLER_CHILD_H
