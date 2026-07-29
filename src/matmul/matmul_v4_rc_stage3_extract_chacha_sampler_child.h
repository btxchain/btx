// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EXTRACT_CHACHA_SAMPLER_CHILD_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EXTRACT_CHACHA_SAMPLER_CHILD_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_air_parent_composer.h>

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
    /**
     * Canonical AlgHash commitment to every verifier-owned preprocessed
     * column, including its absolute column index and complete H-domain
     * values.  The native Split-RAP verifier still enforces those values
     * through dual-OOD openings; this compact root is the exact statement
     * handle consumed by a normalized parent.
     */
    uint256 preprocessed_schedule_commitment{};
    /** AlgHash commitment to the six R0-derived ProgramTable challenges. */
    uint256 program_challenge_commitment{};
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

inline constexpr uint32_t kProgramChallengeWidthV1 = 6;

/**
 * Exact verifier reconstruction of the challenge-bearing child relation.
 *
 * Order is consensus-canonical for the composed child ProgramTable:
 *   [0] ChaCha SSA gamma1, [1] gamma2, [2] alpha1, [3] alpha2,
 *   [4] RcSampler gamma, [5] alpha.
 *
 * All six values are derived after the same authenticated R0 commitment.
 * `preprocessed_schedule_commitment` names the complete verifier-owned
 * schedule whose dual-OOD openings the native child proof enforces.
 */
struct ProgramChallengeBindingV1 {
    uint16_t version{kVersionV1};
    uint256 r0_root{};
    uint256 public_boundary_statement{};
    uint256 preprocessed_schedule_commitment{};
    uint256 challenge_commitment{};
    std::array<gkr_field::Fp3, kProgramChallengeWidthV1>
        challenges{};
    uint32_t preprocessed_columns{0};
    bool all_challenges_r0_derived{false};
    bool preprocessed_dual_ood_bound{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ProgramChallengeBindingV1
BuildProgramChallengeBindingV1(
    const TileStatementV1& statement);

/**
 * Challenge-independent projection of one complete Extract tile relation.
 *
 * `cs` contains exactly the columns which must be committed before any of the
 * six semantic challenges are sampled.  The challenge-dependent columns and
 * every constraint which consumes a challenge are deliberately absent.  The
 * two maps retain the canonical full-relation column identity, so finalization
 * can reconnect the committed cells without a copied receipt or a second R0.
 */
struct DeterministicComponentV1 {
    TileStatementV1 statement;
    aq::AirConstraintSystem<gkr_field::Fp3> cs;
    std::vector<std::vector<gkr_field::Fp3>> columns;
    std::vector<uint32_t> deterministic_to_full_column;
    std::vector<uint32_t> full_to_deterministic_column;
    std::array<int64_t, 32> private_input{};
    uint32_t full_relation_columns{0};
    uint32_t full_relation_constraints{0};
    bool every_preprocessed_column_in_r0{false};
    bool challenge_columns_absent{false};
    bool parent_r0_pending{false};
    bool valid{false};
    std::string note;
};

/**
 * Result of attaching the challenge-dependent suffix to an already attached
 * deterministic component.
 */
struct ParentFinalizationV1 {
    TileStatementV1 statement;
    ProgramChallengeBindingV1 challenge_binding;
    std::vector<uint32_t> full_local_to_parent_column;
    std::array<CellV1, 32> output_cells{};
    std::vector<CellV1> position_cells;
    std::vector<std::array<CellV1, 64>> input_bit_cells;
    uint32_t dependent_column_base{UINT32_MAX};
    uint32_t dependent_columns{0};
    uint32_t constraints_appended{0};
    uint32_t canonical_constraints_relocated{0};
    uint32_t native_constraints_mapped{0};
    bool parent_owned_r0_consumed{false};
    bool deterministic_witness_preserved{false};
    bool exact_six_challenge_order{false};
    bool valid{false};
    std::string note;
};

/**
 * Witness-free reconstruction of the pre-R0 Extract component.  This is the
 * consensus-verifier counterpart of DeterministicComponentV1: it carries the
 * same public preprocessing and the same full/local column bijection, but no
 * accumulator input or trace values.
 */
struct VerifierComponentV1 {
    TileStatementV1 statement;
    aq::AirConstraintSystem<gkr_field::Fp3> cs;
    std::vector<uint32_t> deterministic_to_full_column;
    std::vector<uint32_t> full_to_deterministic_column;
    uint32_t full_relation_columns{0};
    uint32_t full_relation_constraints{0};
    bool every_preprocessed_column_in_r0{false};
    bool challenge_columns_absent{false};
    bool valid{false};
    std::string note;
};

struct VerifierParentFinalizationV1 {
    ProgramChallengeBindingV1 challenge_binding;
    std::vector<uint32_t> full_local_to_parent_column;
    std::array<CellV1, 32> output_cells{};
    std::vector<CellV1> position_cells;
    std::vector<std::array<CellV1, 64>> input_bit_cells;
    uint32_t dependent_column_base{UINT32_MAX};
    uint32_t dependent_columns{0};
    uint32_t constraints_appended{0};
    uint32_t canonical_constraints_relocated{0};
    uint32_t native_constraints_mapped{0};
    bool parent_owned_r0_consumed{false};
    bool public_statement_rebuilt{false};
    bool exact_six_challenge_order{false};
    bool valid{false};
    std::string note;
};

/**
 * Build the only form of the Extract relation which may enter a normalized
 * parent before that parent's single R0 commitment.
 */
[[nodiscard]] bool BuildDeterministicComponentV1(
    const uint256& statement_commitment,
    const uint256& public_fs_seed,
    const uint256& prf_key,
    uint32_t row,
    uint32_t block,
    const std::array<int64_t, 32>& input,
    DeterministicComponentV1& out,
    std::string* why = nullptr);

/**
 * Finalize an already attached deterministic component from the wider
 * parent's R0.  Only challenge-dependent columns are appended.  Every final
 * constraint is rebuilt against a literal map from its original local column
 * to either the existing attachment or the new dependent suffix.
 */
[[nodiscard]] bool AppendFinalRelationToParentV1(
    const DeterministicComponentV1& component,
    const stage3_air_parent_composer::ChildAttachmentV1& attachment,
    const aq::AirQuotientTwoEpochBaseRowSession& parent_r0_session,
    aq::AirConstraintSystem<gkr_field::Fp3>& parent_cs,
    std::vector<std::vector<gkr_field::Fp3>>& parent_columns,
    ParentFinalizationV1& out,
    std::string* why = nullptr);

/** Rebuild the deterministic projection without private witness cells. */
[[nodiscard]] bool BuildVerifierComponentV1(
    const TileStatementV1& statement,
    VerifierComponentV1& out,
    std::string* why = nullptr);

/**
 * Append the verifier's identical challenge-dependent CS to a frozen parent
 * attachment.  No private input, deterministic columns, or host acceptance
 * bit is accepted by this interface.
 */
[[nodiscard]] bool AppendVerifierRelationToParentV1(
    const VerifierComponentV1& component,
    const stage3_air_parent_composer::ChildAttachmentV1& attachment,
    const uint256& parent_r0_root,
    aq::AirConstraintSystem<gkr_field::Fp3>& parent_cs,
    VerifierParentFinalizationV1& out,
    std::string* why = nullptr);

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
