// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECEIPT_PUBLIC_STATEMENT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECEIPT_PUBLIC_STATEMENT_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_recursive_receipt_v2.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::receipt_public_statement {

namespace aq = air_quotient;
namespace fp = recursive_fixedpoint;
namespace gf = gkr_field;
namespace rr2 = recursive_receipt_v2;

inline constexpr uint16_t kReceiptPublicStatementVersionV1 = 1;
inline constexpr uint32_t kReceiptPublicStatementMaxChildrenV1 = 2;

/**
 * Exact ordered public statement consumed by one child verifier.
 *
 * `child_slot` is part of the statement.  Consequently swapping two otherwise
 * valid receipts, or relabelling a proof from slot 0 as slot 1, changes the
 * Fiat--Shamir seed before the first trace commitment.
 */
struct ReceiptPublicStatementTupleV1 {
    uint16_t version{kReceiptPublicStatementVersionV1};
    uint32_t child_slot{0};
    uint256 program_root{};
    uint256 exact_set_manifest_root{};
    uint256 source_identity{};
    uint256 statement_root{};

    bool operator==(const ReceiptPublicStatementTupleV1&) const = default;
};

struct RootU32CellsV1 {
    std::array<uint32_t, 8> limb{};
};

/**
 * Output of successful local child verification.  These are the exact cells
 * a normalized parent verifier must expose as public-input cells.
 *
 * This object is not, by itself, recursive authority: a same-parent verifier
 * still has to replay the child's transcript under `bound_fs_seed` and
 * equality-constrain its public-input cells to these values.
 */
struct VerifiedReceiptPublicCellsV1 {
    uint16_t version{kReceiptPublicStatementVersionV1};
    uint32_t child_slot{0};
    RootU32CellsV1 program_root;
    RootU32CellsV1 exact_set_manifest_root;
    RootU32CellsV1 source_identity;
    RootU32CellsV1 statement_root;
    RootU32CellsV1 tuple_commitment;
    RootU32CellsV1 bound_fs_seed;
    bool tuple_canonical{false};
    bool child_proof_verified{false};
    bool fs_seed_recomputed_by_verifier{false};
    bool cells_exported_after_verification{false};
    bool same_parent_verifier_consumed{false};
    bool recursive_authority{false};
    std::string note;
};

/**
 * Complete AIR child relation proved under the tuple-bound seed.
 *
 * This uses the existing row-streaming AirQuotient producer, then converts to
 * the canonical Alg proof consumed by BuildFoldBusCompositionMulti.  The seed
 * is:
 *
 *   H(domain, base_v2_seed, H(ordered tuple))
 *
 * and is passed to AirQuotientProveRows before that routine creates its first
 * trace commitment.
 */
struct StatementBoundChildProofV1 {
    uint16_t version{kReceiptPublicStatementVersionV1};
    ReceiptPublicStatementTupleV1 statement;
    uint256 tuple_commitment{};
    uint256 base_v2_seed{};
    uint256 bound_fs_seed{};
    fp::AlgAirProof proof;
    uint256 proof_commitment{};
    bool relation_proved{false};
    bool relation_locally_verified{false};
    bool tuple_bound_before_first_commitment{false};
    bool canonical_alg_proof{false};
    bool same_parent_verifier_consumed{false};
    bool recursive_authority{false};
    bool valid{false};
    std::string note;
};

/**
 * V10 transcript canary over an explicit low-degree trace statement.
 *
 * V10 has named producer/verifier entry points accepting the tuple-bound seed
 * before commitment.  It is not yet an AirQuotient backend, so this canary
 * demonstrates transcript binding only and must never be read as an AIR
 * relation proof or recursive authority.
 */
struct StatementBoundV10TraceCanaryV1 {
    uint16_t version{kReceiptPublicStatementVersionV1};
    ReceiptPublicStatementTupleV1 statement;
    uint256 tuple_commitment{};
    uint256 base_v2_seed{};
    uint256 bound_fs_seed{};
    Fri3AlgBatchProof proof;
    bool v10_trace_low_degree_proved{false};
    bool tuple_bound_before_first_commitment{false};
    bool air_quotient_relation_proved{false};
    bool same_trace_join_with_child_air{false};
    bool recursive_authority{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool ValidateReceiptPublicStatementTupleV1(
    const ReceiptPublicStatementTupleV1& statement,
    std::string* why = nullptr);

/** Build the exact tuple from fields already present in V2 plus the missing
 * higher-level exact-set root and the canonical arity-two slot. */
[[nodiscard]] bool BuildReceiptPublicStatementTupleFromV2(
    const rr2::ShardSourceTerminalBindingV2& binding,
    const uint256& exact_set_manifest_root,
    uint32_t child_slot,
    ReceiptPublicStatementTupleV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 CommitReceiptPublicStatementTupleV1(
    const ReceiptPublicStatementTupleV1& statement);

[[nodiscard]] uint256 ComputeStatementBoundReceiptFsSeedV1(
    const ReceiptPublicStatementTupleV1& statement,
    const uint256& base_v2_seed);

[[nodiscard]] StatementBoundChildProofV1
ProveStatementBoundChildRelationV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const std::vector<std::vector<gf::Fp3>>& child_columns,
    const ReceiptPublicStatementTupleV1& statement,
    const uint256& base_v2_seed,
    const aq::AirProveOptions& options = {});

[[nodiscard]] bool VerifyStatementBoundChildRelationV1(
    const aq::AirConstraintSystem<gf::Fp3>& child_cs,
    const StatementBoundChildProofV1& proof,
    const ReceiptPublicStatementTupleV1& expected_statement,
    const uint256& expected_base_v2_seed,
    VerifiedReceiptPublicCellsV1* cells = nullptr,
    std::string* why = nullptr);

[[nodiscard]] StatementBoundV10TraceCanaryV1
ProveStatementBoundV10TraceCanaryV1(
    const std::vector<std::vector<gf::Fp3>>& coefficient_columns,
    const ReceiptPublicStatementTupleV1& statement,
    const uint256& base_v2_seed,
    uint64_t pow_grind_nonce = 0);

[[nodiscard]] bool VerifyStatementBoundV10TraceCanaryV1(
    const StatementBoundV10TraceCanaryV1& proof,
    const ReceiptPublicStatementTupleV1& expected_statement,
    const uint256& expected_base_v2_seed,
    VerifiedReceiptPublicCellsV1* cells = nullptr,
    std::string* why = nullptr);

inline constexpr bool kReceiptPublicStatementLocalVerifierExecutableV1 = true;
inline constexpr bool kReceiptPublicStatementV10TranscriptCanaryV1 = true;
inline constexpr bool kReceiptPublicStatementSameParentVerifierExecutableV1 =
    false;
inline constexpr bool kReceiptPublicStatementRecursiveAuthorityV1 = false;
inline constexpr bool kReceiptPublicStatementProductionCompleteV1 = false;
static_assert(kReceiptPublicStatementLocalVerifierExecutableV1);
static_assert(kReceiptPublicStatementV10TranscriptCanaryV1);
static_assert(!kReceiptPublicStatementSameParentVerifierExecutableV1);
static_assert(!kReceiptPublicStatementRecursiveAuthorityV1);
static_assert(!kReceiptPublicStatementProductionCompleteV1);

} // namespace matmul::v4::rc::receipt_public_statement

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECEIPT_PUBLIC_STATEMENT_H
