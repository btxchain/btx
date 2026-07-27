// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RECURSIVE_VERIFIER_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RECURSIVE_VERIFIER_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_decoder_join.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_deep_vm.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_parent_join.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_recursive_verifier {

namespace abi = stage3_multirow_v11_proof_abi;
namespace backend = stage3_multirow_v11_backend;
namespace cb = constraint_bytecode;
namespace dj = stage3_multirow_v11_decoder_join;
namespace dvm = stage3_multirow_v11_deep_vm;
namespace gf = gkr_field;
namespace mf = stage3_multirow_v11_merkle_fold;
namespace pj = stage3_multirow_v11_parent_join;
namespace tp = stage3_multirow_p2_transcript;

inline constexpr uint16_t kRecursiveVerifierVersionV1 = 1;
inline constexpr uint32_t kQueryShardsV1 = 3;
inline constexpr uint32_t kQueriesPerShardV1 = 64;
inline constexpr uint32_t kTraceRowsCapV1 = 1U << 20;
inline constexpr uint32_t kLdeRowsCapV1 = 1U << 24;
inline constexpr uint32_t kReceiptRootWordsV1 = 8;

static_assert(
    kQueryShardsV1 * kQueriesPerShardV1 ==
    abi::kQueryCountV11);

/**
 * The direct 1,298-column parent-join is deliberately not the recursive
 * program.  Interpreting all 1,276 callback constraints at all Q192 sites
 * exceeds the 2^20 trace cap.  V1 keeps the one-row Poseidon operation table
 * and partitions query occurrences into three transcript-identical Q64
 * verifier shards.  Only compact shard receipts enter the binary recursive
 * join.
 */
struct QueryRangeV1 {
    uint32_t ordinal{0};
    uint32_t first_query{0};
    uint32_t query_count{0};

    bool operator==(const QueryRangeV1&) const = default;
};

[[nodiscard]] constexpr std::array<QueryRangeV1, kQueryShardsV1>
CanonicalQueryRangesV1()
{
    return {{
        {0, 0, kQueriesPerShardV1},
        {1, kQueriesPerShardV1, kQueriesPerShardV1},
        {2, 2 * kQueriesPerShardV1, kQueriesPerShardV1},
    }};
}

enum ResidualV1 : uint32_t {
    /** Product rows still have proof-owned pins in their local R0 tables. */
    kResidualSameParentR0Alias = 1U << 0,
    /** Shard receipts are not yet verified by a V11 verifier AIR. */
    kResidualRecursiveReceiptVerification = 1U << 1,
    /** The normalized verifier's canonical ProgramTable is not registered. */
    kResidualCanonicalVerifierProgram = 1U << 2,
    /** Three receipts have not yet been joined by the binary 2+1 tree. */
    kResidualBinaryReceiptJoin = 1U << 3,
    /** Full codec/ABI sponge ownership is not yet an in-AIR table. */
    kResidualCodecAbiSponge = 1U << 4,
};

struct CapAuditV1 {
    uint32_t child_columns{0};
    uint32_t child_constraints{0};
    uint32_t assumed_instructions_per_constraint{0};
    uint64_t direct_q192_vm_rows{0};
    uint64_t q64_vm_rows{0};
    uint32_t q64_trace_rows{0};
    uint32_t q64_lde_rows{0};
    bool direct_exceeds_trace_cap{false};
    bool q64_fits_trace_cap{false};
    bool q64_fits_lde_cap{false};
    bool valid{false};
    std::string note;
};

/**
 * Checked row-budget arithmetic.  The instruction multiplier is an explicit
 * input because opaque callbacks have no canonical instruction inventory.
 * A caller may use this only as a lower-bound/cap audit, never as evidence
 * that a callback relation has been migrated.
 */
[[nodiscard]] CapAuditV1 AuditDirectAndQ64RowsV1(
    uint32_t child_columns,
    uint32_t child_constraints,
    uint32_t assumed_instructions_per_constraint);

struct ShardReceiptV1 {
    uint16_t version{kRecursiveVerifierVersionV1};
    QueryRangeV1 range{};
    uint256 child_abi_root{};
    uint256 child_wire_root{};
    uint256 child_statement_root{};
    uint256 full_q192_transcript_root{};
    uint256 public_fs_seed{};
    alg_hash::Digest program_root{};
    uint256 parent_join_r0_root{};
    uint256 merkle_hash_r0_root{};
    uint256 merkle_fold_r0_root{};
    uint256 deep_vm_r0_root{};
    uint256 decoder_join_r0_root{};
    uint32_t merkle_hash_rows{0};
    uint32_t merkle_hash_columns{0};
    uint32_t merkle_fold_rows{0};
    uint32_t merkle_fold_columns{0};
    uint32_t deep_vm_rows{0};
    uint32_t deep_vm_columns{0};
    uint32_t decoder_join_rows{0};
    uint32_t decoder_join_columns{0};
    uint64_t materialized_trace_cells{0};
    /** Zero until actual component proofs have been serialized and measured. */
    uint64_t measured_unaggregated_wire_bytes{0};
    uint256 receipt_root{};
};

struct ShardProductV1 {
    QueryRangeV1 range{};
    mf::ShardProductV1 merkle_fold{};
    dvm::ProductV1 deep_vm{};
    ShardReceiptV1 receipt{};
    bool exact_query_range{false};
    bool merkle_and_fold_air_executable{false};
    bool deep_quotient_vm_air_executable{false};
    bool identical_child_statement_bound{false};
    bool proof_owned_roots_recomputed{false};
    bool recursive_receipt_verified_in_air{false};
    bool valid{false};
    std::string note;
};

struct InputV1 {
    backend::ProofV1 proof{};
    tp::ReceiptV1 transcript{};
    cb::ProgramTable child_program{};
    alg_hash::Digest expected_child_program_root{};
    /** Consensus/application statement selected before the proof exists. */
    uint256 expected_child_statement_root{};
    pj::ProductV1 parent_join{};
    std::vector<abi::ParentPublicCellV1> parent_public;
};

struct ProductV1 {
    std::array<ShardProductV1, kQueryShardsV1> shards{};
    dj::ProductV1 decoder_join{};
    uint256 child_abi_root{};
    uint256 child_wire_root{};
    uint256 full_q192_transcript_root{};
    uint256 shard_set_root{};
    CapAuditV1 direct_parent_join_cap_audit{};
    uint32_t residual_mask{0};
    uint32_t exact_queries_covered{0};
    uint32_t duplicate_query_occurrences_preserved{0};
    uint32_t binary_join_internal_nodes{0};
    uint32_t binary_join_depth{0};
    bool exact_disjoint_q192_partition{false};
    bool identical_commitment_transcript_statement{false};
    bool every_merkle_fold_shard_air_executable{false};
    bool every_deep_vm_shard_air_executable{false};
    bool decoder_ownership_join_executable{false};
    bool binary_receipt_tree_executable{false};
    bool canonical_recursive_verifier_program_executable{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Materialize the three real Q64 verifier shards from one actual V11 proof.
 * This executes the published Merkle/fold and DEEP/quotient/bytecode AIRs and
 * the full decoder ownership join.  It does not use a host VerifyV1 result as
 * an acceptance bit: recursive authority remains false until the receipt
 * verifier and same-parent R0 aliases consume these exact roots in AIR.
 */
[[nodiscard]] ProductV1 BuildProductV1(const InputV1& input);

/**
 * Focused construction/audit entry point for one bounded range.  It executes
 * the same real proof path as BuildProductV1 but deliberately does not claim
 * Q192 coverage.  Production uses only the canonical three-range entry point;
 * this function exists so a one-query proof-cell substitution can be tested
 * without allocating all three Q64 traces.
 */
[[nodiscard]] ShardProductV1 BuildSingleShardAuditV1(
    const InputV1& input,
    const QueryRangeV1& range);

[[nodiscard]] uint256 ComputeShardReceiptRootV1(
    const ShardReceiptV1& receipt);
[[nodiscard]] uint256 ComputeFullTranscriptRootV1(
    const tp::ReceiptV1& transcript);
[[nodiscard]] uint256 ComputeShardSetRootV1(
    const std::array<ShardReceiptV1, kQueryShardsV1>& receipts);

struct ReadinessV1 {
    bool exact_q192_query_partition_executable{true};
    bool bounded_q64_merkle_fold_air_executable{true};
    bool bounded_q64_deep_vm_air_executable{true};
    bool decoder_ownership_join_executable{true};
    bool same_parent_r0_alias_executable{false};
    bool recursive_receipt_verifier_executable{false};
    bool canonical_verifier_program_executable{false};
    bool binary_receipt_tree_executable{false};
    bool recursive_authority_ready{false};
};

[[nodiscard]] constexpr ReadinessV1 CurrentReadinessV1()
{
    return {};
}

} // namespace matmul::v4::rc::stage3_multirow_v11_recursive_verifier

#endif
