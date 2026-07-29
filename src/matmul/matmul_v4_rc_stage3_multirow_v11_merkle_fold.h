// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_MERKLE_FOLD_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_MERKLE_FOLD_H

#include <matmul/matmul_v4_rc_stage3_multirow_p2_transcript.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_backend.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_proof_abi.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_merkle_fold {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace backend = stage3_multirow_v11_backend;
namespace gf = gkr_field;
namespace pa = stage3_poseidon_air;
namespace tp = stage3_multirow_p2_transcript;

inline constexpr uint16_t kMerkleFoldChipVersionV1 = 1;
inline constexpr uint32_t kProductionQueriesV1 = abi::kQueryCountV11;
inline constexpr uint32_t kHashPinColumnsV1 =
    alg_hash::kAlgHashT + alg_hash::kAlgHashDigestLen;

enum class HashTaskKindV1 : uint8_t {
    RowLeaf = 1,
    FoldLeaf = 2,
    MerkleNode = 3,
    Padding = 4,
};

/**
 * One exact Poseidon2 permutation in the bounded operation-table schedule.
 * `source_addresses` are canonical proof-ABI cells used to construct this
 * operation. They are audit metadata until the same-parent decoder
 * permutation/equality join consumes them.
 */
struct HashTaskV1 {
    HashTaskKindV1 kind{HashTaskKindV1::Padding};
    uint32_t query{0};
    uint32_t group{0};
    uint32_t fold{0};
    uint32_t level{0};
    alg_hash::State input{};
    alg_hash::State output{};
    std::vector<uint32_t> source_addresses;
};

struct HashLayoutV1 {
    pa::Layout poseidon{};
    uint32_t input_pin_base{0};
    uint32_t output_pin_base{0};
    uint32_t n_columns{0};

    [[nodiscard]] uint32_t InputPin(uint32_t lane) const
    {
        return input_pin_base + lane;
    }
    [[nodiscard]] uint32_t OutputPin(uint32_t lane) const
    {
        return output_pin_base + lane;
    }
};

struct FoldLayoutV1 {
    uint32_t even{0};
    uint32_t odd{0};
    uint32_t beta{0};
    uint32_t x{0};
    uint32_t even_part{0};
    uint32_t odd_part{0};
    uint32_t folded{0};
    uint32_t here{0};
    uint32_t final_value{0};
    uint32_t index{0};
    uint32_t even_index{0};
    uint32_t odd_index{0};
    uint32_t half{0};
    uint32_t side{0};
    uint32_t chain_next{0};
    uint32_t terminal{0};
    uint32_t n_columns{0};
};

[[nodiscard]] HashLayoutV1 CanonicalHashLayoutV1();
[[nodiscard]] FoldLayoutV1 CanonicalFoldLayoutV1();

enum class ParentConsumerKindV1 : uint8_t {
    QueryIndex = 1,
    CurrentRowValue = 2,
    NextRowValue = 3,
};

/**
 * Literal canonical-decoder cell consumed by the later AirQuotient/VM chip.
 * Fp3 values expose all three coordinates and both u32 limbs. Query indices
 * expose their one u32 cell. No copied scalar is accepted as a substitute.
 */
struct ParentConsumerCellRefV1 {
    ParentConsumerKindV1 kind{ParentConsumerKindV1::QueryIndex};
    uint32_t query{0};
    uint32_t group{0};
    uint32_t item{0};
    uint32_t coordinate{0};
    uint8_t limb{0};
    uint32_t source_address{0};
    uint32_t value{0};
};

[[nodiscard]] std::vector<ParentConsumerCellRefV1>
BuildParentConsumerCellRefsV1(const abi::DecodedV1& decoded);

struct NativeAuditV1 {
    uint32_t queries_checked{0};
    uint32_t current_paths_checked{0};
    uint32_t next_paths_checked{0};
    uint32_t fold_paths_checked{0};
    uint32_t fold_equations_checked{0};
    uint64_t poseidon_permutations{0};
    uint64_t source_cells_consumed{0};
    uint32_t duplicate_query_count{0};
    uint32_t parent_consumer_cells{0};
    bool canonical_abi{false};
    bool transcript_receipt_verified{false};
    bool query_indices_transcript_bound{false};
    bool current_group_paths_verified{false};
    bool next_group_paths_verified{false};
    bool fold_paths_verified{false};
    bool fold_equations_verified{false};
    bool terminal_value_verified{false};
    bool terminal_fold_tree_root_verified{false};
    bool exact_source_addresses{false};
    bool duplicate_queries_preserved{false};
    bool literal_parent_consumer_refs{false};
    bool full_q192_coverage{false};
    bool valid{false};
    std::string note;
};

/**
 * Execute all Q192 current/next/fold path checks and every binary Fp3 fold.
 * This is the exact scalar model used to build shards; it retains no
 * O(Q log N) operation trace.
 */
[[nodiscard]] NativeAuditV1 AuditAllV1(
    const abi::DecodedV1& decoded,
    const tp::ReceiptV1& transcript);

/** Canonically decode the actual additive V11 backend proof, then audit it. */
[[nodiscard]] NativeAuditV1 AuditAllV1(
    const backend::ProofV1& proof,
    const tp::ReceiptV1& transcript);

struct ShardProductV1 {
    uint32_t first_query{0};
    uint32_t query_count{0};
    uint32_t hash_real_rows{0};
    uint32_t hash_trace_rows{0};
    uint32_t fold_real_rows{0};
    uint32_t fold_trace_rows{0};
    uint32_t hash_constraints{0};
    uint32_t fold_constraints{0};
    uint32_t hash_max_degree{0};
    uint32_t fold_max_degree{0};
    uint64_t hash_violations{0};
    uint64_t fold_violations{0};
    uint64_t source_cells_consumed{0};
    HashLayoutV1 hash_layout{};
    FoldLayoutV1 fold_layout{};
    aq::AirConstraintSystem<gf::Fp3> hash_cs;
    aq::AirConstraintSystem<gf::Fp3> fold_cs;
    std::vector<std::vector<gf::Fp3>> hash_columns;
    std::vector<std::vector<gf::Fp3>> fold_columns;
    std::vector<HashTaskV1> hash_tasks;
    std::vector<ParentConsumerCellRefV1> parent_consumer_refs;
    bool canonical_abi{false};
    bool transcript_receipt_verified{false};
    bool current_group_paths_verified{false};
    bool next_group_paths_verified{false};
    bool fold_paths_verified{false};
    bool fold_equations_air_constrained{false};
    bool terminal_value_air_constrained{false};
    bool terminal_fold_tree_root_air_constrained{false};
    bool proof_owned_pins_ood_bound{false};
    bool proof_owned_pins_root_pinned{false};
    bool constant_width_schedule{false};
    bool duplicate_queries_preserved{false};
    bool literal_parent_consumer_refs{false};
    bool same_parent_decoder_aliases{false};
    bool deep_quotient_constrained{false};
    bool canonical_vm_constrained{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Materialize a bounded contiguous Q-shard. A one-query shard has constant
 * width independent of proof width and Merkle depth; larger instances add
 * rows, never columns. Every input/output pin is a canonical preprocessed
 * column dual-OOD-bound by the row backend, so a proof made for one child
 * cannot verify under substituted pins. Exact Split-RAP row-root equality
 * remains a same-parent integration residual and is reported separately.
 */
[[nodiscard]] ShardProductV1 BuildShardV1(
    const abi::DecodedV1& decoded,
    const tp::ReceiptV1& transcript,
    uint32_t first_query,
    uint32_t query_count);

/** Actual ProofV1 entry point; no parallel or synthetic proof schema. */
[[nodiscard]] ShardProductV1 BuildShardV1(
    const backend::ProofV1& proof,
    const tp::ReceiptV1& transcript,
    uint32_t first_query,
    uint32_t query_count);

/**
 * Native SAFE-V13 entry point.
 *
 * The legacy V11 shard takes a caller-supplied Poseidon transcript receipt.
 * SAFE V13 has a distinct Fiat-Shamir schedule, so translating it into that
 * receipt would silently re-introduce the frozen V11 transcript.  This entry
 * point instead verifies the complete Split-RAP SAFE-V2 proof with the
 * unmodified verifier, canonically decodes the V13 proof tape, and treats the
 * verifier-accepted fold challenges/query indices as the sole transcript
 * authority.
 */
[[nodiscard]] ShardProductV1 BuildShardSafeV13(
    const aq::AirConstraintSystem<gf::Fp3>& expected_cs,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& public_fs_seed,
    uint32_t first_query,
    uint32_t query_count);

[[nodiscard]] uint64_t RecountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

struct ReadinessV1 {
    bool canonical_abi_consumption_executable{true};
    bool all_current_next_paths_executable{true};
    bool all_fold_paths_executable{true};
    bool fp3_fold_equations_executable{true};
    bool bounded_poseidon_operation_table_executable{true};
    bool same_parent_decoder_aliases_executable{false};
    bool deep_quotient_executable{false};
    bool canonical_vm_executable{false};
    bool recursive_authority_ready{false};
};

[[nodiscard]] constexpr ReadinessV1 CurrentReadinessV1()
{
    return {};
}

} // namespace matmul::v4::rc::stage3_multirow_v11_merkle_fold

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_MERKLE_FOLD_H
