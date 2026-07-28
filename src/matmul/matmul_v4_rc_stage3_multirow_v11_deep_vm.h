// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_DEEP_VM_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_DEEP_VM_H

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_backend.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_merkle_fold.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_deep_vm {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace backend = stage3_multirow_v11_backend;
namespace cb = constraint_bytecode;
namespace gf = gkr_field;
namespace mf = stage3_multirow_v11_merkle_fold;
namespace tp = stage3_multirow_p2_transcript;

inline constexpr uint16_t kDeepVmVersionV1 = 1;
inline constexpr uint32_t kMaxOperationRowsV1 = 1U << 24;

enum class RowKindV1 : uint8_t {
    Padding = 0,
    DeepTerm = 1,
    DeepFinalize = 2,
    VmInstruction = 3,
    QuotientIdentity = 4,
};

/**
 * Exact origin of a proof-owned scalar used by the operation trace.  Fp3
 * values carry all six canonical u32 source addresses.  A transcript-derived
 * or program-derived scalar has no proof address and is instead committed in
 * the ordered preprocessed row tape.
 */
struct ScalarOriginV1 {
    abi::SourceKeyV1 key{};
    std::array<uint32_t, 6> source_addresses{};
    gf::Fp3 value{};
    bool literal_proof_source{false};
    bool transcript_derived_root_pin{false};
    bool program_derived_root_pin{false};
};

struct LayoutV1 {
    uint32_t active{0};
    uint32_t deep_term{0};
    uint32_t deep_finalize{0};
    uint32_t vm_instruction{0};
    uint32_t quotient_identity{0};
    uint32_t query{0};
    uint32_t item{0};
    uint32_t source_address{0};

    uint32_t current_value{0};
    uint32_t eval_z1{0};
    uint32_t eval_z2{0};
    uint32_t coefficient{0};
    uint32_t x_power{0};
    uint32_t z1_power{0};
    uint32_t z2_power{0};
    uint32_t u_before{0};
    uint32_t u_after{0};
    uint32_t v1_before{0};
    uint32_t v1_after{0};
    uint32_t v2_before{0};
    uint32_t v2_after{0};
    uint32_t u_weight{0};
    uint32_t u_contribution{0};
    uint32_t v1_weight{0};
    uint32_t v1_contribution{0};
    uint32_t v2_weight{0};
    uint32_t v2_contribution{0};
    uint32_t deep_start{0};
    uint32_t deep_chain{0};

    uint32_t x{0};
    uint32_t z1{0};
    uint32_t z2{0};
    uint32_t inv_x_minus_z1{0};
    uint32_t inv_x_minus_z2{0};
    uint32_t w1{0};
    uint32_t w2{0};
    uint32_t expected_deep{0};
    uint32_t first_fold_value{0};
    uint32_t inv_product1{0};
    uint32_t inv_product2{0};
    uint32_t deep_diff_inv1{0};
    uint32_t deep_rhs_term1{0};
    uint32_t deep_diff_inv2{0};
    uint32_t deep_rhs_term2{0};
    uint32_t deep_rhs{0};

    uint32_t op_current{0};
    uint32_t op_next{0};
    uint32_t op_constant{0};
    uint32_t op_add{0};
    uint32_t op_sub{0};
    uint32_t op_mul{0};
    uint32_t operand_lhs{0};
    uint32_t operand_rhs{0};
    uint32_t instruction_result{0};
    uint32_t mul_product{0};
    uint32_t program_end{0};
    uint32_t vm_start{0};
    uint32_t vm_chain{0};
    uint32_t vm_to_quotient{0};
    uint32_t air_lambda{0};
    uint32_t lambda_power{0};
    uint32_t selector{0};
    uint32_t selected_result{0};
    uint32_t lambda_selected{0};
    uint32_t program_contribution{0};
    uint32_t lambda_delta{0};
    uint32_t lambda_after{0};
    uint32_t composition_before{0};
    uint32_t composition_after{0};

    uint32_t y{0};
    uint32_t zh{0};
    uint32_t quotient_value{0};
    uint32_t quotient_product{0};
    uint32_t n_columns{0};
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

struct ProductV1 {
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    alg_hash::Digest program_root{};
    std::vector<ScalarOriginV1> scalar_origins;
    std::vector<mf::ParentConsumerCellRefV1> parent_consumer_refs;
    uint32_t first_query{0};
    uint32_t query_count{0};
    uint32_t real_rows{0};
    uint32_t trace_rows{0};
    uint32_t deep_term_rows{0};
    uint32_t vm_instruction_rows{0};
    uint32_t quotient_rows{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint64_t violations{0};
    bool canonical_abi{false};
    bool transcript_receipt_verified{false};
    bool backend_proof_verified{false};
    bool literal_current_next_refs{false};
    bool duplicate_queries_preserved{false};
    bool deep_rlc_air_constrained{false};
    bool denominator_inverse_air_constrained{false};
    bool first_fold_equality_air_constrained{false};
    bool quotient_identity_air_constrained{false};
    bool canonical_bytecode_vm_air_constrained{false};
    bool lambda_accumulation_air_constrained{false};
    bool exact_program_root_checked{false};
    bool ordered_preprocessed_root_pinned{false};
    bool same_parent_decoder_aliases{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Build a bounded-width query shard over the actual V11 proof ABI.  Rows grow
 * with queries, columns in the proof, and bytecode instructions; width is
 * independent of all three.  Duplicate query occurrences are retained.
 *
 * `expected_program_root` is the registry-selected recursive AlgHash root of
 * `table`.  Passing a table under any other root fails before witness
 * construction.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const backend::ProofV1& proof,
    const tp::ReceiptV1& transcript,
    const cb::ProgramTable& table,
    const alg_hash::Digest& expected_program_root,
    uint32_t first_query,
    uint32_t query_count);

/** Re-evaluate the AIR and the exact ordered preprocessed row commitment. */
[[nodiscard]] uint64_t RecountViolationsV1(
    const ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns);

struct ReadinessV1 {
    bool deep_rlc_executable{true};
    bool denominator_inverse_executable{true};
    bool first_fold_link_executable{true};
    bool quotient_identity_executable{true};
    bool canonical_bytecode_vm_executable{true};
    bool lambda_accumulation_executable{true};
    bool same_parent_decoder_aliases_executable{false};
    bool recursive_authority_ready{false};
};

[[nodiscard]] constexpr ReadinessV1 CurrentReadinessV1()
{
    return {};
}

} // namespace matmul::v4::rc::stage3_multirow_v11_deep_vm

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_DEEP_VM_H
