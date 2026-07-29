// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_Q96_CHILD_VERIFIER_BRIDGE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_Q96_CHILD_VERIFIER_BRIDGE_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_receipt_join_q96.h>
#include <matmul/matmul_v4_rc_stage3_verifier_air.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::
    stage3_multirow_v11_q96_child_verifier_bridge {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace q96 =
    stage3_multirow_v11_receipt_join_q96;
namespace va = stage3_verifier_air;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kTraceRowsCapV1 = 1U << 20;
inline constexpr uint32_t kLdeRowsCapV1 = 1U << 24;
inline constexpr uint32_t kRootLimbsV1 =
    alg_hash::kAlgHashDigestLen;

struct CapacityAuditV1 {
    uint32_t child_rows{0};
    uint32_t child_columns{0};
    uint32_t child_constraints{0};
    uint32_t child_quotient_len{0};
    uint32_t verifier_active_rows{0};
    uint32_t verifier_trace_rows{0};
    uint32_t verifier_max_constraint_degree{0};
    uint32_t verifier_quotient_len{0};
    uint32_t verifier_commitment_coefficients{0};
    uint32_t verifier_lde_rows{0};
    uint32_t verifier_poseidon_rows{0};
    uint32_t verifier_merkle_depth{0};
    uint32_t verifier_fold_count{0};
    uint32_t verifier_queries{0};
    bool exact_q96_child_shape{false};
    bool canonical_split_rap_program{false};
    bool quotient_cap_audit_complete{false};
    bool trace_cap_fits{false};
    bool lde_cap_fits{false};
    bool valid{false};
    std::string note;
};

/**
 * Exact sizing pass. It constructs the statement-owned Q96 child relation and
 * canonical verifier schedule but does not allocate the large verifier
 * witness.
 */
[[nodiscard]] CapacityAuditV1 AuditCapacityV1(
    const q96::StatementV1& statement);

struct ProductV1 {
    q96::StatementV1 statement{};
    q96::ProductV1 child{};
    va::MultiRowV2SplitRapProgramV1 verifier_program{};
    va::MultiRowV2SplitRapVerifierWitnessV1 verifier{};
    aq::AirConstraintSystem<gf::Fp3> parent_cs{};
    std::vector<std::vector<gf::Fp3>> parent_columns;
    std::vector<uint32_t> preprocessed_columns;
    uint256 preprocessed_row_group_root{};
    uint256 expected_child_r0_root{};
    uint256 child_program_statement{};
    uint256 child_proof_statement{};
    uint256 child_output_statement{};
    uint32_t group0_program_row{0};
    uint32_t expected_r0_limb_base{0};
    uint32_t group0_selector_column{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t constraints{0};
    uint32_t max_constraint_degree{0};
    uint32_t quotient_len{0};
    uint64_t materialized_trace_cells{0};
    uint64_t violations{0};
    bool exact_q96_statement_to_child_r0{false};
    bool child_split_rap_proof_native_verified{false};
    bool canonical_verifier_program{false};
    bool all_merkle_fold_deep_quotient_checks_in_air{false};
    bool all_active_rows_locally_accepted{false};
    bool group0_r0_output_directly_aliased_in_air{false};
    bool exact_program_proof_output_statements{false};
    bool ordered_parent_r0_root_pinned{false};
    /** False: expected/check tapes are rebuilt from child_proof in R0. */
    bool cs_independent_of_child_witness{false};
    /** False: VerifyV1 currently accepts child_proof as an input. */
    bool verifier_input_excludes_child_proof{false};
    /** Still false: proof codec bytes do not source verifier claimed cells. */
    bool child_proof_codec_owned_in_parent_air{false};
    /** Still false: Poseidon operation inputs remain host-decoded pins. */
    bool poseidon_semantic_copy_bus_complete{false};
    /** Still false: transcript SHA/Poseidon challenges are host-replayed. */
    bool fiat_shamir_replayed_in_parent_air{false};
    bool every_consumed_cell_constrained{false};
    bool recursive_authority_ready{false};
    bool valid_foundation{false};
    std::string note;
};

/**
 * Materialize one actual Q96 receipt-join proof inside the canonical
 * MultiRow-V2 verifier relation, then add same-trace equality constraints
 * from the verifier's Group-0 root output cells to the exact Q96 child R0
 * root. No host acceptance boolean is copied into the parent.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const q96::StatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof& child_proof,
    const uint256& child_fs_seed);

struct ProveResultV1 {
    aq::AirQuotientSplitRapRowsProof proof{};
    uint256 parent_r0_root{};
    uint64_t proof_wire_bytes{0};
    uint64_t prove_micros{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] ProveResultV1 ProveV1(
    const q96::StatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof& child_proof,
    const uint256& child_fs_seed,
    const uint256& parent_fs_seed);

struct VerifyResultV1 {
    uint64_t verify_micros{0};
    bool accepted{false};
    bool every_consumed_cell_constrained{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] VerifyResultV1 VerifyV1(
    const q96::StatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof& child_proof,
    const uint256& child_fs_seed,
    const aq::AirQuotientSplitRapRowsProof& parent_proof,
    const uint256& parent_fs_seed);

} // namespace matmul::v4::rc::stage3_multirow_v11_q96_child_verifier_bridge

#endif
