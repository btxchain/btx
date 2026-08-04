// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RECURSIVE_PARENT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RECURSIVE_PARENT_H

#include <matmul/matmul_v4_rc_stage3_multirow_v11_backend.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_merkle_fold.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_parent_join.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_recursive_parent {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace backend = stage3_multirow_v11_backend;
namespace gf = gkr_field;
namespace mf = stage3_multirow_v11_merkle_fold;
namespace pj = stage3_multirow_v11_parent_join;
namespace tp = stage3_multirow_p2_transcript;

inline constexpr uint16_t kRecursiveParentVersionV1 = 1;
inline constexpr uint32_t kRecursiveParentArityV1 = 2;
/** Minimum trace domain accepted by Q192 at the production blowup. */
inline constexpr uint32_t kRecursiveParentTraceRowsV1 = 256;
inline constexpr uint32_t kRecursiveParentWireMagicV1 =
    0x31505256U; // "VRP1"
inline constexpr uint32_t kRootWordsV1 = 8;
inline constexpr uint32_t kMaxReceiptBytesV1 = 16U << 20;

/**
 * Additive fixed-trace parent statement.  V1 remains frozen as the native
 * foundation; V2 uses the SAFE FixedTrace V3 proof route and never infers the
 * expected fixed root or column manifest from the proof.
 */
inline constexpr uint16_t kRecursiveParentVersionV2 = 2;
inline constexpr uint32_t kRecursiveParentWireMagicV2 =
    0x32505256U; // "VRP2"
inline constexpr uint32_t kRecursiveParentDependentColumnsV2 = 1;

enum ResidualV1 : uint32_t {
    kResidualSameParentDecoderJoin = 1U << 0,
    kResidualDeepQuotientChip = 1U << 1,
    kResidualCanonicalConstraintVm = 1U << 2,
    kResidualRecursiveV11Verifier = 1U << 3,
    kResidualFullShardMaterialization = 1U << 4,
    kResidualCanonicalParentProgram = 1U << 5,
};

enum ResidualV2 : uint32_t {
    /** Existing callbacks are not yet canonical constraint bytecode. */
    kResidualV2CanonicalConstraintBytecode = 1U << 0,
    /** No consensus registry membership proof exists for the parent program. */
    kResidualV2ProgramRegistryMembership = 1U << 1,
    /** Child verification and statement hashing remain host-side. */
    kResidualV2SameParentRecursiveVerifier = 1U << 2,
};

/**
 * Consensus-owned identity surrounding one V11 proof.  The application
 * statement is deliberately separate from the proof ABI: role and program
 * ownership are not fields of the FRI envelope.
 */
struct ChildStatementV1 {
    uint32_t role{0};
    uint256 program_root{};
    uint256 application_statement_root{};
    uint256 public_fs_seed{};
};

/**
 * Actual child material accepted by the host-side foundation.  `cs` and
 * `base_column_indices` are verifier inputs, never inferred from the proof.
 * The parent-join and Merkle/fold products are proof-aware construction
 * products which are committed into the child statement.
 */
struct ChildInputV1 {
    ChildStatementV1 statement{};
    aq::AirConstraintSystem<gf::Fp3> cs{};
    std::vector<uint32_t> base_column_indices;
    backend::ProofV1 proof{};
    pj::ProductV1 parent_join{};
    std::vector<mf::ShardProductV1> merkle_fold_shards;
};

struct ChildReceiptV1 {
    uint32_t ordinal{0};
    uint32_t role{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t quotient_len{0};
    uint32_t proof_bytes{0};
    uint32_t shard_count{0};
    uint32_t shard_queries{0};
    uint256 program_root{};
    uint256 application_statement_root{};
    uint256 public_fs_seed{};
    uint256 proof_abi_root{};
    uint256 proof_wire_root{};
    uint256 parent_join_root{};
    uint256 merkle_fold_root{};
    uint256 child_statement_root{};
};

/**
 * Constant layout: increasing a child's proof width changes rows in its own
 * proof, never columns in this two-row acceptance table.
 */
struct LayoutV1 {
    uint32_t active{0};
    uint32_t ordinal{0};
    uint32_t accepted{0};
    uint32_t role{0};
    uint32_t trace_rows{0};
    uint32_t trace_columns{0};
    uint32_t quotient_len{0};
    uint32_t proof_bytes{0};
    uint32_t shard_count{0};
    uint32_t shard_queries{0};
    uint32_t roots_base{0};
    uint32_t n_columns{0};

    [[nodiscard]] uint32_t RootWord(uint32_t root, uint32_t word) const
    {
        return roots_base + root * kRootWordsV1 + word;
    }
};

enum RootSlotV1 : uint32_t {
    kProgramRootV1 = 0,
    kApplicationStatementRootV1 = 1,
    kPublicFsSeedV1 = 2,
    kProofAbiRootV1 = 3,
    kProofWireRootV1 = 4,
    kParentJoinRootV1 = 5,
    kMerkleFoldRootV1 = 6,
    kChildStatementRootV1 = 7,
    kRootSlotsV1 = 8,
};

[[nodiscard]] LayoutV1 CanonicalLayoutV1();

struct ParentReceiptV1 {
    uint16_t version{kRecursiveParentVersionV1};
    uint32_t arity{kRecursiveParentArityV1};
    uint32_t acceptance_rows{0};
    uint32_t acceptance_columns{0};
    uint256 parent_program_root{};
    uint256 parent_application_statement_root{};
    uint256 parent_fs_seed{};
    uint256 acceptance_row_root{};
    uint256 parent_proof_root{};
    std::array<ChildReceiptV1, kRecursiveParentArityV1> children{};
    backend::ProofV1 parent_proof{};
    uint256 receipt_root{};
};

/**
 * Exact public statement which owns the V2 FixedTrace pin.
 *
 * `parent_program_protocol_root` is the strongest program provenance present
 * in V1 today.  `parent_program_registry_root` remains null until canonical
 * constraint bytecode and registry membership are available; that absence is
 * carried as an explicit residual and can never close recursive authority.
 */
struct ParentPublicStatementV2 {
    uint16_t version{kRecursiveParentVersionV2};
    uint32_t arity{kRecursiveParentArityV1};
    uint32_t trace_rows{kRecursiveParentTraceRowsV1};
    uint32_t semantic_columns{0};
    uint32_t proof_columns{0};
    uint256 parent_program_protocol_root{};
    uint256 parent_program_registry_root{};
    std::vector<uint32_t> fixed_trace_columns;
    uint256 fixed_trace_manifest_root{};
    std::array<uint256, kRecursiveParentArityV1>
        ordered_child_statement_roots{};
    uint256 parent_application_statement_root{};
    uint256 acceptance_row_root{};
    uint256 statement_root{};

    bool operator==(const ParentPublicStatementV2&) const = default;
};

struct ParentReceiptV2 {
    uint16_t version{kRecursiveParentVersionV2};
    ParentPublicStatementV2 statement{};
    uint256 parent_fs_seed{};
    uint256 parent_proof_root{};
    std::array<ChildReceiptV1, kRecursiveParentArityV1> children{};
    aq::AirQuotientSplitRapRowsProof parent_proof{};
    uint256 receipt_root{};
};

struct ProductV2 {
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> parent_proof_cs{};
    std::vector<std::vector<gf::Fp3>> acceptance_columns;
    std::vector<uint32_t> fixed_trace_columns;
    ParentReceiptV2 receipt{};
    aq::AirQuotientSplitRapSafeFixedReplayV3 parent_replay{};
    uint32_t residual_mask{0};
    uint32_t native_children_verified{0};
    uint64_t parent_prove_micros{0};
    uint64_t parent_verify_micros{0};
    size_t parent_proof_bytes{0};
    size_t encoded_bytes{0};
    bool acceptance_root_rebuilt_independently{false};
    bool exact_fixed_trace_manifest{false};
    bool fixed_trace_v3_proved{false};
    bool fixed_trace_v3_verified{false};
    bool dependent_zero_column_constrained{false};
    bool canonical_program_registry_bound{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

struct ProductV1 {
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> acceptance_cs{};
    aq::AirConstraintSystem<gf::Fp3> parent_proof_cs{};
    std::vector<std::vector<gf::Fp3>> acceptance_columns;
    std::vector<uint32_t> preprocessed_columns;
    std::vector<uint32_t> parent_base_column_indices;
    ParentReceiptV1 receipt{};
    tp::ReceiptV1 parent_transcript{};
    uint32_t residual_mask{0};
    uint32_t native_children_verified{0};
    uint32_t published_parent_joins_consumed{0};
    uint32_t published_merkle_fold_products_consumed{0};
    uint32_t fully_materialized_children{0};
    uint32_t width_slope_per_child_proof_column{0};
    uint64_t parent_prove_micros{0};
    uint64_t parent_verify_micros{0};
    size_t parent_proof_bytes{0};
    size_t encoded_bytes{0};
    bool exact_arity_and_order{false};
    bool role_program_statement_seed_bound{false};
    bool proof_abi_roots_recomputed{false};
    bool child_proof_payloads_native_verified{false};
    bool parent_join_roots_recomputed{false};
    bool merkle_fold_roots_recomputed{false};
    bool acceptance_rows_root_pinned{false};
    bool constant_width_acceptance{false};
    bool parent_own_v11_proof_executed{false};
    bool parent_own_v11_proof_verified{false};
    bool level_two_native_reentry_supported{false};
    bool child_verifier_executed_in_parent_air{false};
    bool canonical_recursive_verifier_executable{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/** A protocol constant, not a mutable consensus registry root. */
[[nodiscard]] uint256 CanonicalParentProgramRootV1();

[[nodiscard]] uint256 ComputeChildStatementRootV1(
    const ChildReceiptV1& child);
[[nodiscard]] uint256 ComputeParentReceiptRootV1(
    const ParentReceiptV1& receipt);

[[nodiscard]] std::vector<uint32_t>
CanonicalFixedTraceColumnsV2();
[[nodiscard]] uint256 ComputeFixedTraceManifestRootV2(
    const std::vector<uint32_t>& ordered_columns);
[[nodiscard]] uint256 ComputeParentPublicStatementRootV2(
    const ParentPublicStatementV2& statement);
[[nodiscard]] uint256 ComputeParentReceiptRootV2(
    const ParentReceiptV2& receipt);

/**
 * Verify both real V11 children, consume their proof-aware products, build the
 * root-pinned arity-two acceptance table and prove its mirror AIR with V11.
 * Host verification is not mislabeled recursive verification: residuals stay
 * set until the V11 decoder/DEEP/VM chips consume these exact cells.
 */
[[nodiscard]] ProductV1 BuildProductV1(
    const std::array<ChildInputV1, kRecursiveParentArityV1>& children);

/**
 * Recompute every child identity and product root from the expected inputs,
 * verify the embedded parent proof, and check the canonical receipt root.
 */
[[nodiscard]] bool VerifyReceiptV1(
    const std::array<ChildInputV1, kRecursiveParentArityV1>& expected_children,
    const ParentReceiptV1& receipt,
    std::string* why = nullptr);

/**
 * Build the additive V2 fixed-trace parent.  All 74 semantic acceptance
 * columns are the verifier-pinned FixedTrace group; one appended column is
 * constrained to zero and forms the non-empty dependent group required by
 * Split-RAP.  Program bytecode/registry and same-parent recursion remain
 * explicit residuals.
 */
[[nodiscard]] ProductV2 BuildProductV2(
    const std::array<ChildInputV1, kRecursiveParentArityV1>& children);
[[nodiscard]] bool VerifyReceiptV2(
    const std::array<ChildInputV1, kRecursiveParentArityV1>& expected_children,
    const ParentReceiptV2& receipt,
    std::string* why = nullptr);

[[nodiscard]] size_t SerializeReceiptV1(
    const ParentReceiptV1& receipt,
    std::vector<unsigned char>& out);
[[nodiscard]] std::optional<ParentReceiptV1> DeserializeReceiptV1(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);
[[nodiscard]] size_t SerializeReceiptV2(
    const ParentReceiptV2& receipt,
    std::vector<unsigned char>& out);
[[nodiscard]] std::optional<ParentReceiptV2> DeserializeReceiptV2(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);

struct ReadinessV1 {
    bool real_child_v11_native_verification_executable{true};
    bool role_program_statement_seed_binding_executable{true};
    bool canonical_proof_abi_root_executable{true};
    bool parent_join_product_binding_executable{true};
    bool merkle_fold_product_binding_executable{true};
    bool constant_width_root_pinned_acceptance_executable{true};
    bool parent_own_v11_proof_executable{true};
    bool level_two_native_reentry_executable{true};
    bool same_parent_decoder_deep_vm_executable{false};
    bool recursive_authority_ready{false};
};

[[nodiscard]] constexpr ReadinessV1 CurrentReadinessV1()
{
    return {};
}

} // namespace matmul::v4::rc::stage3_multirow_v11_recursive_parent

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_RECURSIVE_PARENT_H
