// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_COMPLETE_CHILD_PARENT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_COMPLETE_CHILD_PARENT_H

#include <matmul/matmul_v4_rc_stage3_v13_deep_source_logup_parent.h>
#include <matmul/matmul_v4_rc_stage3_v13_merkle_fold_parent.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_complete_child_parent {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace composer = stage3_air_parent_composer;
namespace deep = stage3_v13_deep_source_logup_parent;
namespace gf = gkr_field;
namespace merkle = stage3_v13_merkle_fold_parent;
namespace mf = stage3_multirow_v11_merkle_fold;
namespace rv = stage3_multirow_v11_recursive_verifier;
namespace tape = stage3_multirow_v13_proof_tape_air;

inline constexpr uint16_t kVersionV1 = 1;

/**
 * Proof-independent relation schedule plus the honest witness for one
 * canonical SAFE-V13 query shard, before any challenge-dependent columns.
 *
 * This is the reusable embedding interface.  A normalized arity-two parent
 * appends two of these components, commits every deterministic column in one
 * global R0 session, then finalizes each component against that same session.
 * No child-local R0 root or standalone proof is retained.
 */
struct DeterministicComponentV1 {
    uint16_t version{kVersionV1};
    tape::PublicShapeV1 tape_shape{};
    tape::PublicBindingV1 tape_binding{};
    rv::QueryRangeV1 range{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;

    merkle::PublicConstraintSystemsV1
        public_merkle_systems;
    merkle::OrdinaryHashProductV1 hash;
    merkle::OrdinaryFoldProductV1 fold;
    merkle::ParentAliasAttachmentV1 merkle_aliases;
    composer::ChildAttachmentV1 merkle_tape_attachment;
    composer::ChildAttachmentV1 hash_attachment;
    composer::ChildAttachmentV1 fold_attachment;
    composer::ChildAttachmentV1 merkle_parent_attachment;

    deep::BaseProductV1 deep_base;
    composer::ChildAttachmentV1 deep_base_attachment;
    uint32_t terminal_acceptance_column{UINT32_MAX};
    uint32_t shared_tape_aliases{0};
    uint64_t violations{UINT64_MAX};
    bool exact_shared_tape_binding{false};
    bool exact_shared_tape_cells_aliased{false};
    bool verifier_merkle_systems_rebuilt{false};
    bool merkle_fold_complete{false};
    bool quotient_deep_base_complete{false};
    bool challenge_columns_absent{false};
    bool terminal_acceptance_connected{false};
    bool canonical_embedding_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildDeterministicComponentV1(
    const abi::DecodedV1& decoded,
    const tape::ProductV1& tape_product,
    const mf::ShardProductV1& shard,
    const deep::ProductV1& deep_product,
    DeterministicComponentV1& out,
    std::string* why = nullptr);

struct ComponentFinalizationV1 {
    composer::ChildAttachmentV1
        relocated_deep_base_attachment;
    deep::ParentFinalizationV1 deep;
    uint32_t terminal_acceptance_column{UINT32_MAX};
    bool deterministic_component_inside_r0{false};
    bool terminal_acceptance_relocated{false};
    bool valid{false};
    std::string note;
};

/**
 * Append this component's dependent LogUp relation to a wider parent.
 *
 * parent_r0_session must commit a canonical [0,n) prefix containing the
 * entire deterministic component.  It may be reused by a later sibling:
 * challenge-dependent columns appended by the first child follow that prefix
 * and never enter the second child's challenge source.
 */
[[nodiscard]] bool AppendFinalRelationToParentV1(
    const DeterministicComponentV1& component,
    const composer::ChildAttachmentV1& component_attachment,
    const uint256& domain_separated_public_seed,
    const aq::AirQuotientTwoEpochBaseRowSession& parent_r0_session,
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    ComponentFinalizationV1& out,
    std::string* why = nullptr);

/**
 * One query-shard child verifier relation.
 *
 * Both branches consume the same canonical V13 tape binding:
 *  - tape + complete Merkle/hash/fold constraints and literal ABI aliases;
 *  - tape + quotient/DeepVM constraints and dual-Fp3 source LogUp.
 *
 * Every deterministic column from both branches is attached before a single
 * parent R0 row commitment. Only then are the DEEP/quotient LogUp challenges,
 * inverses and running sums appended. The terminal acceptance cell is an
 * ordinary parent column equality-constrained to both hash and fold children.
 */
struct ProductV1 {
    uint16_t version{kVersionV1};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;

    merkle::PublicConstraintSystemsV1
        public_merkle_systems;
    merkle::OrdinaryHashProductV1 hash;
    merkle::OrdinaryFoldProductV1 fold;
    merkle::ParentAliasAttachmentV1 merkle_aliases;
    composer::ChildAttachmentV1 merkle_tape_attachment;
    composer::ChildAttachmentV1 hash_attachment;
    composer::ChildAttachmentV1 fold_attachment;
    composer::ChildAttachmentV1 merkle_parent_attachment;
    composer::ChildAttachmentV1 component_attachment;

    deep::BaseProductV1 deep_base;
    composer::ChildAttachmentV1 deep_base_attachment;
    ComponentFinalizationV1 component_finalization;
    deep::ParentFinalizationV1 deep_finalization;

    aq::AirQuotientTwoEpochBaseRowSession r0_session;
    std::vector<uint32_t> r0_base_column_indices;
    uint32_t terminal_acceptance_column{UINT32_MAX};
    uint32_t shared_tape_aliases{0};
    uint64_t violations{UINT64_MAX};
    bool exact_shared_tape_binding{false};
    bool exact_shared_tape_cells_aliased{false};
    bool verifier_merkle_systems_rebuilt{false};
    bool verifier_constraint_system_rebuilt{false};
    bool merkle_fold_complete{false};
    bool quotient_deep_complete{false};
    bool every_deterministic_column_precedes_r0{false};
    bool terminal_acceptance_connected{false};
    bool proof_ready{false};
    bool recursively_consumed{false};
    bool authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildProductV1(
    const abi::DecodedV1& decoded,
    const tape::ProductV1& tape_product,
    const mf::ShardProductV1& shard,
    const deep::ProductV1& deep_product,
    const uint256& public_seed,
    ProductV1& out,
    std::string* why = nullptr);

/**
 * Complete public statement needed to reconstruct the one-query V13 child
 * verifier. The ProgramTable is frozen consensus bytecode and
 * child_program_root must commit it exactly.
 */
struct PublicStatementV1 {
    uint16_t version{kVersionV1};
    tape::PublicShapeV1 tape_shape{};
    tape::PublicBindingV1 tape_binding{};
    rv::QueryRangeV1 range{};
    cb::ProgramTable child_program{};
    alg_hash::Digest child_program_root{};
    uint256 public_seed{};
};

/**
 * Verifier-owned callback graph rebuilt without decoded proof words, shard
 * witnesses, prover constraint callbacks, or retained prover columns.
 *
 * r0_row_root is read from the proof's first commitment group and is used
 * only as the Fiat-Shamir challenge source and exact R0 group pin.
 */
struct VerifierConstraintSystemV1 {
    uint16_t version{kVersionV1};
    PublicStatementV1 statement{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<uint32_t>
        r0_base_column_indices;
    merkle::PublicConstraintSystemsV1
        merkle_systems{};
    deep::PublicBaseConstraintSystemV1
        deep_base{};
    deep::ParentFinalizationV1
        deep_finalization{};
    uint32_t shared_tape_aliases{0};
    uint32_t terminal_acceptance_column{
        UINT32_MAX};
    bool deterministic_system_rebuilt{false};
    bool challenge_system_rebuilt{false};
    bool proof_values_excluded{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildConstraintSystemV1(
    const PublicStatementV1& statement,
    const uint256& r0_row_root,
    VerifierConstraintSystemV1& out,
    std::string* why = nullptr);

/** Rebuild the CS from the statement and proof R0 root, then invoke the
 * unmodified SAFE Split-RAP verifier. */
[[nodiscard]] bool VerifyProofV1(
    const PublicStatementV1& statement,
    const aq::AirQuotientSplitRapRowsProof& proof,
    std::string* why = nullptr);

inline constexpr bool kExecutableV1 = true;
inline constexpr bool kRecursiveConsumptionV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;

static_assert(!kRecursiveConsumptionV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_complete_child_parent

#endif
