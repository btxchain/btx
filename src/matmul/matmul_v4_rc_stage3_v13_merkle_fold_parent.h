// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_MERKLE_FOLD_PARENT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_MERKLE_FOLD_PARENT_H

#include <matmul/matmul_v4_rc_stage3_air_parent_composer.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_merkle_fold.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_recursive_verifier.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_unified_verifier_air.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v13_proof_tape_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_merkle_fold_parent {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace composer = stage3_air_parent_composer;
namespace gf = gkr_field;
namespace mf = stage3_multirow_v11_merkle_fold;
namespace rv = stage3_multirow_v11_recursive_verifier;
namespace tape = stage3_multirow_v13_proof_tape_air;
namespace transcript = stage3_multirow_p2_transcript;
namespace unified =
    stage3_multirow_v11_unified_verifier_air;

inline constexpr uint16_t kVersionV1 = 1;

struct CellRefV1 {
    uint32_t column{UINT32_MAX};
    uint32_t row{UINT32_MAX};

    bool operator==(const CellRefV1&) const = default;
};

enum class HashLaneExpressionKindV1 : uint8_t {
    Unresolved = 0,
    Constant = 1,
    AbiU32 = 2,
    AbiFpCoordinate = 3,
    PriorOutput = 4,
    PriorOutputPlusConstant = 5,
    PriorOutputPlusAbiU32 = 6,
    PriorOutputPlusAbiFpCoordinate = 7,
    DerivedNextIndex = 8,
    PriorOutputPlusDerivedNextIndex = 9,
    SelectPriorOrSiblingLeft = 10,
    SelectPriorOrSiblingRight = 11,
};

/**
 * A verifier-owned expression for one Poseidon input lane.  ABI field
 * coordinates always name both canonical u32 limbs.  Prior outputs name a
 * concrete earlier permutation row/lane.  Selection expressions additionally
 * name the exact ABI index word and bit that orders a Merkle edge.
 */
struct HashLaneExpressionV1 {
    uint32_t task_row{UINT32_MAX};
    uint32_t lane{UINT32_MAX};
    HashLaneExpressionKindV1 kind{
        HashLaneExpressionKindV1::Unresolved};
    std::array<uint32_t, 2> source_addresses{
        UINT32_MAX, UINT32_MAX};
    uint32_t prior_task_row{UINT32_MAX};
    uint32_t prior_output_lane{UINT32_MAX};
    uint32_t selector_address{UINT32_MAX};
    uint8_t selector_bit{0};
    bool selector_is_derived_next{false};
    gf::Fp3 constant{};
    bool resolved{false};
};

struct HashOutputAliasV1 {
    uint32_t task_row{UINT32_MAX};
    uint32_t lane{UINT32_MAX};
    std::array<uint32_t, 2> source_addresses{
        UINT32_MAX, UINT32_MAX};
};

struct TypedHashPlanV1 {
    std::vector<HashLaneExpressionV1> inputs;
    std::vector<HashOutputAliasV1> outputs;
    uint32_t task_rows{0};
    uint32_t resolved_input_lanes{0};
    uint32_t expected_input_lanes{0};
    uint32_t output_aliases{0};
    uint32_t expected_output_aliases{0};
    bool every_input_lane_resolved{false};
    bool every_prior_precedes_consumer{false};
    bool every_source_address_canonical{false};
    bool lane_ownership_unique{false};
    bool output_inventory_complete{false};
    bool valid{false};
    std::string note;
};

struct SourceCarrierV1 {
    uint32_t source_address{UINT32_MAX};
    abi::SourceKeyV1 source_key{};
    CellRefV1 cell{};
};

struct OrdinaryHashProductV1 {
    TypedHashPlanV1 plan{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<SourceCarrierV1> source_carriers;
    CellRefV1 acceptance{};
    uint64_t violations{UINT64_MAX};
    bool proof_pins_ordinary{false};
    bool selectors_and_constants_only_preprocessed{false};
    bool all_abi_words_exported{false};
    bool all_prior_edges_constrained{false};
    bool all_output_roots_constrained{false};
    uint32_t canonical_typed_input_constraints{0};
    bool typed_inputs_canonical_bytecode{false};
    uint32_t canonical_relation_constraints{0};
    bool all_relation_constraints_canonical_bytecode{
        false};
    bool valid{false};
    std::string note;
};

/**
 * Derive a proof-value-free, typed lane ownership plan from public shape and
 * the canonical ABI address inventory.  Values are used only to materialize
 * the honest witness and are never admitted as preprocessed columns.
 */
[[nodiscard]] TypedHashPlanV1 BuildTypedHashPlanV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard);

/**
 * Replace proof-owned hash pins by ordinary committed cells and constrain
 * every lane to either a canonical ABI source, a prior constrained output, or
 * a verifier-owned constant.  Unresolved expressions fail closed.
 */
[[nodiscard]] OrdinaryHashProductV1 BuildOrdinaryHashProductV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard);

struct FoldRowSourcePlanV1 {
    uint32_t row{UINT32_MAX};
    uint32_t query{UINT32_MAX};
    uint32_t fold{UINT32_MAX};
    std::array<uint32_t, 6> even{};
    std::array<uint32_t, 6> odd{};
    std::array<uint32_t, 6> beta{};
    std::array<uint32_t, 6> final_value{};
    uint32_t index{UINT32_MAX};
    uint32_t even_index{UINT32_MAX};
    uint32_t odd_index{UINT32_MAX};
    uint32_t half{0};
    bool terminal{false};
    bool valid{false};
};

struct TypedFoldPlanV1 {
    std::vector<FoldRowSourcePlanV1> rows;
    uint32_t real_rows{0};
    uint32_t expected_real_rows{0};
    bool every_source_address_canonical{false};
    bool exact_query_fold_schedule{false};
    bool valid{false};
    std::string note;
};

struct OrdinaryFoldProductV1 {
    TypedFoldPlanV1 plan{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<SourceCarrierV1> source_carriers;
    CellRefV1 acceptance{};
    uint64_t violations{UINT64_MAX};
    bool proof_pins_ordinary{false};
    bool schedule_only_preprocessed{false};
    bool all_abi_words_exported{false};
    bool index_bits_constrained{false};
    bool domain_point_exponentiation_constrained{false};
    bool fold_chain_constrained{false};
    uint32_t canonical_relation_constraints{0};
    bool all_relation_constraints_canonical_bytecode{
        false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] TypedFoldPlanV1 BuildTypedFoldPlanV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard);

/**
 * Replace the old all-preprocessed fold witness by ordinary columns.  The
 * domain point x = omega_width^even_index is computed with a 32-step
 * square-and-multiply chip from a canonical bit decomposition of even_index.
 */
[[nodiscard]] OrdinaryFoldProductV1 BuildOrdinaryFoldProductV1(
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard);

/**
 * Proof-value-independent reconstruction of the exact transformed
 * Merkle/hash/fold constraint systems used by the complete V13 child.
 *
 * The canonical task order, source addresses, row counts and immutable fold
 * schedule are regenerated from PublicShape, PublicBinding and QueryRange.
 * No child root, opening, query index, fold challenge or proof-owned witness
 * is accepted as a constructor input.
 */
struct PublicConstraintSystemsV1 {
    tape::PublicShapeV1 tape_shape{};
    tape::PublicBindingV1 tape_binding{};
    rv::QueryRangeV1 range{};
    unified::MerkleFoldPublicShapeV1
        canonical_shape{};
    unified::MerkleFoldPublicPlanV1
        canonical_plan{};
    TypedHashPlanV1 hash_plan{};
    TypedFoldPlanV1 fold_plan{};
    aq::AirConstraintSystem<gf::Fp3> hash_cs;
    aq::AirConstraintSystem<gf::Fp3> fold_cs;
    std::vector<SourceCarrierV1>
        hash_source_carriers;
    std::vector<SourceCarrierV1>
        fold_source_carriers;
    CellRefV1 hash_acceptance{};
    CellRefV1 fold_acceptance{};
    uint32_t structural_hash_tasks{0};
    uint32_t structural_fold_rows{0};
    bool source_schedule_regenerated{false};
    bool task_schedule_regenerated{false};
    bool transformed_systems_rebuilt{false};
    bool hash_relations_canonical_bytecode{false};
    bool fold_relations_canonical_bytecode{false};
    bool proof_values_excluded{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildPublicConstraintSystemsV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& binding,
    const rv::QueryRangeV1& range,
    PublicConstraintSystemsV1& out,
    std::string* why = nullptr);

/**
 * Materialize honest proof-owned columns under the independently rebuilt
 * public systems.  The native shard is used only as witness data and task
 * metadata; its callbacks and preprocessed vectors are never adopted.
 */
[[nodiscard]] bool BuildOrdinaryProductsFromPublicSystemsV1(
    const PublicConstraintSystemsV1& public_systems,
    const abi::DecodedV1& decoded,
    const mf::ShardProductV1& shard,
    OrdinaryHashProductV1& hash,
    OrdinaryFoldProductV1& fold,
    std::string* why = nullptr);

struct ParentAliasAttachmentV1 {
    uint32_t source_aliases{0};
    uint32_t constraints{0};
    uint64_t violations{UINT64_MAX};
    bool tape_cells_literal{false};
    bool child_carriers_ordinary{false};
    bool cross_row_transport_constrained{false};
    bool global_r0_pending{true};
    bool valid{false};
    std::string note;
};

/**
 * Alias every ordinary ABI carrier exported by hash/fold children to the
 * literal V13 tape value cell with the same canonical source address.
 */
[[nodiscard]] bool AppendProofTapeAliasesV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const tape::ProductV1& tape_product,
    const composer::ChildAttachmentV1& tape_attachment,
    const OrdinaryHashProductV1& hash_product,
    const composer::ChildAttachmentV1& hash_attachment,
    const OrdinaryFoldProductV1& fold_product,
    const composer::ChildAttachmentV1& fold_attachment,
    ParentAliasAttachmentV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

inline constexpr bool kExecutableV1 = true;
inline constexpr bool kRecursiveConsumptionV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;

static_assert(!kRecursiveConsumptionV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_merkle_fold_parent

#endif
