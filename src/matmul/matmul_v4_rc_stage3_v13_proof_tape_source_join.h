// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_PROOF_TAPE_SOURCE_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_PROOF_TAPE_SOURCE_JOIN_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_v13_derived_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_v13_selection_query_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_proof_tape_source_join {

namespace abi = stage3_multirow_v11_proof_abi;
namespace aq = air_quotient;
namespace derived = stage3_v13_derived_hash_air;
namespace gf = gkr_field;
namespace selection = stage3_v13_selection_query_air;
namespace tape = stage3_multirow_v13_proof_tape_air;

inline constexpr uint16_t kProofTapeSourceJoinVersionV1 = 1;
inline constexpr uint32_t kLookupLanesV1 = 2;
inline constexpr uint32_t kTapeSourceSlotsV1 =
    tape::kRecordsPerRowV1;
inline constexpr uint32_t kDerivedSelectedSourceSlotsV1 =
    alg_hash::kAlgHashRate;
inline constexpr uint32_t kSourceSlotsV1 =
    kTapeSourceSlotsV1 + kDerivedSelectedSourceSlotsV1;
inline constexpr uint32_t kDerivedConsumerSlotsV1 =
    2 * alg_hash::kAlgHashRate;
inline constexpr uint32_t kSelectionZConsumerSlotsV1 = 6;
inline constexpr uint32_t kSelectionQueryConsumerSlotsV1 = 1;
inline constexpr uint32_t kConsumerSlotsV1 =
    kDerivedConsumerSlotsV1 +
    kSelectionZConsumerSlotsV1 +
    kSelectionQueryConsumerSlotsV1;

enum class EndpointRoleV1 : uint8_t {
    TapeWordToDerivedLow = 1,
    TapeWordToDerivedHigh = 2,
    DerivedSelectedToSelectionZ = 3,
    TapeQueryToSelectionQuery = 4,
};

struct CellRefV1 {
    uint32_t column{UINT32_MAX};
    uint32_t row{UINT32_MAX};

    bool operator==(const CellRefV1&) const = default;
};

struct LookupEndpointV1 {
    EndpointRoleV1 role{
        EndpointRoleV1::TapeWordToDerivedLow};
    abi::SourceKeyV1 key{};
    uint32_t address{UINT32_MAX};
    uint32_t lookup_slot{UINT32_MAX};
    CellRefV1 address_cell{};
    CellRefV1 value_cell{};
    std::array<CellRefV1, 32> bits{};
    bool address_is_ordinary_cell{false};
    bool bits_are_ordinary_cells{false};

    bool operator==(const LookupEndpointV1&) const = default;
};

/**
 * The complete verifier-rebuilt multiset map.  Tape words and selected
 * derived-hash messages are sources; derived limbs and the remaining
 * Selection proof-tape inputs are consumers.  No proof value enters this
 * plan.
 */
struct PlanV1 {
    uint16_t version{kProofTapeSourceJoinVersionV1};
    tape::PublicShapeV1 shape{};
    uint32_t n_lde{0};
    uint32_t query_count{0};
    uint32_t parent_rows{0};
    uint32_t tape_column_offset{0};
    uint32_t derived_column_offset{0};
    uint32_t selection_column_offset{0};
    std::vector<LookupEndpointV1> sources;
    std::vector<LookupEndpointV1> consumers;
    uint32_t derived_limb_relations{0};
    uint32_t selected_z_relations{0};
    uint32_t query_index_relations{0};
    alg_hash::Digest plan_root{};
    bool exact_tape_schedule{false};
    bool exact_derived_schedule{false};
    bool exact_selection_schedule{false};
    bool all_tape_addresses_mapped{false};
    bool exact_multiset_cardinality{false};
    bool valid{false};
    std::string note;

    bool operator==(const PlanV1&) const = default;
};

[[nodiscard]] bool BuildCanonicalPlanV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    uint32_t n_lde,
    uint32_t query_count,
    uint32_t parent_rows,
    uint32_t tape_column_offset,
    uint32_t derived_column_offset,
    uint32_t selection_column_offset,
    PlanV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateCanonicalPlanV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    uint32_t n_lde,
    uint32_t query_count,
    const PlanV1& claimed,
    std::string* why = nullptr);

struct ChallengesV1 {
    std::array<gf::Fp3, kLookupLanesV1> gamma{};
    std::array<gf::Fp3, kLookupLanesV1> alpha{};

    bool operator==(const ChallengesV1& other) const;
};

[[nodiscard]] bool DeriveChallengesV1(
    const PlanV1& plan,
    const uint256& public_seed,
    const uint256& parent_r0_row_root,
    ChallengesV1& out,
    std::string* why = nullptr);

struct LayoutV1 {
    uint32_t tape_base{0};
    uint32_t tape_columns{0};
    uint32_t derived_base{0};
    uint32_t derived_columns{0};
    uint32_t selection_base{0};
    uint32_t selection_columns{0};
    uint32_t source_active_base{0};
    uint32_t source_address_base{0};
    uint32_t source_multiplicity_base{0};
    uint32_t consumer_active_base{0};
    uint32_t consumer_address_base{0};
    uint32_t dependent_base{0};
    uint32_t source_inverse_base{0};
    uint32_t consumer_inverse_base{0};
    uint32_t running_base{0};
    uint32_t end{0};

    [[nodiscard]] uint32_t SourceActive(uint32_t slot) const
    {
        return source_active_base + slot;
    }
    [[nodiscard]] uint32_t SourceAddress(uint32_t slot) const
    {
        return source_address_base + slot;
    }
    [[nodiscard]] uint32_t SourceMultiplicity(uint32_t slot) const
    {
        return source_multiplicity_base + slot;
    }
    [[nodiscard]] uint32_t ConsumerActive(uint32_t slot) const
    {
        return consumer_active_base + slot;
    }
    [[nodiscard]] uint32_t ConsumerAddress(uint32_t slot) const
    {
        return consumer_address_base + slot;
    }
    [[nodiscard]] uint32_t SourceInverse(
        uint32_t lane, uint32_t slot) const
    {
        return source_inverse_base +
            lane * kSourceSlotsV1 + slot;
    }
    [[nodiscard]] uint32_t ConsumerInverse(
        uint32_t lane, uint32_t slot) const
    {
        return consumer_inverse_base +
            lane * kConsumerSlotsV1 + slot;
    }
    [[nodiscard]] uint32_t Running(uint32_t lane) const
    {
        return running_base + lane;
    }
};

struct ProductV1 {
    PlanV1 plan{};
    LayoutV1 layout{};
    ChallengesV1 challenges{};
    tape::PublicBindingV1 tape_binding{};
    derived::BindingV1 derived_binding{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> r0_base_column_indices;
    aq::AirQuotientTwoEpochBaseRowSession r0_session;
    uint64_t violations{UINT64_MAX};
    bool tape_verifier_resident{false};
    bool derived_hash_verifier_resident{false};
    bool selection_verifier_resident{false};
    bool address_value_bit_cells_referenced{false};
    bool selection_proof_tape_inputs_closed{false};
    bool v14_selection_inputs_resident{false};
    bool dual_fp3_rational_identity_constrained{false};
    bool terminal_cancellation_constrained{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildProductV1(
    const tape::ProductV1& tape_product,
    const derived::ProductV1& derived_product,
    const selection::ProductV1& selection_product,
    const uint256& public_seed,
    ProductV1& out,
    std::string* why = nullptr);

struct ProofV1 {
    uint16_t version{kProofTapeSourceJoinVersionV1};
    alg_hash::Digest plan_root{};
    uint256 r0_row_root{};
    aq::AirQuotientSplitRapRowsProof proof{};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] bool ProveV1(
    const ProductV1& product,
    const uint256& public_seed,
    ProofV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const derived::BindingV1& derived_binding,
    uint32_t n_lde,
    uint32_t query_count,
    const PlanV1& canonical_plan,
    const uint256& public_seed,
    const ProofV1& proof,
    std::string* why = nullptr);

[[nodiscard]] uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

/**
 * Bounded q=2 relation canary.  It uses the production physical
 * Address/Value/Bit columns, schedule columns, post-R0 challenge derivation
 * and dual-Fp3 rational identity, but only two verifier-rebuilt source
 * addresses.  This keeps proof-level regression tests bounded without
 * weakening or adding a second production protocol.
 */
struct BoundedCanaryStatementV1 {
    uint16_t version{kProofTapeSourceJoinVersionV1};
    std::array<uint32_t, 2> source_address{{101, 203}};

    bool operator==(const BoundedCanaryStatementV1&) const = default;
};

struct BoundedCanaryProductV1 {
    BoundedCanaryStatementV1 statement{};
    PlanV1 plan{};
    LayoutV1 layout{};
    ChallengesV1 challenges{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    std::vector<uint32_t> r0_base_column_indices;
    aq::AirQuotientTwoEpochBaseRowSession r0_session;
    uint64_t violations{UINT64_MAX};
    bool exact_production_equations{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildBoundedCanaryProductV1(
    const BoundedCanaryStatementV1& statement,
    const std::array<uint32_t, 2>& witness_values,
    const uint256& public_seed,
    BoundedCanaryProductV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyBoundedCanaryV1(
    const BoundedCanaryStatementV1& statement,
    const uint256& public_seed,
    const ProofV1& proof,
    std::string* why = nullptr);

inline constexpr bool kProofTapeSourceJoinExecutableV1 = true;
inline constexpr bool kProofTapeSourceJoinRecursivelyConsumedV1 = false;
inline constexpr bool kProofTapeSourceJoinAuthorityReadyV1 = false;

static_assert(!kProofTapeSourceJoinRecursivelyConsumedV1);
static_assert(!kProofTapeSourceJoinAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_proof_tape_source_join

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_PROOF_TAPE_SOURCE_JOIN_H
