// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_ALI_SAME_PARENT_BRIDGE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_ALI_SAME_PARENT_BRIDGE_H

#include <matmul/matmul_v4_rc_stage3_ali_manifest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_ali_same_parent_bridge {

namespace ali = stage3_ali_manifest;
namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kAliSameParentBridgeVersionV1 = 1;
inline constexpr uint32_t kAliDigestLanesV1 =
    alg_hash::kAlgHashDigestLen;

struct CellRefV1 {
    uint32_t column{UINT32_MAX};
    uint32_t row{UINT32_MAX};

    bool operator==(const CellRefV1&) const = default;
};

struct CellPairV1 {
    /** Existing cell emitted by the manifest/program selection side. */
    CellRefV1 manifest_producer;
    /** Existing cell consumed by the normalized family-VM statement. */
    CellRefV1 normalized_vm_consumer;

    bool operator==(const CellPairV1&) const = default;
};

enum class StatementWordKindV1 : uint16_t {
    FamilyIndex = 1,
    ProofSiteKind = 2,
    RelationRole = 3,
    SemanticRelationComplete = 4,
    SemanticEndpointCount = 5,
    SemanticEndpoint = 6,
    SourceCurrentWidth = 7,
    SourceNextWidth = 8,
    SourceChallengeWidth = 9,
    SourceConstraintCount = 10,
    SourceInstructionCount = 11,
    SourceChallengeLoads = 12,
    SourceMaximumDegree = 13,
    SourceMaximumComposedDegree = 14,
    SourceQuotientLen = 15,
    SourceNCoeffs = 16,
    SourceNLde = 17,
    CompiledCurrentWidth = 18,
    CompiledNextWidth = 19,
    CompiledChallengeWidth = 20,
    CompiledConstraintCount = 21,
    CompiledInstructionCount = 22,
    CompiledChallengeLoads = 23,
    CompiledMaximumDegree = 24,
    CompiledMaximumComposedDegree = 25,
    CompiledQuotientLen = 26,
    CompiledNCoeffs = 27,
    CompiledNLde = 28,
    CompiledPhysicalColumns = 29,
    SemanticRows = 30,
    PaddedSourceRows = 31,
    VerticalLogicalRows = 32,
    VerticalPaddedRows = 33,
    CoefficientCap = 34,
    MinimumVmSegments = 35,
    SourceTableCanonical = 36,
    SourceTableNonStub = 37,
    ChallengeClassDegreeChecked = 38,
    CompiledTableCanonical = 39,
    ExactQ192Rows = 40,
    QuotientAndLdeBoundsDerived = 41,
    WithinCoefficientCap = 42,
    ConstantWidth53 = 43,
};

/**
 * One u32-injective statement word. `ordinal` is zero except for vector
 * fields and the low/high words of a uint64.  Values are never absorbed as
 * raw uint64 field lanes.
 */
struct StatementWordV1 {
    StatementWordKindV1 kind{
        StatementWordKindV1::FamilyIndex};
    uint32_t ordinal{0};
    uint32_t value{0};

    bool operator==(const StatementWordV1&) const = default;
};

struct CanonicalAliVmStatementV1 {
    uint16_t version{kAliSameParentBridgeVersionV1};
    uint32_t family_index{0};
    alg_hash::Digest manifest_commitment{};
    alg_hash::Digest source_program_key{};
    alg_hash::Digest compiled_program_key{};
    std::vector<StatementWordV1> words;

    bool operator==(const CanonicalAliVmStatementV1&) const = default;
};

struct StatementWordRefsV1 {
    StatementWordKindV1 kind{
        StatementWordKindV1::FamilyIndex};
    uint32_t ordinal{0};
    CellPairV1 cells;

    bool operator==(const StatementWordRefsV1&) const = default;
};

struct AliSameParentRefsV1 {
    uint16_t version{kAliSameParentBridgeVersionV1};
    uint32_t family_index{0};
    std::array<CellPairV1, kAliDigestLanesV1>
        manifest_commitment;
    std::array<CellPairV1, kAliDigestLanesV1>
        source_program_key;
    std::array<CellPairV1, kAliDigestLanesV1>
        compiled_program_key;
    std::vector<StatementWordRefsV1> words;
};

struct EqualityLayoutV1 {
    uint32_t carrier{UINT32_MAX};
    uint32_t source_selector{UINT32_MAX};
    uint32_t sink_selector{UINT32_MAX};
    uint32_t carry_selector{UINT32_MAX};
    bool same_row{false};
};

struct AppendResultV1 {
    bool valid{false};
    uint32_t family_index{0};
    uint32_t original_columns{0};
    uint32_t appended_columns{0};
    uint32_t equality_count{0};
    uint32_t manifest_commitment_equalities{0};
    uint32_t source_key_equalities{0};
    uint32_t compiled_key_equalities{0};
    uint32_t statement_word_equalities{0};
    uint32_t degree_words_constrained{0};
    uint32_t constraint_count_words_constrained{0};
    uint32_t row_and_cap_words_constrained{0};
    bool exact_manifest_commitment_root_pinned{false};
    bool exact_source_and_compiled_keys_pinned{false};
    bool exact_word_order_and_values_pinned{false};
    bool literal_parent_refs_reused{false};
    bool cross_row_transport_constrained{false};
    bool only_position_selectors_preprocessed{false};
    bool actual_values_preprocessed{true};
    bool normalized_vm_cell_ownership_proved{false};
    bool canonical_manifest_hash_replayed_in_parent{false};
    bool recursively_consumed{false};
    bool recursive_authority{false};
    std::vector<EqualityLayoutV1> equality_layouts;
    std::vector<std::string> residuals;
    std::string note;
};

/**
 * Derive the exact normalized statement for one family from the canonical
 * 28-family manifest.  The returned words contain every inventory scalar,
 * including both u32 halves of each uint64 field.
 */
[[nodiscard]] bool BuildCanonicalAliVmStatementV1(
    uint32_t family_index,
    CanonicalAliVmStatementV1& out,
    std::string* why = nullptr);

/**
 * Append literal same-parent equality/pin constraints.
 *
 * On success every producer and consumer cell is AIR-constrained to the
 * canonical statement value. Existing values are ordinary committed witness
 * cells; only row-position selectors are verifier-preprocessed. The call is
 * fail-before-mutate for malformed, duplicate, preprocessed, collapsed, or
 * value-mismatched references.
 */
[[nodiscard]] bool AppendAliSameParentBridgeV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const AliSameParentRefsV1& refs,
    AppendResultV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint32_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

inline constexpr bool
    kAliSameParentNormalizedVmOwnershipProvedV1 = false;
inline constexpr bool
    kAliSameParentRecursiveConsumptionV1 = false;
inline constexpr bool kAliSameParentAuthorityV1 = false;
static_assert(!kAliSameParentNormalizedVmOwnershipProvedV1);
static_assert(!kAliSameParentRecursiveConsumptionV1);
static_assert(!kAliSameParentAuthorityV1);

} // namespace matmul::v4::rc::stage3_ali_same_parent_bridge

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_ALI_SAME_PARENT_BRIDGE_H
