// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_PROOF_ABI_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_PROOF_ABI_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_proof_abi {

namespace aq = air_quotient;
namespace gf = gkr_field;

/**
 * Canonical field-cell ABI for the additive MultiRow V11 research backend.
 *
 * This is deliberately not the on-wire proof codec. It is the exact,
 * proof-owned input tape that a normalized parent verifier consumes. Every
 * scalar is split into canonical u32 cells, and every cell is preceded by its
 * monotonically increasing source address. The address makes omission,
 * duplication and record reordering fail closed while also giving same-parent
 * equality joins a stable target.
 */
inline constexpr uint32_t kFieldAbiMagicV1 = 0x31414246U; // "FBA1"
inline constexpr uint32_t kFieldAbiVersionV1 = 1;
inline constexpr uint32_t kMultiRowProtocolVersionV11 = 11;
inline constexpr uint64_t kMultiRowProtocolDomainV11 =
    0x4d525032'51313932ULL; // "MRP2Q192"
inline constexpr uint32_t kMultiRowProtocolVersionV13 = 13;
inline constexpr uint64_t kMultiRowProtocolDomainV13 =
    0x4d525331'33513139ULL; // "MRS13Q19"
inline constexpr uint32_t kQueryCountV11 = 192;
inline constexpr uint32_t kQueryCandidatesV11 = 2;
inline constexpr uint32_t kFieldAbiHeaderWordsV1 = 6;
inline constexpr uint32_t kFieldAbiMaxSourceCellsV1 = 8U << 20;
inline constexpr uint32_t kDerivedTranscriptAddressBaseV1 = 0x80000000U;

enum class FieldKindV1 : uint16_t {
    PublicFsSeed = 1,
    SplitVersion = 2,
    TraceRows = 3,
    TraceColumns = 4,
    QuotientLen = 5,
    BaseColumnCount = 6,
    BaseColumnIndex = 7,
    AirConstraintLambda = 8,
    BatchVersion = 9,
    PowGrindNonce = 10,
    Blowup = 11,
    NCoeffs = 12,
    GroupCount = 13,
    GroupRole = 14,
    GroupFirstColumn = 15,
    GroupColumnCount = 16,
    GroupRoot = 17,
    GroupLeaves = 18,
    ColumnCount = 19,
    ColumnLen = 20,
    Lambda = 21,
    Z1 = 22,
    Z2 = 23,
    EvalZ1Count = 24,
    EvalZ1 = 25,
    EvalZ2Count = 26,
    EvalZ2 = 27,
    DeepWeight1 = 28,
    DeepWeight2 = 29,
    FoldLayerCount = 30,
    FoldRoot = 31,
    FoldLeaves = 32,
    FinalValue = 33,
    FoldChallengeCount = 34,
    FoldChallenge = 35,
    QueryCount = 36,
    QueryCandidateCount = 37,
    QueryCandidateDigest = 38,
    QuerySelectedCandidate = 39,
    QueryIndex = 40,
    QueryGroupCount = 41,
    QueryRowValueCount = 42,
    QueryRowValue = 43,
    QueryRowSiblingCount = 44,
    QueryRowSibling = 45,
    QueryStepCount = 46,
    QueryStepEvenIndex = 47,
    QueryStepOddIndex = 48,
    QueryStepEven = 49,
    QueryStepOdd = 50,
    QueryStepEvenSiblingCount = 51,
    QueryStepEvenSibling = 52,
    QueryStepOddSiblingCount = 53,
    QueryStepOddSibling = 54,
    NextQueryCount = 55,
    NextGroupCount = 56,
    NextRowValueCount = 57,
    NextRowValue = 58,
    NextRowSiblingCount = 59,
    NextRowSibling = 60,
};
static_assert(
    static_cast<uint16_t>(
        FieldKindV1::NextRowSibling) == 60,
    "canonical proof ABI must retain all 60 semantic field families");

/** A semantic coordinate independent of its physical parent column. */
struct SourceKeyV1 {
    FieldKindV1 kind{FieldKindV1::PublicFsSeed};
    uint32_t a{0};
    uint32_t b{0};
    uint32_t c{0};
    uint32_t d{0};
    uint8_t limb{0};

    bool operator==(const SourceKeyV1&) const = default;
    bool operator<(const SourceKeyV1& other) const;
};

enum class OwnershipClassV1 : uint8_t {
    PublicStatement = 1,
    ChildProofEnvelope = 2,
    DerivedTranscript = 3,
};

struct SourceCellV1 {
    uint32_t address{0};
    SourceKeyV1 key{};
    uint32_t value{0};
    OwnershipClassV1 ownership{OwnershipClassV1::ChildProofEnvelope};

    friend bool operator==(
        const SourceCellV1&,
        const SourceCellV1&) = default;
};

struct QueryCandidatesV1 {
    std::array<Fri3AlgDigest, kQueryCandidatesV11> digest{};
    uint32_t selected_ordinal{kQueryCandidatesV11};
};

struct EnvelopeV1 {
    /** Little-endian u32 words of the external public Fiat-Shamir seed. */
    std::array<uint32_t, 8> public_fs_seed{};
    /** Explicit V11 statement fields; checked against the payload shape. */
    uint32_t trace_columns{0};
    uint32_t quotient_len{0};
    aq::AirQuotientSplitRapRowsProof split{};
};

struct DecodedV1 {
    EnvelopeV1 envelope{};
    std::vector<SourceCellV1> sources;
    bool canonical{false};
    bool complete{false};
    bool addresses_unique{false};
    bool semantic_keys_unique{false};
    uint32_t public_statement_cells{0};
    uint32_t child_proof_cells{0};
    uint32_t derived_transcript_cells{0};
    std::string note;
};

/**
 * Layout:
 *   [magic, abi_version, protocol_version, domain_lo, domain_hi, cell_count]
 *   repeated cell_count times: [source_address, u32_value].
 *
 * Integers and field elements are little-endian. u64/Fp use two u32 cells,
 * Fp3 uses six, and a Poseidon digest uses eight. Fp limbs must reconstruct a
 * value strictly below the Goldilocks modulus; x+p aliases are rejected.
 */
[[nodiscard]] bool EncodeCanonicalV1(
    const EnvelopeV1& envelope,
    std::vector<uint32_t>& words,
    std::vector<SourceCellV1>* sources = nullptr,
    std::string* why = nullptr);

[[nodiscard]] std::optional<DecodedV1> DecodeCanonicalV1(
    const std::vector<uint32_t>& words,
    std::string* why = nullptr);

/**
 * SAFE/Q192/K=2 V13 uses the same complete 60-family semantic inventory and
 * canonical u32/Fp decomposition, but has a distinct ABI header and accepts
 * only the V13 multi-row batch version.  These functions are additive: the
 * frozen V11 encoding remains byte-for-byte unchanged.
 */
[[nodiscard]] bool EncodeCanonicalSafeV13(
    const EnvelopeV1& envelope,
    std::vector<uint32_t>& words,
    std::vector<SourceCellV1>* sources = nullptr,
    std::string* why = nullptr);

[[nodiscard]] std::optional<DecodedV1> DecodeCanonicalSafeV13(
    const std::vector<uint32_t>& words,
    std::string* why = nullptr);

/** Reject duplicate physical addresses or duplicate semantic coordinates. */
[[nodiscard]] bool ValidateSourceCellsV1(
    const std::vector<SourceCellV1>& sources,
    std::string* why = nullptr);

/** Stable lookup used when appending a same-parent equality constraint. */
[[nodiscard]] std::optional<uint32_t> FindSourceAddressV1(
    const std::vector<SourceCellV1>& sources,
    const SourceKeyV1& key);

/**
 * Candidates are transcript outputs, not attacker-supplied proof fields.
 * They are therefore never serialized by EncodeCanonicalV1. This helper
 * allocates stable, disjoint verifier-cell addresses only after checking the
 * K=2 first-valid rule and equality of the selected index to the proof field.
 * A caller must still equality-constrain these cells to a P2 replay chip.
 */
struct DerivedTranscriptExportsV1 {
    std::vector<SourceCellV1> sources;
    bool canonical_candidates{false};
    bool k2_first_valid{false};
    bool selected_indices_match_proof{false};
    bool transcript_equality_constrained{false};
    bool recursively_consumed{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] DerivedTranscriptExportsV1
BuildDerivedQueryCandidateExportsV1(
    const DecodedV1& decoded,
    const std::array<QueryCandidatesV1, kQueryCountV11>& candidates);

struct ParentPublicCellV1 {
    SourceKeyV1 key{};
    uint32_t parent_column{0};
    uint32_t value{0};
};

struct PublicStatementJoinV1 {
    struct Equality {
        uint32_t source_address{0};
        uint32_t parent_column{0};
    };
    std::vector<Equality> equalities;
    uint32_t required_cells{0};
    uint32_t matched_cells{0};
    bool exact_public_inventory{false};
    bool values_equal{false};
    bool parent_columns_unique{false};
    bool actual_air_constraints_appended{false};
    bool valid{false};
    std::string note;
};

/**
 * Exact host-side append plan for equality to parent public columns. It
 * rejects an omitted, duplicated or value-substituted public cell. The
 * `actual_air_constraints_appended` flag remains false until a parent builder
 * consumes the plan.
 */
[[nodiscard]] PublicStatementJoinV1 BuildPublicStatementJoinV1(
    const DecodedV1& decoded,
    const std::vector<ParentPublicCellV1>& parent);

struct ReadinessV1 {
    bool canonical_decoder_executable{true};
    bool exact_field_inventory_executable{true};
    bool stable_source_addresses_executable{true};
    bool public_statement_join_plan_executable{true};
    bool public_statement_air_equalities_appended{false};
    bool same_parent_consumer_joins_executable{false};
    bool v11_backend_executable{false};
    bool recursive_authority_ready{false};
};

[[nodiscard]] constexpr ReadinessV1 CurrentReadinessV1()
{
    return {};
}

} // namespace matmul::v4::rc::stage3_multirow_v11_proof_abi

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_PROOF_ABI_H
