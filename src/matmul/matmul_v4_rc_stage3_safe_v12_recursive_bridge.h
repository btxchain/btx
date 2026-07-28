// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_RECURSIVE_BRIDGE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_RECURSIVE_BRIDGE_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_domain_registry.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_nirop_reduction.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

/**
 * Executable narrow bridge for the acyclic V12 transcript:
 *
 *   typed FRI terminal receipts
 *        -> post-FRI tax sigma + one g20 nonce
 *        -> two independently typed 384-lane SAFE query squeezes
 *        -> two first-distinct Q96 sampler inputs/outputs.
 *
 * The shape-derived five-channel domain-registry root is the only
 * preprocessed value. Every receipt, tax, nonce, query and sampler cell is an
 * ordinary proof-owned column. A verifier-rebuilt fixed row map gives every
 * equality an exact producer/consumer role, lane, ordinal and source offset.
 *
 * This is deliberately additive. It proves the bridge relation as a real
 * AirQuotient proof, but it does not claim recursive authority until the
 * normalized parent copies its actual child cells into this exact map. Until
 * that copy-in lands, the standalone proof has no public source-value
 * statement: its only external proof-instance binding is the caller-supplied
 * `fs_seed`. "Executable" below means executable foundation, never complete
 * statement or consensus authority.
 */
namespace matmul::v4::rc::stage3_safe_v12_recursive_bridge {

namespace aq = air_quotient;
namespace cb = constraint_bytecode;
namespace domains = stage3_safe_v12_domain_registry;
namespace fsair = stage3_safe_v12_fs_air;
namespace gf = gkr_field;
namespace nirop = stage3_safe_v12_nirop_reduction;
namespace qsampler = stage3_safe_v12_query_sampler;

inline constexpr uint16_t kRecursiveBridgeVersionV12 = 1;
inline constexpr uint32_t kTraceRowsV12 = 1024;
inline constexpr uint32_t kFriTerminalReceiptRowsV12 = 8;
inline constexpr uint32_t kTaxSigmaRowsV12 = 8;
inline constexpr uint32_t kNonceRowsV12 = 4;
inline constexpr uint32_t kQueryCandidateRowsV12 =
    fsair::kFriLaneCountV12 *
    fsair::kQueryCandidatesPerLaneV12 * 3;
inline constexpr uint32_t kQueryOutputRowsV12 =
    fsair::kFriLaneCountV12 * fsair::kQueriesPerLaneV12;
inline constexpr uint32_t kActiveMapRowsV12 =
    kFriTerminalReceiptRowsV12 + kTaxSigmaRowsV12 +
    kNonceRowsV12 + kQueryCandidateRowsV12 +
    kQueryOutputRowsV12;
inline constexpr uint32_t kPaddingRowsV12 =
    kTraceRowsV12 - kActiveMapRowsV12;
inline constexpr uint32_t kTaxCoreLanesV12 = 55;
inline constexpr uint32_t kQueryAbsorbLanesV12 = 14;
inline constexpr uint32_t kQuerySqueezeLanesV12 =
    fsair::kQueryCandidatesPerLaneV12 * 3;
inline constexpr uint32_t kLimbBitsV12 = 64;
inline constexpr uint32_t kHighAndChunkV12 = 6;
inline constexpr uint32_t kHighAndStepsV12 = 6;

static_assert(kActiveMapRowsV12 == 980);
static_assert(kPaddingRowsV12 == 44);
static_assert(kQuerySqueezeLanesV12 == 384);

enum class CellKindV12 : uint8_t {
    FriTerminalReceipt = 1,
    TaxSigma = 2,
    SharedNonce = 3,
    QueryCandidate = 4,
    QueryOutput = 5,
    Padding = 6,
};

/**
 * Exact semantic meaning of one source==consumer row.
 *
 * `source_offset` and `consumer_offset` are offsets in the named producer and
 * consumer vectors, not prover-supplied witness values.
 */
struct CellMapEntryV12 {
    uint32_t row{0};
    CellKindV12 kind{CellKindV12::Padding};
    uint32_t lane{0};
    uint32_t ordinal{0};
    uint32_t source_offset{0};
    uint32_t consumer_offset{0};

    bool operator==(const CellMapEntryV12&) const = default;
};

struct LayoutV12 {
    uint32_t expected_registry_root_base{0};
    uint32_t proof_registry_root_base{
        expected_registry_root_base + 4};
    uint32_t fri_terminal_base{
        proof_registry_root_base + 4};
    uint32_t tax_core_base{
        fri_terminal_base + 8};
    uint32_t tax_sigma_base{
        tax_core_base + kTaxCoreLanesV12};
    uint32_t nonce_base{tax_sigma_base + 4};
    uint32_t query_absorb_base{nonce_base + 2};
    uint32_t source{
        query_absorb_base +
        fsair::kFriLaneCountV12 * kQueryAbsorbLanesV12};
    uint32_t consumer{source + 1};
    uint32_t bit_base{consumer + 1};
    uint32_t high_and_base{bit_base + kLimbBitsV12};
    uint32_t row_counter{high_and_base + kHighAndStepsV12};
    uint32_t end{row_counter + 1};

    [[nodiscard]] constexpr uint32_t ExpectedRegistryRoot(
        uint32_t lane) const
    {
        return expected_registry_root_base + lane;
    }
    [[nodiscard]] constexpr uint32_t ProofRegistryRoot(
        uint32_t lane) const
    {
        return proof_registry_root_base + lane;
    }
    [[nodiscard]] constexpr uint32_t FriTerminal(
        uint32_t lane, uint32_t limb) const
    {
        return fri_terminal_base + 4 * lane + limb;
    }
    [[nodiscard]] constexpr uint32_t TaxCore(uint32_t offset) const
    {
        return tax_core_base + offset;
    }
    [[nodiscard]] constexpr uint32_t TaxSigma(uint32_t limb) const
    {
        return tax_sigma_base + limb;
    }
    [[nodiscard]] constexpr uint32_t Nonce(uint32_t word) const
    {
        return nonce_base + word;
    }
    [[nodiscard]] constexpr uint32_t QueryAbsorb(
        uint32_t lane, uint32_t offset) const
    {
        return query_absorb_base +
            kQueryAbsorbLanesV12 * lane + offset;
    }
    [[nodiscard]] constexpr uint32_t Bit(uint32_t bit) const
    {
        return bit_base + bit;
    }
    [[nodiscard]] constexpr uint32_t HighAnd(uint32_t step) const
    {
        return high_and_base + step;
    }
};

inline constexpr uint32_t kAirColumnsV12 = LayoutV12{}.end;

struct RecursiveBridgeV12 {
    LayoutV12 layout{};
    fsair::ShapeV12 shape{};
    domains::TranscriptDomainRegistryV12 registry{};
    cb::ProgramTable program_table{};
    alg_hash::Digest program_root{};
    std::vector<CellMapEntryV12> cell_map;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t verifier_owned_preprocessed_columns{0};
    uint32_t proof_owned_preprocessed_columns{0};
    uint32_t equality_constraints{0};
    uint32_t canonical_encoding_constraints{0};
    uint32_t violations{0};
    bool exact_cell_map_rebuilt{false};
    bool domain_registry_root_pinned{false};
    bool typed_terminal_receipts_mapped{false};
    bool shared_tax_and_nonce_mapped{false};
    bool both_query_candidate_vectors_mapped{false};
    bool both_q96_outputs_mapped{false};
    bool proof_cells_are_ordinary_columns{false};
    bool canonical_bytecode_is_relation_source{false};
    bool normalized_parent_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

struct RecursiveBridgeProofV12 {
    uint16_t version{kRecursiveBridgeVersionV12};
    fsair::ShapeV12 shape{};
    alg_hash::Digest registry_root{};
    alg_hash::Digest program_root{};
    aq::AirQuotientRowsProof proof{};
    bool canonical_proof_encoding{false};
    bool verified{false};
    bool normalized_parent_consumed{false};
    bool recursive_authority_ready{false};
    std::string note;
};

/** Verifier-rebuilt exact producer/consumer inventory (980 active + 44 pad). */
[[nodiscard]] std::vector<CellMapEntryV12>
CanonicalCellMapV12();

/**
 * Shape-specific canonical bytecode. Shape constants and all five typed SAFE
 * tags are verifier-rebuilt from `registry`; no proof field changes the
 * program.
 */
[[nodiscard]] bool BuildRecursiveBridgeProgramTableV12(
    const fsair::ManifestV12& manifest,
    const domains::TranscriptDomainRegistryV12& registry,
    cb::ProgramTable& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildRecursiveBridgeV12(
    const fsair::ManifestV12& manifest,
    const nirop::HybridInputsV12& inputs,
    const nirop::HybridReceiptV12& receipt,
    const alg_hash::Digest& proof_registry_root,
    RecursiveBridgeV12& out,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateRecursiveBridgeV12(
    const fsair::ManifestV12& manifest,
    const nirop::HybridInputsV12& inputs,
    const nirop::HybridReceiptV12& receipt,
    const alg_hash::Digest& proof_registry_root,
    const RecursiveBridgeV12& bridge,
    std::string* why = nullptr);

[[nodiscard]] uint32_t CountViolationsV12(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

[[nodiscard]] bool ProveRecursiveBridgeV12(
    const RecursiveBridgeV12& bridge,
    const uint256& fs_seed,
    RecursiveBridgeProofV12& out,
    std::string* why = nullptr);

/**
 * Rebuilds the shape/domain/program relation and verifies the real quotient
 * proof. It also rejects noncanonical in-memory Fp3 representatives before
 * invoking the backend; serialization canonicalization is not accepted as a
 * substitute for unique proof encoding.
 */
[[nodiscard]] bool VerifyRecursiveBridgeProofV12(
    const fsair::ManifestV12& manifest,
    const RecursiveBridgeProofV12& receipt,
    const uint256& fs_seed,
    std::string* why = nullptr);

inline constexpr bool kRecursiveBridgeExecutableV12 = true;
inline constexpr bool kRecursiveBridgePublicSourceStatementBoundV12 = false;
inline constexpr bool kRecursiveBridgeNormalizedParentConsumedV12 = false;
inline constexpr bool kRecursiveBridgeAuthorityReadyV12 = false;

static_assert(!kRecursiveBridgePublicSourceStatementBoundV12);
static_assert(!kRecursiveBridgeNormalizedParentConsumedV12);
static_assert(!kRecursiveBridgeAuthorityReadyV12);

} // namespace matmul::v4::rc::stage3_safe_v12_recursive_bridge

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_RECURSIVE_BRIDGE_H
