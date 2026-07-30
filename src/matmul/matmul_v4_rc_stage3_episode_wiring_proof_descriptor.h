// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_PROOF_DESCRIPTOR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_PROOF_DESCRIPTOR_H

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_episode_wiring_product.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_episode_wiring_proof_descriptor {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kMagicV1 = 0x31504457U; // "WDP1"
inline constexpr uint32_t kMaxRecordsV1 = 1U << 28;
inline constexpr uint32_t kTerminalLanesV1 = 2;

/**
 * Exact owner of one verifier-read word.  Section values are deliberately
 * public integers rather than a lossy "relation vs memory" bit: the same
 * proof bytes under a different edge, memory slot, or shard are a different
 * recursive statement.
 */
enum class OwnerFamilyV1 : uint8_t {
    Product = 0,
    Transpose = 1,
    Residual = 2,
    RoundOrder = 3,
};

enum class OwnerSectionV1 : uint8_t {
    ProductEnvelope = 0,
    EdgeSchedule = 1,
    EdgePin = 2,
    EdgeProof = 3,
    EdgeEnvelope = 4,
    MemoryBundle0 = 5,
    MemoryBundle1 = 6,
    MemoryBundle2 = 7,
};

struct OwnerV1 {
    OwnerFamilyV1 family{OwnerFamilyV1::Product};
    OwnerSectionV1 section{OwnerSectionV1::ProductEnvelope};
    uint32_t edge_ordinal{UINT32_MAX};
    uint32_t shard_ordinal{UINT32_MAX};

    bool operator==(const OwnerV1&) const = default;
};

/**
 * Semantic class of one canonical u32 word.  The coordinates below identify
 * the exact vector/path position.  Roots and field elements are decomposed
 * into little-endian u32 limbs; Fp limbs are accepted only when the joined
 * u64 is strictly below Goldilocks p.
 */
enum class RecordKindV1 : uint16_t {
    ProductField = 1,
    EdgeScheduleField = 2,
    EdgePinField = 3,
    EdgeEnvelopeField = 4,
    MemoryBundleField = 5,
    MemoryShardField = 6,
    MemoryManifestField = 7,
    MemoryProofField = 8,
    ProofVectorLength = 9,
    BatchHeader = 10,
    ColumnRoot = 11,
    ColumnLeaves = 12,
    ColumnLength = 13,
    BatchChallenge = 14,
    OodEvaluation = 15,
    FoldRoot = 16,
    FoldLeaves = 17,
    FinalValue = 18,
    FoldChallenge = 19,
    QueryIndex = 20,
    QueryOpeningValue = 21,
    QueryOpeningSibling = 22,
    FoldStepIndex = 23,
    FoldStepValue = 24,
    FoldStepSibling = 25,
    TraceCommit = 26,
    NextOpeningIndex = 27,
    NextOpeningValue = 28,
    NextOpeningSibling = 29,
};

struct RecordV1 {
    uint32_t ordinal{UINT32_MAX};
    OwnerV1 owner{};
    RecordKindV1 kind{RecordKindV1::ProductField};
    std::array<uint32_t, 4> coordinate{};
    uint32_t value{0};

    bool operator==(const RecordV1&) const = default;
};

struct ManifestV1 {
    uint32_t magic{kMagicV1};
    uint16_t version{kVersionV1};
    uint256 product_commitment{};
    uint256 statement_commitment{};
    uint256 schedule_root{};
    uint256 proof_wire_root{};
    std::vector<RecordV1> records;
    uint32_t relation_proofs{0};
    uint32_t memory_proofs{0};
    uint32_t root_words{0};
    uint32_t opening_words{0};
    bool exact_product_envelope{false};
    bool exact_edge_order{false};
    bool exact_memory_shard_order{false};
    bool every_verifier_read_classified{false};
    bool canonical_u32_words{false};
    bool valid{false};
    std::string note;

    bool operator==(const ManifestV1&) const = default;
};

/** Reject the Goldilocks x / x+p alias at the byte-to-field boundary. */
[[nodiscard]] bool DecodeCanonicalFpWordPairV1(
    uint32_t low,
    uint32_t high,
    uint64_t& out);

/**
 * Append every field read by AirQuotientVerify<Fp3> for the legacy
 * per-column backend, including all roots, OOD claims, folds, query openings,
 * next-row openings, path siblings and vector lengths.
 */
[[nodiscard]] bool AppendCanonicalLegacyProofRecordsV1(
    const OwnerV1& owner,
    const aq::AirQuotientProof<gf::Fp3>& proof,
    std::vector<RecordV1>& records,
    std::string* why = nullptr);

/**
 * Canonicalize the complete EpisodeWiring product in verifier order:
 * transpose, residual, round-order; relation proof before memory slots; shard
 * order inside each memory bundle.  This function does not grant semantic
 * credit.  It only makes the exact legacy verifier tape available to a
 * recursive equality join.
 */
[[nodiscard]] bool BuildManifestV1(
    const RCStage3EpisodeWiringProduct& product,
    ManifestV1& out,
    std::string* why = nullptr);

/** Rebuild-and-compare validation. */
[[nodiscard]] bool ValidateManifestV1(
    const RCStage3EpisodeWiringProduct& product,
    const ManifestV1& claimed,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeScheduleRootV1(
    const std::vector<RecordV1>& records);

[[nodiscard]] uint256 ComputeProofWireRootV1(
    const std::vector<RecordV1>& records);

struct ChallengesV1 {
    std::array<gf::Fp3, kTerminalLanesV1> gamma{};
    std::array<gf::Fp3, kTerminalLanesV1> alpha{};

    bool operator==(const ChallengesV1& other) const
    {
        for (uint32_t lane = 0;
             lane < kTerminalLanesV1; ++lane) {
            if (!gf::Eq(gamma[lane], other.gamma[lane]) ||
                !gf::Eq(alpha[lane], other.alpha[lane])) {
                return false;
            }
        }
        return true;
    }
};

[[nodiscard]] bool DeriveChallengesV1(
    const ManifestV1& manifest,
    ChallengesV1& out);

struct LayoutV1 {
    uint32_t active{0};
    uint32_t ordinal{1};
    uint32_t value{2};
    uint32_t value_bit_base{3};
    uint32_t inverse_base{35};
    uint32_t running_base{37};
    uint32_t expected_terminal_base{39};

    [[nodiscard]] uint32_t ValueBit(uint32_t bit) const
    {
        return value_bit_base + bit;
    }
    [[nodiscard]] uint32_t Inverse(uint32_t lane) const
    {
        return inverse_base + lane;
    }
    [[nodiscard]] uint32_t Running(uint32_t lane) const
    {
        return running_base + lane;
    }
    [[nodiscard]] uint32_t ExpectedTerminal(uint32_t lane) const
    {
        return expected_terminal_base + lane;
    }
    [[nodiscard]] uint32_t End() const
    {
        return expected_terminal_base + kTerminalLanesV1;
    }
};

struct ProductV1 {
    ManifestV1 manifest{};
    LayoutV1 layout{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    ChallengesV1 challenges{};
    std::array<gf::Fp3, kTerminalLanesV1> source_terminal{};
    uint32_t active_rows{0};
    uint32_t trace_rows{0};
    uint32_t violations{0};
    bool exact_public_schedule_preprocessed{false};
    bool canonical_u32_decomposition_air{false};
    bool dual_fp3_source_terminal_air{false};
    bool parent_terminal_cancelled{false};
    bool recursively_consumed{false};
    bool semantic_sites_credited{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] ProductV1 BuildProductV1(
    const ManifestV1& manifest);

struct ProofV1 {
    uint16_t version{kVersionV1};
    uint256 schedule_root{};
    uint256 proof_wire_root{};
    std::array<gf::Fp3, kTerminalLanesV1> source_terminal{};
    AirQuotientProofAlg proof{};
    std::vector<unsigned char> canonical_proof_bytes;
    uint32_t active_rows{0};
    uint32_t trace_rows{0};
    bool locally_verified{false};
    bool parent_terminal_cancelled{false};
    bool recursively_consumed{false};
    bool semantic_sites_credited{false};
};

[[nodiscard]] bool ProveV1(
    const ProductV1& product,
    ProofV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV1(
    const ManifestV1& expected_manifest,
    const ProofV1& proof,
    std::string* why = nullptr);

inline constexpr bool kDescriptorProofExecutableV1 = true;
inline constexpr bool kParentTerminalCancelledV1 = false;
inline constexpr bool kRecursivelyConsumedV1 = false;
inline constexpr bool kSemanticSitesCreditedV1 = false;
inline constexpr bool kAuthorityReadyV1 = false;

static_assert(!kParentTerminalCancelledV1);
static_assert(!kRecursivelyConsumedV1);
static_assert(!kSemanticSitesCreditedV1);
static_assert(!kAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_episode_wiring_proof_descriptor

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_WIRING_PROOF_DESCRIPTOR_H
