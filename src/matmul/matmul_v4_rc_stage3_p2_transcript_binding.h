// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_TRANSCRIPT_BINDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_TRANSCRIPT_BINDING_H

#include <matmul/matmul_v4_rc_stage3_p2_transcript_air.h>

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Proof-owned source and consumer-cell binding for the V10 P2 transcript AIR.
//
// This adapter deliberately accepts no caller-provided transcript bytes.  It
// reconstructs the exact active Fri3Alg FS byte prefixes from canonical proof
// fields and public parameters in the order used by Fri3AlgBatchVerify:
//
//   parameters/shape/root -> lambda -> z1/z2 -> OOD-claim root -> w1/w2
//   -> ordered fold roots/betas -> ordered query indices.
//
// It also defines the one canonical row-tagged map from each V10 AIR event to
// the verifier cell that consumes it.  The existing recursive verifier has no
// such cell table yet, so the layout is explicitly appendable and
// same_parent_cells_bound remains false.  In particular, a canonical layout
// descriptor is not evidence that a parent AIR enforced its equalities.
// ============================================================================

namespace matmul::v4::rc::stage3_p2_transcript_binding {

namespace p2tx = stage3_p2_transcript_air;
namespace gf = gkr_field;

inline constexpr uint32_t kBindingVersion = 10;
inline constexpr char kBindingDomainTag[] =
    "BTX_RC_STAGE3_P2_TRANSCRIPT_BINDING_V10";
inline constexpr uint32_t kV10K2ProofVersion =
    kRCFri3AlgP2Q192K2ProofVersionV10;
inline constexpr const char* kV10K2ProtocolDomainTag =
    kRCFri3AlgP2Q192K2DomainTagV10;
inline constexpr uint32_t kMaxOodDraws = 4096;

enum class ConsumerFamily : uint32_t {
    AppendableAirqLambda = 1,
    ProofLambda = 2,
    ProofZ1 = 3,
    ProofZ2 = 4,
    ProofW1 = 5,
    ProofW2 = 6,
    ProofFoldChallenge = 7,
    ProofQueryIndex = 8,
};

/**
 * The exact active-verifier prefix and result for one semantic draw.  Airq
 * lambda has no source event in Fri3Alg and therefore appears only in the
 * consumer manifest, never in this vector.
 */
struct ProofOwnedEvent {
    p2tx::EventKind kind{p2tx::EventKind::FriLambda};
    uint32_t semantic_index{0};
    uint32_t draw_index{0};
    std::string label;
    std::vector<unsigned char> fs_prefix;
    gf::Fp3 challenge{};
    uint32_t query_index{0};
    bool is_query{false};
};

enum class PrefixSourceKind : uint32_t {
    MissingAirqTranscript = 1,
    FriInitialLambda = 2,
    FriPostLambdaOod = 3,
    FriPostZClaimWeights = 4,
    FriPostFoldRoot = 5,
    FriTerminalQueries = 6,
};

/**
 * Compact schedule of distinct FS buffers. Query events intentionally share
 * one terminal prefix. Lambda and OOD do not: the real verifier absorbs
 * lambda before drawing z, so merging those sources would be incorrect.
 */
struct PrefixScheduleEntry {
    uint32_t ordinal{0};
    PrefixSourceKind source_kind{
        PrefixSourceKind::MissingAirqTranscript};
    uint32_t semantic_index{0};
    uint32_t first_event_ordinal{0};
    uint32_t event_count{0};
    std::vector<unsigned char> fs_prefix;
    bool proof_owned{false};
};

/**
 * Canonical appendable verifier-cell address. `consumer_index` is an index
 * inside the named family, not an unconstrained witness offset.  `width` is 3
 * for Fp3 and 1 for a query index.
 */
struct ConsumerCellMapEntry {
    uint32_t event_ordinal{0};
    p2tx::EventKind kind{p2tx::EventKind::FriLambda};
    uint32_t semantic_index{0};
    ConsumerFamily family{ConsumerFamily::ProofLambda};
    uint32_t consumer_index{0};
    uint32_t width{0};
    gf::Fp3 fp3_value{};
    uint32_t index_value{0};
    bool value_available{false};
};

struct ConsumerMappingManifest {
    uint32_t version{kBindingVersion};
    std::string domain_tag{kBindingDomainTag};
    std::vector<ConsumerCellMapEntry> entries;
    Fri3AlgDigest commitment{};
    bool canonical{false};
    // There is currently no production parent column family exporting these
    // cells.  This cannot become true merely by constructing the manifest.
    bool appendable_layout_only{true};
    bool same_parent_cells_bound{false};
};

struct BindingResult {
    uint32_t version{kBindingVersion};
    std::string domain_tag{kBindingDomainTag};
    uint32_t source_proof_version{0};
    std::string source_protocol_domain;
    uint32_t target_proof_version{kV10K2ProofVersion};
    std::string target_protocol_domain{kV10K2ProtocolDomainTag};
    p2tx::Statement statement;
    std::vector<unsigned char> canonical_proof_bytes;
    std::vector<ProofOwnedEvent> source_events;
    std::vector<PrefixScheduleEntry> prefix_schedule;
    ConsumerMappingManifest consumer_manifest;
    Fri3AlgDigest source_commitment{};

    bool canonical_proof_codec{false};
    bool native_proof_verified{false};
    bool proof_owned_prefix_reconstructed{false};
    bool compact_prefix_schedule_canonical{false};
    bool exact_active_transcript_replayed{false};
    bool source_event_order_complete{false};
    bool consumer_mapping_canonical{false};
    bool proof_owned_source_cells_bound{false};

    // The event-specific local AIR schedule matches the additive V10
    // producer, but these remain separate from recursive same-parent CTLs.
    bool local_air_event_prefixes_match_active_protocol{false};
    // This names the additive producer only; activation remains false.
    bool v10_k2_protocol_producer_executable{false};
    bool recursive_consumer_cells_bound{false};
    bool recursive_authority{false};

    /** Valid means the non-authoritative source/mapping foundation is exact. */
    bool valid{false};
    std::string note;
};

/**
 * Build exclusively from a canonical proof and the public FS seed.  This
 * verifies the active P2 proof before treating any proof cell as owned.
 */
[[nodiscard]] BindingResult BuildProofOwnedTranscriptBindingV10(
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed);

/**
 * Recompute the complete binding and compare every byte, event, cell address,
 * value and commitment.  This is intentionally strict: omission, reordering,
 * payload extension and alternate-domain replay are all invalid encodings.
 */
[[nodiscard]] bool ValidateProofOwnedTranscriptBindingV10(
    const BindingResult& binding,
    const Fri3AlgBatchProof& proof,
    const uint256& fs_seed,
    std::string* why = nullptr);

/**
 * Compare a local AIR result with the canonical consumer manifest.  It
 * returns false on today's construction (including the absent Airq consumer)
 * and lists the mismatching event ordinals.  This provides executable
 * evidence for the residual instead of silently upgrading an appendable
 * layout into a same-parent equality claim.
 */
[[nodiscard]] bool AssessLocalAirConsumerEqualityV10(
    const BindingResult& binding,
    const p2tx::BuildResult& air,
    std::vector<uint32_t>& mismatching_ordinals,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::stage3_p2_transcript_binding

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_TRANSCRIPT_BINDING_H
