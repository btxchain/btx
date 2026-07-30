// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_TRANSCRIPT_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_TRANSCRIPT_AIR_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Stage-3 V10 Poseidon2/Q192/K=2 transcript AIR foundation.
//
// This module is deliberately additive and is selected by no protocol path.
// It arithmetizes one canonical, row-multiplexed event program for:
//
//   * a prefix-free, version-10/Q192/K=2 statement wrapper;
//   * the FRI lambda, both fixed-window OOD points, both DEEP weights;
//   * every fold challenge and all 192 query challenges;
//   * every x^7 S-box through the quadratic Poseidon AIR;
//   * every rate-8 sponge absorb and capacity-state transition; and
//   * first-acceptable selection from each fixed two-candidate OOD window,
//     including the load-bearing z2 != z1 predicate.
//
// Every event carries its own exact FRI transcript prefix. The AIR pins the
// complete canonical schedule as preprocessed columns, but this file does NOT
// prove that those prefix cells came from a child proof, nor does it
// equality-link the selected values into recursive verifier consumers. AIRQ
// lambda is intentionally absent: it belongs to a distinct quotient
// transcript and must never be aliased to a Fri3Alg squeeze.
// ============================================================================

namespace matmul::v4::rc::stage3_p2_transcript_air {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace pa = stage3_poseidon_air;

using gf::Fp3;

inline constexpr uint32_t kArtifactVersion = 10;
inline constexpr uint32_t kQueries = 192;
inline constexpr uint32_t kOodCandidates = 2;
inline constexpr uint32_t kZ1FirstDrawIndex = 0;
inline constexpr uint32_t kZ2FirstDrawIndex = 2;
inline constexpr uint32_t kMaxFolds = 32;
inline constexpr char kStatementDomainTag[] =
    "BTX_RC_FRIB3ALG_P2_Q192_K2_TRANSCRIPT_V10";
inline constexpr char kOodLabel[] = "fra3_z";
inline constexpr size_t kMaxPayloadBytes = size_t{1} << 20;

enum class EventKind : uint32_t {
    FriLambda = 1,
    OodZ1 = 2,
    OodZ2 = 3,
    DeepW1 = 4,
    DeepW2 = 5,
    Fold = 6,
    Query = 7,
};

struct EventDescriptor {
    uint32_t ordinal{0};
    EventKind kind{EventKind::FriLambda};
    uint32_t semantic_index{0};
    uint32_t draw_index{0};
    std::string label;
};

/**
 * One exact event-specific Fri3Alg FS buffer. Entries are positionally and
 * semantically bound to CanonicalEventManifest; an omitted, duplicated or
 * reordered entry is invalid even when two events share identical bytes.
 */
struct EventPrefix {
    EventKind kind{EventKind::FriLambda};
    uint32_t semantic_index{0};
    std::vector<unsigned char> bytes;
};

/**
 * Public statement of this proof-only slice. `event_prefixes` is the exact
 * incremental FRI transcript schedule supplied by the proof-owned adapter.
 * CanonicalStatementPrefix returns a compact commitment to the entire
 * schedule; it is not itself used as any event's challenge preimage.
 */
struct Statement {
    uint32_t version{kArtifactVersion};
    uint32_t queries{kQueries};
    uint32_t ood_candidates{kOodCandidates};
    uint32_t n_folds{2};
    // V10 restricts the query domain to a power of two so the index is an
    // exact low-bit projection of canonical c0, with no modular division.
    uint32_t query_modulus{1024};
    std::vector<EventPrefix> event_prefixes;
};

/**
 * Prefix-free commitment wrapper for the entire event-prefix schedule.
 * Challenge generation uses each EventPrefix::bytes directly, never `out`.
 */
[[nodiscard]] bool CanonicalStatementPrefix(
    const Statement& statement,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

/** Validate and return the exact prefix for one canonical event. */
[[nodiscard]] bool CanonicalEventPrefix(
    const Statement& statement,
    const EventDescriptor& event,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

/**
 * Produce/validate the one permitted V10 event order. Omission, duplication,
 * or reordering is not a different valid statement encoding.
 */
[[nodiscard]] bool CanonicalEventManifest(
    const Statement& statement,
    std::vector<EventDescriptor>& out,
    std::string* why = nullptr);
[[nodiscard]] bool IsCanonicalEventManifest(
    const Statement& statement,
    const std::vector<EventDescriptor>& manifest,
    std::string* why = nullptr);

/**
 * Two parallel decomposed Poseidon permutations are reused for every event.
 * Scalar events duplicate their squeeze in both lanes; OOD events use the
 * lanes for the two fixed candidates. Width is therefore independent of the
 * number of folds and query challenges.
 */
struct Layout {
    pa::Layout candidate[kOodCandidates];
    uint32_t message_base[kOodCandidates]{};
    uint32_t active_col{0};
    uint32_t event_start_col{0};
    uint32_t terminal_col{0};
    uint32_t event_ordinal_col{0};
    uint32_t event_kind_col{0};
    uint32_t semantic_index_col{0};
    uint32_t draw_index_col{0};
    uint32_t z1_terminal_col{0};
    uint32_t z2_terminal_col{0};
    uint32_t query_terminal_col{0};
    uint32_t query_index_col{0};
    uint32_t zero_base{0};       // [candidate][c1,c2]
    uint32_t inverse_base{0};    // [candidate][c1,c2]
    uint32_t ext_accept_base{0}; // [candidate]
    uint32_t eligible_base{0};   // [candidate]
    uint32_t selected_base{0};   // [z_slot][c0,c1,c2]
    uint32_t z1_memory_base{0};  // c0,c1,c2
    uint32_t diff_zero_base{0};  // [candidate][c0,c1,c2]
    uint32_t diff_inverse_base{0};
    uint32_t diff_and_base{0};   // [candidate][and01,equal]
    uint32_t distinct_base{0};   // [candidate]
    uint32_t query_bit_base{0};  // canonical c0 bits [0,64)
    uint32_t query_high_and_base{0}; // prefix AND of bits [32,64)
    uint32_t query_low_zero_col{0};
    uint32_t query_low_inverse_col{0};

    [[nodiscard]] uint32_t MessageCol(uint32_t candidate_index,
                                      uint32_t lane) const;
    [[nodiscard]] uint32_t ZeroCol(uint32_t candidate_index,
                                   uint32_t ext_coord) const;
    [[nodiscard]] uint32_t InverseCol(uint32_t candidate_index,
                                      uint32_t ext_coord) const;
    [[nodiscard]] uint32_t ExtAcceptCol(uint32_t candidate_index) const;
    [[nodiscard]] uint32_t EligibleCol(uint32_t candidate_index) const;
    [[nodiscard]] uint32_t SelectedCol(uint32_t z_slot,
                                       uint32_t coord) const;
    [[nodiscard]] uint32_t Z1MemoryCol(uint32_t coord) const;
    [[nodiscard]] uint32_t DiffZeroCol(uint32_t candidate_index,
                                      uint32_t coord) const;
    [[nodiscard]] uint32_t DiffInverseCol(uint32_t candidate_index,
                                         uint32_t coord) const;
    [[nodiscard]] uint32_t DiffAndCol(uint32_t candidate_index,
                                     uint32_t stage) const;
    [[nodiscard]] uint32_t DistinctCol(uint32_t candidate_index) const;
    [[nodiscard]] uint32_t QueryBitCol(uint32_t bit) const;
    [[nodiscard]] uint32_t QueryHighAndCol(uint32_t stage) const;
    [[nodiscard]] uint32_t End() const;
    [[nodiscard]] bool IsCanonical(std::string* why = nullptr) const;
};

[[nodiscard]] Layout CanonicalLayout(uint32_t base = 0);

struct BuildResult {
    Statement statement;
    Layout layout;
    aq::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>> columns;
    std::vector<EventDescriptor> manifest;
    std::vector<Fp3> event_challenges;
    std::vector<uint32_t> query_indices;
    Fp3 z_candidate[2][kOodCandidates]{};
    Fp3 selected_z1{};
    Fp3 selected_z2{};
    uint32_t permutations_per_scalar_event{0};
    uint32_t active_rows{0};
    uint32_t n_rows{0};
    uint32_t n_columns{0};
    uint32_t n_constraints{0};
    uint32_t max_alg_degree{0};
    uint32_t violations{1};

    bool canonical_parameters{false};
    bool prefix_free_v10_statement{false};
    bool exact_p2_absorb_lanes{false};
    bool canonical_event_manifest{false};
    bool all_event_challenges_constrained{false};
    bool all_query_indices_constrained{false};
    bool absorb_lanes_preprocessed_pinned{false};
    bool poseidon_permutations_constrained{false};
    bool sponge_state_chain_constrained{false};
    bool z1_k2_selection_constrained{false};
    bool z2_k2_distinct_selection_constrained{false};
    bool selected_values_publicly_pinned{false};

    // Fail-closed integration predicates.  These remain false in this module.
    bool proof_owned_source_cells_bound{false};
    bool recursive_consumer_cells_bound{false};
    bool recursive_authority{false};

    /** Complete only for the explicitly scoped local statement. */
    bool local_air_complete{false};
    bool valid{false};
    std::string note;
};

/**
 * Build the honest trace and the verifier-regenerable constraint system.
 *
 * The z1 candidate indices are protocol-fixed at 0,1 and the z2 indices at
 * 2,3. Making either start caller-selectable would turn a K=2 window into an
 * unbounded grinding surface, so no draw-index field exists in Statement.
 *
 * Selection accepts the first candidate with (c1,c2) != (0,0), and rejects
 * the statement if neither candidate is acceptable.  That event has
 * probability 1/p^4 under ideal independent Fp3 draws for K=2.
 * This conditional calculation is not a certified-bits claim; an eventual
 * lane still needs its transcript-independence/composition proof.
 */
[[nodiscard]] BuildResult BuildTranscriptAirV10(
    const Statement& statement);

/**
 * Build the identical V10 transcript AIR at an existing parent's next
 * column. `minimum_rows`, when nonzero, must be a power of two large enough
 * for the complete transcript. This permits literal same-parent joins
 * without rebasing captured constraint indices after construction.
 */
[[nodiscard]] BuildResult BuildTranscriptAirV10At(
    const Statement& statement,
    uint32_t base_column,
    uint32_t minimum_rows = 0);

/**
 * Append a shifted V10 transcript table and all of its constraints and
 * public position/data pins to one existing same-row-domain parent.
 */
[[nodiscard]] bool AppendTranscriptAirV10ToParent(
    aq::AirConstraintSystem<Fp3>& parent_cs,
    std::vector<std::vector<Fp3>>& parent_columns,
    const Statement& statement,
    BuildResult& transcript,
    std::string* why = nullptr);

/** Backwards-compatible name for the original local foundation. */
[[nodiscard]] inline BuildResult BuildOodWindowAirV10(
    const Statement& statement)
{
    return BuildTranscriptAirV10(statement);
}

/**
 * Direct algebraic row-domain violation scan used by fail-first tests.
 * It does not check the separate verifier-side preprocessed-column pins;
 * proof-level tests exercise those through AirQuotientVerify.
 */
[[nodiscard]] uint32_t CountViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns);

} // namespace matmul::v4::rc::stage3_p2_transcript_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_P2_TRANSCRIPT_AIR_H
