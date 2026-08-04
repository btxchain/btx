// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_PROVENANCE_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_PROVENANCE_JOIN_H

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_stage3_provenance_graph.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::recursive_provenance_join {

namespace aq = air_quotient;
namespace gf = gkr_field;

inline constexpr uint16_t kRecursiveProvenanceJoinVersionV1 = 1;
inline constexpr uint32_t kRecursiveProvenanceEndpointCountV1 = 52;
inline constexpr uint32_t kRecursiveProvenanceRoleCountV1 = 14;
inline constexpr uint32_t kRecursiveProvenanceRootLimbsV1 = 8;

/**
 * Public, immutable schedule shape.
 *
 * The three coupled dimensions are sufficient to expand every temporal
 * equality already executed by ValidateRCStage3CoupledChainProduct.  They do
 * not claim to expand the still-missing all-tile/hash manifests.
 */
struct RecursiveProvenanceShapeV1 {
    uint16_t version{kRecursiveProvenanceJoinVersionV1};
    uint32_t episode_round_roots{0};
    uint32_t coupled_barriers{0};
    uint32_t coupled_lobes{0};
    uint32_t coupled_exchange_rounds{0};
    uint256 episode_builder_params_root{};
    uint256 episode_header_target_root{};

    bool operator==(const RecursiveProvenanceShapeV1&) const = default;
};

/**
 * A graph edge is the exact named aggregate-root equality from
 * CurrentRCStage3ProvenanceGraphAudit.  Temporal events are additional,
 * position-preserving equality cells.  In particular, MaterialRoundChain is
 * endpoint 36 at round r-1 -> endpoint 34 at round r; it must not be replaced
 * by one commitment to a vector of all rounds.
 */
enum class RecursiveProvenanceEventKindV1 : uint16_t {
    GraphNamedRoot = 1,
    EpisodeTileRootAtRound = 2,
    EpisodeRoundRootFeedback = 3,
    CoupledBankPageToGemmB = 4,
    CoupledPriorExtractToGemmA = 5,
    CoupledGemmYToFixedExchange = 6,
    CoupledPermutationToMix = 7,
    CoupledMixToMaterialRound0 = 8,
    CoupledMaterialRoundChain = 9,
    CoupledZeroRoundMixToExtract = 10,
    CoupledFinalMaterialToExtract = 11,
    CoupledBarrierOutputToDigest = 12,
};

struct RecursiveProvenanceEventKeyV1 {
    RCStage3RelationEndpoint producer{};
    RCStage3RelationEndpoint consumer{};
    RecursiveProvenanceEventKindV1 kind{
        RecursiveProvenanceEventKindV1::GraphNamedRoot};
    /**
     * Exact producer/consumer positions in their named streams.  UINT32_MAX
     * means the graph-level aggregate root rather than an indexed event.
     */
    uint32_t producer_position{UINT32_MAX};
    uint32_t consumer_position{UINT32_MAX};
    std::string construction;

    bool operator==(const RecursiveProvenanceEventKeyV1&) const = default;
};

struct RecursiveProvenanceRoleCellV1 {
    RCStage3RelationRole role{};
    uint256 locally_verified_child_root{};
    uint256 named_role_root{};
    bool child_locally_verified{false};

    bool operator==(const RecursiveProvenanceRoleCellV1&) const = default;
};

struct RecursiveProvenanceEndpointCellV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    uint256 locally_verified_child_output_root{};
    uint256 named_endpoint_root{};
    bool child_locally_verified{false};

    bool operator==(const RecursiveProvenanceEndpointCellV1&) const = default;
};

struct RecursiveProvenanceEventCellV1 {
    RecursiveProvenanceEventKeyV1 key;
    uint256 producer_child_output_root{};
    uint256 consumer_named_input_root{};
    bool producer_child_locally_verified{false};
    bool consumer_child_locally_verified{false};

    bool operator==(const RecursiveProvenanceEventCellV1&) const = default;
};

struct RecursiveProvenanceWitnessV1 {
    uint16_t version{kRecursiveProvenanceJoinVersionV1};
    std::vector<RecursiveProvenanceRoleCellV1> roles;
    std::vector<RecursiveProvenanceEndpointCellV1> endpoints;
    std::vector<RecursiveProvenanceEventCellV1> events;
};

enum class RecursiveProvenanceRowKindV1 : uint16_t {
    Padding = 0,
    Role = 1,
    Endpoint = 2,
    Event = 3,
};

/**
 * Column layout:
 *
 *   ordinary witness:
 *     claimed row identity/position | left root | right root
 *   verifier preprocessing:
 *     active + exact canonical identity/position | public anchor root
 *
 * Only selectors, positions, identifiers, and the two public anchor roots are
 * preprocessed.  No role, endpoint, producer, or consumer proof value is.
 */
struct RecursiveProvenanceJoinLayoutV1 {
    uint32_t claimed_row_kind{0};
    uint32_t claimed_role{0};
    uint32_t claimed_endpoint{0};
    uint32_t claimed_producer{0};
    uint32_t claimed_consumer{0};
    uint32_t claimed_event_kind{0};
    uint32_t claimed_producer_position{0};
    uint32_t claimed_consumer_position{0};
    std::array<uint32_t, kRecursiveProvenanceRootLimbsV1> left_root{};
    std::array<uint32_t, kRecursiveProvenanceRootLimbsV1> right_root{};

    uint32_t pp_active{0};
    uint32_t pp_row_kind{0};
    uint32_t pp_role{0};
    uint32_t pp_endpoint{0};
    uint32_t pp_producer{0};
    uint32_t pp_consumer{0};
    uint32_t pp_event_kind{0};
    uint32_t pp_producer_position{0};
    uint32_t pp_consumer_position{0};
    uint32_t pp_anchor_selector{0};
    std::array<uint32_t, kRecursiveProvenanceRootLimbsV1> pp_anchor_root{};
    uint32_t total_columns{0};
};

struct RecursiveProvenanceJoinProductV1 {
    uint16_t version{kRecursiveProvenanceJoinVersionV1};
    RecursiveProvenanceShapeV1 shape;
    uint256 schedule_commitment{};
    RecursiveProvenanceJoinLayoutV1 layout;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    uint32_t active_rows{0};
    uint32_t graph_named_root_events{0};
    uint32_t temporal_events{0};
    uint32_t violations{0};
    bool exact_role_order{false};
    bool exact_endpoint_order{false};
    bool exact_event_order{false};
    bool public_anchors_1_and_25_pinned{false};
    bool every_supplied_cell_host_reported_locally_verified{false};
    bool values_are_ordinary_witness_columns{false};
    bool selectors_and_positions_preprocessed{false};
    bool temporal_edges_explicit{false};
    bool same_parent_child_verifier_owned{false};
    bool recursive_authority{false};
    bool production_complete{false};
    bool valid{false};
    std::string note;
};

/**
 * Standalone proof of the equality AIR.  This is useful evidence that the
 * constraints survive quotient/FRI compilation.  It is not yet the recursive
 * authority: the normalized parent still has to replace the ordinary
 * child-value lanes with direct aliases to output cells of executable child
 * verifier chips.
 */
struct RecursiveProvenanceJoinProofV1 {
    uint16_t version{kRecursiveProvenanceJoinVersionV1};
    RecursiveProvenanceShapeV1 shape;
    uint256 schedule_commitment{};
    uint256 fs_seed{};
    aq::AirQuotientRowsProof proof;
    std::vector<unsigned char> canonical_proof_bytes;
    uint64_t prove_micros{0};
    uint64_t verify_micros{0};
    bool quotient_division_exact{false};
    bool locally_verified{false};
    bool canonical_codec{false};
    bool same_parent_child_verifier_owned{false};
    bool recursive_authority{false};
    bool production_complete{false};
    bool valid{false};
    std::string note;
};

/**
 * Literal addresses in an already-existing recursive-parent trace.
 *
 * These are addresses, not values.  The alias attachment below rejects every
 * address whose column is preprocessed, so a caller cannot manufacture
 * "proof ownership" by installing a claimed root as verifier preprocessing.
 */
struct RecursiveProvenanceParentCellRefV1 {
    uint32_t column{UINT32_MAX};
    uint32_t row{UINT32_MAX};

    bool operator==(
        const RecursiveProvenanceParentCellRefV1&) const = default;
};

struct RecursiveProvenanceParentRootRefV1 {
    std::array<
        RecursiveProvenanceParentCellRefV1,
        kRecursiveProvenanceRootLimbsV1> limb{};

    bool operator==(
        const RecursiveProvenanceParentRootRefV1&) const = default;
};

/**
 * One typed source/sink pair.  `verifier_output` must eventually be emitted
 * by the executable child-proof verifier/decoder chip; `named_consumer` is
 * the exact relation/provenance consumer cell.  The append-only seam proves
 * their equality but deliberately cannot certify who allocated the source
 * column.
 */
struct RecursiveProvenanceParentRootAliasV1 {
    RecursiveProvenanceParentRootRefV1 verifier_output;
    RecursiveProvenanceParentRootRefV1 named_consumer;
};

struct RecursiveProvenanceParentRoleAliasV1 {
    RCStage3RelationRole role{};
    RecursiveProvenanceParentRootAliasV1 root;
};

struct RecursiveProvenanceParentEndpointAliasV1 {
    RCStage3RelationEndpoint endpoint{};
    RCStage3RelationRole role{};
    RecursiveProvenanceParentRootAliasV1 root;
};

struct RecursiveProvenanceParentEventAliasV1 {
    RecursiveProvenanceEventKeyV1 key;
    RecursiveProvenanceParentRootAliasV1 root;
};

struct RecursiveProvenanceParentAliasRefsV1 {
    uint16_t version{kRecursiveProvenanceJoinVersionV1};
    /** Parent-witness shape in which every literal address is interpreted. */
    uint32_t parent_rows{0};
    uint32_t parent_original_columns{0};
    std::array<
        RecursiveProvenanceParentRoleAliasV1,
        kRecursiveProvenanceRoleCountV1> roles{};
    std::array<
        RecursiveProvenanceParentEndpointAliasV1,
        kRecursiveProvenanceEndpointCountV1> endpoints{};
    std::vector<RecursiveProvenanceParentEventAliasV1> events;
};

struct RecursiveProvenanceParentAliasAttachmentV1 {
    uint16_t version{kRecursiveProvenanceJoinVersionV1};
    uint32_t original_columns{0};
    uint32_t appended_columns{0};
    uint32_t role_root_aliases{0};
    uint32_t endpoint_root_aliases{0};
    uint32_t temporal_root_aliases{0};
    uint32_t limb_equalities{0};
    uint32_t same_row_equalities{0};
    uint32_t cross_row_equalities{0};
    uint32_t public_anchor_equalities{0};
    uint32_t selector_columns{0};
    uint32_t carrier_columns{0};
    uint32_t violations{0};
    uint256 fixed_offset_schedule_commitment{};
    bool exact_role_order{false};
    bool exact_endpoint_order{false};
    bool exact_event_order{false};
    bool parent_witness_shape_exact{false};
    bool fixed_offset_schedule_bound{false};
    bool all_66_root_aliases_literal{false};
    bool every_temporal_alias_literal{false};
    bool aliased_values_are_ordinary_columns{false};
    bool source_and_sink_cells_disjoint{false};
    bool semantic_export_cells_distinct{false};
    bool selectors_only_new_preprocessing{false};
    bool cross_row_transport_constrained{false};
    /**
     * Values stay in ordinary parent-witness columns.  The enclosing STARK
     * commitment therefore binds them without hashing the complete child tape
     * a second time.
     */
    bool no_child_tape_hash_required{false};
    bool parent_trace_commitment_binding_model{false};
    /**
     * Still false in this bounded slice: the source cells are at canonical
     * verifier-output offsets, but the complete child verifier has not yet
     * constrained their semantics in this same parent.
     */
    bool verifier_output_semantics_constrained{false};
    /** Likewise false until the relation chips constrain every sink cell. */
    bool named_consumer_semantics_constrained{false};
    /**
     * The current verifier AIR does not provide a complete proof-byte decoder,
     * full Fiat-Shamir replay, and acceptance bit in this same parent.  No
     * caller-provided boolean is accepted as a substitute.
     */
    bool complete_child_acceptance_in_same_parent{false};
    bool same_parent_child_verifier_owned{false};
    bool recursive_authority{false};
    bool valid{false};
    std::vector<std::string> residuals;
    std::string note;
};

/**
 * Commit only the immutable parent-witness address schedule and typed
 * identities.  Root values are deliberately absent: the parent STARK's
 * ordinary-column commitment binds them, so no monolithic child-tape hash is
 * introduced.
 */
[[nodiscard]] uint256
ComputeRecursiveProvenanceParentAliasScheduleCommitmentV1(
    const RecursiveProvenanceShapeV1& shape,
    const RecursiveProvenanceParentAliasRefsV1& refs);

[[nodiscard]] uint256
ComputeRecursiveProvenanceParentAliasFsSeedV1(
    const RecursiveProvenanceShapeV1& shape,
    const uint256& fixed_offset_schedule_commitment);

/**
 * Append every canonical role, endpoint, and temporal equality to an existing
 * recursive parent.  Each equality uses the referenced cells directly.  For
 * cross-row pairs the function adds a committed carrier plus public position
 * selectors:
 *
 *   sel_source * (carrier - source) = 0
 *   sel_carry  * (carrier' - carrier) = 0
 *   sel_sink   * (carrier - sink) = 0
 *
 * Only selectors are added to preprocessing.  Source/sink columns that
 * already occur in `parent_cs.preprocessed` are rejected.
 *
 * Success closes the mapping seam, not child-verifier ownership.  The latter
 * remains false until a complete proof decoder, Fiat-Shamir replay, and child
 * acceptance chip allocate the 66 `verifier_output` roots in this parent.
 * `expected_fixed_offset_schedule_commitment` must come from the verifier's
 * independently root-pinned parent program.  Recomputing it from prover-owned
 * `refs` would deliberately forfeit the fixed-address binding.
 */
[[nodiscard]] bool AppendRecursiveProvenanceParentAliasesV1(
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const RecursiveProvenanceShapeV1& shape,
    const RecursiveProvenanceParentAliasRefsV1& refs,
    const uint256& expected_fixed_offset_schedule_commitment,
    RecursiveProvenanceParentAliasAttachmentV1& out,
    std::string* why = nullptr);

/** Exact fourteen-role ABI order, excluding CompositionLink. */
[[nodiscard]] const std::array<RCStage3RelationRole,
                               kRecursiveProvenanceRoleCountV1>&
CanonicalRecursiveProvenanceRoleOrderV1();

/**
 * Recompute the graph schedule and append every explicit temporal instance.
 * The result is producer-major, then consumer/kind/position major.
 */
[[nodiscard]] bool BuildCanonicalRecursiveProvenanceEventScheduleV1(
    const RecursiveProvenanceShapeV1& shape,
    std::vector<RecursiveProvenanceEventKeyV1>& out,
    std::string* why = nullptr);

[[nodiscard]] uint256
ComputeRecursiveProvenanceScheduleCommitmentV1(
    const RecursiveProvenanceShapeV1& shape,
    const std::vector<RecursiveProvenanceEventKeyV1>& events);

/**
 * Build the equality AIR.  Canonical omission/duplicate/relabel/reorder errors
 * are rejected before construction.  Root substitutions remain in the trace
 * and therefore cause non-zero AIR violations rather than being repaired by
 * the witness builder.
 */
[[nodiscard]] RecursiveProvenanceJoinProductV1
BuildRecursiveProvenanceJoinV1(
    const RecursiveProvenanceShapeV1& shape,
    const RecursiveProvenanceWitnessV1& witness);

[[nodiscard]] uint32_t CountRecursiveProvenanceJoinViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

[[nodiscard]] uint256 ComputeRecursiveProvenanceJoinFsSeedV1(
    const RecursiveProvenanceShapeV1& shape,
    const uint256& schedule_commitment);

[[nodiscard]] RecursiveProvenanceJoinProofV1
ProveRecursiveProvenanceJoinV1(
    const RecursiveProvenanceJoinProductV1& product,
    const aq::AirProveOptions& options = {});

/**
 * Rebuilds the canonical 14-role/52-endpoint/event preprocessing from the
 * expected public shape before invoking AirQuotientVerifyRows.  The caller
 * never supplies a constraint callback or selector column.
 */
[[nodiscard]] bool VerifyRecursiveProvenanceJoinProofV1(
    const RecursiveProvenanceShapeV1& expected_shape,
    const RecursiveProvenanceJoinProofV1& proof,
    std::string* why = nullptr);

inline constexpr bool kRecursiveProvenanceJoinEqualityAirExecutableV1 =
    true;
inline constexpr bool
    kRecursiveProvenanceJoinSameParentChildVerifierOwnedV1 = false;
inline constexpr bool kRecursiveProvenanceJoinRecursiveAuthorityV1 =
    false;
inline constexpr bool kRecursiveProvenanceJoinProductionCompleteV1 =
    false;
static_assert(kRecursiveProvenanceJoinEqualityAirExecutableV1);
static_assert(
    !kRecursiveProvenanceJoinSameParentChildVerifierOwnedV1);
static_assert(!kRecursiveProvenanceJoinRecursiveAuthorityV1);
static_assert(!kRecursiveProvenanceJoinProductionCompleteV1);

} // namespace matmul::v4::rc::recursive_provenance_join

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_PROVENANCE_JOIN_H
