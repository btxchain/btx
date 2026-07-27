// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_NIROP_HYBRID_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_NIROP_HYBRID_H

#include <matmul/matmul_v4_rc_stage3_multirow_p2_transcript.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid {

namespace gf = gkr_field;
namespace p2 = stage3_multirow_p2_transcript;

inline constexpr uint16_t kManifestVersionV1 = 1;
inline constexpr uint32_t kTranscriptDomainCountV1 = 14;

/**
 * The fourteen native V11 transcript hash roles, in transcript order.
 * Several roles occur more than once, but every occurrence has exactly one
 * of these domain prefixes.
 */
enum class TranscriptRoleV1 : uint8_t {
    ShapeCommit = 1,
    AirLambda = 2,
    FriSeed = 3,
    OodZ1Candidate = 4,
    OodZ2Candidate = 5,
    OodEvaluationCommit = 6,
    BatchSeed = 7,
    BatchCoefficient = 8,
    DeepWeight = 9,
    FoldState = 10,
    FoldBeta = 11,
    QuerySeed = 12,
    QueryCandidate = 13,
    Padding = 14,
};

struct TranscriptDomainV1 {
    TranscriptRoleV1 role{};
    uint64_t domain{0};
    const char* label{nullptr};
};

/** Exact, reviewable list used by the independent replay audit. */
[[nodiscard]] const std::array<
    TranscriptDomainV1, kTranscriptDomainCountV1>&
CanonicalTranscriptDomainsV1();

/**
 * A concrete identical-input witness between two nominal oracle roles.
 *
 * `LeafHashRow` hashes [three coordinates per row cell, row_index] with the
 * generic zero-capacity SpongeHashFp mode. A V11 coefficient, fold-beta or
 * query-candidate draw hashes
 * [domain_lo32, domain_hi32, digest[0..3], ordinal]. For a two-cell row those
 * are the same seven lanes, not merely equal digests.
 */
struct CrossRoleIdenticalInputV1 {
    TranscriptRoleV1 transcript_role{
        TranscriptRoleV1::BatchCoefficient};
    uint64_t transcript_domain{0};
    std::array<gf::Fp3, 2> row_cells{};
    uint32_t row_index{0};
    std::vector<gf::Fp> transcript_sponge_input;
    std::vector<gf::Fp> row_leaf_sponge_input;
    Fri3AlgDigest transcript_digest{};
    Fri3AlgDigest row_leaf_digest{};
    bool lane_vectors_identical{false};
    bool padded_inputs_identical{false};
    bool digests_identical_without_collision{false};
};

struct TranscriptDagAuditV1 {
    uint16_t manifest_version{kManifestVersionV1};
    uint32_t protocol_version{0};
    uint64_t protocol_domain{0};
    uint32_t transcript_domain_count{0};
    uint32_t expected_hash_events{0};
    uint32_t independently_replayed_hash_events{0};
    uint32_t queries{0};
    uint32_t query_candidates{0};

    bool statement_shape_precedes_shape_commit{false};
    bool statement_prefix_precedes_r0_rdep_roots_in_air_lambda{false};
    bool statement_prefix_precedes_all_roots_in_fri_seed{false};
    bool air_lambda_before_quotient_root{false};
    bool all_roots_before_ood_draws{false};
    bool ood_claims_before_batch_coefficients{false};
    bool each_fold_root_before_its_beta{false};
    bool terminal_before_query_seed{false};
    bool query_seed_before_all_q192_candidates{false};
    bool q192_k2_schedule_injective{false};
    bool q192_with_replacement{false};

    bool fourteen_domains_pairwise_distinct{false};
    bool u64_domains_split_into_two_canonical_u32_lanes{false};
    bool independent_replay_matches_native_receipt{false};
    bool native_receipt_verifies{false};

    bool rbr_parameters_match_v11{false};
    bool q192_rbr_ledger_machine_checked{false};
    double rbr_query_proximity_bits{0.0};
    double rbr_poseidon_collision_bits{0.0};
    double rbr_composed_single_lane_bits{0.0};

    bool merkle_node_capacity_domain_separated{false};
    bool fold_leaf_fixed_width_rate_tagged{false};
    bool fold_leaf_capacity_domain_separated{false};
    bool row_leaf_role_domain_separated{false};
    bool merkle_oracle_and_fs_sponge_inputs_disjoint{false};
    /** V11's SpongeHashFp adds blocks into the rate; it is not overwrite DS. */
    bool v11_uses_add_absorb_sponge{false};
    bool v11_uses_overwrite_mode_duplex{false};
    /** DSFS starts capacity from h(instance); V11 starts it at zero. */
    bool v11_uses_instance_derived_capacity_start{false};
    bool published_duplex_fs_premises_match{false};
    bool custom_add_absorb_hash_chain_hybrid_complete{false};
    CrossRoleIdenticalInputV1 row_leaf_vs_coefficient;
    CrossRoleIdenticalInputV1 row_leaf_vs_fold_beta;
    CrossRoleIdenticalInputV1 row_leaf_vs_query_candidate;

    /**
     * A first-collision hybrid may only be asserted after every role has
     * disjoint input encoding, so this remains false for V11.
     */
    bool poseidon_first_collision_hybrid_complete{false};
    bool nirop_bcs_composition_complete{false};
    bool production_authority_ready{false};
    std::vector<std::string> required_call_site_migrations;
    std::string required_protocol_change;
    std::string note;
};

/**
 * Independently replay the native V11 transcript and inspect the real
 * Merkle/fold encodings. No readiness constant is consumed or produced.
 */
[[nodiscard]] TranscriptDagAuditV1 AssessV1(
    const p2::StatementV1& statement);

// -------------------------------------------------------------------------
// Additive V12 hash-role encoding. This is the mandatory protocol-version
// fix identified by AssessV1; no V11 call site selects it yet.
// -------------------------------------------------------------------------

inline constexpr uint16_t kTypedHashVersionV1 = 1;
inline constexpr uint32_t kTypedHashProtocolVersionV12 = 12;
inline constexpr gf::Fp kTypedHashCapacityMagicV1 =
    0x4254585459504544ULL; // "BTXTYPED", canonical in Goldilocks.

enum class TypedHashRoleV1 : uint32_t {
    MerkleRowLeaf = 1,
    MerkleFoldLeaf = 2,
    MerkleInternalNode = 3,
    TranscriptShapeCommit = 4,
    TranscriptAirLambda = 5,
    TranscriptFriSeed = 6,
    TranscriptOodZ1 = 7,
    TranscriptOodZ2 = 8,
    TranscriptOodEvaluations = 9,
    TranscriptBatchSeed = 10,
    TranscriptBatchCoefficient = 11,
    TranscriptDeepWeight = 12,
    TranscriptFoldState = 13,
    TranscriptFoldBeta = 14,
    TranscriptQuerySeed = 15,
    TranscriptQueryCandidate = 16,
    TranscriptPadding = 17,
    ReceiptCommitment = 18,
    ProgramTableCommitment = 19,
    ApplicationStatementCommitment = 20,
};

struct TypedPermutationCallV1 {
    TypedHashRoleV1 role{};
    std::array<gf::Fp, alg_hash::kAlgHashT> input{};
    std::array<gf::Fp, alg_hash::kAlgHashT> output{};
};

struct TypedHashResultV1 {
    Fri3AlgDigest digest{};
    std::vector<TypedPermutationCallV1> calls;
    bool valid{false};
};

/** Variable-length typed sponge. Role lives in non-witness capacity lanes. */
[[nodiscard]] TypedHashResultV1 TypedSpongeHashFpV1(
    TypedHashRoleV1 role,
    const std::vector<gf::Fp>& lanes);

/** Typed, fixed-width encodings for the two Merkle primitives. */
[[nodiscard]] TypedHashResultV1 TypedRowLeafV1(
    const std::vector<gf::Fp3>& row, uint32_t index);
/**
 * Column-chunked implementation of the same row encoding. `columns_per_block`
 * affects memory traversal only; the absorbed lane sequence is identical.
 */
[[nodiscard]] TypedHashResultV1 TypedRowLeafStreamingV1(
    const std::vector<gf::Fp3>& row, uint32_t index,
    uint32_t columns_per_block);
[[nodiscard]] TypedHashResultV1 TypedFoldLeafV1(
    const gf::Fp3& value, uint32_t index);
[[nodiscard]] TypedHashResultV1 TypedMerkleNodeV1(
    const Fri3AlgDigest& left, const Fri3AlgDigest& right);

struct TypedHashSeparationAuditV1 {
    uint16_t typed_hash_version{kTypedHashVersionV1};
    uint32_t protocol_version{kTypedHashProtocolVersionV12};
    uint32_t role_count{0};
    bool capacity_magic_canonical{false};
    bool every_role_capacity_tuple_unique{false};
    bool rate_lanes_cannot_overwrite_capacity_domain{false};
    bool variable_length_padding_injective{false};
    bool host_poseidon_air_permutation_parity{false};
    uint32_t parity_calls_checked{0};
    bool initial_call_role_encodings_disjoint{false};
    bool fixed_leaf_node_vs_sponge_starts_disjoint{false};
    bool row_leaf_streaming_equivalent{false};
    bool active_v11_backend_migrated{false};
    bool recursive_replay_migrated{false};
    bool first_collision_hybrid_ready{false};
    bool production_authority_ready{false};
    std::string note;
};

/**
 * Exercise every typed role on adversarial rate lanes (including domain-like
 * prefixes) and compare every host permutation call with the Poseidon AIR
 * witness. Readiness remains false until V11 is version-bumped and migrated.
 */
[[nodiscard]] TypedHashSeparationAuditV1
AuditTypedHashSeparationV1();

} // namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_MULTIROW_V11_NIROP_HYBRID_H
