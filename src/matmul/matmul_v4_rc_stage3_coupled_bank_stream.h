// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_STREAM_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_STREAM_H

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_coupled_missing_relations.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3CoupledBankStreamVersion = 1;
inline constexpr uint8_t kRCStage3CoupledBankStreamArity = 4;
inline constexpr uint32_t kRCStage3CoupledBankSourceChunkBytes = 64;
inline constexpr uint32_t kRCStage3CoupledBankStreamTestMaxBytes =
    16U * 1024U * 1024U;

/**
 * Compact verifier-derived production schedule for
 *
 *   SHA256d(bank_tag || page[0] || ... || page[bank_pages-1]).
 *
 * Counts are 64-bit and no page bytes, padded blocks or per-block chaining
 * states are stored in this manifest.
 */
struct RCStage3CoupledBankStreamManifest {
    uint16_t version{kRCStage3CoupledBankStreamVersion};
    uint8_t aggregation_arity{kRCStage3CoupledBankStreamArity};
    uint256 statement_commitment{};
    RCStage3CoupledShape shape{};
    uint256 bank_page_byte_root{};
    uint64_t bank_page_bytes{0};
    uint64_t first_message_bytes{0};
    uint64_t first_pass_blocks{0};
    uint64_t source_chunks{0};
    uint64_t source_tree_leaves{0};
    uint32_t source_tree_depth{0};
    uint32_t aggregation_levels{0};
    uint64_t aggregation_parent_sites{0};
    uint256 schedule_commitment{};
    uint256 commitment{};

    bool operator==(const RCStage3CoupledBankStreamManifest&) const =
        default;
};

[[nodiscard]] bool BuildRCStage3CoupledBankStreamManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& expected_shape,
    const uint256& expected_bank_page_byte_root,
    RCStage3CoupledBankStreamManifest& out,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitRCStage3CoupledBankStreamManifest(
    const RCStage3CoupledBankStreamManifest& manifest);
[[nodiscard]] bool ValidateRCStage3CoupledBankStreamManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& expected_shape,
    const uint256& expected_bank_page_byte_root,
    const RCStage3CoupledBankStreamManifest& manifest,
    std::string* why = nullptr);

/** One canonical source-tree opening for a 64-byte page-major bank chunk.
 * The final chunk may be short; unused bytes must be zero. */
struct RCStage3CoupledBankSourceOpening {
    uint64_t chunk_index{0};
    uint32_t byte_count{0};
    std::array<uint8_t, kRCStage3CoupledBankSourceChunkBytes> bytes{};
    std::vector<uint256> authentication_path;

    bool operator==(const RCStage3CoupledBankSourceOpening&) const =
        default;
};

[[nodiscard]] bool VerifyRCStage3CoupledBankSourceOpening(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankSourceOpening& opening,
    std::string* why = nullptr);

/** Bounded prover/test helper. Production page generation uses the same leaf
 * and node definitions through a streaming tree builder. */
[[nodiscard]] bool BuildRCStage3CoupledBankSourceOpeningForTest(
    const std::vector<uint8_t>& page_bytes,
    uint64_t chunk_index,
    uint256& root,
    RCStage3CoupledBankSourceOpening& opening,
    std::string* why = nullptr);

/**
 * One first-pass compression leaf. The verifier reconstructs every one of
 * the 64 padded-block bytes from immutable tag/padding bytes and authenticated
 * source openings. It then derives the canonical 88-word fixed-program
 * boundary and executes the provenance AIR. SHA is never replayed natively.
 */
struct RCStage3CoupledBankStreamLeafProof {
    uint16_t version{kRCStage3CoupledBankStreamVersion};
    uint64_t block_index{0};
    std::array<uint8_t, 64> padded_block{};
    std::array<uint32_t, 8> h_in{};
    std::array<uint32_t, 8> h_out{};
    std::vector<RCStage3CoupledBankSourceOpening> source_openings;
    stage3_hash_air::FixedProgramProvenanceAirProof compression_proof;
    uint256 leaf_commitment{};
};

[[nodiscard]] uint256 ComputeRCStage3CoupledBankStreamLeafSeed(
    const RCStage3CoupledBankStreamManifest& manifest,
    uint64_t block_index);
[[nodiscard]] uint256 CommitRCStage3CoupledBankStreamLeaf(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamLeafProof& leaf);
[[nodiscard]] bool VerifyRCStage3CoupledBankStreamLeaf(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamLeafProof& leaf,
    std::string* why = nullptr);

/**
 * Arity-four structural interval receipt. Level zero receipts are derived
 * only from verified leaf proofs. Parent receipts bind 1..4 consecutive child
 * commitments and enforce SHA chaining equality at every join.
 *
 * This receipt is the integration seam for the normalized recursive verifier;
 * by itself it is not a cryptographic recursive-child proof.
 */
struct RCStage3CoupledBankStreamIntervalReceipt {
    uint16_t version{kRCStage3CoupledBankStreamVersion};
    uint32_t level{0};
    uint64_t index{0};
    uint64_t first_block{0};
    uint64_t block_count{0};
    std::array<uint32_t, 8> first_h_in{};
    std::array<uint32_t, 8> last_h_out{};
    std::vector<uint256> child_commitments;
    uint256 commitment{};

    bool operator==(const RCStage3CoupledBankStreamIntervalReceipt&) const =
        default;
};

/** Canonical interval-statement commitment. Exposed so recursive provers can
 * bind a relation proof before the full child artifact is assembled. This is
 * a commitment helper only; it does not validate or prove the receipt. */
[[nodiscard]] uint256 CommitRCStage3CoupledBankStreamIntervalReceipt(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamIntervalReceipt& receipt);
[[nodiscard]] bool BuildRCStage3CoupledBankStreamLeafReceipt(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamLeafProof& verified_leaf,
    RCStage3CoupledBankStreamIntervalReceipt& out,
    std::string* why = nullptr);
[[nodiscard]] bool BuildRCStage3CoupledBankStreamParentReceipt(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>& children,
    RCStage3CoupledBankStreamIntervalReceipt& out,
    std::string* why = nullptr);
[[nodiscard]] bool ValidateRCStage3CoupledBankStreamRootReceipt(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamIntervalReceipt& root,
    std::string* why = nullptr);

using RCStage3CoupledBankStreamIntervalAirProof =
    air_quotient::AirQuotientProof<
        gkr_field::Fp3,
        air_quotient::AirFriBackendAlg<gkr_field::Fp3>>;
using RCStage3CoupledBankStreamDualIntervalAirProof =
    air_recurse::DualAlgAirProof;

/**
 * Prove/verify the arity-four interval relation itself. The four-row
 * algebraic AIR pins every child receipt, enforces active-prefix arity,
 * contiguous block ranges, all eight SHA chaining words, running coverage,
 * and the parent first/last boundary.
 *
 * These APIs do not establish child validity on their own. The recursive
 * wrapper below first verifies every embedded leaf/parent proof, then invokes
 * this verifier.
 */
[[nodiscard]] bool ProveRCStage3CoupledBankStreamIntervalRelation(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>& children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    RCStage3CoupledBankStreamIntervalAirProof& out,
    std::string* why = nullptr);
[[nodiscard]] bool BuildRCStage3CoupledBankStreamIntervalConstraintSystem(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>& children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledBankStreamIntervalRelation(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>& children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    const RCStage3CoupledBankStreamIntervalAirProof& proof,
    std::string* why = nullptr);
[[nodiscard]] bool ProveRCStage3CoupledBankStreamDualIntervalRelation(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>& children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    const uint256& fs_seed,
    RCStage3CoupledBankStreamDualIntervalAirProof& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledBankStreamDualIntervalRelation(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamIntervalReceipt>& children,
    const RCStage3CoupledBankStreamIntervalReceipt& parent,
    const uint256& fs_seed,
    const RCStage3CoupledBankStreamDualIntervalAirProof& proof,
    std::string* why = nullptr);

/**
 * Executable binary full-family mirror witness. Each logical child can use a
 * distinct pinned relation CS and independent FS seed. Both ordered V5 lanes
 * are verified in the shared normalized trace. The 18 bank interval output
 * cells (first/count/h_in/h_out) are taken from proof-derived DEEP evaluation
 * columns, lane-equality constrained, chained, and exported as the final 18
 * preprocessed parent columns in the same trace.
 *
 * This object intentionally retains prover columns for measurement/mutation
 * tests. Its 70,974-column trace fits the current backend cap, but it is not
 * yet a proof artifact: proof emission/verification, artifact integration,
 * resource evidence and semantic/transcript closure remain open.
 */
struct RCStage3CoupledBankFullBinaryMirrorWitness {
    uint16_t version{kRCStage3CoupledBankStreamVersion};
    std::vector<air_quotient::AirConstraintSystem<gkr_field::Fp3>>
        child_constraint_systems;
    std::vector<uint256> child_fs_seeds;
    std::vector<uint32_t> child_output_column_bases;
    std::vector<air_recurse::ChildPublicInputs> lane_public_inputs;
    std::vector<air_recurse::DualV5RecursiveChildPin> child_pins;
    air_quotient::AirConstraintSystem<gkr_field::Fp3> parent_cs;
    std::vector<std::vector<gkr_field::Fp3>> parent_columns;
    uint32_t parent_output_column_base{0};
    std::array<uint32_t, 18> parent_output_words{};
    uint32_t violations{0};
    bool independent_child_seeds{false};
    bool both_children_executed{false};
    bool all_vcs_families_enabled{false};
    bool lane_output_equality_same_trace{false};
    bool bank_interval_join_same_trace{false};
    bool under_column_cap{false};
    bool parent_proof_emitted{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] RCStage3CoupledBankFullBinaryMirrorWitness
BuildRCStage3CoupledBankFullBinaryMirrorWitness(
    const std::vector<
        air_quotient::AirConstraintSystem<gkr_field::Fp3>>& child_css,
    const std::vector<air_recurse::DualAlgAirProof>& children,
    const std::vector<uint256>& child_fs_seeds,
    const std::vector<uint32_t>& child_output_column_bases);

/**
 * Executable V1 recursive tree artifact. Level-zero nodes contain and verify
 * the complete fixed-program SHA leaf proof. Parent nodes contain all child
 * artifacts and an algebraic proof of their interval relation.
 *
 * This closes recursive verification semantically but is intentionally an
 * expanding proof tree, not the normalized fixed-size recursive proof. It
 * must not be accepted as succinct consensus authority.
 */
struct RCStage3CoupledBankStreamRecursiveProof {
    uint16_t version{kRCStage3CoupledBankStreamVersion};
    RCStage3CoupledBankStreamIntervalReceipt receipt;
    RCStage3CoupledBankStreamLeafProof leaf;
    std::vector<RCStage3CoupledBankStreamRecursiveProof> children;
    RCStage3CoupledBankStreamIntervalAirProof interval_relation_proof;
    uint256 recursive_commitment{};
};

[[nodiscard]] uint256 CommitRCStage3CoupledBankStreamRecursiveProof(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamRecursiveProof& proof);
[[nodiscard]] bool BuildRCStage3CoupledBankStreamRecursiveLeafProof(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamLeafProof& verified_leaf,
    RCStage3CoupledBankStreamRecursiveProof& out,
    std::string* why = nullptr);
[[nodiscard]] bool BuildRCStage3CoupledBankStreamRecursiveParentProof(
    const RCStage3CoupledBankStreamManifest& manifest,
    const std::vector<RCStage3CoupledBankStreamRecursiveProof>& children,
    RCStage3CoupledBankStreamRecursiveProof& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledBankStreamRecursiveProof(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamRecursiveProof& proof,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledBankStreamRecursiveRoot(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamRecursiveProof& root,
    std::string* why = nullptr);

/**
 * Descendant-free normalized verifier step over dual-Q128/V5 algebraic child
 * proofs. The artifact contains only the normalized parent proof, its public
 * lane inputs, complete child proof/transcript commitments, and seeds; it
 * never embeds child proofs or descendants.
 *
 * This is the executable fixed-size proof-verifier step available today.
 * Bank interval-output cells are not yet joined to its same trace, and V5
 * SHA Fiat-Shamir/master-binding equations are still host-replayed. Those
 * omissions keep the succinct-authority flag false.
 */
struct RCStage3CoupledBankNormalizedVerifierStep {
    uint16_t version{kRCStage3CoupledBankStreamVersion};
    uint32_t logical_children{0};
    uint256 child_fs_seed{};
    uint256 parent_fs_seed{};
    uint256 effective_fs_seed{};
    uint256 child_statement_commitment{};
    air_recurse::VerifierAirFamilies families{};
    air_recurse::DualAlgAirProof normalized_parent;
    std::vector<air_recurse::ChildPublicInputs> lane_public_inputs;
    std::vector<air_recurse::DualV5RecursiveChildPin> child_pins;
    uint256 normalized_parent_proof_commitment{};
    uint256 commitment{};
    uint32_t rows{0};
    uint32_t columns{0};
    uint32_t constraints{0};
    uint64_t prove_micros{0};
    bool descendant_free{false};
    bool all_available_algebraic_families{false};
    bool complete_child_proof_commitments{false};
    bool fiat_shamir_replayed_on_host{false};
    bool fiat_shamir_equations_in_air{false};
    bool bank_interval_relation_same_trace{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] RCStage3CoupledBankNormalizedVerifierStep
BuildRCStage3CoupledBankNormalizedVerifierStep(
    const air_quotient::AirConstraintSystem<gkr_field::Fp3>& child_cs,
    const std::vector<air_recurse::DualAlgAirProof>& children,
    const uint256& child_fs_seed,
    const uint256& parent_fs_seed,
    const air_recurse::VerifierAirFamilies& families = {});
[[nodiscard]] bool VerifyRCStage3CoupledBankNormalizedVerifierStep(
    const RCStage3CoupledBankNormalizedVerifierStep& step,
    std::string* why = nullptr);
[[nodiscard]] air_quotient::AirConstraintSystem<gkr_field::Fp3>
BuildRCStage3CoupledBankNormalizedOutputConstraintSystem(
    const RCStage3CoupledBankNormalizedVerifierStep& step);

/** The second SHA pass is one canonical compression whose first 32 bytes are
 * the first-pass terminal state. Its provenance proof binds the public bank
 * root without native SHA replay. */
struct RCStage3CoupledBankStreamSecondPassProof {
    uint16_t version{kRCStage3CoupledBankStreamVersion};
    std::array<uint32_t, 8> first_pass_terminal{};
    std::array<uint32_t, 8> second_pass_output{};
    stage3_hash_air::FixedProgramProvenanceAirProof compression_proof;
    uint256 bank_root{};
};

[[nodiscard]] uint256 ComputeRCStage3CoupledBankStreamSecondPassSeed(
    const RCStage3CoupledBankStreamManifest& manifest,
    const uint256& root_receipt_commitment);
[[nodiscard]] bool VerifyRCStage3CoupledBankStreamSecondPass(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamIntervalReceipt& root,
    const RCStage3CoupledBankStreamSecondPassProof& second,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledBankStreamRecursiveRootAndSecondPass(
    const RCStage3CoupledBankStreamManifest& manifest,
    const RCStage3CoupledBankStreamRecursiveProof& root,
    const RCStage3CoupledBankStreamSecondPassProof& second,
    std::string* why = nullptr);

struct RCStage3CoupledBankStreamAudit {
    bool production_counts_manifest_derived{false};
    bool source_chunk_openings_executable{false};
    bool byte_to_sha_word_projection_executable{false};
    bool fixed_program_leaf_proof_executable{false};
    bool exact_chaining_aggregation_schedule_executable{false};
    bool interval_relation_air_executable{false};
    bool recursive_child_tree_verifier_executable{false};
    bool second_pass_and_bank_root_executable{false};
    bool recursive_interval_proof_executable{false};
    bool normalized_descendant_free_step_executable{false};
    bool normalized_two_level_execution_tested{false};
    bool normalized_full_four_child_families_executable{false};
    bool normalized_full_binary_mirror_executable{false};
    bool normalized_binary_interval_same_trace{false};
    bool normalized_full_binary_parent_proof_executable{false};
    bool succinct_fixed_point_executable{false};
    bool strict_semantic_complete{false};
    std::string remaining;
};

[[nodiscard]] RCStage3CoupledBankStreamAudit
CurrentRCStage3CoupledBankStreamAudit();

struct RCStage3CoupledBankStreamCostEstimate {
    uint64_t leaf_proofs{0};
    uint64_t parent_proofs{0};
    uint64_t total_proofs{0};
    uint32_t tree_depth{0};
    long double expanded_verify_seconds{0.0L};
    bool succinct{false};
};

[[nodiscard]] RCStage3CoupledBankStreamCostEstimate
EstimateRCStage3CoupledBankStreamRecursiveCost(
    const RCStage3CoupledBankStreamManifest& manifest,
    uint64_t measured_leaf_verify_micros,
    uint64_t measured_parent_verify_micros);

inline constexpr bool
    kRCStage3CoupledBankStreamingScheduleExecutable = true;
inline constexpr bool
    kRCStage3CoupledBankStreamingLeafVerifierExecutable = true;
inline constexpr bool
    kRCStage3CoupledBankStreamingStructuralAggregationExecutable = true;
inline constexpr bool
    kRCStage3CoupledBankStreamingRecursiveTreeVerifierExecutable = true;
inline constexpr bool
    kRCStage3CoupledBankStreamingSuccinctFixedPointExecutable = false;
inline constexpr bool
    kRCStage3CoupledBankStreamingRecursiveAuthorityReady = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_BANK_STREAM_H
