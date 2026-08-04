// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_GEMM_OPENINGS_PROOF_OWNED_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_GEMM_OPENINGS_PROOF_OWNED_H

#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>
#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::episode_gemm_openings_proof_owned {

namespace gf = gkr_field;
namespace sites = soundness_scenarios;
namespace topo = universal_topology;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint32_t kEndpointCountV1 = 3;

struct EndpointStatementV1 {
    RCStage3RelationEndpoint endpoint{};
    uint64_t total_instance_count{0};
    uint64_t address_begin{0};
    uint64_t address_stride{0};
    std::vector<uint256> canonical_value_roots;

    bool operator==(const EndpointStatementV1&) const = default;
};

struct ProductionShapeV1 {
    std::array<uint64_t, kEndpointCountV1> endpoint_instances{};
    uint64_t total_instances{0};
    uint256 site_manifest_commitment{};
    bool exact_manifest_total{false};
};

/**
 * Public statement for the production EpisodeGemmOpenings family.
 *
 * The source ProgramTable commitments and family index are reconstructed from
 * the canonical 28-family registry.  The three ordered endpoint statements
 * commit every A/B/Y shard root and exact address interval.
 */
struct StatementV1 {
    uint16_t version{kVersionV1};
    uint256 episode_statement_commitment{};
    uint32_t family_index{UINT32_MAX};
    constraint_bytecode::ProgramTableCommitmentPair program;
    std::array<EndpointStatementV1, kEndpointCountV1> endpoints;
    uint256 production_site_manifest_commitment{};
    /** Derived, never caller asserted. Requires exact production A/B/Y
     * counts and canonical flattened address schedules. */
    bool production_manifest_counts_bound{false};
    uint256 statement_commitment{};

    bool operator==(const StatementV1&) const = default;
};

struct ProofV1 {
    uint16_t version{kVersionV1};
    uint256 statement_commitment{};
    std::array<
        RCStage3EpisodeSemanticMemoryBundle,
        kEndpointCountV1> endpoint_bundles;
    uint256 ordered_proof_set_commitment{};
};

/**
 * Exact executable status for this one family.  `recursively_consumed` is
 * deliberately separate: these children use the consensus SHA-backed FRI
 * backend, while the current normalized fold-bus consumes AlgHash proofs.
 * A root-only SHA->AlgHash conversion is not an equality proof.
 */
struct AuditV1 {
    bool valid{false};
    bool canonical_family_selected{false};
    bool exact_endpoint_order{false};
    bool exact_shard_partition{false};
    bool every_memory_child_proof_verified{false};
    /** The memory children own the complete A/B/Y vectors. */
    bool memory_roots_proof_owned{false};
    /** False until those memory roots equal authenticated columns exported
     * by the owning GEMM/builder relation proofs. */
    bool owning_producer_roots_bound{false};
    /** The serialized per-layer *_root_alg values were recomputed from the
     * exact A/B/Y/Extract vectors and matched the manifest. */
    bool owning_manifest_authority_roots_bound{false};
    /** The complete flat GEMM product verifier executed before the equality
     * bridge was accepted. */
    bool owning_relation_product_verified{false};
    /** Current bridge rebuilds the flattened vectors on the host. It is
     * useful hardening/evidence, but not a sublinear production path. */
    bool source_bridge_host_linear{false};
    bool source_bridge_normalized_recursive{false};
    bool producer_root_mutation_rejected{false};
    bool distinct_producer_root_transplant_available{false};
    bool producer_root_transplant_rejected{false};
    bool exact_all_instance_aggregation{false};
    bool production_all_instance_aggregation{false};
    bool proof_level_tamper_rejected{false};
    bool normalized_parent_accepts_sha_children{false};
    bool cross_hash_value_equality_proved{false};
    bool recursively_consumed{false};
    uint32_t residual_obligations{0};
    std::string note;
};

[[nodiscard]] const std::array<
    RCStage3RelationEndpoint, kEndpointCountV1>&
CanonicalEndpointOrderV1();

[[nodiscard]] ProductionShapeV1 BuildProductionShapeV1();

/** Compute the exact default-FRI column roots for a canonical shard split. */
[[nodiscard]] bool ComputeCanonicalShardRootsV1(
    const std::vector<gf::Fp3>& values,
    std::vector<uint256>& out,
    std::string* why = nullptr);

[[nodiscard]] bool BuildStatementV1(
    const uint256& episode_statement_commitment,
    const std::array<EndpointStatementV1, kEndpointCountV1>& endpoints,
    StatementV1& out,
    std::string* why = nullptr);

/**
 * Derive the only A/B/Y opening statement compatible with a validated
 * RCStage3EpisodeGemmProduct.  The helper recomputes every per-layer
 * VectorRootAlg and then flattens the exact layer vectors in Λ order before
 * computing the SHA-FRI shard roots.  It never trusts caller-provided
 * canonical_value_roots.
 */
[[nodiscard]] bool BuildStatementFromOwningGemmProductV1(
    const RCStage3SuccinctProof& episode_statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    StatementV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint256 ComputeStatementCommitmentV1(
    const StatementV1& statement);

[[nodiscard]] uint256 ComputeOrderedProofSetCommitmentV1(
    const ProofV1& proof);

[[nodiscard]] bool ProveV1(
    const StatementV1& statement,
    const std::array<
        std::vector<gf::Fp3>, kEndpointCountV1>& values,
    ProofV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool VerifyV1(
    const StatementV1& expected_statement,
    const ProofV1& proof,
    std::string* why = nullptr);

/**
 * Execute the owning GEMM relation proof, validate all per-layer AlgHash
 * authority roots, regenerate the exact flattened A/B/Y statement, and only
 * then accept the proof-owned opening bundles.
 *
 * This is intentionally not a production-recursive claim: the equality is
 * currently established by walking the flat vectors on the host.
 */
[[nodiscard]] bool VerifyWithOwningGemmProductV1(
    const RCStage3SuccinctProof& episode_statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    const StatementV1& expected_statement,
    const ProofV1& proof,
    std::string* why = nullptr);

/** Re-verifies the proof and derives status; no caller-supplied booleans. */
[[nodiscard]] AuditV1 AssessV1(
    const StatementV1& expected_statement,
    const ProofV1& proof);

[[nodiscard]] AuditV1 AssessWithOwningGemmProductV1(
    const RCStage3SuccinctProof& episode_statement,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    const StatementV1& expected_statement,
    const ProofV1& proof);

inline constexpr bool kProofOwnedOpeningsExecutableV1 = true;
inline constexpr bool kRecursiveConsumptionExecutableV1 = false;
static_assert(kProofOwnedOpeningsExecutableV1);
static_assert(!kRecursiveConsumptionExecutableV1);

} // namespace matmul::v4::rc::episode_gemm_openings_proof_owned

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_GEMM_OPENINGS_PROOF_OWNED_H
