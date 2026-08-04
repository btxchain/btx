// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_HIERARCHY_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_HIERARCHY_H

#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::recursive_hierarchy {

namespace aq = air_quotient;
namespace fp = recursive_fixedpoint;
namespace gf = gkr_field;

inline constexpr uint16_t kShardOrdinalManifestVersionV1 = 1;
inline constexpr uint16_t kShardOrdinalManifestVersionV2 = 2;
inline constexpr uint16_t kRetainedHierarchyNodeVersionV1 = 1;
inline constexpr uint16_t
    kRetainedSplitRapHierarchyNodeVersionV2 = 2;

/**
 * One verifier-owned shard in the global semantic-constraint ordinal space.
 *
 * The intervals are half open.  `statement_root` is the commitment to the
 * verifier-reconstructed shard statement (normally the canonical program /
 * role statement root), not a prover-provided description of that statement.
 */
struct ShardOrdinalEntryV1 {
    uint32_t shard_ordinal{0};
    uint64_t first_ordinal{0};
    uint64_t ordinal_count{0};
    uint256 statement_root{};

    bool operator==(const ShardOrdinalEntryV1&) const = default;
};

/**
 * Exact, verifier-recomputable partition of [0, total_ordinals).
 *
 * Validation requires entries in shard-ordinal order, non-empty adjacent
 * intervals, no arithmetic overflow, exact terminal coverage and the exact
 * domain-separated commitment.  Sorting is deliberately forbidden: a
 * reordered manifest is a different (and invalid) statement.
 */
struct ShardOrdinalManifestV1 {
    uint16_t version{kShardOrdinalManifestVersionV1};
    uint64_t total_ordinals{0};
    std::vector<ShardOrdinalEntryV1> entries;
    uint256 commitment{};

    bool operator==(const ShardOrdinalManifestV1&) const = default;
};

[[nodiscard]] uint256 CommitShardOrdinalManifestV1(
    const ShardOrdinalManifestV1& manifest);

[[nodiscard]] ShardOrdinalManifestV1 BuildShardOrdinalManifestV1(
    uint64_t total_ordinals,
    const std::vector<ShardOrdinalEntryV1>& entries);

[[nodiscard]] bool ValidateShardOrdinalManifestV1(
    const ShardOrdinalManifestV1& manifest,
    std::string* why = nullptr);

/**
 * One verifier-owned shard whose canonical program ordinals need not form an
 * interval.  This is the exact-set form required by the existing
 * first-fit-decreasing shard packer.  `program_ordinals` must be non-empty and
 * strictly increasing; sorting prover input is deliberately forbidden.
 */
struct ShardOrdinalEntryV2 {
    uint32_t shard_ordinal{0};
    std::vector<uint64_t> program_ordinals;
    uint256 statement_root{};

    bool operator==(const ShardOrdinalEntryV2&) const = default;
};

/**
 * Exact verifier-recomputable set partition of [0, total_ordinals).
 *
 * Entries remain in canonical shard order while each entry may own a
 * non-contiguous exact set.  Validation requires every global ordinal exactly
 * once: omission, duplication, cross-shard overlap, out-of-range ordinals,
 * entry reorder and within-entry reorder all fail.
 */
struct ShardOrdinalManifestV2 {
    uint16_t version{kShardOrdinalManifestVersionV2};
    uint64_t total_ordinals{0};
    std::vector<ShardOrdinalEntryV2> entries;
    uint256 commitment{};

    bool operator==(const ShardOrdinalManifestV2&) const = default;
};

[[nodiscard]] uint256 CommitShardOrdinalManifestV2(
    const ShardOrdinalManifestV2& manifest);

[[nodiscard]] ShardOrdinalManifestV2 BuildShardOrdinalManifestV2(
    uint64_t total_ordinals,
    const std::vector<ShardOrdinalEntryV2>& entries);

[[nodiscard]] bool ValidateShardOrdinalManifestV2(
    const ShardOrdinalManifestV2& manifest,
    std::string* why = nullptr);

/**
 * A node covers a canonical adjacent run of manifest shards and therefore one
 * exact adjacent run of global semantic ordinals.
 */
struct ShardOrdinalCoverageV1 {
    uint32_t first_shard_ordinal{0};
    uint32_t shard_count{0};
    uint64_t first_ordinal{0};
    uint64_t ordinal_count{0};
    uint256 commitment{};

    bool operator==(const ShardOrdinalCoverageV1&) const = default;
};

[[nodiscard]] ShardOrdinalCoverageV1 BuildShardOrdinalCoverageV1(
    const ShardOrdinalManifestV1& manifest,
    uint32_t first_shard_ordinal,
    uint32_t shard_count);

[[nodiscard]] uint256 CommitShardOrdinalCoverageV1(
    const ShardOrdinalManifestV1& manifest,
    const ShardOrdinalCoverageV1& coverage);

[[nodiscard]] bool ValidateShardOrdinalCoverageV1(
    const ShardOrdinalManifestV1& manifest,
    const ShardOrdinalCoverageV1& coverage,
    std::string* why = nullptr);

/**
 * Require one hierarchy level to cover the complete manifest exactly once.
 *
 * The caller must supply the nodes in canonical left-to-right order.  Omitted,
 * duplicate, reordered and overlapping coverage all fail without sorting.
 */
[[nodiscard]] bool ValidateExactHierarchyLevelCoverageV1(
    const ShardOrdinalManifestV1& manifest,
    const std::vector<ShardOrdinalCoverageV1>& level,
    std::string* why = nullptr);

/**
 * Stable statement identifier for a reconstructed AIR constraint system.
 *
 * This commits all serializable structure and public/preprocessed data, but a
 * std::function callback has no canonical byte encoding.  Consequently it is
 * a mix-up guard, not permission to trust an artifact-owned constraint
 * system.  ValidateRetainedHierarchyNodeV1 always verifies against a separate
 * verifier-reconstructed `expected_cs`.
 */
[[nodiscard]] uint256 ComputeHierarchyConstraintSystemCommitmentV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs);

/**
 * A proof-owned, reusable hierarchy node.
 *
 * `constraint_system`, `proof`, `fs_seed`, `node_root`, quotient terminals
 * and exact ordinal coverage remain live together.  `proof_bytes` are the
 * canonical whole-proof encoding.  `full_byte_count` is the exact size of the
 * canonical node envelope (metadata, roots, q terminals and whole proof);
 * the reconstructed constraint system is intentionally not sent on the wire.
 *
 * The three booleans are evidence labels, not authority switches.  Validation
 * recomputes every commitment, canonical encoding, exact byte count and runs
 * the real AirQuotientVerify against `expected_cs`.  Setting the labels on a
 * prove=false/empty artifact cannot make it valid.
 */
struct RetainedHierarchyNodeV1 {
    uint16_t version{kRetainedHierarchyNodeVersionV1};
    uint32_t level{0};
    uint32_t node_ordinal{0};
    ShardOrdinalCoverageV1 coverage;
    uint256 manifest_commitment{};
    uint256 covered_statement_root{};
    uint256 constraint_system_commitment{};
    uint256 fs_seed{};
    uint256 proof_commitment{};
    uint256 node_root{};
    std::vector<gf::Fp3> quotient_terminals;
    aq::AirConstraintSystem<gf::Fp3> constraint_system;
    fp::AlgAirProof proof;
    std::vector<unsigned char> proof_bytes;
    uint64_t full_byte_count{0};
    bool proof_retained{false};
    bool native_proof_verified{false};
    bool cryptographic_child{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] uint256 ComputeCoveredShardStatementRootV1(
    const ShardOrdinalManifestV1& manifest,
    const ShardOrdinalCoverageV1& coverage);

[[nodiscard]] uint256 ComputeRetainedHierarchyNodeRootV1(
    const RetainedHierarchyNodeV1& node);

[[nodiscard]] uint64_t ComputeRetainedHierarchyNodeFullBytesV1(
    const RetainedHierarchyNodeV1& node);

/**
 * Extract the authenticated quotient opening from every child query row.
 * Each row is required to contain exactly W trace values followed by q.
 */
[[nodiscard]] bool ExtractProofQuotientTerminalsV1(
    const aq::AirConstraintSystem<gf::Fp3>& constraint_system,
    const fp::AlgAirProof& proof,
    std::vector<gf::Fp3>& out,
    std::string* why = nullptr);

/** Materialize the canonical envelope whose exact size is `full_byte_count`. */
[[nodiscard]] bool SerializeRetainedHierarchyNodeEnvelopeV1(
    const RetainedHierarchyNodeV1& node,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

/**
 * Retain one already-produced proof. `quotient_terminals` must equal the
 * authenticated q cell extracted from every proof query row; envelope-only
 * caller metadata cannot substitute it.
 */
[[nodiscard]] RetainedHierarchyNodeV1 RetainVerifiedHierarchyNodeV1(
    const ShardOrdinalManifestV1& manifest,
    const ShardOrdinalCoverageV1& coverage,
    uint32_t level,
    uint32_t node_ordinal,
    const aq::AirConstraintSystem<gf::Fp3>& constraint_system,
    const fp::AlgAirProof& proof,
    const uint256& fs_seed,
    const std::vector<gf::Fp3>& quotient_terminals);

/**
 * Validate an artifact against the independently reconstructed statement.
 * The retained `constraint_system` is checked for canonical structural
 * identity, but the native verifier always consumes `expected_cs`.
 */
[[nodiscard]] bool ValidateRetainedHierarchyNodeV1(
    const ShardOrdinalManifestV1& manifest,
    const aq::AirConstraintSystem<gf::Fp3>& expected_cs,
    const RetainedHierarchyNodeV1& node,
    std::string* why = nullptr);

/**
 * Validate a complete level of retained nodes in canonical node-ordinal order.
 * All nodes must have the same level, their coverage must partition the
 * manifest exactly once, and each proof is natively verified against the
 * corresponding independently reconstructed constraint system.
 */
[[nodiscard]] bool ValidateRetainedHierarchyLevelV1(
    const ShardOrdinalManifestV1& manifest,
    const std::vector<aq::AirConstraintSystem<gf::Fp3>>& expected_css,
    const std::vector<RetainedHierarchyNodeV1>& nodes,
    std::string* why = nullptr);

/**
 * Canonical retained child for a SAFE Split-RAP relation.
 *
 * Unlike RetainedHierarchyNodeV1, this node retains the one proof that owns
 * all base, dependent and quotient groups.  The verifier supplies the
 * independently reconstructed constraint system, exact R0 column list and
 * public Fiat-Shamir seed.  The artifact cannot select any of those values.
 */
struct RetainedSplitRapHierarchyNodeV2 {
    uint16_t version{
        kRetainedSplitRapHierarchyNodeVersionV2};
    uint32_t level{0};
    uint32_t node_ordinal{0};
    ShardOrdinalCoverageV1 coverage;
    uint256 manifest_commitment{};
    uint256 covered_statement_root{};
    uint256 constraint_system_commitment{};
    std::vector<uint32_t> base_column_indices;
    uint256 fs_seed{};
    uint256 proof_commitment{};
    uint256 node_root{};
    std::vector<gf::Fp3> quotient_terminals;
    aq::AirConstraintSystem<gf::Fp3> constraint_system;
    aq::AirQuotientSplitRapRowsProof proof;
    std::vector<unsigned char> proof_bytes;
    uint64_t full_byte_count{0};
    bool proof_retained{false};
    bool native_proof_verified{false};
    bool cryptographic_child{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool ExtractSplitRapProofQuotientTerminalsV2(
    const aq::AirConstraintSystem<gf::Fp3>& constraint_system,
    const aq::AirQuotientSplitRapRowsProof& proof,
    std::vector<gf::Fp3>& out,
    std::string* why = nullptr);

[[nodiscard]] uint64_t
ComputeRetainedSplitRapHierarchyNodeFullBytesV2(
    const RetainedSplitRapHierarchyNodeV2& node);

[[nodiscard]] uint256
ComputeRetainedSplitRapHierarchyNodeRootV2(
    const RetainedSplitRapHierarchyNodeV2& node);

[[nodiscard]] bool
SerializeRetainedSplitRapHierarchyNodeEnvelopeV2(
    const RetainedSplitRapHierarchyNodeV2& node,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

[[nodiscard]] RetainedSplitRapHierarchyNodeV2
RetainVerifiedSplitRapHierarchyNodeV2(
    const ShardOrdinalManifestV1& manifest,
    const ShardOrdinalCoverageV1& coverage,
    uint32_t level,
    uint32_t node_ordinal,
    const aq::AirConstraintSystem<gf::Fp3>& constraint_system,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const std::vector<uint32_t>& base_column_indices,
    const uint256& fs_seed);

[[nodiscard]] bool ValidateRetainedSplitRapHierarchyNodeV2(
    const ShardOrdinalManifestV1& manifest,
    const aq::AirConstraintSystem<gf::Fp3>& expected_cs,
    const std::vector<uint32_t>& expected_base_column_indices,
    const uint256& expected_fs_seed,
    const RetainedSplitRapHierarchyNodeV2& node,
    std::string* why = nullptr);

[[nodiscard]] bool ValidateRetainedSplitRapHierarchyLevelV2(
    const ShardOrdinalManifestV1& manifest,
    const std::vector<aq::AirConstraintSystem<gf::Fp3>>&
        expected_css,
    const std::vector<std::vector<uint32_t>>&
        expected_base_column_indices,
    const std::vector<uint256>& expected_fs_seeds,
    const std::vector<RetainedSplitRapHierarchyNodeV2>& nodes,
    std::string* why = nullptr);

/**
 * One exact, cryptographic hierarchy reduction.
 *
 * The input nodes must form a complete canonical level over `manifest`.
 * Their canonical proof bytes are decoded, verified against independently
 * reconstructed child constraint systems, and consumed by the real narrow
 * multi-child FoldBus/FRI parent.  The ordered child node roots and exact
 * manifest derive the parent transcript context.  The resulting proof is
 * retained as a new full-coverage node and is independently reconstructed
 * and verified before `cryptographically_valid` can become true.
 *
 * Budget labels remain separate.  This object is evidence for the former
 * boolean-child hierarchy seam; it does not flip AggregationReady.
 */
struct RetainedHierarchyRootV1 {
    uint16_t version{1};
    uint32_t child_level{0};
    uint32_t parent_level{0};
    uint32_t child_count{0};
    uint256 manifest_commitment{};
    uint256 parent_context_binding{};
    std::vector<uint256> ordered_child_node_roots;
    fp::NarrowMultiChildL2FriConsumeV1 consumed;
    RetainedHierarchyNodeV1 root;
    bool all_children_independently_verified{false};
    bool exact_level_coverage{false};
    bool parent_statement_reconstructed{false};
    bool parent_proof_independently_verified{false};
    bool child_substitution_rejected{false};
    bool cryptographically_valid{false};
    bool production_budget_met{false};
    std::string note;
};

/** Domain-separated ordered context committed by the parent FS transcript. */
[[nodiscard]] uint256 ComputeRetainedHierarchyRootContextV1(
    const ShardOrdinalManifestV1& manifest,
    const std::vector<RetainedHierarchyNodeV1>& children,
    uint32_t parent_level);

/**
 * Consume a complete retained level into one real proof-owned root.
 * `prove=false` is not accepted as cryptographic evidence.
 */
[[nodiscard]] RetainedHierarchyRootV1
ExecuteRetainedHierarchyRootV1(
    const ShardOrdinalManifestV1& manifest,
    const std::vector<aq::AirConstraintSystem<gf::Fp3>>&
        expected_child_css,
    const std::vector<RetainedHierarchyNodeV1>& children,
    bool prove = true);

/**
 * Fresh-verifier validation.  The verifier decodes child bytes, rebuilds the
 * FoldBus parent, recomputes the parent seed, and verifies the root proof
 * against that reconstructed parent AIR.
 */
[[nodiscard]] bool ValidateRetainedHierarchyRootV1(
    const ShardOrdinalManifestV1& manifest,
    const std::vector<aq::AirConstraintSystem<gf::Fp3>>&
        expected_child_css,
    const std::vector<RetainedHierarchyNodeV1>& children,
    const RetainedHierarchyRootV1& root,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::recursive_hierarchy

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_RECURSIVE_HIERARCHY_H
