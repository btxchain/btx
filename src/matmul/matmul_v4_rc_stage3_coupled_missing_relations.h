// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_MISSING_RELATIONS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_MISSING_RELATIONS_H

#include <matmul/matmul_v4_rc_stage3_coupled_semantic.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint16_t kRCStage3CoupledMissingRelationsVersion = 1;

/**
 * A proof-owned boundary port of an executed fixed-program hash.
 *
 * The verifier regenerates the boundary order from the typed manifest and
 * recomputes VALUE root, row counts, schedule and semantic-memory root.  The
 * pin therefore cannot relabel a prover-selected vector as another endpoint.
 */
struct RCStage3CoupledBoundaryPortPin {
    uint16_t version{kRCStage3CoupledMissingRelationsVersion};
    RCStage3RelationEndpoint endpoint{};
    stage3_hash_semantic::BoundaryPort port{
        stage3_hash_semantic::BoundaryPort::External};
    uint256 statement_commitment{};
    uint256 shape_commitment{};
    uint256 manifest_commitment{};
    uint256 schedule_commitment{};
    uint64_t instance_count{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint256 value_root{};
    uint256 semantic_memory_root{};

    bool operator==(const RCStage3CoupledBoundaryPortPin&) const = default;
};

/** Typed bank SHA256d statement. page_bytes are exactly
 * bank_pages*lobe_width*lobe_width bytes in page-major order.  The prover
 * helper may construct the SHA witness natively; verification executes every
 * registered SHA compression proof and never accepts native replay. */
struct RCStage3CoupledBankRootManifest {
    uint16_t version{kRCStage3CoupledMissingRelationsVersion};
    uint256 statement_commitment{};
    RCStage3CoupledShape shape{};
    stage3_hash_air::ShaManifest sha256d;
    uint256 bank_root{};
    uint256 commitment{};

    bool operator==(const RCStage3CoupledBankRootManifest&) const = default;
};

struct RCStage3CoupledBankRootExecution {
    RCStage3CoupledBankRootManifest manifest;
    stage3_hash_semantic::FlatBoundaryProofBundle hash_proofs;
    RCStage3CoupledBoundaryPortPin bank_bytes;
    RCStage3CoupledBoundaryPortPin bank_digest;
};

[[nodiscard]] bool BuildRCStage3CoupledBankRootManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<uint8_t>& page_bytes,
    RCStage3CoupledBankRootManifest& out,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitRCStage3CoupledBankRootManifest(
    const RCStage3CoupledBankRootManifest& manifest);
[[nodiscard]] bool BuildRCStage3CoupledBoundaryPortPin(
    RCStage3RelationEndpoint endpoint,
    stage3_hash_semantic::BoundaryPort port,
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const uint256& manifest_commitment,
    const std::vector<stage3_hash_air::FixedProgramBoundaryInstance>&
        boundaries,
    RCStage3CoupledBoundaryPortPin& out,
    std::string* why = nullptr);
/** Honest flat all-SHA prover for endpoint 29. */
[[nodiscard]] bool ProveRCStage3CoupledBankRootExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const std::vector<uint8_t>& page_bytes,
    RCStage3CoupledBankRootExecution& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3CoupledBankRootExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& expected_shape,
    const RCStage3CoupledBankRootExecution& execution,
    std::string* why = nullptr);

/**
 * Canonical all-output-cell range schedule for the coupled GEMMs.
 *
 * V1 proves |Y| <= W*48*48 over exactly
 * barriers*lobes*pages_per_barrier_lobe*rows_per_lobe*W cells.  Shards are
 * fixed consecutive intervals of kRCStage3SignedRangeMaxShardRows.
 */
struct RCStage3CoupledSignedRangeManifest {
    uint16_t version{kRCStage3CoupledMissingRelationsVersion};
    uint256 statement_commitment{};
    RCStage3CoupledShape shape{};
    uint64_t scheduled_gemms{0};
    uint64_t total_output_cells{0};
    uint64_t max_abs{0};
    uint32_t shard_count{0};
    uint256 schedule_commitment{};
    uint256 commitment{};

    bool operator==(const RCStage3CoupledSignedRangeManifest&) const =
        default;
};

struct RCStage3CoupledSignedRangeShardProof {
    RCStage3SignedRangePin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
};

struct RCStage3CoupledSignedRangeExecution {
    RCStage3CoupledSignedRangeManifest manifest;
    std::vector<RCStage3CoupledSignedRangeShardProof> shards;
    /** Ordered commitment of every proof's RANGE_VALUE column root. */
    uint256 value_roots_commitment{};
};

[[nodiscard]] bool BuildRCStage3CoupledSignedRangeManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    RCStage3CoupledSignedRangeManifest& out,
    std::string* why = nullptr);
[[nodiscard]] uint256 CommitRCStage3CoupledSignedRangeManifest(
    const RCStage3CoupledSignedRangeManifest& manifest);
[[nodiscard]] bool MakeRCStage3CoupledSignedRangePin(
    const RCStage3CoupledSignedRangeManifest& manifest,
    uint32_t shard_index,
    RCStage3SignedRangePin& out,
    std::string* why = nullptr);
[[nodiscard]] uint256
CommitRCStage3CoupledSignedRangeValueRoots(
    const RCStage3CoupledSignedRangeManifest& manifest,
    const std::vector<RCStage3CoupledSignedRangeShardProof>& shards);
[[nodiscard]] bool VerifyRCStage3CoupledSignedRangeExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& expected_shape,
    const RCStage3CoupledSignedRangeExecution& execution,
    std::string* why = nullptr);

/** One barrier SHA proof simultaneously owns the input state and output
 * digest ports.  Cross-role equality to Extract and the digest relation is
 * intentionally left to the executed global root-link graph. */
struct RCStage3CoupledBarrierEndpointExecution {
    stage3_hash_air::CoupledBarrierManifest manifest;
    stage3_hash_semantic::FlatBoundaryProofBundle hash_proofs;
    RCStage3CoupledBoundaryPortPin input;
    RCStage3CoupledBoundaryPortPin output;
};

[[nodiscard]] bool VerifyRCStage3CoupledBarrierEndpointExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledBarrierEndpointExecution& execution,
    std::string* why = nullptr);

/** One coupled-digest SHA proof owns the ordered bank+barrier input words and
 * the digest output.  `require_public_digest` additionally enforces equality
 * to the immutable outer statement. */
struct RCStage3CoupledDigestEndpointExecution {
    stage3_hash_air::CoupledDigestManifest manifest;
    stage3_hash_semantic::FlatBoundaryProofBundle hash_proofs;
    RCStage3CoupledBoundaryPortPin bank_and_barriers;
    RCStage3CoupledBoundaryPortPin digest_value;
};

[[nodiscard]] bool VerifyRCStage3CoupledDigestEndpointExecution(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledDigestEndpointExecution& execution,
    bool require_public_digest,
    std::string* why = nullptr);

struct RCStage3CoupledMissingEndpointAudit {
    RCStage3RelationEndpoint endpoint{};
    bool local_engine_executable{false};
    bool verifier_derived_schedule{false};
    bool exact_all_instance_proof_execution{false};
    bool proof_owned_memory_root{false};
    bool outer_statement_equality{false};
    bool local_relation_complete{false};
    bool producer_graph_complete{false};
    bool strict_semantic_complete{false};
    std::string remaining;
};

/** Exact six-endpoint audit.  Local execution is distinguished from strict
 * inter-role completion so this module cannot silently replace root links. */
[[nodiscard]] std::vector<RCStage3CoupledMissingEndpointAudit>
CurrentRCStage3CoupledMissingEndpointAudit(
    const RCStage3CoupledShape& shape);

inline constexpr bool kRCStage3CoupledBankRootLocalEngineExecutable = true;
inline constexpr bool kRCStage3CoupledSignedRangeLocalEngineExecutable = true;
inline constexpr bool kRCStage3CoupledBarrierPortsLocalEngineExecutable = true;
inline constexpr bool kRCStage3CoupledDigestPortsLocalEngineExecutable = true;
inline constexpr bool kRCStage3CoupledMissingRelationsAuthorityReady = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_COUPLED_MISSING_RELATIONS_H
