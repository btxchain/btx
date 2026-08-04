// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_HASH_SEMANTIC_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_HASH_SEMANTIC_H

#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_hash_semantic {

namespace hash_air = stage3_hash_air;
using gkr_field::Fp3;

inline constexpr uint16_t kFlatBundleVersion = 1;
inline constexpr uint32_t kMaxFlatBoundaryProofs = 1U << 20;

/**
 * Version-one all-instance hash proof.
 *
 * The manifest adapters in stage3_hash_air deterministically enumerate every
 * SHA-256 compression or ChaCha20 block boundary. This bundle must contain
 * exactly one complete internal-SSA provenance proof for every enumerated
 * boundary, in order. It is intentionally a flat verifier: recursion may
 * replace the vector later without changing the semantic statement.
 */
struct FlatBoundaryProofBundle {
    uint16_t version{kFlatBundleVersion};
    RCStage3RelationEndpoint endpoint{};
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    std::vector<hash_air::FixedProgramProvenanceAirProof> proofs;
};

/**
 * Drop-in all-instance bundle using the 63-active vertical AIR. Full chunks
 * schedule 64 lanes; a canonical partial tail schedules the smallest
 * power-of-two lane count (minimum two).
 *
 * Boundaries retain the identical typed-manifest order and are partitioned
 * into canonical consecutive chunks of at most 63. No prover-selected chunk
 * boundaries are serialized.
 */
struct VerticalBoundaryProofBundle {
    uint16_t version{kFlatBundleVersion};
    RCStage3RelationEndpoint endpoint{};
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    uint32_t boundary_count{0};
    std::vector<
        hash_air::FixedProgramVerticalProvenanceAirProof> proofs;
};

enum class BoundaryPort : uint8_t {
    External = 1,
    Final = 2,
    ExternalThenFinal = 3,
};

/** Domain-separated seed for one exact boundary proof. */
[[nodiscard]] uint256 ComputeBoundaryProofSeed(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    uint32_t boundary_index,
    uint32_t boundary_count);

/**
 * Honest all-instance prover for a canonical fixed-program boundary list.
 *
 * The caller must obtain `boundaries` from a typed manifest adapter.  This
 * routine proves every internal-SSA execution in list order and therefore
 * cannot manufacture, omit, or reorder a boundary.  Verification still
 * regenerates the list from the typed manifest.
 */
[[nodiscard]] bool ProveFlatBoundaryProofBundle(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const hash_air::FixedProgram& program,
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    FlatBoundaryProofBundle& out,
    std::string* why = nullptr);

/**
 * Verify every canonical boundary proof. There is no native hash replay and
 * no callback-selected constraint system: `program` is one of the immutable
 * SHA/ChaCha programs and every proof executes the fixed provenance AIR.
 */
[[nodiscard]] bool VerifyFlatBoundaryProofBundle(
    const hash_air::FixedProgram& program,
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    const uint256& expected_manifest_commitment,
    const FlatBoundaryProofBundle& bundle,
    std::string* why = nullptr);

/** Canonical 63-boundary vertical analogue of the flat prover/verifier. */
[[nodiscard]] bool ProveVerticalBoundaryProofBundle(
    RCStage3RelationEndpoint endpoint,
    const uint256& statement_commitment,
    const uint256& manifest_commitment,
    const hash_air::FixedProgram& program,
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    VerticalBoundaryProofBundle& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyVerticalBoundaryProofBundle(
    const hash_air::FixedProgram& program,
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    const uint256& expected_manifest_commitment,
    const VerticalBoundaryProofBundle& bundle,
    std::string* why = nullptr);

/**
 * Canonical proof-owned semantic word stream for a selected boundary port.
 * Instance order and word order are preserved. The returned values are base
 * field embeddings, suitable for the endpoint semantic-memory VALUE column.
 */
[[nodiscard]] bool BuildCanonicalBoundaryValues(
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    BoundaryPort port,
    std::vector<Fp3>& out,
    std::string* why = nullptr);

/** Commitment of BuildCanonicalBoundaryValues padded to the next power of 2. */
[[nodiscard]] bool ComputeCanonicalBoundaryValueRoot(
    const std::vector<hash_air::FixedProgramBoundaryInstance>& boundaries,
    BoundaryPort port,
    uint256& root,
    uint32_t& logical_rows,
    uint32_t& n_rows,
    std::string* why = nullptr);

/** Structural manifest adapters plus exact all-instance AIR verification. */
[[nodiscard]] bool VerifyShaManifestBundle(
    RCStage3RelationEndpoint endpoint,
    const hash_air::ShaManifest& manifest,
    const FlatBoundaryProofBundle& bundle,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyCounterXofManifestBundle(
    RCStage3RelationEndpoint endpoint,
    const hash_air::CounterXofManifest& manifest,
    const FlatBoundaryProofBundle& bundle,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyChaChaManifestBundle(
    RCStage3RelationEndpoint endpoint,
    const hash_air::ChaChaConsumptionManifest& manifest,
    const FlatBoundaryProofBundle& bundle,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyTileTreeManifestBundle(
    RCStage3RelationEndpoint endpoint,
    const hash_air::TileTreeManifest& manifest,
    const FlatBoundaryProofBundle& bundle,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyDirectSha256dManifestBundle(
    RCStage3RelationEndpoint endpoint,
    const hash_air::DirectSha256dManifest& manifest,
    const FlatBoundaryProofBundle& bundle,
    std::string* why = nullptr);

inline constexpr bool kFlatAllInstanceHashSemanticProofExecutable = true;
inline constexpr bool kFlatAllInstanceHashSemanticProofRecursive = false;

} // namespace matmul::v4::rc::stage3_hash_semantic

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_HASH_SEMANTIC_H
