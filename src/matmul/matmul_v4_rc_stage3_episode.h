// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_H

#include <matmul/matmul_v4_rc_stage3.h>

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// Stage-3 episode relation adapters.
//
// The Stage-3 envelope deliberately stores opaque byte strings so its wire ABI
// does not depend on a particular proof system.  Consensus code must not treat
// "non-empty bytes" as a proof.  This module supplies the fixed, typed inner
// framing for the six episode roles and binds each inner section to:
//
//   * its outer role;
//   * every Stage-3 public input;
//   * its exact payload bytes; and
//   * the matching outer commitment.
//
// Existing episode machinery is classified honestly below.  EpisodeAirV1
// proves only low-degree GEMM/Extract fragments.  WinnerGkrV7NativeV1,
// DirectNativeV1, and RecursionPrototypeV1 retain native/unproved residuals.
// None is a complete Stage-3 authority engine, so the authority verifier
// remains fail-closed even if a section claims every obligation bit.
// ============================================================================

namespace matmul::v4::rc {

inline constexpr uint32_t kRCStage3EpisodeSectionMagic = 0x33504552U; // "REP3"
inline constexpr uint16_t kRCStage3EpisodeSectionVersion = 1;
inline constexpr size_t kRCStage3EpisodeMaxSectionPayload = 4U * 1024U * 1024U;

/** Implementations that exist in the tree.  This enum intentionally has no
 * "complete" value: adding one requires a concrete proof-only verifier, a
 * canonical codec, and removal of every gap reported by
 * CurrentRCStage3EpisodeRelationGaps(). */
enum class RCStage3EpisodeEngine : uint8_t {
    EpisodeAirV1 = 1,
    WinnerGkrV7NativeV1 = 2,
    DirectNativeV1 = 3,
    RecursionPrototypeV1 = 4,
};

/** Globally unique obligation bits.  A role is complete only when its exact
 * RequiredRCStage3EpisodeCoverage(role) mask is proof-verified. */
enum class RCStage3EpisodeObligation : uint64_t {
    BuilderParamsFromHeader = uint64_t{1} << 0,
    BuilderSeedChain = uint64_t{1} << 1,
    BuilderOperandExpansion = uint64_t{1} << 2,
    BuilderTraceBinding = uint64_t{1} << 3,

    GemmEveryLayer = uint64_t{1} << 4,
    GemmSumcheck = uint64_t{1} << 5,
    GemmOperandOpenings = uint64_t{1} << 6,
    GemmSignedAccumulatorRange = uint64_t{1} << 7,

    ExtractEveryTile = uint64_t{1} << 8,
    ExtractSamplerWalk = uint64_t{1} << 9,
    ExtractChaChaBinding = uint64_t{1} << 10,
    ExtractScaleBinding = uint64_t{1} << 11,
    ExtractDequantAndRange = uint64_t{1} << 12,
    ExtractOutputBinding = uint64_t{1} << 13,

    WiringCopies = uint64_t{1} << 14,
    WiringTransposes = uint64_t{1} << 15,
    WiringResiduals = uint64_t{1} << 16,
    WiringRoundOrder = uint64_t{1} << 17,

    TileTreeCompleteStream = uint64_t{1} << 18,
    TileTreeLeafHash = uint64_t{1} << 19,
    TileTreeInternalHash = uint64_t{1} << 20,
    TileTreeRootBinding = uint64_t{1} << 21,

    DigestRoundRoots = uint64_t{1} << 22,
    DigestEpisode = uint64_t{1} << 23,
    DigestHeaderAndTarget = uint64_t{1} << 24,
    DigestPowBinding = uint64_t{1} << 25,
};

struct RCStage3EpisodeRelationProof {
    uint32_t magic{kRCStage3EpisodeSectionMagic};
    uint16_t version{kRCStage3EpisodeSectionVersion};
    RCStage3RelationRole role{};
    RCStage3EpisodeEngine engine{};
    uint64_t covered_obligations{0};
    /** Domain-separated commitment to the complete outer public statement. */
    uint256 statement_commitment{};
    /** Canonical engine-specific proof bytes.  Native witness bytes are never
     * accepted as a complete proof by this module. */
    std::vector<unsigned char> payload;

    bool operator==(const RCStage3EpisodeRelationProof&) const = default;
};

struct RCStage3EpisodeRelationGap {
    RCStage3RelationRole role{};
    uint64_t missing_obligations{0};
    std::string reason;
};

struct RCStage3EpisodeProveResult {
    bool ok{false};
    std::string note;
    std::vector<RCStage3Commitment> commitments;
    std::vector<RCStage3ProofSection> sections;
    std::vector<RCStage3EpisodeRelationGap> gaps;
};

[[nodiscard]] bool IsRCStage3EpisodeRole(RCStage3RelationRole role);
[[nodiscard]] uint64_t RequiredRCStage3EpisodeCoverage(RCStage3RelationRole role);
[[nodiscard]] const char* RCStage3EpisodeEngineName(RCStage3EpisodeEngine engine);

/** Commitment to statement kind plus the pre-proof public inputs, using the
 * repository's existing SHA256d primitive and fixed little-endian framing.
 * transcript_commitment is intentionally excluded: it is computed from the
 * finished relation sections and including it here would create a fixed point. */
[[nodiscard]] uint256
RCStage3EpisodeStatementCommitment(const RCStage3SuccinctProof& statement);

/** Commitment expected in the outer RCStage3Commitment for an exact canonical
 * inner section. */
[[nodiscard]] uint256
RCStage3EpisodeSectionCommitment(const std::vector<unsigned char>& canonical_section);

/** Canonical typed inner codec.  Decoder rejects unknown roles/engines, unknown
 * obligation bits, oversize claims, reserved-byte mutations, and trailing
 * bytes. */
[[nodiscard]] bool
EncodeRCStage3EpisodeRelationProof(const RCStage3EpisodeRelationProof& proof,
                                   std::vector<unsigned char>& out,
                                   std::string* why = nullptr);
[[nodiscard]] bool
DecodeRCStage3EpisodeRelationProof(const std::vector<unsigned char>& bytes,
                                   RCStage3EpisodeRelationProof& out,
                                   std::string* why = nullptr);

/** Validate all six typed inner sections and their outer commitment/public
 * statement bindings.  This is structural/binding validation, not proof
 * verification, and is exposed separately to prevent callers confusing the
 * two. */
[[nodiscard]] bool
ValidateRCStage3EpisodeRelationBindings(
    const RCStage3SuccinctProof& proof,
    std::vector<RCStage3EpisodeRelationProof>* decoded = nullptr,
    std::string* why = nullptr);

/** Typed prover adapter.  It will not manufacture authority sections from
 * partial/native artifacts.  Until a complete engine exists it returns
 * ok=false, empty output sections, and the exact six-role gap report. */
[[nodiscard]] RCStage3EpisodeProveResult
ProveRCStage3EpisodeRelations(
    const RCStage3SuccinctProof& statement,
    const std::vector<RCStage3EpisodeRelationProof>& relation_proofs);

/** Consensus-facing episode authority verifier.  Coupled-only statements are
 * rejected.  Episode/Composed statements can pass only after every required
 * obligation of all six roles is verified by a complete proof-only engine. */
[[nodiscard]] bool
VerifyRCStage3EpisodeRelations(const RCStage3SuccinctProof& proof,
                               std::string* why = nullptr);

[[nodiscard]] std::vector<RCStage3EpisodeRelationGap>
CurrentRCStage3EpisodeRelationGaps();

/**
 * MEASURED — not a hardcoded literal disconnected from the tree.
 *
 * src/test/matmul_v4_rc_stage3_episode_recursion_prototype_tests.cpp drives
 * each role's real C_rho through a REAL child air_quotient::AirQuotientProve/
 * Verify FRI proof, a REAL air_recurse::ProveAggregate/VerifyAggregate (k=1)
 * recursion root, and AssessRCStage3RecursiveReadiness, and asserts
 * `constraints_resolved && backend_shape_supported` for that genuine
 * instance. That is exactly the condition the corresponding Gaps() entries
 * name ("recursive child proof engines are ... executed" / "no complete
 * recursive hash/stream proof" / etc.) — it is no longer honest to list those
 * role-specific obligations as missing once the matching flag is true.
 *
 * These flags do NOT mean the roles are consensus-ready. On the identical
 * carriers, VerifyRCStage3RecursiveProof still (correctly) fails closed on
 * the shared cross-lane authority gates (ChildFiatShamirReplayNotClosed,
 * SelfSimilarFixedPointNotClosed, ProductionPerformanceUnmeasured,
 * AuthorityDisabled — see matmul_v4_rc_stage3_recursive.h), which are
 * tracked independently by the global soundness ledger's own g2/g4 gates and
 * cannot be closed by any episode-only change.
 *
 * Flip a flag back to false immediately if its prototype test regresses.
 * kRCStage3EpisodeRelationsReady may be true only when Gaps().empty().
 */
inline constexpr bool kRCStage3EpisodeGemmRecursionEnginesExecuted = true;
inline constexpr bool kRCStage3EpisodeTileTreeRecursionEnginesExecuted = true;
inline constexpr bool kRCStage3EpisodeDigestRecursionEnginesExecuted = true;
inline constexpr bool kRCStage3EpisodeBuilderRecursionEnginesExecuted = false;
inline constexpr bool kRCStage3EpisodeExtractRecursionEnginesExecuted = false;
inline constexpr bool kRCStage3EpisodeWiringRecursionEnginesExecuted = false;

/** Separate readiness predicate for root composition.  It is false while any
 * complete proof binding is absent, independent of envelope structure. */
inline constexpr bool kRCStage3EpisodeRelationsReady = false;
[[nodiscard]] constexpr bool RCStage3EpisodeRelationsReady()
{
    return kRCStage3EpisodeRelationsReady;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_H
