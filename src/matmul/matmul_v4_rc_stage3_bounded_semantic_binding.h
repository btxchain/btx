// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_BOUNDED_SEMANTIC_BINDING_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_BOUNDED_SEMANTIC_BINDING_H

#include <matmul/matmul_v4_rc_stage3_bounded_semantic_composition.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace matmul::v4::rc {

inline constexpr uint32_t
    kRCStage3BoundedSemanticBindingMagic = 0x31425342U; // "BSB1"
inline constexpr uint16_t
    kRCStage3BoundedSemanticBindingVersion = 1;
inline constexpr uint16_t
    kRCStage3BoundedSemanticBindingRecordCount = 23;

/**
 * Fixed registry for the proof-owned identities consumed by the bounded
 * semantic verifier. Values are a durable format ABI and must not be reused.
 */
enum class RCStage3BoundedSemanticSidecarId : uint16_t {
    PublicComposition = 1,
    EpisodeSeedChain = 2,
    EpisodeOperandXof = 3,
    EpisodeBuilderTrace = 4,
    EpisodeGemmExtractManifest = 5,
    EpisodeGemm = 6,
    EpisodeSignedRange = 7,
    EpisodeExtract = 8,
    EpisodeTileStream = 9,
    EpisodeWiring = 10,
    EpisodeDigestRootChain = 11,
    EpisodeRoundRootProducers = 12,
    EpisodeHeaderTarget = 13,
    EpisodePow = 14,
    CoupledBank = 15,
    CoupledBankRoot = 16,
    CoupledInitialState = 17,
    CoupledGemm = 18,
    CoupledSignedRange = 19,
    CoupledExchangePermutation = 20,
    CoupledMix = 21,
    CoupledExtract = 22,
    CoupledRootChain = 23,
};

struct RCStage3BoundedSemanticBindingRecord {
    RCStage3BoundedSemanticSidecarId id{};
    uint256 root{};

    bool operator==(
        const RCStage3BoundedSemanticBindingRecord&) const = default;
};

/**
 * Canonical commitment manifest for all typed inputs of
 * VerifyRCStage3BoundedSemanticComposition.
 *
 * The manifest is carried inside the CompositionLink section, whose outer
 * commitment root is the manifest commitment. The ordinary Stage-3
 * transcript therefore binds the manifest bytes and root.
 *
 * This is a durable *binding* for an externally supplied typed composition,
 * not serialization of the large child proofs themselves. A verifier still
 * needs the typed sidecar object; authority and durable-serialization flags
 * remain false.
 */
struct RCStage3BoundedSemanticBindingManifest {
    uint32_t magic{kRCStage3BoundedSemanticBindingMagic};
    uint16_t version{kRCStage3BoundedSemanticBindingVersion};
    uint256 statement_commitment{};
    std::vector<RCStage3BoundedSemanticBindingRecord> records;
    uint256 manifest_commitment{};

    bool operator==(
        const RCStage3BoundedSemanticBindingManifest&) const = default;
};

[[nodiscard]] uint256 ComputeRCStage3BoundedSemanticBindingCommitment(
    const RCStage3BoundedSemanticBindingManifest& manifest);

[[nodiscard]] bool BuildRCStage3BoundedSemanticBindingManifest(
    const RCStage3SuccinctProof& statement,
    const RCStage3BoundedSemanticComposition& composition,
    RCStage3BoundedSemanticBindingManifest& out,
    std::string* why = nullptr);

[[nodiscard]] bool SerializeRCStage3BoundedSemanticBindingManifest(
    const RCStage3BoundedSemanticBindingManifest& manifest,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);

[[nodiscard]] std::optional<RCStage3BoundedSemanticBindingManifest>
DeserializeRCStage3BoundedSemanticBindingManifest(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);

/**
 * Preserve the pre-existing CompositionLink payload inside a canonical
 * envelope and attach the binding manifest. This updates only the
 * CompositionLink outer root/section and the transcript commitment.
 */
[[nodiscard]] bool AttachRCStage3BoundedSemanticBinding(
    RCStage3SuccinctProof& statement,
    const RCStage3BoundedSemanticComposition& composition,
    std::string* why = nullptr);

/**
 * Check exact envelope bytes, manifest order/commitment, CompositionLink
 * outer root, transcript binding, and equality to the supplied typed
 * composition identities.
 */
[[nodiscard]] bool VerifyRCStage3BoundedSemanticBinding(
    const RCStage3SuccinctProof& statement,
    const RCStage3BoundedSemanticComposition& composition,
    std::string* why = nullptr);

inline constexpr bool
    kRCStage3BoundedSemanticCompositionDurablyCommitmentBound = true;
static_assert(
    !kRCStage3BoundedSemanticCompositionDurablySerialized);
static_assert(
    !kRCStage3BoundedSemanticCompositionAuthorityReady);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_BOUNDED_SEMANTIC_BINDING_H
