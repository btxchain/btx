// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_H

#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ============================================================================
// ENC_RC Stage 3 — proof-only consensus envelope (FOUNDATION, authority OFF).
//
// This module deliberately does not promote the existing sampled carrier,
// witness-carrying RCGkrProofV7, compact verifier, or native-grounded coupled
// verifier. It defines the canonical, bounded object that a future COMPLETE
// proof-only verifier must consume:
//
//   * public statement bindings only;
//   * one fixed-role commitment and proof section per complete relation;
//   * no raw episode/coupled witness columns;
//   * no timings, notes, callbacks, environment switches, or cache handles;
//   * a canonical word packing for CBlock::matrix_c_data, which is already
//     serialized on the block wire and to blk*.dat.
//
// The relation-role registry is intentionally exhaustive. A composed proof is
// structurally incomplete if either the episode leg, the coupled leg, or the
// explicit link relation is absent. Structural validity is NOT mathematical
// proof validity: the eventual verifier must verify every registered section.
//
// Consensus authority remains hard-disabled by
// kRCStage3SuccinctAuthorityReady. Do not flip it until the proof-only
// implementations for every role are complete, production-sized, independently
// reviewed, and verified without exact replay/native witness reconstruction.
// ============================================================================

namespace matmul::v4::rc {

inline constexpr uint32_t kRCStage3ProofMagic = 0x33534352U; // bytes: "RCS3"
inline constexpr uint16_t kRCStage3ProofVersion = 2;
inline constexpr uint32_t kRCStage3BlockPayloadMagic = 0x33505442U; // bytes: "BTP3"
inline constexpr uint16_t kProductionProgramConsensusPinVersionV1 = 1;

/** Leaves room under the 24 MB consensus block cap for transactions/framing. */
inline constexpr size_t kRCStage3MaxProofBytes = 16U * 1024U * 1024U;
inline constexpr uint16_t kRCStage3MaxRelationSections = 32;

/** Orthogonal to workload/profile selection. A sampled prefilter is never a
 * complete-proof authority. */
enum class RCProofAuthority : uint8_t {
    ExactReplay = 1,
    SampledPrefilter = 2,
    SuccinctV1 = 3,
};

enum class RCStage3StatementKind : uint8_t {
    Episode = 1,
    Coupled = 2,
    Composed = 3,
};

/** Fixed constraint-registry identifiers. Values are consensus-format ABI and
 * must never be reused with different semantics. */
enum class RCStage3RelationRole : uint16_t {
    EpisodeDeterministicBuilder = 1,
    EpisodeGemm = 2,
    EpisodeExtract = 3,
    EpisodeWiring = 4,
    EpisodeTileTree = 5,
    EpisodeDigest = 6,

    CoupledBank = 16,
    CoupledGemm = 17,
    CoupledExchange = 18,
    CoupledPermutation = 19,
    CoupledMix = 20,
    CoupledExtract = 21,
    CoupledBarrier = 22,
    CoupledDigest = 23,

    CompositionLink = 32,
};

/**
 * Consensus/public-input projection of the immutable ProgramTable registry.
 *
 * `recursive_alg_hash_root` is the sole verifying-key/program authority. It
 * is the canonical little-endian packing of four Goldilocks field elements;
 * encodings with a limb >= p are rejected. The SHA256d root is carried only
 * for external audit and transport diagnostics and is never an alternate
 * authority.
 */
struct ProductionProgramConsensusPinV1 {
    uint16_t version{kProductionProgramConsensusPinVersionV1};
    uint256 recursive_alg_hash_root{};
    uint256 external_sha256d_audit_root{};
    /** SHA256d commitment to the manifest/schedule/registry pin tuple. */
    uint256 registry_binding{};

    bool operator==(const ProductionProgramConsensusPinV1&) const = default;
};

struct RCStage3PublicInputs {
    int32_t height{0};
    uint32_t n_bits{0};
    uint32_t episode_profile{0};
    uint32_t coupled_profile{0};
    uint32_t transcript_version{0};

    ProductionProgramConsensusPinV1 program_consensus_pin{};

    /** Commitment to the canonical header projection used by the statement. */
    uint256 header_commitment{};
    /** Commitment to every resolved episode/coupled shape and option. */
    uint256 params_commitment{};
    /** Exact target encoded as a canonical 256-bit integer. */
    uint256 target{};
    uint256 sigma{};
    uint256 episode_digest{};
    uint256 coupled_digest{};
    uint256 final_digest{};
    /** Root of the fixed-order Stage-3 transcript after all primary roots. */
    uint256 transcript_commitment{};

    bool operator==(const RCStage3PublicInputs&) const = default;
};

/** Canonical pin validation shared by the wire codec and consensus params. */
[[nodiscard]] bool ValidateProductionProgramConsensusPinV1(
    const ProductionProgramConsensusPinV1& pin,
    std::string* why = nullptr);

struct RCStage3Commitment {
    RCStage3RelationRole role{};
    uint256 root{};

    bool operator==(const RCStage3Commitment&) const = default;
};

struct RCStage3ProofSection {
    RCStage3RelationRole role{};
    std::vector<unsigned char> proof;

    bool operator==(const RCStage3ProofSection&) const = default;
};

struct RCStage3SuccinctProof {
    uint32_t magic{kRCStage3ProofMagic};
    uint16_t version{kRCStage3ProofVersion};
    RCProofAuthority authority{RCProofAuthority::SuccinctV1};
    RCStage3StatementKind statement{RCStage3StatementKind::Composed};
    RCStage3PublicInputs public_inputs{};
    std::vector<RCStage3Commitment> commitments;
    std::vector<RCStage3ProofSection> sections;

    bool operator==(const RCStage3SuccinctProof&) const = default;
};

/** Canonical required-role list, in the only permitted wire order. */
[[nodiscard]] std::vector<RCStage3RelationRole>
RequiredRCStage3RelationRoles(RCStage3StatementKind statement);

[[nodiscard]] const char* RCStage3RelationRoleName(RCStage3RelationRole role);

/** Structural envelope validation only. Does not verify any mathematical
 * relation or commitment opening. */
[[nodiscard]] bool ValidateRCStage3ProofStructure(const RCStage3SuccinctProof& proof,
                                                  std::string* why = nullptr);

/** Canonical little-endian codec. Deserialization rejects unknown ids,
 * noncanonical ordering, oversized allocation claims, and trailing bytes. */
[[nodiscard]] bool SerializeRCStage3Proof(const RCStage3SuccinctProof& proof,
                                          std::vector<unsigned char>& out,
                                          std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3SuccinctProof>
DeserializeRCStage3Proof(const std::vector<unsigned char>& bytes,
                         std::string* why = nullptr);

/** Durable CBlock::matrix_c_data carriage:
 *   word[0] = kRCStage3BlockPayloadMagic
 *   word[1] = exact serialized-byte length
 *   word[2..] = little-endian bytes, zero-padded to uint32_t.
 * Exact word count and zero padding make the representation canonical. */
[[nodiscard]] bool PackRCStage3ProofWords(const RCStage3SuccinctProof& proof,
                                          std::vector<uint32_t>& out,
                                          std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3SuccinctProof>
UnpackRCStage3ProofWords(const std::vector<uint32_t>& words,
                         std::string* why = nullptr);

[[nodiscard]] bool IsRCStage3ProofWords(const std::vector<uint32_t>& words);

/** Tight raw-accumulator bounds for the pinned profile-2 operand range
 * [-48, 48]. These are relation design constants, not activation knobs. */
struct RCStage3Profile2AccumulatorBounds {
    int64_t qkt_abs_max{294'912};
    int64_t sv_abs_max{1'811'939'328};
    int64_t up_abs_max{9'437'184};
    int64_t down_residual_abs_max{37'748'784};
};

inline constexpr RCStage3Profile2AccumulatorBounds kRCStage3Profile2AccumulatorBounds{};
static_assert(kRCStage3Profile2AccumulatorBounds.sv_abs_max <= INT32_MAX);
static_assert(kRCStage3Profile2AccumulatorBounds.down_residual_abs_max <= INT32_MAX);

/** Compile-time authority gate. The envelope/codec/tests may land while this
 * remains false; no consensus path may accept Stage 3 while false. */
inline constexpr bool kRCStage3ProductionProgramRegistryReady = false;
inline constexpr bool kRCStage3SuccinctAuthorityReady = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_H
