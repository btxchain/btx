// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_AIR_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_episode.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ============================================================================
// Stage-3 episode proof-only AIR adapter (research seam, authority unchanged).
//
// This registry exposes the relation fragments that can already be checked
// from committed Fp3 columns plus an AIR proof.  It never accepts native
// RCGkrV7 witness vectors and never reconstructs an episode.  The public pin
// commits every trace-column root. The external AIR seed binds only the
// proof-independent statement and shard shape; the existing two-epoch
// RcSampler transcript then absorbs base roots into gamma/alpha and all trace
// roots into the quotient/FRI challenges. This avoids a challenge/root fixed
// point for the gamma-dependent LogUp columns.
//
// The registry is deliberately partial:
//   * GEMM: only the final endpoint identity gf = a*b;
//   * Extract: the existing RcSampler low-degree core;
//   * Wiring: direct row equality only.
//
// The sibling stage3_gemm_extract module now supplies an exact Λ-derived
// all-layer/all-tile manifest and an executable signed-accumulator range AIR.
// They are not counted here until CTL links their columns/recursive roots to
// these shards. Builder, complete GEMM operand openings, ChaCha/scale proof,
// execution of the all-tile recursive roots, transpose/ordering wiring,
// tile-tree SHA, digest composition, recursive aggregation, and a canonical
// proof-payload codec remain gaps. Therefore this module can validate research
// shards but cannot make any of the six Stage-3 episode roles complete.
// ============================================================================

namespace matmul::v4::rc {

inline constexpr uint32_t kRCStage3EpisodeAirPinMagic = 0x33415045U; // "EPA3"
inline constexpr uint16_t kRCStage3EpisodeAirPinVersion = 1;
inline constexpr uint16_t kRCStage3EpisodeAirRegistryVersion = 1;
inline constexpr uint32_t kRCStage3EpisodeAirMaxPinnedColumns = 64;
inline constexpr uint32_t kRCStage3EpisodeAirMaxShards = 1U << 20;

enum class RCStage3EpisodeAirFamily : uint8_t {
    GemmEndpointFp3V1 = 1,
    ExtractSamplerCoreFp3V1 = 2,
    WiringEqualityFp3V1 = 3,
};

struct RCStage3EpisodeAirColumnPin {
    uint32_t column{0};
    uint256 root{};

    bool operator==(const RCStage3EpisodeAirColumnPin&) const = default;
};

/**
 * Proof-independent public input of one AIR shard.
 *
 * column_roots must contain every trace column in ascending order.  They are
 * commitments, not witness values; the verifier compares them to the roots
 * carried by the AIR proof before running the quotient verifier.
 */
struct RCStage3EpisodeAirPublicPin {
    uint32_t magic{kRCStage3EpisodeAirPinMagic};
    uint16_t version{kRCStage3EpisodeAirPinVersion};
    uint16_t registry_version{kRCStage3EpisodeAirRegistryVersion};
    RCStage3RelationRole role{};
    RCStage3EpisodeAirFamily family{};
    uint256 statement_commitment{};
    uint32_t shard_index{0};
    uint32_t shard_count{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint32_t n_coeffs{0};
    /** ExtractSamplerCore only; zero for every other family. */
    uint8_t extract_scale_e{0};
    std::vector<RCStage3EpisodeAirColumnPin> column_roots;

    bool operator==(const RCStage3EpisodeAirPublicPin&) const = default;
};

struct RCStage3EpisodeAirCapability {
    RCStage3RelationRole role{};
    RCStage3EpisodeAirFamily family{};
    uint64_t locally_enforced_obligations{0};
    bool proof_only{true};
    bool complete_role{false};
    const char* detail{nullptr};
};

[[nodiscard]] const char*
RCStage3EpisodeAirFamilyName(RCStage3EpisodeAirFamily family);

/** Immutable registry entries in canonical (role, family) order. */
[[nodiscard]] std::vector<RCStage3EpisodeAirCapability>
CurrentRCStage3EpisodeAirCapabilities();

/**
 * Canonical relation source for the migrated local kernels.  GEMM, Wiring, and
 * Extract are all available: Extract returns the full RcSampler relation as
 * challenge-independent bytecode (via the shared RcSampler kernel, committed
 * under the EpisodeExtract role) at the canonical scale_e=0. The C_rho-
 * assembling lane calls BuildRCStage3EpisodeExtractLocalKernelProgramTable
 * directly for other public scale exponents.
 */
[[nodiscard]] bool BuildRCStage3EpisodeLocalKernelProgramTable(
    RCStage3EpisodeAirFamily family,
    constraint_bytecode::ProgramTable& out,
    std::string* why = nullptr);

/** Canonical bounded pin codec. Unknown ids, non-sequential/null roots,
 * reserved bytes, inconsistent shapes, and trailing bytes are rejected. */
[[nodiscard]] bool SerializeRCStage3EpisodeAirPublicPin(
    const RCStage3EpisodeAirPublicPin& pin,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3EpisodeAirPublicPin>
DeserializeRCStage3EpisodeAirPublicPin(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);

/** Commitment to the complete canonical public pin, including every trace
 * root. It is suitable for the outer section/manifest commitment, but is not
 * itself the AIR base seed because Extract LogUp roots are challenge-derived. */
[[nodiscard]] uint256
ComputeRCStage3EpisodeAirPinCommitment(
    const RCStage3EpisodeAirPublicPin& pin);

/** AIR Fiat-Shamir base seed: Stage-3 episode statement plus canonical shard
 * shape, excluding trace roots. RcSampler absorbs base roots in its existing
 * epoch-1 challenge and AirQuotient absorbs all trace roots afterward. */
[[nodiscard]] uint256 ComputeRCStage3EpisodeAirSeed(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeAirPublicPin& pin);

/**
 * Resolve the immutable AIR constraint system for a registered family.
 *
 * ExtractSamplerCore delegates to BuildRcSamplerConstraintSystem<Fp3> and
 * derives its gamma/alpha exactly as the existing RcSampler verifier does.
 */
[[nodiscard]] bool ResolveRCStage3EpisodeAirConstraintSystem(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeAirPublicPin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

struct RCStage3EpisodeAirReadiness {
    bool structurally_valid{false};
    bool constraint_system_resolved{false};
    bool proof_only{true};
    bool role_complete{false};
    uint64_t locally_enforced_obligations{0};
    uint64_t missing_obligations{0};
    std::vector<std::string> gaps;
};

/** Exact readiness report for one public pin. It never runs a prover. */
[[nodiscard]] RCStage3EpisodeAirReadiness
AssessRCStage3EpisodeAirReadiness(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeAirPublicPin& pin);

/**
 * Verify one registered research shard using only its public pin and AIR
 * proof. Success means that fragment is valid; it does not mean the owning
 * Stage-3 role or episode is complete.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeAirShard(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeAirPublicPin& pin,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

struct RCStage3EpisodeAirRoleGap {
    RCStage3RelationRole role{};
    uint64_t locally_enforced_obligations{0};
    uint64_t missing_obligations{0};
    std::string reason;
};

/** One exact entry for each of the six registered episode roles. */
[[nodiscard]] std::vector<RCStage3EpisodeAirRoleGap>
CurrentRCStage3EpisodeAirRoleGaps();

inline constexpr bool kRCStage3EpisodeAirRegistryComplete = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_EPISODE_AIR_H
