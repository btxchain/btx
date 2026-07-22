// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_ACCEL_POLICY_H
#define BTX_MATMUL_MATMUL_V4_RC_ACCEL_POLICY_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_extract.h>

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

// ENC_RC / ENC_RC_COUPLED — shared native-first mining interface freeze (WS0).
//
// Policy, provenance, lane IDs, exactness-qualification cache keys, and a
// versioned coupled consensus configuration. No backends. Heights stay
// INT32_MAX. GKR arbiter stays OFF. V1 defaults match the current toy/legacy
// coupled path; V3 production fields are selected only once the public coupled
// activation height is deliberately made finite.

namespace matmul::v4::rc {

/** Mining execution policy (compute path only; never consensus-oracle). */
enum class RCAccelerationPolicy : uint8_t {
    /** Default for accelerator mining: genuinely native tensor lane required. */
    NativeRequired = 0,
    /** Opt-in portable/legacy participation; never auto-selected as native. */
    PortableExplicit = 1,
};

/** Distinct compute-lane identifiers (native ≠ portable ≠ dense INT8 legacy). */
enum class RCComputeLaneId : uint8_t {
    NativeMxfp4 = 0,
    NativeFp8 = 1,
    NativeBf16 = 2,
    NativeFp16 = 3,
    PortableReference = 4,
    DenseInt8Legacy = 5,
};

/**
 * Residency / packing mode recorded in provenance (NON-consensus). Digest must
 * match across Packed / Resident / Streamed when the committed work is identical.
 */
enum class RCAccelResidencyMode : uint8_t {
    Packed = 0,
    Resident = 1,
    Streamed = 2,
};

/** Default mining policy for accelerators. */
inline constexpr RCAccelerationPolicy kRCAccelerationPolicyDefault =
    RCAccelerationPolicy::NativeRequired;

/**
 * Execution result / provenance snapshot for a mining attempt.
 * Filled by later workstreams; WS0 freezes the shape only.
 */
struct RCAccelerationProvenance {
    std::string provider;                 // vendor / backend name
    std::string device_uuid;              // physical UUID / PCI identity
    std::string arch;                     // e.g. sm_120, gfx950
    std::string runtime_version;          // CUDA/ROCm/Metal runtime
    std::string compiler_version;         // nvcc / hipcc / metalc …
    std::string library_version;          // cuBLASLt / hipBLASLt / …
    RCComputeLaneId requested_lane{RCComputeLaneId::PortableReference};
    RCComputeLaneId executed_lane{RCComputeLaneId::PortableReference};
    std::string native_instruction_evidence; // algorithm / ISA / library algo id
    std::string exactness_qual_key;          // BuildExactnessQualCacheKey(...)
    std::string qual_dims;                   // live shape string used at qual time
    RCAccelResidencyMode residency_mode{RCAccelResidencyMode::Streamed};
    uint32_t device_count{0};
    std::string fabric; // e.g. nvlink / xgmi / pcie / empty
    bool no_host_fallback{false};
    bool no_dense_int8_fallback{false};
    std::string failure_reason;
};

/** Packed MX layout version pin for qualification keys (V1 = current helpers). */
inline constexpr uint32_t kRCMxPackedLayoutVersionV1 = 1;
inline constexpr uint32_t kRCMxPackedLayoutVersion = kRCMxPackedLayoutVersionV1;

/** ExtractMX alphabet/version pin (V1 = current int64 ExtractMXTileInt64). */
inline constexpr uint32_t kRCExtractVersionV1 = 1;
inline constexpr uint32_t kRCExtractVersion = kRCExtractVersionV1;

/** Page-selection algorithm versions (coupled bank). */
inline constexpr uint32_t kRCCoupPageSelectionLegacyV1 = 1; // (barrier+lobe)%bank_pages
inline constexpr uint32_t kRCCoupPageSelectionFullBankV2 = 2;
inline constexpr uint32_t kRCCoupPageSelectionFullBankV3 = 3; // 24 pages/slot, M=128

inline constexpr uint32_t kRCCoupConsensusConfigVersionV1 = 1;
inline constexpr uint32_t kRCCoupConsensusConfigVersionV2 = 2;
inline constexpr uint32_t kRCCoupConsensusConfigVersionV3 = 3;

/**
 * Versioned coupled consensus configuration — every digest-affecting knob.
 *
 * Default = V3 AI datacenter thesis (1536/24/M=128, packed ≈51 GiB /
 * expanded int8 96 GiB, exchange_rounds=4). Heights stay INT32_MAX; changing
 * activation height is the separate public consensus decision.
 *
 * Shape fields rows_per_lobe / pages_per_barrier_lobe MUST be projected by
 * RCCoupParamsFromConsensusConfig (F8). Regtest selects the live consensus
 * family via Consensus::Params::nMatMulRCCoupledProfile ×
 * fMatMulRCCoupledUseToyDims (see ResolveRCCoupParams); this descriptor is the
 * non-consensus policy/golden-diff view, not the resolver.
 */
struct RCCoupConsensusConfig {
    uint32_t config_version{kRCCoupConsensusConfigVersionV3};

    // Shape — V3 MakeProductionV3RCCoupParams() (expanded 96 GiB / packed ≈51 GiB).
    uint32_t barriers{8};
    uint32_t lobes{8};
    uint32_t lobe_width{8192};
    uint32_t bank_pages{1536};
    uint32_t rows_per_lobe{128};

    // Page schedule — full bank (24 pages / barrier×lobe).
    uint32_t pages_per_barrier_lobe{dc::kRCCoupPagesPerBarrierLobeV3};
    uint32_t page_selection_version{kRCCoupPageSelectionFullBankV3};

    // Material exchange ON — fabric domain in mix.
    bool material_exchange_enabled{dc::kRCCoupMaterialExchangeEnabled};
    uint32_t material_exchange_rows{dc::kRCCoupExchangeRowsDefault};
    uint32_t material_exchange_rounds{4};
    uint32_t material_exchange_cols{8192};

    // Transcript / Extract / segmentation.
    uint32_t transcript_version{kRCTranscriptVersion};
    uint32_t extract_version{kRCExtractVersionV1};
    uint32_t seg_len{kRCSegLen};
    uint32_t wgrad_exact_chunk{kRCWgradExactChunk};
    uint32_t tile_leaf_bytes{kRCTileLeafBytes};
    uint32_t mx_block_len{kRCMxBlockLen};
    uint32_t mx_packed_layout_version{kRCMxPackedLayoutVersionV1};

    // Full-bank schedule ON.
    bool full_bank_schedule_enabled{dc::kRCCoupFullBankScheduleEnabled};
    uint32_t v2_pages_per_barrier_lobe{dc::kRCCoupPagesPerBarrierLobe};

    // V3 profile selected; activation height stays INT32_MAX (public inert).
    bool v3_profile_enabled{true};
    int32_t v3_activation_height{std::numeric_limits<int32_t>::max()};
};

/** Default consensus config — AI datacenter levers (production + full-bank). */
[[nodiscard]] RCCoupConsensusConfig MakeDefaultRCCoupConsensusConfig();

/** Frozen toy/legacy V1 config (single-page, exchange off) for golden diffs. */
[[nodiscard]] RCCoupConsensusConfig MakeLegacyV1RCCoupConsensusConfig();

/**
 * V3 hypothesis consensus config (heights INT32_MAX). Sets config_version=3,
 * transcript_version=ENC_RC_V3, production V3 shape knobs. Does not activate.
 */
[[nodiscard]] RCCoupConsensusConfig MakeProductionV3RCCoupConsensusConfig();
/**
 * True iff cfg matches the frozen V1 toy/legacy digest-affecting defaults
 * (shape, single-page schedule, exchange off, transcript/extract V1, V3 inert).
 */
[[nodiscard]] bool IsRCCoupConsensusConfigV1Compatible(const RCCoupConsensusConfig& cfg);

/**
 * Map consensus config shape fields onto RCCoupParams.
 */
[[nodiscard]] RCCoupParams RCCoupParamsFromConsensusConfig(const RCCoupConsensusConfig& cfg);

/**
 * Map consensus config exchange/schedule fields onto RCCoupOptions.
 */
[[nodiscard]] RCCoupOptions RCCoupOptionsFromConsensusConfig(const RCCoupConsensusConfig& cfg);

/**
 * Qualification cache key:
 *   provider + arch + runtime + compiler + library + profile_version +
 *   dims + layout_version
 *
 * Canonical form (pipe-separated, no whitespace trimming of components):
 *   {provider}|{arch}|{runtime}|{compiler}|{library}|{profile_version}|{dims}|{layout_version}
 */
[[nodiscard]] std::string BuildExactnessQualCacheKey(
    std::string_view provider, std::string_view arch, std::string_view runtime_version,
    std::string_view compiler_version, std::string_view library_version,
    uint32_t profile_version, std::string_view dims, uint32_t layout_version);

[[nodiscard]] const char* ToString(RCAccelerationPolicy policy);
[[nodiscard]] const char* ToString(RCComputeLaneId lane);
[[nodiscard]] const char* ToString(RCAccelResidencyMode mode);

/**
 * Resolve mining acceleration policy.
 * Default: NativeRequired (kRCAccelerationPolicyDefault).
 * Opt-in portable/legacy INT8 inject: BTX_RC_ACCEL_POLICY=portable|PortableExplicit.
 * Under NativeRequired the central ExactGemm resolver must NOT fall through to
 * dense device INT8 when native MX is unavailable.
 */
[[nodiscard]] RCAccelerationPolicy ResolveRCAccelerationPolicy();

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_ACCEL_POLICY_H
