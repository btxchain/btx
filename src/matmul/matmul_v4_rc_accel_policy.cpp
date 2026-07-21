// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_accel_policy.h>

#include <cstdlib>
#include <limits>
#include <sstream>
#include <string>

namespace matmul::v4::rc {

RCCoupConsensusConfig MakeDefaultRCCoupConsensusConfig()
{
    // Aggregate default-initialized production / AI-lever config.
    return RCCoupConsensusConfig{};
}

RCCoupConsensusConfig MakeLegacyV1RCCoupConsensusConfig()
{
    RCCoupConsensusConfig cfg;
    cfg.config_version = kRCCoupConsensusConfigVersionV1;
    const RCCoupParams toy = MakeToyRCCoupParams();
    cfg.barriers = toy.barriers;
    cfg.lobes = toy.lobes;
    cfg.lobe_width = toy.lobe_width;
    cfg.bank_pages = toy.bank_pages;
    cfg.pages_per_barrier_lobe = 1;
    cfg.page_selection_version = kRCCoupPageSelectionLegacyV1;
    cfg.material_exchange_enabled = false;
    cfg.material_exchange_rows = dc::kRCCoupExchangeRowsDefault;
    cfg.material_exchange_cols = kRCCoupLobeWidth;
    cfg.full_bank_schedule_enabled = false;
    cfg.v2_pages_per_barrier_lobe = dc::kRCCoupPagesPerBarrierLobe;
    cfg.v2_profile_enabled = false;
    cfg.v2_activation_height = std::numeric_limits<int32_t>::max();
    return cfg;
}

bool IsRCCoupConsensusConfigV1Compatible(const RCCoupConsensusConfig& cfg)
{
    const RCCoupConsensusConfig legacy = MakeLegacyV1RCCoupConsensusConfig();
    return cfg.config_version == legacy.config_version &&
           cfg.barriers == legacy.barriers && cfg.lobes == legacy.lobes &&
           cfg.lobe_width == legacy.lobe_width && cfg.bank_pages == legacy.bank_pages &&
           cfg.pages_per_barrier_lobe == legacy.pages_per_barrier_lobe &&
           cfg.page_selection_version == legacy.page_selection_version &&
           cfg.material_exchange_enabled == legacy.material_exchange_enabled &&
           cfg.transcript_version == legacy.transcript_version &&
           cfg.extract_version == legacy.extract_version && cfg.seg_len == legacy.seg_len &&
           cfg.wgrad_exact_chunk == legacy.wgrad_exact_chunk &&
           cfg.tile_leaf_bytes == legacy.tile_leaf_bytes &&
           cfg.mx_block_len == legacy.mx_block_len &&
           cfg.mx_packed_layout_version == legacy.mx_packed_layout_version &&
           cfg.full_bank_schedule_enabled == legacy.full_bank_schedule_enabled &&
           cfg.v2_profile_enabled == legacy.v2_profile_enabled &&
           cfg.v2_activation_height == legacy.v2_activation_height;
}

RCCoupParams RCCoupParamsFromConsensusConfig(const RCCoupConsensusConfig& cfg)
{
    RCCoupParams p;
    p.barriers = cfg.barriers;
    p.lobes = cfg.lobes;
    p.lobe_width = cfg.lobe_width;
    p.bank_pages = cfg.bank_pages;
    return p;
}

std::string BuildExactnessQualCacheKey(std::string_view provider, std::string_view arch,
                                       std::string_view runtime_version,
                                       std::string_view compiler_version,
                                       std::string_view library_version,
                                       uint32_t profile_version, std::string_view dims,
                                       uint32_t layout_version)
{
    std::ostringstream os;
    os << provider << '|' << arch << '|' << runtime_version << '|' << compiler_version << '|'
       << library_version << '|' << profile_version << '|' << dims << '|' << layout_version;
    return os.str();
}

const char* ToString(RCAccelerationPolicy policy)
{
    switch (policy) {
    case RCAccelerationPolicy::NativeRequired:
        return "NativeRequired";
    case RCAccelerationPolicy::PortableExplicit:
        return "PortableExplicit";
    }
    return "Unknown";
}

const char* ToString(RCComputeLaneId lane)
{
    switch (lane) {
    case RCComputeLaneId::NativeMxfp4:
        return "NativeMxfp4";
    case RCComputeLaneId::NativeFp8:
        return "NativeFp8";
    case RCComputeLaneId::NativeBf16:
        return "NativeBf16";
    case RCComputeLaneId::NativeFp16:
        return "NativeFp16";
    case RCComputeLaneId::PortableReference:
        return "PortableReference";
    case RCComputeLaneId::DenseInt8Legacy:
        return "DenseInt8Legacy";
    }
    return "Unknown";
}

const char* ToString(RCAccelResidencyMode mode)
{
    switch (mode) {
    case RCAccelResidencyMode::Packed:
        return "Packed";
    case RCAccelResidencyMode::Resident:
        return "Resident";
    case RCAccelResidencyMode::Streamed:
        return "Streamed";
    }
    return "Unknown";
}

RCAccelerationPolicy ResolveRCAccelerationPolicy()
{
    const char* e = std::getenv("BTX_RC_ACCEL_POLICY");
    if (e != nullptr) {
        const std::string v{e};
        if (v == "portable" || v == "PortableExplicit" || v == "PORTABLE") {
            return RCAccelerationPolicy::PortableExplicit;
        }
    }
    return kRCAccelerationPolicyDefault;
}

} // namespace matmul::v4::rc
