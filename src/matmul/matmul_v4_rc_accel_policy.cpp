// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_accel_policy.h>

#include <sstream>

namespace matmul::v4::rc {

RCCoupConsensusConfig MakeDefaultRCCoupConsensusConfig()
{
    return RCCoupConsensusConfig{};
}

bool IsRCCoupConsensusConfigV1Compatible(const RCCoupConsensusConfig& cfg)
{
    const RCCoupParams toy = MakeToyRCCoupParams();
    return cfg.config_version == kRCCoupConsensusConfigVersionV1 &&
           cfg.barriers == toy.barriers && cfg.lobes == toy.lobes &&
           cfg.lobe_width == toy.lobe_width && cfg.bank_pages == toy.bank_pages &&
           cfg.pages_per_barrier_lobe == 1u &&
           cfg.page_selection_version == kRCCoupPageSelectionLegacyV1 &&
           !cfg.material_exchange_enabled &&
           cfg.transcript_version == kRCTranscriptVersion &&
           cfg.extract_version == kRCExtractVersionV1 && cfg.seg_len == kRCSegLen &&
           cfg.wgrad_exact_chunk == kRCWgradExactChunk &&
           cfg.tile_leaf_bytes == kRCTileLeafBytes && cfg.mx_block_len == kRCMxBlockLen &&
           cfg.mx_packed_layout_version == kRCMxPackedLayoutVersionV1 &&
           !cfg.full_bank_schedule_enabled && !cfg.v2_profile_enabled &&
           cfg.v2_activation_height == std::numeric_limits<int32_t>::max();
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

} // namespace matmul::v4::rc
