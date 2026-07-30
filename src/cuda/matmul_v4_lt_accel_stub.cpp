// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_accel.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class CBlockHeader;

// No-CUDA build: the MatMul v4.4 ENC-DR-LT ("MatExpand") backend is
// unavailable, so every entry point declines. Callers fall back to the
// host ExactGemm / WindowSketchMinerLT fail-closed path
// (matmul::v4::lt::ComputeDigestBMX4CLT) — that host path is the safety net,
// not a complete device accelerator. Keeps the tree building without a CUDA
// toolkit when BTX_ENABLE_CUDA_EXPERIMENTAL is OFF.

namespace matmul_v4::cuda {

bool IsMatMulLTCudaAvailable()
{
    return false;
}

bool LaunchGemmS8S8(const std::vector<int8_t>&, const std::vector<int8_t>&,
                    uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

bool LaunchGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                     uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

bool LaunchProjectedRightMx(const std::vector<int8_t>&, const std::vector<uint8_t>&,
                            const std::vector<int8_t>&, uint32_t, uint32_t,
                            std::vector<int32_t>& out,
                            matmul::v4::lt::MxLaneProvenance* provenance)
{
    out.clear();
    if (provenance != nullptr) *provenance = {};
    return false;
}

bool ComputeDigestsOnlyLTCuda(const CBlockHeader& /*tmpl*/, uint32_t /*n*/,
                              const uint64_t* /*nonces*/, size_t /*count*/,
                              std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    return false;
}

bool ComputeDigestsOnlyLTCuda(
    const std::vector<CBlockHeader>& /*headers*/, uint32_t /*n*/,
    std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
    LtCudaBatchProvenance* provenance)
{
    out.clear();
    if (provenance != nullptr) *provenance = {};
    return false;
}

bool ComputeDigestsOnlyLTCudaTelemetryCampaign(
    const std::vector<CBlockHeader>& /*headers*/, uint32_t /*n*/, uint32_t /*qstar*/,
    std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
    LtCudaBatchProvenance* provenance)
{
    out.clear();
    if (provenance != nullptr) *provenance = {};
    return false;
}

bool RunMatMulLTCudaExtendedSelfTest(std::string& error)
{
    error = "CUDA backend not compiled";
    return false;
}

bool LtLastS8S8UsedImma()
{
    return false;
}

matmul::v4::lt::MxLaneProvenance LtLastMxProvenance()
{
    return {};
}

bool IsLtExactMxScalePartitionedAvailable()
{
    return false;
}

uint32_t LtCudaCompiledRuntimeVersion()
{
    return 0;
}

bool IsLtCudaCublasLtBlockScaleApiCompiled()
{
    return false;
}

matmul::v4::lt::MxLaneProvenance ProbeLtCudaMxNativeProvenance()
{
    return {};
}

bool IsLtNativeMxfp4Qualified()
{
    return false;
}

bool IsLtNativeFp8Qualified()
{
    return false;
}

bool TryLaunchNativeMxfp4ProjectedRight(const std::vector<int8_t>&, const std::vector<uint8_t>&,
                                        const std::vector<int8_t>&, uint32_t, uint32_t,
                                        std::vector<int32_t>& out,
                                        matmul::v4::lt::MxLaneProvenance* provenance)
{
    out.clear();
    if (provenance != nullptr) {
        *provenance = {};
        provenance->native_mxfp4_attempted = true;
    }
    return false;
}

bool TryLaunchNativeFp8ProjectedRight(const std::vector<int8_t>&, const std::vector<uint8_t>&,
                                      const std::vector<int8_t>&, uint32_t, uint32_t,
                                      std::vector<int32_t>& out,
                                      matmul::v4::lt::MxLaneProvenance* provenance)
{
    out.clear();
    if (provenance != nullptr) {
        *provenance = {};
        provenance->native_fp8_attempted = true;
    }
    return false;
}

bool SelfQualifyLtNativeMxLanesOnce()
{
    return false;
}

bool IsLtResidentNativeMxWired()
{
    return false;
}

bool TryLaunchResidentNativeMxProjectedRightDevice(const int8_t*, const uint8_t*, const int8_t*,
                                                   int32_t*, uint32_t, uint32_t, void*,
                                                   matmul::v4::lt::MxLaneProvenance* provenance)
{
    if (provenance != nullptr) {
        *provenance = {};
    }
    return false;
}

bool IsLtPeakMxCapableDevice()
{
    return false;
}

matmul::v4::lt::LtPeakMxPathStatus ProbeLtPeakMxPathStatus()
{
    matmul::v4::lt::LtPeakMxPathStatus s;
    s.production_shape_qualified = false;
    s.allow_exact_mx_fallback = matmul::v4::lt::AllowLtExactMxFallback();
    s.deficit_reason =
        "CUDA LT native TU not linked (stub); resident_native_mx_wired=false "
        "(no device-pointer resident pack)";
    matmul::v4::lt::DeriveLtPeakMxFlags(s); // peak_ready/blocks stay false
    return s;
}

void DiagnoseLtPeakMxPathOnce() {}

bool LtPeakMxBlocksDeviceResident()
{
    return false;
}

} // namespace matmul_v4::cuda
