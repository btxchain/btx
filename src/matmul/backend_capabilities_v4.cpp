// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/backend_capabilities_v4.h>

#include <ascend/matmul_v4_lt_accel.h>
#include <cuda/matmul_accel.h>
#include <metal/matmul_accel.h>

#if defined(BTX_ENABLE_HIP)
#include <hip/hip_runtime.h>
#endif

#if defined(BTX_HAVE_CANN)
#include <acl/acl.h>
#endif

#include <algorithm>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace matmul_v4::backend {
namespace {

char ToLowerAscii(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c + ('a' - 'A'));
    }
    return c;
}

std::string ToLower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](char c) {
        return ToLowerAscii(c);
    });
    return value;
}

Eligibility DisabledByBuild()
{
    return Eligibility{
        .compiled = false,
        .available = false,
        .admissible = false,
        .self_test_required = true,
        .reason = "disabled_by_build",
    };
}

Eligibility CpuEligibility()
{
    // The pure-integer CPU implementation (matmul_v4::ComputeDigest) is the
    // consensus definition (§N.3-v); it does not self-test against itself.
    return Eligibility{
        .compiled = true,
        .available = true,
        .admissible = true,
        .self_test_required = false,
        .reason = "consensus_reference_always_available",
    };
}

Eligibility CudaEligibility()
{
#if defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    const auto probe = btx::cuda::ProbeMatMulDigestAcceleration();
    if (!probe.available) {
        return Eligibility{
            .compiled = true,
            .available = false,
            .admissible = false,
            .self_test_required = true,
            .reason = probe.reason,
        };
    }
    // §S.1: availability of the v3 CUDA path is not enough for v4 mining —
    // the device must be IMMA-capable (Turing+, s8xs8->s32 tensor cores).
    return ClassifyCudaDevice(probe.compute_capability_major,
                              probe.compute_capability_minor);
#else
    return DisabledByBuild();
#endif
}

Eligibility MetalEligibility()
{
#if defined(BTX_ENABLE_METAL)
    const auto probe = btx::metal::ProbeMatMulDigestAcceleration();
    if (!probe.available) {
        return Eligibility{
            .compiled = true,
            .available = false,
            .admissible = false,
            .self_test_required = true,
            .reason = probe.reason,
        };
    }
    // §O.1: only M5-class devices expose Metal 4 INT8 TensorOps
    // (s8xs8->s32). The current Metal backend (built for the v3 32-bit
    // integer field) carries no INT8-TensorOps attestation, so every device
    // classifies as verification-only until the v4 Metal backend lands a
    // real probe and routes it through ClassifyMetalDevice(true) — plus the
    // §N.3-v determinism self-test — on genuine M5 hardware.
    // TODO(v4-metal): replace the constant with the Metal 4 TensorOps probe
    // (MTLDevice supportsFamily + tensor-ops feature query, OS 26.4+).
    Eligibility eligibility = ClassifyMetalDevice(/*has_metal4_int8_tensor_ops=*/false);
    eligibility.reason = "metal4_int8_tensorops_probe_unavailable_in_this_build:" + eligibility.reason;
    return eligibility;
#else
    return DisabledByBuild();
#endif
}

Eligibility HipEligibility()
{
#if defined(BTX_ENABLE_HIP)
    // Real device probe: read the gfx target (hipDeviceProp_t::gcnArchName)
    // and route it through ClassifyHipDevice(). Only CDNA MFMA parts are
    // admissible (§S.1); a missing or unqueryable device reports unavailable
    // so a BTX_ENABLE_HIP build can never silently mine on a device without a
    // qualified exact INT8->INT32 matrix path.
    int device_count = 0;
    if (hipGetDeviceCount(&device_count) != hipSuccess || device_count <= 0) {
        return Eligibility{
            .compiled = true,
            .available = false,
            .admissible = false,
            .self_test_required = true,
            .reason = "hip_no_device",
        };
    }

    int device = 0;
    hipDeviceProp_t props{};
    if (hipGetDevice(&device) != hipSuccess ||
        hipGetDeviceProperties(&props, device) != hipSuccess) {
        return Eligibility{
            .compiled = true,
            .available = false,
            .admissible = false,
            .self_test_required = true,
            .reason = "hip_device_query_failed",
        };
    }

    // §N.3-v determinism self-test still required on top of arch admissibility.
    return ClassifyHipDevice(props.gcnArchName);
#else
    return DisabledByBuild();
#endif
}


Eligibility AscendEligibility()
{
#if defined(BTX_ENABLE_ASCEND)
#if defined(BTX_HAVE_CANN)
    uint32_t count = 0;
    if (aclrtGetDeviceCount(&count) != ACL_SUCCESS || count == 0) {
        return Eligibility{
            .compiled = true,
            .available = false,
            .admissible = false,
            .self_test_required = true,
            .reason = "ascend_no_device",
        };
    }

    std::string soc = "ascend_unknown";
    if (const char* env = std::getenv("ASCEND_DEVICE_SOC")) {
        if (env[0] != '\0') soc = env;
    } else if (const char* env = std::getenv("ASCEND_SOC_VERSION")) {
        if (env[0] != '\0') soc = env;
    } else {
        soc = "dav-3510";
    }

    Eligibility eligibility = ClassifyAscendDevice(soc);
    if (!eligibility.admissible) {
        return eligibility;
    }
    if (!matmul_v4::ascend::IsAscendExactGemmAvailable()) {
        eligibility.admissible = false;
        eligibility.reason =
            "ascend_exactgemm_self_qual_failed_or_unavailable:" + eligibility.reason;
        return eligibility;
    }
    eligibility.reason = "cube_s8s8s32_exactgemm_self_qual:" + eligibility.reason;
    return eligibility;
#else
    return Eligibility{
        .compiled = true,
        .available = false,
        .admissible = false,
        .self_test_required = true,
        .reason = "cann_sdk_not_found",
    };
#endif
#else
    return DisabledByBuild();
#endif
}

Kind ParseKind(const std::string& requested, bool& known)
{
    const std::string normalized = ToLower(requested);
    if (normalized == "cpu") {
        known = true;
        return Kind::CPU;
    }
    if (normalized == "cuda" || normalized == "nvidia") {
        known = true;
        return Kind::CUDA;
    }
    if (normalized == "metal" || normalized == "mlx" || normalized == "apple") {
        known = true;
        return Kind::METAL;
    }
    if (normalized == "hip" || normalized == "rocm" || normalized == "amd") {
        known = true;
        return Kind::HIP;
    }
    if (normalized == "ascend" || normalized == "huawei" || normalized == "npu") {
        known = true;
        return Kind::ASCEND;
    }

    known = false;
    return Kind::CPU;
}

//! Strip ROCm feature suffixes: "gfx90a:sramecc+:xnack-" -> "gfx90a".
std::string_view GfxBaseArch(std::string_view gcn_arch_name)
{
    const auto colon = gcn_arch_name.find(':');
    if (colon != std::string_view::npos) {
        gcn_arch_name = gcn_arch_name.substr(0, colon);
    }
    return gcn_arch_name;
}

} // namespace

std::string ToString(Kind kind)
{
    switch (kind) {
    case Kind::CPU:
        return "cpu";
    case Kind::CUDA:
        return "cuda";
    case Kind::METAL:
        return "metal";
    case Kind::HIP:
        return "hip";
    case Kind::ASCEND:
        return "ascend";
    }

    return "cpu";
}

Eligibility EligibilityFor(Kind kind)
{
    switch (kind) {
    case Kind::CPU:
        return CpuEligibility();
    case Kind::CUDA:
        return CudaEligibility();
    case Kind::METAL:
        return MetalEligibility();
    case Kind::HIP:
        return HipEligibility();
    case Kind::ASCEND:
        return AscendEligibility();
    }

    return CpuEligibility();
}

std::vector<std::pair<Kind, Eligibility>> AllEligibility()
{
    return {
        {Kind::CPU, EligibilityFor(Kind::CPU)},
        {Kind::CUDA, EligibilityFor(Kind::CUDA)},
        {Kind::METAL, EligibilityFor(Kind::METAL)},
        {Kind::HIP, EligibilityFor(Kind::HIP)},
        {Kind::ASCEND, EligibilityFor(Kind::ASCEND)},
    };
}

Selection ResolveBackend(const std::string& requested)
{
    Selection selection;
    selection.requested_input = requested;

    bool known{false};
    selection.requested = ParseKind(requested, known);
    selection.requested_known = known;

    if (!known) {
        selection.active = Kind::CPU;
        selection.reason = "unknown_backend_fallback_to_cpu";
        return selection;
    }

    const Eligibility eligibility = EligibilityFor(selection.requested);
    if (!eligibility.available) {
        selection.active = Kind::CPU;
        selection.reason = ToString(selection.requested) + "_unavailable_fallback_to_cpu:" + eligibility.reason;
        return selection;
    }
    if (!eligibility.admissible) {
        // §S.1: runtime present but no bit-exact INT8 tensor path — the
        // device is verification-only and MUST NOT mine (a device without an
        // exact s8xs8->s32 path cannot reproduce the consensus digest).
        selection.active = Kind::CPU;
        selection.reason = ToString(selection.requested) + "_inadmissible_fallback_to_cpu:" + eligibility.reason;
        return selection;
    }

    selection.active = selection.requested;
    selection.reason = "requested_backend_admissible";
    return selection;
}

Eligibility ClassifyCudaDevice(uint32_t cc_major, uint32_t cc_minor)
{
    Eligibility eligibility{
        .compiled = true,
        .available = true,
        .admissible = false,
        .self_test_required = true,
        .reason = "",
    };

    const std::string sm = "sm_" + std::to_string(cc_major) + std::to_string(cc_minor);
    if (cc_major < 7) {
        // Pascal and older, incl. CMP 30HX/TU116-class rebrands: no tensor
        // cores at all (§S.4.2). DP4A is integer but is not the tensor path.
        eligibility.reason = "pre_tensor_no_int8_mma:" + sm;
        return eligibility;
    }
    if (cc_major == 7 && cc_minor < 5) {
        // Volta (sm_70/72): first-generation tensor cores are FP16-multiply
        // only — non-deterministic accumulate, inadmissible (§S.4.2).
        eligibility.reason = "volta_fp16_tensor_only_inadmissible:" + sm;
        return eligibility;
    }

    // Turing (sm_75) introduced IMMA s8xs8->s32; every later architecture
    // (Ampere sm_8x, Ada sm_89, Hopper sm_90, Blackwell sm_10x/sm_12x)
    // retains the exact integer tensor path (§B.6).
    eligibility.admissible = true;
    eligibility.reason = "imma_s8s8s32_tensor_path:" + sm;
    return eligibility;
}

Eligibility ClassifyHipDevice(std::string_view gcn_arch_name)
{
    Eligibility eligibility{
        .compiled = true,
        .available = true,
        .admissible = false,
        .self_test_required = true,
        .reason = "",
    };

    const std::string arch{GfxBaseArch(gcn_arch_name)};

    // CDNA MFMA generations with exact INT8->INT32 matrix ops
    // (v_mfma_i32_*i8): CDNA1 MI100, CDNA2 MI200, CDNA3 MI300, CDNA4 MI350.
    static constexpr std::string_view kCdnaMfmaArchs[] = {
        "gfx908", // CDNA1  (MI100)
        "gfx90a", // CDNA2  (MI210/MI250/MI250X)
        "gfx940", // CDNA3  (MI300 early)
        "gfx941", // CDNA3  (MI300 early)
        "gfx942", // CDNA3  (MI300A/MI300X/MI325X)
        "gfx950", // CDNA4  (MI350 series)
    };
    for (const auto& cdna : kCdnaMfmaArchs) {
        if (arch == cdna) {
            eligibility.admissible = true;
            eligibility.reason = "mfma_i8i8i32_tensor_path:" + arch;
            return eligibility;
        }
    }

    // RDNA (gfx10xx/gfx11xx/gfx12xx): consumer parts. RDNA3+ WMMA has an
    // iu8 mode, but it is not the CDNA MFMA path the §S.1 rule admits;
    // verification-only until cross-vendor golden vectors qualify it
    // (§B.6, Appendix C-3).
    if (arch.rfind("gfx10", 0) == 0 || arch.rfind("gfx11", 0) == 0 ||
        arch.rfind("gfx12", 0) == 0) {
        eligibility.reason = "rdna_wmma_not_qualified_verification_only:" + arch;
        return eligibility;
    }

    // GCN/Vega (gfx900/gfx902/gfx906...): no matrix cores.
    if (arch.rfind("gfx9", 0) == 0) {
        eligibility.reason = "gcn_no_matrix_cores:" + arch;
        return eligibility;
    }

    eligibility.reason = "unknown_or_non_cdna_arch:" + (arch.empty() ? std::string{"(empty)"} : arch);
    return eligibility;
}

Eligibility ClassifyMetalDevice(bool has_metal4_int8_tensor_ops)
{
    Eligibility eligibility{
        .compiled = true,
        .available = true,
        .admissible = false,
        .self_test_required = true,
        .reason = "",
    };

    if (!has_metal4_int8_tensor_ops) {
        // Pre-M5 GPUs have no matrix units; the ANE's "INT8" dequantizes to
        // FP16 internally — no exact integer accumulate (§K.1, §O.1).
        eligibility.reason = "no_integer_tensor_path_verification_only";
        return eligibility;
    }

    // M5-class GPU Neural Accelerator, Metal 4 INT8 TensorOps (s8xs8->s32,
    // OS 26.4+). Admissible pending the mandatory §N.3-v self-test.
    eligibility.admissible = true;
    eligibility.reason = "metal4_int8_tensorops_m5_class";
    return eligibility;
}

Eligibility ClassifyAscendDevice(std::string_view soc_name)
{
    Eligibility eligibility{
        .compiled = true,
        .available = true,
        .admissible = false,
        .self_test_required = true,
        .reason = "",
    };

    std::string soc{soc_name};
    for (char& c : soc) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    }

    // Ascend 950PR/DT (dav-3510) and related Cube INT8 NPU ids from CANN docs.
    const bool is_950_class =
        soc.find("dav-3510") != std::string::npos ||
        soc.find("3510") != std::string::npos ||
        soc.find("950pr") != std::string::npos ||
        soc.find("950dt") != std::string::npos ||
        soc.find("ascend950") != std::string::npos ||
        soc.find("ascend-950") != std::string::npos ||
        soc.find("ascend910") != std::string::npos ||
        soc.find("ascend-910") != std::string::npos;

    if (!is_950_class) {
        eligibility.reason =
            "non_ascend950_cube_verification_only:" +
            (soc.empty() ? std::string{"(empty)"} : soc);
        return eligibility;
    }

    eligibility.admissible = true;
    eligibility.reason = "ascend_cube_int8_candidate:" + soc;
    return eligibility;
}

} // namespace matmul_v4::backend
