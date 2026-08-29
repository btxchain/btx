// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// MatMul v4.4-LT ExactGemm TensorOps preference (Apple Metal).
//
// Production path: Metal 4 mpp::tensor_ops::matmul2d INT8×INT8→INT32 (MPP /
// GPU neural accelerators on M5-class silicon), compiled at runtime with an
// explicit metal4.0 language version. Recipe mirrors
// metal/matmul_v4_bmx4_accel.mm / Apple's MPP Programming Guide.
//
// HARD RULES:
//   * IsLtTensorOpsGemmAvailable is true ONLY after ExactGemmS8S8 self-qual.
//   * Never claim TensorOps when the plain ALU shader ran.
//   * S32S8 declines (no dedicated TensorOps shape) — callers keep ALU/CPU.
//   * M4-class vs M5-class capability strings stay separate.
//   * MXFP4 / FP8 / MX·E8M0 block-scale matmul2d is NOT used here. Apple may
//     expose those for ML dequant, but they are not self-qualified as exact
//     vs ComputeProjectedRightMxBlockScaleLT. MX B̂·V lives in
//     matmul_v4_lt_accel.mm as four exact INT8 partitions (never labeled
//     native MXFP4).

#include <cuda/matmul_v4_lt_tensor_gemm.h>

#include "matmul_v4_lt_tensor_gemm_source.h"

#include <logging.h>
#include <matmul/matmul_v4_lt.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <vector>
#include <mach-o/dyld.h>
#include <unistd.h>

namespace matmul_v4::metal {
namespace {

constexpr uint32_t kTensorTileM = 32;
constexpr uint32_t kTensorTileN = 32;

void AppendUniquePath(std::vector<std::string>& paths, const char* path)
{
    if (path == nullptr || path[0] == '\0') return;
    if (std::find(paths.begin(), paths.end(), path) == paths.end()) {
        paths.emplace_back(path);
    }
}

std::optional<std::string> ExecutableDirectory()
{
    uint32_t size = PATH_MAX;
    std::vector<char> buffer(size);
    if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
        buffer.resize(size);
        if (_NSGetExecutablePath(buffer.data(), &size) != 0) {
            return std::nullopt;
        }
    }

    char resolved[PATH_MAX];
    const char* executable_path = realpath(buffer.data(), resolved) != nullptr ? resolved : buffer.data();
    std::string path{executable_path};
    const auto separator = path.find_last_of('/');
    if (separator == std::string::npos) {
        return std::nullopt;
    }
    return path.substr(0, separator);
}

std::vector<std::string> LtTensorMetallibCandidatePaths()
{
    std::vector<std::string> paths;
    AppendUniquePath(paths, std::getenv("BTX_MATMUL_V4_LT_TENSOR_METALLIB_PATH"));
    if (const auto executable_dir = ExecutableDirectory()) {
        AppendUniquePath(paths, (*executable_dir + "/metal/matmul_v4_lt_tensor_gemm.metallib").c_str());
    }
#if defined(BTX_MATMUL_V4_LT_TENSOR_METALLIB_PATH)
    AppendUniquePath(paths, BTX_MATMUL_V4_LT_TENSOR_METALLIB_PATH);
#endif
    return paths;
}

struct GemmParamsHost {
    uint32_t m_rows{0};
    uint32_t k{0};
    uint32_t n_cols{0};
};

struct TensorOpsContext {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> tensor_pipeline{nil};
    id<MTLBuffer> scratchA{nil};
    id<MTLBuffer> scratchB{nil};
    id<MTLBuffer> scratchD{nil};
    id<MTLBuffer> scratchParams{nil};
    size_t scratchA_bytes{0};
    size_t scratchB_bytes{0};
    size_t scratchD_bytes{0};
    std::string device_name;
    std::string tensor_path_reason{"uninitialized"};
    bool device_present{false};
    bool compile_ok{false};
    // scratchA/B/D/Params are shared by every caller. Keep the entire upload,
    // encode, execute, and readback lifetime serialized; otherwise concurrent
    // Phase-B slots can overwrite buffers still referenced by a command buffer.
    std::mutex launch_mutex;

    [[nodiscard]] bool EnsureScratch(size_t a_bytes, size_t b_bytes, size_t d_bytes)
    {
        auto grow = [&](id<MTLBuffer> __strong& buf, size_t& have, size_t need) -> bool {
            if (need <= have && buf != nil) return true;
            buf = [device newBufferWithLength:need options:MTLResourceStorageModeShared];
            if (buf == nil) {
                have = 0;
                return false;
            }
            have = need;
            return true;
        };
        if (scratchParams == nil) {
            scratchParams = [device newBufferWithLength:sizeof(GemmParamsHost)
                                               options:MTLResourceStorageModeShared];
            if (scratchParams == nil) return false;
        }
        return grow(scratchA, scratchA_bytes, a_bytes) &&
               grow(scratchB, scratchB_bytes, b_bytes) &&
               grow(scratchD, scratchD_bytes, d_bytes);
    }
};

bool EnvFlagDisabled(const char* name)
{
    const char* env = std::getenv(name);
    return env != nullptr && env[0] == '0';
}

// Reporting / golden-row selection only. Mining admission is
// IsLtTensorOpsGemmAvailable() (SelfTestTensorOpsOnce), not this string match.
LtMetalArchNameClass ClassifyFromDeviceName(const std::string& name)
{
    auto has = [&](const char* needle) {
        return name.find(needle) != std::string::npos;
    };
    if (has("M5") || has("m5")) return LtMetalArchNameClass::M5Class;
    if (has("M4") || has("M3") || has("M2") || has("M1") ||
        has("m4") || has("m3") || has("m2") || has("m1")) {
        return LtMetalArchNameClass::M4Class;
    }
    if (!name.empty()) return LtMetalArchNameClass::Other;
    return LtMetalArchNameClass::Unknown;
}

const char* NameClassString(LtMetalArchNameClass c)
{
    switch (c) {
    case LtMetalArchNameClass::M4Class: return "m4_class";
    case LtMetalArchNameClass::M5Class: return "m5_class";
    case LtMetalArchNameClass::Other: return "other";
    case LtMetalArchNameClass::Unknown:
    default: return "unknown";
    }
}

TensorOpsContext& Ctx()
{
    static TensorOpsContext ctx;
    static std::once_flag once;
    std::call_once(once, [] {
        @autoreleasepool {
            if (EnvFlagDisabled("BTX_MATMUL_V4_LT_TENSOR_OPS")) {
                ctx.tensor_path_reason = "disabled_by_environment";
                return;
            }

            NSArray<id<MTLDevice>>* all_devices = MTLCopyAllDevices();
            if (all_devices == nil || all_devices.count == 0) {
                ctx.tensor_path_reason = "no_metal_device";
                return;
            }
            ctx.device = all_devices[0];
            ctx.device_present = true;
            ctx.device_name = ctx.device.name != nil
                ? std::string{[ctx.device.name UTF8String]}
                : "unknown";
            ctx.queue = [ctx.device newCommandQueue];
            if (ctx.queue == nil) {
                ctx.tensor_path_reason = "no_command_queue";
                return;
            }

            // Prefer a build-time Metal 4 metallib so launchd/daemon btxd does
            // not have to reach MTLCompilerService (issue 51). Fall back to
            // newLibraryWithSource only when no metallib is present.
            NSError* err = nil;
            id<MTLLibrary> lib = nil;
            std::string load_source;
            for (const auto& candidate_path : LtTensorMetallibCandidatePaths()) {
                NSString* precompiled_path = [NSString stringWithUTF8String:candidate_path.c_str()];
                if (![[NSFileManager defaultManager] fileExistsAtPath:precompiled_path]) {
                    continue;
                }
                err = nil;
                lib = [ctx.device newLibraryWithURL:[NSURL fileURLWithPath:precompiled_path] error:&err];
                if (lib != nil) {
                    load_source = "precompiled_metallib";
                    break;
                }
            }
            if (lib == nil) {
                MTLCompileOptions* options = [MTLCompileOptions new];
                options.languageVersion = static_cast<MTLLanguageVersion>(4 << 16);
                err = nil;
                lib = [ctx.device newLibraryWithSource:[NSString stringWithUTF8String:kBtxLtTensorGemmMetalKernelSource]
                                               options:options
                                                 error:&err];
                if (lib != nil) load_source = "inline_source_fallback";
            }
            id<MTLFunction> fn = lib != nil
                ? [lib newFunctionWithName:@"matmul_v4_lt_s8_gemm_s32_tensor"]
                : nil;
            if (lib != nil && fn == nil && load_source == "precompiled_metallib") {
                // Stale or TensorOps-less metallib: try runtime metal4 compile.
                MTLCompileOptions* options = [MTLCompileOptions new];
                options.languageVersion = static_cast<MTLLanguageVersion>(4 << 16);
                err = nil;
                lib = [ctx.device newLibraryWithSource:[NSString stringWithUTF8String:kBtxLtTensorGemmMetalKernelSource]
                                               options:options
                                                 error:&err];
                load_source = lib != nil ? "inline_source_fallback" : load_source;
                fn = lib != nil ? [lib newFunctionWithName:@"matmul_v4_lt_s8_gemm_s32_tensor"] : nil;
            }
            if (lib == nil) {
                ctx.tensor_path_reason = err != nil
                    ? std::string{"metal4_compile_failed:"} + [[err localizedDescription] UTF8String]
                    : "metal4_compile_failed";
                return;
            }
            if (fn == nil) {
                ctx.tensor_path_reason = "tensor_ops_kernel_absent:" + load_source;
                return;
            }
            ctx.tensor_pipeline = [ctx.device newComputePipelineStateWithFunction:fn error:&err];
            if (ctx.tensor_pipeline == nil) {
                ctx.tensor_path_reason = err != nil
                    ? std::string{"tensor_pipeline_failed:"} + [[err localizedDescription] UTF8String]
                    : "tensor_pipeline_failed";
                return;
            }
            ctx.compile_ok = true;
            ctx.tensor_path_reason = "ok:" + load_source;
        }
        if (!ctx.compile_ok) {
            LogPrintf("MATMUL-METAL WARNING: Metal 4 INT8 TensorOps not admitted (%s). "
                      "v4 mining will use CPU. Prefer a build-time metallib "
                      "(BTX_MATMUL_V4_LT_TENSOR_METALLIB_PATH); runtime compile needs "
                      "MTLCompilerService, which launchd/daemon often cannot reach.\n",
                      ctx.tensor_path_reason);
        }
    });
    return ctx;
}

[[nodiscard]] bool LaunchTensorOpsS8S8Raw(const std::vector<int8_t>& left,
                                          const std::vector<int8_t>& right,
                                          uint32_t rows, uint32_t k, uint32_t cols,
                                          std::vector<int32_t>& out)
{
    auto& ctx = Ctx();
    if (!ctx.compile_ok || ctx.tensor_pipeline == nil || ctx.queue == nil) return false;
    if (rows == 0 || k == 0 || cols == 0) {
        out.clear();
        return true;
    }

    const size_t lhs_elems = size_t(rows) * k;
    const size_t rhs_elems = size_t(k) * cols;
    const size_t out_elems = size_t(rows) * cols;
    if (out_elems > std::numeric_limits<size_t>::max() / sizeof(int32_t)) return false;
    const size_t lhs_bytes = lhs_elems * sizeof(int8_t);
    const size_t rhs_bytes = rhs_elems * sizeof(int8_t);
    const size_t out_bytes = out_elems * sizeof(int32_t);
    if (left.size() != lhs_elems || right.size() != rhs_elems) return false;

    std::lock_guard<std::mutex> launch_lock{ctx.launch_mutex};
    if (!ctx.EnsureScratch(lhs_bytes, rhs_bytes, out_bytes)) return false;

    std::memcpy([ctx.scratchA contents], left.data(), lhs_bytes);
    std::memcpy([ctx.scratchB contents], right.data(), rhs_bytes);
    GemmParamsHost params{rows, k, cols};
    std::memcpy([ctx.scratchParams contents], &params, sizeof(params));

    id<MTLCommandBuffer> cmd = [ctx.queue commandBuffer];
    if (cmd == nil) return false;
    id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
    if (enc == nil) return false;
    [enc setComputePipelineState:ctx.tensor_pipeline];
    [enc setBuffer:ctx.scratchParams offset:0 atIndex:0];
    [enc setBuffer:ctx.scratchA offset:0 atIndex:1];
    [enc setBuffer:ctx.scratchB offset:0 atIndex:2];
    [enc setBuffer:ctx.scratchD offset:0 atIndex:3];
    const MTLSize groups = MTLSizeMake((cols + kTensorTileN - 1) / kTensorTileN,
                                       (rows + kTensorTileM - 1) / kTensorTileM, 1);
    const MTLSize group_size = MTLSizeMake(32, 1, 1);
    [enc dispatchThreadgroups:groups threadsPerThreadgroup:group_size];
    [enc endEncoding];
    [cmd commit];
    [cmd waitUntilCompleted];
    if (cmd.status != MTLCommandBufferStatusCompleted) return false;

    out.resize(out_elems);
    std::memcpy(out.data(), [ctx.scratchD contents], out_bytes);
    return true;
}

[[nodiscard]] bool SelfTestTensorOpsOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        if (!Ctx().compile_ok) return;

        constexpr uint32_t kDim = 32;
        std::vector<int8_t> left(size_t(kDim) * kDim);
        std::vector<int8_t> right(size_t(kDim) * kDim);
        for (uint32_t i = 0; i < kDim * kDim; ++i) {
            left[i] = matmul::v4::lt::FoldInt32ToEmax48(int32_t(i) * 7 - 101);
            right[i] = matmul::v4::lt::FoldInt32ToEmax48(int32_t(i) * 11 + 53);
        }
        const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu;
        if (!LaunchTensorOpsS8S8Raw(left, right, kDim, kDim, kDim, gpu) || gpu != cpu) {
            Ctx().tensor_path_reason = "exact_gemm_s8s8_self_qual_failed";
            LogPrintf("MATMUL-METAL WARNING: ExactGemm TensorOps self-qual failed (%s). "
                      "v4 Metal is not admissible; mining will use CPU.\n",
                      Ctx().tensor_path_reason);
            return;
        }

        constexpr uint32_t kN = 64;
        constexpr uint32_t kW = 16;
        std::vector<int8_t> G(size_t(kN) * kN);
        std::vector<int8_t> W(size_t(kN) * kW);
        for (uint32_t i = 0; i < kN * kN; ++i) {
            G[i] = matmul::v4::lt::FoldInt32ToEmax48(int32_t(i) * 3 - 17);
        }
        for (uint32_t i = 0; i < kN * kW; ++i) {
            W[i] = matmul::v4::lt::FoldInt32ToEmax48(int32_t(i) * 5 + 9);
        }
        const auto cpu_panel = matmul::v4::lt::ExactGemmS8S8(G, W, kN, kN, kW);
        std::vector<int32_t> gpu_panel;
        if (!LaunchTensorOpsS8S8Raw(G, W, kN, kN, kW, gpu_panel) || gpu_panel != cpu_panel) {
            Ctx().tensor_path_reason = "exact_gemm_s8s8_panel_self_qual_failed";
            LogPrintf("MATMUL-METAL WARNING: ExactGemm TensorOps self-qual failed (%s). "
                      "v4 Metal is not admissible; mining will use CPU.\n",
                      Ctx().tensor_path_reason);
            return;
        }
        ok = true;
        Ctx().tensor_path_reason = "exact_gemm_s8s8_self_qual_passed";
    });
    return ok;
}

} // namespace

LtMetalArchProbe ProbeLtMetalArch()
{
    LtMetalArchProbe out;
    const auto& ctx = Ctx();
    if (!ctx.device_present) {
        out.name_class_string = NameClassString(LtMetalArchNameClass::Unknown);
        return out;
    }
    out.available = true;
    out.device_name = ctx.device_name;
    out.recommended_working_set_bytes =
        static_cast<uint64_t>(ctx.device.recommendedMaxWorkingSetSize);
    out.metal4_tensor_ops_compile_ok = ctx.compile_ok;

    // API/shader compilation is not silicon identity. Metal 4 MPP compiles and
    // passes exactness tests on M4, so treating compile_ok as proof of M5 made an
    // M4 Max falsely advertise itself as M5-class in qualification reports.
    out.name_class = ClassifyFromDeviceName(ctx.device_name);
    out.name_class_string = NameClassString(out.name_class);
    return out;
}

LtMetalExactGemmCapabilities ProbeLtMetalExactGemmCapabilities()
{
    LtMetalExactGemmCapabilities caps;
    caps.arch = ProbeLtMetalArch();
    caps.exact_s8_s8_s32 = IsLtTensorOpsGemmAvailable();
    caps.exact_partitioned_s32_s8 = false;
    caps.device_alu_gemm = caps.arch.available;
    caps.device_hashing = false;
    return caps;
}

bool IsLtTensorOpsGemmAvailable()
{
    return SelfTestTensorOpsOnce();
}

bool TryLaunchLtTensorOpsGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t inner, uint32_t cols,
                                  std::vector<int32_t>& out)
{
    if (!IsLtTensorOpsGemmAvailable()) return false;
    return LaunchTensorOpsS8S8Raw(left, right, rows, inner, cols, out);
}

bool TryLaunchLtTensorOpsGemmS32S8(const std::vector<int32_t>& /*left*/,
                                   const std::vector<int8_t>& /*right*/,
                                   uint32_t /*rows*/, uint32_t /*inner*/, uint32_t /*cols*/,
                                   std::vector<int32_t>& /*out*/)
{
    return false;
}

} // namespace matmul_v4::metal
