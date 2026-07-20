// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal host glue for MatMul v4.4 ENC-DR-LT (MatExpand).
// Exact int8×int8→int32 and int32×int8→int32 GEMM compute kernels (MSL ALU),
// with Metal 4 MPP TensorOps preferred for s8xs8 when ExactGemmS8S8 self-qual
// passes. Injected via ExactGemmBackend into WindowSketchMinerLT (fail-closed
// host ExactGemm when Metal declines). Never label ALU shaders as TensorOps.
//
// Lever-B MX twin (this TU):
//   * Extract stays HOST-side (ExtractMatExpandMxTileMantissas /
//     DeriveMatExpandMxScale via MatExpandCorePrepared). No Metal Extract twin.
//   * B̂·V uses exact e∈{0..3} INT8 scale partitions via
//     ComputeProjectedRightMxScalePartitionedGemmLT + Metal ExactGemmS8S8
//     (TensorOps or ALU). Byte-identical to ComputeProjectedRightMxBlockScaleLT.
//   * Native Apple MX·E8M0 / FP8 matmul2d dequant FAIL CLOSED — not proven
//     exact vs BTX M11×2^{e}. Digests remain bit-identical to the CPU oracle.

#include <logging.h>
#include <metal/matmul_v4_lt_accel.h>

#include <arith_uint256.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>
#include <primitives/block.h>
#include <uint256.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <limits>
#include <mutex>
#include <vector>

namespace matmul_v4::metal {
namespace {

std::atomic_bool g_lt_last_s8s8_tensor_ops{false};
std::mutex g_mx_prov_mutex;
LtMetalMxProvenance g_lt_last_mx_provenance{};

static NSString* const kGemmLibrarySource = @R"MSL(
#include <metal_stdlib>
using namespace metal;

kernel void gemm_s8s8(device const signed char* A [[buffer(0)]],
                      device const signed char* B [[buffer(1)]],
                      device int* D [[buffer(2)]],
                      constant int& M [[buffer(3)]],
                      constant int& N [[buffer(4)]],
                      constant int& K [[buffer(5)]],
                      uint2 gid [[thread_position_in_grid]])
{
    const int col = int(gid.x);
    const int row = int(gid.y);
    if (row >= M || col >= N) return;
    int acc = 0;
    const size_t arow = size_t(row) * size_t(K);
    for (int k = 0; k < K; ++k) {
        // signed char: never promote 0xFF as +255 (unsigned-char trap).
        acc += int(A[arow + size_t(k)]) * int(B[size_t(k) * size_t(N) + size_t(col)]);
    }
    D[size_t(row) * size_t(N) + size_t(col)] = acc;
}

kernel void gemm_s32s8(device const int* A [[buffer(0)]],
                       device const signed char* B [[buffer(1)]],
                       device int* D [[buffer(2)]],
                       constant int& M [[buffer(3)]],
                       constant int& N [[buffer(4)]],
                       constant int& K [[buffer(5)]],
                       uint2 gid [[thread_position_in_grid]])
{
    const int col = int(gid.x);
    const int row = int(gid.y);
    if (row >= M || col >= N) return;
    long acc = 0;
    const size_t arow = size_t(row) * size_t(K);
    for (int k = 0; k < K; ++k) {
        acc += long(A[arow + size_t(k)]) * long(B[size_t(k) * size_t(N) + size_t(col)]);
    }
    D[size_t(row) * size_t(N) + size_t(col)] = int(acc);
}
)MSL";

struct MetalGemmContext {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> s8s8{nil};
    id<MTLComputePipelineState> s32s8{nil};
    // Cross-call persistent scratch (grow-only) — avoids per-nonce buffer alloc.
    id<MTLBuffer> scratchA{nil};
    id<MTLBuffer> scratchB{nil};
    id<MTLBuffer> scratchD{nil};
    size_t scratchA_bytes{0};
    size_t scratchB_bytes{0};
    size_t scratchD_bytes{0};
    bool ready{false};
    // Both ALU entry points reuse the same grow-only buffers. The lock must
    // cover upload through command completion and readback, not just growth.
    std::mutex launch_mutex;

    [[nodiscard]] bool EnsureScratch(size_t a_bytes, size_t b_bytes, size_t d_bytes)
    {
        auto grow = [&](id<MTLBuffer> __strong& buf, size_t& have, size_t need) -> bool {
            if (need <= have && buf != nil) return true;
            buf = [device newBufferWithLength:need options:MTLResourceStorageModeShared];
            if (buf == nil) { have = 0; return false; }
            have = need;
            return true;
        };
        return grow(scratchA, scratchA_bytes, a_bytes) &&
               grow(scratchB, scratchB_bytes, b_bytes) &&
               grow(scratchD, scratchD_bytes, d_bytes);
    }
};

MetalGemmContext& Ctx()
{
    static MetalGemmContext ctx;
    static std::once_flag once;
    std::call_once(once, [] {
        ctx.device = MTLCreateSystemDefaultDevice();
        if (ctx.device == nil) return;
        ctx.queue = [ctx.device newCommandQueue];
        if (ctx.queue == nil) return;
        NSError* err = nil;
        id<MTLLibrary> lib = [ctx.device newLibraryWithSource:kGemmLibrarySource
                                                      options:nil
                                                        error:&err];
        if (lib == nil) return;
        id<MTLFunction> f8 = [lib newFunctionWithName:@"gemm_s8s8"];
        id<MTLFunction> f32 = [lib newFunctionWithName:@"gemm_s32s8"];
        if (f8 == nil || f32 == nil) return;
        ctx.s8s8 = [ctx.device newComputePipelineStateWithFunction:f8 error:&err];
        ctx.s32s8 = [ctx.device newComputePipelineStateWithFunction:f32 error:&err];
        ctx.ready = (ctx.s8s8 != nil && ctx.s32s8 != nil);
    });
    return ctx;
}

bool LaunchAluGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                       uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    auto& ctx = Ctx();
    if (!ctx.ready) return false;
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }

    const size_t lhs_elems = size_t(rows) * k;
    const size_t rhs_elems = size_t(k) * cols;
    const size_t out_elems = size_t(rows) * cols;
    if (out_elems > std::numeric_limits<size_t>::max() / sizeof(int32_t) ||
        left.size() != lhs_elems || right.size() != rhs_elems) return false;
    const size_t lhs_bytes = lhs_elems * sizeof(int8_t);
    const size_t rhs_bytes = rhs_elems * sizeof(int8_t);
    const size_t out_bytes = out_elems * sizeof(int32_t);

    std::lock_guard<std::mutex> launch_lock{ctx.launch_mutex};
    if (!ctx.EnsureScratch(lhs_bytes, rhs_bytes, out_bytes)) return false;
    std::memcpy([ctx.scratchA contents], left.data(), lhs_bytes);
    std::memcpy([ctx.scratchB contents], right.data(), rhs_bytes);

    int M = int(rows), N = int(cols), K = int(k);
    id<MTLBuffer> bM = [ctx.device newBufferWithBytes:&M length:sizeof(M) options:MTLResourceStorageModeShared];
    id<MTLBuffer> bN = [ctx.device newBufferWithBytes:&N length:sizeof(N) options:MTLResourceStorageModeShared];
    id<MTLBuffer> bK = [ctx.device newBufferWithBytes:&K length:sizeof(K) options:MTLResourceStorageModeShared];
    if (bM == nil || bN == nil || bK == nil) return false;

    id<MTLCommandBuffer> cmd = [ctx.queue commandBuffer];
    if (cmd == nil) return false;
    id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
    if (enc == nil) return false;
    [enc setComputePipelineState:ctx.s8s8];
    [enc setBuffer:ctx.scratchA offset:0 atIndex:0];
    [enc setBuffer:ctx.scratchB offset:0 atIndex:1];
    [enc setBuffer:ctx.scratchD offset:0 atIndex:2];
    [enc setBuffer:bM offset:0 atIndex:3];
    [enc setBuffer:bN offset:0 atIndex:4];
    [enc setBuffer:bK offset:0 atIndex:5];
    const MTLSize grid = MTLSizeMake(cols, rows, 1);
    const NSUInteger tw = ctx.s8s8.threadExecutionWidth;
    const MTLSize tgroup = MTLSizeMake(tw, std::max<NSUInteger>(1, ctx.s8s8.maxTotalThreadsPerThreadgroup / tw), 1);
    [enc dispatchThreads:grid threadsPerThreadgroup:tgroup];
    [enc endEncoding];
    [cmd commit];
    [cmd waitUntilCompleted];
    if (cmd.status != MTLCommandBufferStatusCompleted) return false;

    out.resize(out_elems);
    std::memcpy(out.data(), [ctx.scratchD contents], out_bytes);
    return true;
}

bool LaunchAluGemmS32S8(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
                        uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    auto& ctx = Ctx();
    if (!ctx.ready) return false;
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }

    const size_t lhs_elems = size_t(rows) * k;
    const size_t rhs_elems = size_t(k) * cols;
    const size_t out_elems = size_t(rows) * cols;
    if (lhs_elems > std::numeric_limits<size_t>::max() / sizeof(int32_t) ||
        out_elems > std::numeric_limits<size_t>::max() / sizeof(int32_t) ||
        left.size() != lhs_elems || right.size() != rhs_elems) return false;
    const size_t lhs_bytes = lhs_elems * sizeof(int32_t);
    const size_t rhs_bytes = rhs_elems * sizeof(int8_t);
    const size_t out_bytes = out_elems * sizeof(int32_t);

    std::lock_guard<std::mutex> launch_lock{ctx.launch_mutex};
    if (!ctx.EnsureScratch(lhs_bytes, rhs_bytes, out_bytes)) return false;
    std::memcpy([ctx.scratchA contents], left.data(), lhs_bytes);
    std::memcpy([ctx.scratchB contents], right.data(), rhs_bytes);

    int M = int(rows), N = int(cols), K = int(k);
    id<MTLBuffer> bM = [ctx.device newBufferWithBytes:&M length:sizeof(M) options:MTLResourceStorageModeShared];
    id<MTLBuffer> bN = [ctx.device newBufferWithBytes:&N length:sizeof(N) options:MTLResourceStorageModeShared];
    id<MTLBuffer> bK = [ctx.device newBufferWithBytes:&K length:sizeof(K) options:MTLResourceStorageModeShared];
    if (bM == nil || bN == nil || bK == nil) return false;

    id<MTLCommandBuffer> cmd = [ctx.queue commandBuffer];
    if (cmd == nil) return false;
    id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
    if (enc == nil) return false;
    [enc setComputePipelineState:ctx.s32s8];
    [enc setBuffer:ctx.scratchA offset:0 atIndex:0];
    [enc setBuffer:ctx.scratchB offset:0 atIndex:1];
    [enc setBuffer:ctx.scratchD offset:0 atIndex:2];
    [enc setBuffer:bM offset:0 atIndex:3];
    [enc setBuffer:bN offset:0 atIndex:4];
    [enc setBuffer:bK offset:0 atIndex:5];
    const MTLSize grid = MTLSizeMake(cols, rows, 1);
    const NSUInteger tw = ctx.s32s8.threadExecutionWidth;
    const MTLSize tgroup = MTLSizeMake(tw, std::max<NSUInteger>(1, ctx.s32s8.maxTotalThreadsPerThreadgroup / tw), 1);
    [enc dispatchThreads:grid threadsPerThreadgroup:tgroup];
    [enc endEncoding];
    [cmd commit];
    [cmd waitUntilCompleted];
    if (cmd.status != MTLCommandBufferStatusCompleted) return false;

    out.resize(out_elems);
    std::memcpy(out.data(), [ctx.scratchD contents], out_bytes);
    return true;
}

bool LaunchGemmS8S8Internal(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                            uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    // TensorOps only when ExactGemmS8S8 self-qual passed — never label ALU as TensorOps.
    if (TryLaunchLtTensorOpsGemmS8S8(left, right, rows, k, cols, out)) {
        g_lt_last_s8s8_tensor_ops = true;
        return true;
    }
    g_lt_last_s8s8_tensor_ops = false;
    return LaunchAluGemmS8S8(left, right, rows, k, cols, out);
}

bool LaunchGemmS32S8Internal(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
                             uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    if (TryLaunchLtTensorOpsGemmS32S8(left, right, rows, k, cols, out)) {
        return true;
    }
    return LaunchAluGemmS32S8(left, right, rows, k, cols, out);
}

bool SelfTestGemmKernelsOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        // Qualify the ALU shaders directly so availability does not depend on
        // TensorOps (and so a TensorOps-only pass cannot mask an ALU break).
        if (!Ctx().ready) {
            // TensorOps-only devices are still fine for ExactGemmS8S8 via MPP.
            ok = IsLtTensorOpsGemmAvailable();
            return;
        }
        constexpr uint32_t kDim = 24;
        std::vector<int8_t> left(size_t(kDim) * kDim);
        std::vector<int8_t> right(size_t(kDim) * kDim);
        std::vector<int32_t> mid(size_t(kDim) * kDim);
        for (uint32_t i = 0; i < kDim * kDim; ++i) {
            left[i] = matmul::v4::lt::FoldInt32ToEmax48(int32_t(i) * 7 - 101);
            right[i] = matmul::v4::lt::FoldInt32ToEmax48(int32_t(i) * 11 + 53);
            mid[i] = int32_t(left[i]) * 997 - 12345;
        }
        const auto cpu8 = matmul::v4::lt::ExactGemmS8S8(left, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu8;
        if (!LaunchAluGemmS8S8(left, right, kDim, kDim, kDim, gpu8) || gpu8 != cpu8) return;
        const auto cpu32 = matmul::v4::lt::ExactGemmS32S8(mid, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu32;
        if (!LaunchAluGemmS32S8(mid, right, kDim, kDim, kDim, gpu32) || gpu32 != cpu32) return;
        ok = true;
    });
    return ok;
}

bool MetalGemmS8S8Fn(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                     uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    return LaunchGemmS8S8Internal(L, R, rows, inner, cols, out);
}

bool MetalGemmS32S8Fn(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                      uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    return LaunchGemmS32S8Internal(L, R, rows, inner, cols, out);
}

matmul::v4::lt::ExactGemmBackend MakeMetalExactGemmBackend()
{
    matmul::v4::lt::ExactGemmBackend backend;
    backend.gemm_s8s8 = &MetalGemmS8S8Fn;
    backend.gemm_s32s8 = &MetalGemmS32S8Fn;
    return backend;
}

void StoreLastMxProvenance(const LtMetalMxProvenance& p)
{
    std::lock_guard<std::mutex> lock{g_mx_prov_mutex};
    g_lt_last_mx_provenance = p;
}

bool SelfTestMxProjectionOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        if (!SelfTestGemmKernelsOnce()) return;

        // n must be a multiple of kMatExpandMxBlockLen (32). Keep small for
        // process-local self-qual against the CPU MX oracle.
        constexpr uint32_t kN = 32;
        constexpr uint32_t kM = 16; // deep-m analogue (n/2 for production dims)
        const uint32_t nblk = kN / matmul::v4::lt::kMatExpandMxBlockLen;
        std::vector<int8_t> mu(size_t(kN) * kN);
        std::vector<uint8_t> scales(size_t(kN) * nblk);
        std::vector<int8_t> V(size_t(kN) * kM);
        for (uint32_t i = 0; i < kN * kN; ++i) {
            mu[i] = matmul::v4::lt::FoldInt32ToEmax48(int32_t(i) * 13 - 41);
        }
        for (uint32_t i = 0; i < kN * nblk; ++i) {
            scales[i] = static_cast<uint8_t>(i & 0x3u); // e ∈ {0,1,2,3}
        }
        for (uint32_t i = 0; i < kN * kM; ++i) {
            V[i] = matmul::v4::lt::FoldInt32ToEmax48(int32_t(i) * 17 + 7);
        }

        const matmul::v4::lt::ExactGemmBackend gemm = MakeMetalExactGemmBackend();
        const std::vector<int32_t> got =
            matmul::v4::lt::ComputeProjectedRightMxScalePartitionedGemmLT(mu, scales, V, kN, kM,
                                                                         gemm);
        if (got.empty() ||
            !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, kN, kM, got)) {
            return;
        }
        ok = true;
    });
    return ok;
}

bool LaunchProjectedRightMxInternal(const std::vector<int8_t>& mu,
                                    const std::vector<uint8_t>& scales,
                                    const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                    std::vector<int32_t>& out, LtMetalMxProvenance* provenance)
{
    out.clear();
    LtMetalMxProvenance local{};
    local.host_mx_extract = true;
    // Native Apple MX·E8M0 / FP8 dequant is never claimed here.
    local.mx.native_mxfp4_attempted = false;
    local.mx.native_mxfp4_qualified = false;
    local.mx.native_fp8_attempted = false;
    local.mx.native_fp8_qualified = false;

    if (!SelfTestMxProjectionOnce()) {
        if (provenance) *provenance = local;
        return false;
    }
    if (n == 0 || m == 0 || (n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) {
        if (provenance) *provenance = local;
        return false;
    }

    // Clear so projection_used_tensor_ops reflects only this call's GEMMs.
    g_lt_last_s8s8_tensor_ops.store(false, std::memory_order_relaxed);
    const matmul::v4::lt::ExactGemmBackend gemm = MakeMetalExactGemmBackend();
    std::vector<int32_t> Q =
        matmul::v4::lt::ComputeProjectedRightMxScalePartitionedGemmLT(mu, scales, V, n, m, gemm);
    if (Q.empty() || Q.size() != size_t(n) * m) {
        if (provenance) *provenance = local;
        return false;
    }

    local.mx.exact_mx_scale_partitioned = true;
    local.metal_exact_gemm_projection = true;
    local.projection_used_tensor_ops =
        g_lt_last_s8s8_tensor_ops.load(std::memory_order_relaxed);
    out = std::move(Q);
    if (provenance) *provenance = local;
    StoreLastMxProvenance(local);
    return true;
}

} // namespace

bool LaunchGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                    uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    return LaunchGemmS8S8Internal(left, right, rows, k, cols, out);
}

bool LaunchGemmS32S8(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
                     uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    return LaunchGemmS32S8Internal(left, right, rows, k, cols, out);
}

bool IsMatMulLTMetalAvailable()
{
    static std::once_flag once;
    std::call_once(once, [] {
        LogPrintf("MatMul-v4.4-LT Metal MX: native MXFP4/FP8 matmul2d dequant is "
                  "unavailable by design (not proven exact vs BTX M11×2^e). Peak path "
                  "is exact INT8 scale-partitioned TensorOps/ALU; optimize ExactGemm "
                  "and Extract-host + project lanes — do not claim native MX rates.\n");
    });
    return SelfTestGemmKernelsOnce();
}

bool IsMatMulLTMetalMxProjectionAvailable()
{
    return SelfTestMxProjectionOnce();
}

bool LaunchProjectedRightMxBlockScaleLT(const std::vector<int8_t>& mu,
                                        const std::vector<uint8_t>& scales,
                                        const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                        std::vector<int32_t>& out,
                                        LtMetalMxProvenance* provenance)
{
    return LaunchProjectedRightMxInternal(mu, scales, V, n, m, out, provenance);
}

bool TryLaunchLtMetalMxProjectRight(const std::vector<int8_t>& mu,
                                    const std::vector<uint8_t>& scales,
                                    const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                                    std::vector<int32_t>& out,
                                    matmul::v4::lt::MxLaneProvenance* provenance)
{
    LtMetalMxProvenance metal_prov{};
    if (!LaunchProjectedRightMxInternal(mu, scales, V, n, m, out, &metal_prov)) {
        if (provenance) *provenance = {};
        return false;
    }
    if (provenance) *provenance = metal_prov.mx;
    return true;
}

matmul::v4::lt::ExactMxProjectionBackend MakeMetalExactMxProjectionBackend()
{
    matmul::v4::lt::ExactMxProjectionBackend backend;
    if (IsMatMulLTMetalMxProjectionAvailable()) {
        backend.project_right = &TryLaunchLtMetalMxProjectRight;
    }
    return backend;
}

bool TryLaunchNativeMxfp4ProjectedRightLT(const std::vector<int8_t>& /*mu*/,
                                          const std::vector<uint8_t>& /*scales*/,
                                          const std::vector<int8_t>& /*V*/, uint32_t /*n*/,
                                          uint32_t /*m*/, std::vector<int32_t>& out,
                                          LtMetalMxProvenance* provenance)
{
    // FAIL CLOSED: Apple MPP documents FP8 / MX·E8M0 block-scale planes for
    // ML dequant inside matmul2d. That is not a self-qualified exact integer
    // match for BTX Lever-B (M11 mantissas × 2^e, e∈{0..3}). Until an exact
    // path exists, never advertise native MXFP4/FP8.
    out.clear();
    LtMetalMxProvenance local{};
    local.host_mx_extract = true;
    local.mx.native_mxfp4_attempted = false;
    local.mx.native_mxfp4_qualified = false;
    local.mx.native_fp8_attempted = false;
    local.mx.native_fp8_qualified = false;
    if (provenance) *provenance = local;
    StoreLastMxProvenance(local);
    return false;
}

bool TryLaunchResidentNativeMxProjectedRightDeviceLT(const int8_t* /*d_mu*/,
                                                     const uint8_t* /*d_scales*/,
                                                     const int8_t* /*d_V*/, int32_t* /*d_Q*/,
                                                     uint32_t /*n*/, uint32_t /*m*/,
                                                     void* /*metal_command_buffer*/,
                                                     LtMetalMxProvenance* provenance)
{
    // Amendment 1.A: fail closed — no on-device FP4/UE8M0 resident pack on Metal.
    // Never call host TryLaunchNativeMxfp4ProjectedRightLT as a resident stand-in.
    LtMetalMxProvenance local{};
    local.host_mx_extract = true;
    local.mx.native_mxfp4_attempted = false;
    local.mx.native_mxfp4_qualified = false;
    local.mx.native_fp8_attempted = false;
    local.mx.native_fp8_qualified = false;
    if (provenance) *provenance = local;
    return false;
}

bool ComputeDigestsOnlyLTMetal(const CBlockHeader& tmpl, uint32_t n,
                               const uint64_t* nonces, size_t count,
                               std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    if (nonces == nullptr || count == 0) {
        return false;
    }

    uint32_t m = 0;
    if (!matmul::v4::lt::ValidateDimsBMX4CLT(n, m)) {
        return false;
    }

    const bool gemm_ok = IsMatMulLTMetalAvailable();
    const bool mx_ok = IsMatMulLTMetalMxProjectionAvailable();
    const matmul::v4::lt::ExactGemmBackend gemm =
        gemm_ok ? MakeMetalExactGemmBackend() : matmul::v4::lt::ExactGemmBackend{};
    const matmul::v4::lt::ExactMxProjectionBackend mx_proj =
        mx_ok ? MakeMetalExactMxProjectionBackend() : matmul::v4::lt::ExactMxProjectionBackend{};

    // Prefer Metal ExactGemm MatExpand + Metal MX projection when both lanes
    // self-qual. Extract remains host-side (ExpandOperandBMatExpandMxComponents).
    // WindowSketchMinerLT also accepts ExactMxProjectionBackend; this loop keeps
    // the prepared A/U/V/P factors resident across the nonce window.
    if (gemm_ok && mx_ok) {
        namespace lt = matmul::v4::lt;
        namespace bx = matmul::v4::bmx4;
        const auto [seed_u, seed_v] = lt::DeriveProjectorSeedsBMX4CLT(tmpl);
        const std::vector<int8_t> A = lt::ExpandOperandAMatExpand(tmpl, n, gemm);
        const std::vector<int8_t> U = bx::ExpandProjectorBMX4C(seed_u, m, n);
        const std::vector<int8_t> V = bx::ExpandProjectorBMX4C(seed_v, n, m);
        const std::vector<int32_t> P = matmul::v4::ComputeProjectedLeft(U, A, n, m);

        out.reserve(count);
        LtMetalMxProvenance last_prov{};
        for (size_t i = 0; i < count; ++i) {
            CBlockHeader header = tmpl;
            header.nNonce64 = nonces[i];
            header.nNonce = static_cast<uint32_t>(nonces[i]);

            std::vector<int8_t> mu;
            std::vector<uint8_t> scales;
            lt::ExpandOperandBMatExpandMxComponents(header, n, gemm, mu, scales);

            std::vector<int32_t> Q;
            LtMetalMxProvenance prov{};
            if (!LaunchProjectedRightMxBlockScaleLT(mu, scales, V, n, m, Q, &prov)) {
                out.clear();
                return false;
            }
            last_prov = prov;
            const std::vector<matmul::v4::Fq> Chat = matmul::v4::ComputeCombineModQ(P, Q, n, m);
            const uint256 sigma = matmul::v4::DeriveSigma(header);

            matmul::v4::lt::DigestOnlyResultLT res;
            res.nonce = nonces[i];
            res.digest = matmul::v4::ComputeSketchDigestFromFq(sigma, Chat);
            res.target_match = false;
            res.backend_status = matmul::v4::bmx4::DigestOnlyBackendStatus::Ok;
            out.push_back(std::move(res));
        }
        StoreLastMxProvenance(last_prov);
        return true;
    }

    // Fail-closed GEMM / MX: inject available Metal lanes into WindowSketchMinerLT
    // (ComputeProjectedRightMxDispatched fails closed to the CPU oracle).
    matmul::v4::lt::WindowSketchMinerLT miner(tmpl, n, gemm, mx_proj);
    if (!miner.Valid()) {
        return false;
    }

    const std::vector<uint64_t> nonce_vec(nonces, nonces + count);
    const uint256 kNoTarget = ArithToUint256(~arith_uint256{});
    std::vector<matmul::v4::lt::DigestOnlyResultLT> results;
    if (!miner.Mine(nonce_vec, kNoTarget, results, nullptr)) {
        return false;
    }
    const auto status = gemm_ok ? matmul::v4::bmx4::DigestOnlyBackendStatus::Ok
                                : matmul::v4::bmx4::DigestOnlyBackendStatus::Fallback;
    for (auto& r : results) {
        r.target_match = false;
        r.backend_status = status;
    }
    LtMetalMxProvenance fallback_prov{};
    fallback_prov.host_mx_extract = true;
    fallback_prov.mx.exact_mx_scale_partitioned = true; // CPU oracle path
    StoreLastMxProvenance(fallback_prov);
    out = std::move(results);
    return true;
}

LtMetalMxProvenance LtLastMetalMxProvenance()
{
    std::lock_guard<std::mutex> lock{g_mx_prov_mutex};
    return g_lt_last_mx_provenance;
}

bool LtLastS8S8UsedTensorOps()
{
    return g_lt_last_s8s8_tensor_ops.load(std::memory_order_relaxed);
}

} // namespace matmul_v4::metal
