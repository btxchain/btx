// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal host glue for MatMul v4.4 ENC-DR-LT (MatExpand).
// Exact int8×int8→int32 and int32×int8→int32 GEMM compute kernels (MSL),
// self-tested against ExactGemm*, with persistent MTLBuffer scratch reuse
// across launches. Injected via ExactGemmBackend into WindowSketchMinerLT
// (fail-closed host ExactGemm when Metal declines). Fuller
// MatExpand→project→combine device residency lives on the CUDA/HIP LT
// backends; this TU keeps Metal's GEMM offload + buffer reuse honest.

#include <metal/matmul_v4_lt_accel.h>

#include <arith_uint256.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <primitives/block.h>
#include <uint256.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <cstdint>
#include <cstring>
#include <algorithm>
#include <mutex>
#include <vector>

namespace matmul_v4::metal {
namespace {

static NSString* const kGemmLibrarySource = @R"MSL(
#include <metal_stdlib>
using namespace metal;

kernel void gemm_s8s8(device const char* A [[buffer(0)]],
                      device const char* B [[buffer(1)]],
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
        acc += int(A[arow + size_t(k)]) * int(B[size_t(k) * size_t(N) + size_t(col)]);
    }
    D[size_t(row) * size_t(N) + size_t(col)] = acc;
}

kernel void gemm_s32s8(device const int* A [[buffer(0)]],
                       device const char* B [[buffer(1)]],
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

    [[nodiscard]] bool EnsureScratch(size_t a_bytes, size_t b_bytes, size_t d_bytes)
    {
        auto grow = [&](id<MTLBuffer>& buf, size_t& have, size_t need) -> bool {
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

bool LaunchGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                    uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    if (TryLaunchLtTensorOpsGemmS8S8(left, right, rows, k, cols, out)) {
        return true;
    }
    auto& ctx = Ctx();
    if (!ctx.ready) return false;
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }

    const size_t lhs_bytes = size_t(rows) * k * sizeof(int8_t);
    const size_t rhs_bytes = size_t(k) * cols * sizeof(int8_t);
    const size_t out_bytes = size_t(rows) * cols * sizeof(int32_t);

    if (!ctx.EnsureScratch(lhs_bytes, rhs_bytes, out_bytes)) return false;
    std::memcpy([ctx.scratchA contents], left.data(), lhs_bytes);
    std::memcpy([ctx.scratchB contents], right.data(), rhs_bytes);

    int M = int(rows), N = int(cols), K = int(k);
    id<MTLBuffer> bM = [ctx.device newBufferWithBytes:&M length:sizeof(M) options:MTLResourceStorageModeShared];
    id<MTLBuffer> bN = [ctx.device newBufferWithBytes:&N length:sizeof(N) options:MTLResourceStorageModeShared];
    id<MTLBuffer> bK = [ctx.device newBufferWithBytes:&K length:sizeof(K) options:MTLResourceStorageModeShared];

    id<MTLCommandBuffer> cmd = [ctx.queue commandBuffer];
    id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
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

    out.resize(size_t(rows) * cols);
    std::memcpy(out.data(), [ctx.scratchD contents], out_bytes);
    return true;
}

bool LaunchGemmS32S8(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
                     uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    if (TryLaunchLtTensorOpsGemmS32S8(left, right, rows, k, cols, out)) {
        return true;
    }
    auto& ctx = Ctx();
    if (!ctx.ready) return false;
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }

    const size_t lhs_bytes = size_t(rows) * k * sizeof(int32_t);
    const size_t rhs_bytes = size_t(k) * cols * sizeof(int8_t);
    const size_t out_bytes = size_t(rows) * cols * sizeof(int32_t);

    if (!ctx.EnsureScratch(lhs_bytes, rhs_bytes, out_bytes)) return false;
    std::memcpy([ctx.scratchA contents], left.data(), lhs_bytes);
    std::memcpy([ctx.scratchB contents], right.data(), rhs_bytes);

    int M = int(rows), N = int(cols), K = int(k);
    id<MTLBuffer> bM = [ctx.device newBufferWithBytes:&M length:sizeof(M) options:MTLResourceStorageModeShared];
    id<MTLBuffer> bN = [ctx.device newBufferWithBytes:&N length:sizeof(N) options:MTLResourceStorageModeShared];
    id<MTLBuffer> bK = [ctx.device newBufferWithBytes:&K length:sizeof(K) options:MTLResourceStorageModeShared];

    id<MTLCommandBuffer> cmd = [ctx.queue commandBuffer];
    id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
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

    out.resize(size_t(rows) * cols);
    std::memcpy(out.data(), [ctx.scratchD contents], out_bytes);
    return true;
}

bool SelfTestGemmKernelsOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        if (!Ctx().ready) return;
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
        if (!LaunchGemmS8S8(left, right, kDim, kDim, kDim, gpu8) || gpu8 != cpu8) return;
        const auto cpu32 = matmul::v4::lt::ExactGemmS32S8(mid, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu32;
        if (!LaunchGemmS32S8(mid, right, kDim, kDim, kDim, gpu32) || gpu32 != cpu32) return;
        ok = true;
    });
    return ok;
}

bool MetalGemmS8S8Fn(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                     uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    return LaunchGemmS8S8(L, R, rows, inner, cols, out);
}

bool MetalGemmS32S8Fn(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                      uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    return LaunchGemmS32S8(L, R, rows, inner, cols, out);
}

matmul::v4::lt::ExactGemmBackend MakeMetalExactGemmBackend()
{
    matmul::v4::lt::ExactGemmBackend backend;
    backend.gemm_s8s8 = &MetalGemmS8S8Fn;
    backend.gemm_s32s8 = &MetalGemmS32S8Fn;
    return backend;
}

} // namespace

bool IsMatMulLTMetalAvailable()
{
    return SelfTestGemmKernelsOnce();
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

    const bool device_ok = IsMatMulLTMetalAvailable();
    matmul::v4::lt::WindowSketchMinerLT miner(
        tmpl, n, device_ok ? MakeMetalExactGemmBackend() : matmul::v4::lt::ExactGemmBackend{});
    if (!miner.Valid()) {
        return false;
    }

    const std::vector<uint64_t> nonce_vec(nonces, nonces + count);
    const uint256 kNoTarget = ArithToUint256(~arith_uint256{});
    std::vector<matmul::v4::lt::DigestOnlyResultLT> results;
    if (!miner.Mine(nonce_vec, kNoTarget, results, nullptr)) {
        return false;
    }
    const auto status = device_ok ? matmul::v4::bmx4::DigestOnlyBackendStatus::Ok
                                  : matmul::v4::bmx4::DigestOnlyBackendStatus::Fallback;
    for (auto& r : results) {
        r.target_match = false;
        r.backend_status = status;
    }
    out = std::move(results);
    return true;
}

} // namespace matmul_v4::metal
