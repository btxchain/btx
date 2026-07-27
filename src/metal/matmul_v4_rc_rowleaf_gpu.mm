// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal implementation of the Stage-3 Poseidon2 row-leaf accelerator.
// It implements the same provider-neutral C ABI as the CUDA backend, allowing
// the existing real-proof audit and no-silent-fallback policy to remain the
// sole caller-side authority.

#include <matmul/matmul_v4_rc_rowleaf_gpu.h>

#include "matmul_v4_rc_rowleaf_gpu_source.h"

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <string>

namespace {

using u32 = uint32_t;
using u64 = uint64_t;

constexpr u32 kPoseidonWidth = 12;
constexpr u32 kDigestWidth = 4;
constexpr u32 kMaxLanesPerAbsorb = 3072;
constexpr u64 kStagingBudgetBytes = u64{1} << 28; // match CUDA: 256 MiB

struct alignas(8) P2Constants {
    u64 rc_ext[8 * 12];
    u64 rc_int[22];
    u64 mu[12];
};

struct alignas(8) AbsorbParams {
    u32 n_lde;
    u32 n_lanes;
    u64 base_pos;
};

struct alignas(8) FinalizeParams {
    u32 n_lde;
    u32 reserved;
    u64 total_vals;
};

static_assert(sizeof(P2Constants) == (8 * 12 + 22 + 12) * sizeof(u64));
static_assert(sizeof(AbsorbParams) == 16);
static_assert(sizeof(FinalizeParams) == 16);

id<MTLComputePipelineState> MakePipeline(id<MTLDevice> device,
                                         id<MTLLibrary> library,
                                         NSString* name,
                                         std::string& error)
{
    id<MTLFunction> function = [library newFunctionWithName:name];
    if (function == nil) {
        error = std::string{"missing Metal function "} + [name UTF8String];
        return nil;
    }
    NSError* pipeline_error = nil;
    id<MTLComputePipelineState> pipeline =
        [device newComputePipelineStateWithFunction:function error:&pipeline_error];
    if (pipeline == nil) {
        error = pipeline_error != nil
            ? [[pipeline_error localizedDescription] UTF8String]
            : std::string{"failed to create Metal pipeline "} + [name UTF8String];
    }
    return pipeline;
}

struct MetalRowLeafRuntime {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> absorb_pipeline{nil};
    id<MTLComputePipelineState> finalize_pipeline{nil};
    id<MTLBuffer> constants{nil};
    P2Constants constants_host{};
    bool constants_set{false};
    std::string error;
    std::mutex mutex;

    MetalRowLeafRuntime()
    {
        @autoreleasepool {
            NSArray<id<MTLDevice>>* devices = MTLCopyAllDevices();
            if (devices == nil || devices.count == 0) {
                error = "no Metal-compatible device";
                return;
            }
            device = devices[0];
            queue = [device newCommandQueue];
            if (queue == nil) {
                error = "failed to create Metal command queue";
                return;
            }

            id<MTLLibrary> library = nil;
            NSError* library_error = nil;
#if defined(BTX_RC_ROWLEAF_METALLIB_PATH)
            NSString* path =
                [NSString stringWithUTF8String:BTX_RC_ROWLEAF_METALLIB_PATH];
            if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
                library = [device
                    newLibraryWithURL:[NSURL fileURLWithPath:path]
                                error:&library_error];
            }
#endif
            if (library == nil) {
                library_error = nil;
                library = [device
                    newLibraryWithSource:
                        [NSString stringWithUTF8String:
                            kBtxRcRowLeafMetalKernelSource]
                                  options:nil
                                    error:&library_error];
            }
            if (library == nil) {
                error = library_error != nil
                    ? [[library_error localizedDescription] UTF8String]
                    : "failed to compile Stage-3 row-leaf Metal kernels";
                return;
            }
            absorb_pipeline =
                MakePipeline(device, library, @"btx_rc_rowleaf_absorb", error);
            if (absorb_pipeline == nil) return;
            finalize_pipeline =
                MakePipeline(device, library, @"btx_rc_rowleaf_finalize", error);
        }
    }

    bool Ready() const
    {
        return device != nil && queue != nil && absorb_pipeline != nil &&
            finalize_pipeline != nil;
    }
};

MetalRowLeafRuntime& Runtime()
{
    static MetalRowLeafRuntime runtime;
    return runtime;
}

struct RowLeafCtx {
    id<MTLBuffer> state{nil};
    id<MTLBuffer> block{nil};
    id<MTLBuffer> digests{nil};
    u32 n_lde{0};
    u32 max_lanes{0};
    u64 absorbed{0};
};

void Report(const char* where, const std::string& detail)
{
    std::fprintf(stderr, "[BTX_GPU_ROWLEAF] Metal error in %s: %s\n",
                 where, detail.c_str());
}

bool CheckedBytes(u64 count, u64 element_size, NSUInteger& out)
{
    if (element_size != 0 &&
        count > std::numeric_limits<u64>::max() / element_size) {
        return false;
    }
    const u64 bytes = count * element_size;
    if (bytes > std::numeric_limits<NSUInteger>::max()) return false;
    out = static_cast<NSUInteger>(bytes);
    return true;
}

NSUInteger ThreadsPerGroup(id<MTLComputePipelineState> pipeline, u32 n)
{
    static const NSUInteger requested = [] {
        const char* value = std::getenv("BTX_METAL_ROWLEAF_THREADS");
        if (value == nullptr || value[0] == '\0') return NSUInteger{64};
        char* end = nullptr;
        const unsigned long parsed = std::strtoul(value, &end, 10);
        if (end == value || *end != '\0' || parsed == 0) {
            std::fprintf(stderr,
                         "[BTX_GPU_ROWLEAF] invalid "
                         "BTX_METAL_ROWLEAF_THREADS=%s; using 64\n",
                         value);
            return NSUInteger{64};
        }
        return static_cast<NSUInteger>(parsed);
    }();
    NSUInteger width = std::max<NSUInteger>(1, pipeline.threadExecutionWidth);
    NSUInteger threads = std::min(
        requested, pipeline.maxTotalThreadsPerThreadgroup);
    threads = std::min<NSUInteger>(threads, n);
    if (threads >= width) threads = (threads / width) * width;
    return std::max<NSUInteger>(1, threads);
}

bool CompleteCommand(id<MTLCommandBuffer> command, const char* where)
{
    [command commit];
    [command waitUntilCompleted];
    if (command.status == MTLCommandBufferStatusCompleted) return true;
    NSString* message = command.error != nil
        ? [command.error localizedDescription]
        : @"command did not complete";
    Report(where, [message UTF8String]);
    return false;
}

bool DispatchAbsorb(MetalRowLeafRuntime& runtime, RowLeafCtx& ctx,
                    u32 n_lanes, u64 base_pos)
{
    @autoreleasepool {
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder =
            [command computeCommandEncoder];
        if (command == nil || encoder == nil) {
            Report("Absorb", "failed to create command encoder");
            return false;
        }
        const AbsorbParams params{ctx.n_lde, n_lanes, base_pos};
        [encoder setComputePipelineState:runtime.absorb_pipeline];
        [encoder setBytes:&params length:sizeof(params) atIndex:0];
        [encoder setBuffer:runtime.constants offset:0 atIndex:1];
        [encoder setBuffer:ctx.state offset:0 atIndex:2];
        [encoder setBuffer:ctx.block offset:0 atIndex:3];
        const MTLSize grid = MTLSizeMake(ctx.n_lde, 1, 1);
        const MTLSize group = MTLSizeMake(
            ThreadsPerGroup(runtime.absorb_pipeline, ctx.n_lde), 1, 1);
        [encoder dispatchThreads:grid threadsPerThreadgroup:group];
        [encoder endEncoding];
        return CompleteCommand(command, "Absorb");
    }
}

bool DispatchFinalize(MetalRowLeafRuntime& runtime, RowLeafCtx& ctx,
                      u64 total_vals)
{
    @autoreleasepool {
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder =
            [command computeCommandEncoder];
        if (command == nil || encoder == nil) {
            Report("Finalize", "failed to create command encoder");
            return false;
        }
        const FinalizeParams params{ctx.n_lde, 0, total_vals};
        [encoder setComputePipelineState:runtime.finalize_pipeline];
        [encoder setBytes:&params length:sizeof(params) atIndex:0];
        [encoder setBuffer:runtime.constants offset:0 atIndex:1];
        [encoder setBuffer:ctx.state offset:0 atIndex:2];
        [encoder setBuffer:ctx.digests offset:0 atIndex:3];
        const MTLSize grid = MTLSizeMake(ctx.n_lde, 1, 1);
        const MTLSize group = MTLSizeMake(
            ThreadsPerGroup(runtime.finalize_pipeline, ctx.n_lde), 1, 1);
        [encoder dispatchThreads:grid threadsPerThreadgroup:group];
        [encoder endEncoding];
        return CompleteCommand(command, "Finalize");
    }
}

} // namespace

extern "C" int BtxGpuRowLeafAvailable(void)
{
    return Runtime().Ready() ? 1 : 0;
}

extern "C" int BtxGpuRowLeafSetConstants(const u64* rc_ext_8x12,
                                         const u64* rc_int_22,
                                         const u64* mu_12)
{
    if (rc_ext_8x12 == nullptr || rc_int_22 == nullptr || mu_12 == nullptr) {
        return -1;
    }
    MetalRowLeafRuntime& runtime = Runtime();
    std::lock_guard<std::mutex> lock(runtime.mutex);
    if (!runtime.Ready()) {
        Report("SetConstants", runtime.error);
        return -2;
    }
    @autoreleasepool {
        P2Constants packed{};
        std::memcpy(packed.rc_ext, rc_ext_8x12, sizeof(packed.rc_ext));
        std::memcpy(packed.rc_int, rc_int_22, sizeof(packed.rc_int));
        std::memcpy(packed.mu, mu_12, sizeof(packed.mu));
        // Constants are consensus data and immutable after first publication.
        // The dense and streaming callers intentionally have separate
        // once_flags, so a concurrent second upload is valid only when its
        // bytes are identical. Keeping the buffer immutable also lets command
        // encoding read it without holding the provider-wide allocation lock.
        if (runtime.constants_set) {
            if (std::memcmp(&runtime.constants_host, &packed,
                            sizeof(packed)) != 0) {
                Report("SetConstants",
                       "refusing to replace initialized consensus constants");
                return -1;
            }
            return 0;
        }
        id<MTLBuffer> new_constants = [runtime.device
            newBufferWithBytes:&packed
                        length:sizeof(packed)
                       options:MTLResourceStorageModeShared];
        if (new_constants == nil) {
            Report("SetConstants", "failed to allocate constants buffer");
            return -2;
        }
        // Publish only after successful allocation. A failed upload must not
        // discard a previously usable provider state.
        runtime.constants = new_constants;
        runtime.constants_host = packed;
        runtime.constants_set = true;
    }
    return 0;
}

extern "C" int BtxGpuRowLeafBegin(u32 n_lde, void** ctx_out)
{
    if (ctx_out == nullptr || n_lde == 0 ||
        (n_lde & (n_lde - 1)) != 0) {
        return -1;
    }
    *ctx_out = nullptr;
    MetalRowLeafRuntime& runtime = Runtime();
    std::lock_guard<std::mutex> lock(runtime.mutex);
    if (!runtime.Ready() || !runtime.constants_set) {
        Report("Begin", runtime.Ready() ? "constants not set" : runtime.error);
        return -2;
    }

    RowLeafCtx* ctx = new (std::nothrow) RowLeafCtx();
    if (ctx == nullptr) return -2;
    ctx->n_lde = n_lde;
    u64 lanes = kStagingBudgetBytes / (u64{n_lde} * sizeof(u64));
    lanes = std::clamp<u64>(lanes, 3, kMaxLanesPerAbsorb);
    ctx->max_lanes = static_cast<u32>(lanes);

    NSUInteger state_bytes = 0;
    NSUInteger block_bytes = 0;
    NSUInteger digest_bytes = 0;
    if (!CheckedBytes(u64{n_lde} * kPoseidonWidth, sizeof(u64), state_bytes) ||
        !CheckedBytes(u64{n_lde} * ctx->max_lanes, sizeof(u64), block_bytes) ||
        !CheckedBytes(u64{n_lde} * kDigestWidth, sizeof(u64), digest_bytes) ||
        state_bytes > runtime.device.maxBufferLength ||
        block_bytes > runtime.device.maxBufferLength ||
        digest_bytes > runtime.device.maxBufferLength) {
        Report("Begin", "requested buffer exceeds Metal device limits");
        delete ctx;
        return -2;
    }
    @autoreleasepool {
        ctx->state = [runtime.device
            newBufferWithLength:state_bytes
                        options:MTLResourceStorageModeShared];
        ctx->block = [runtime.device
            newBufferWithLength:block_bytes
                        options:MTLResourceStorageModeShared |
                            MTLResourceCPUCacheModeWriteCombined];
        ctx->digests = [runtime.device
            newBufferWithLength:digest_bytes
                        options:MTLResourceStorageModeShared];
    }
    if (ctx->state == nil || ctx->block == nil || ctx->digests == nil) {
        Report("Begin", "Metal buffer allocation failed");
        delete ctx;
        return -2;
    }
    std::memset(ctx->state.contents, 0, state_bytes);
    *ctx_out = ctx;
    return 0;
}

extern "C" int BtxGpuRowLeafAbsorb(void* opaque, const u64* block,
                                   u32 n_lanes, u64 base_pos)
{
    RowLeafCtx* ctx = static_cast<RowLeafCtx*>(opaque);
    if (ctx == nullptr || block == nullptr || n_lanes == 0) return -1;
    if (base_pos != ctx->absorbed) {
        std::fprintf(stderr,
                     "[BTX_GPU_ROWLEAF] Metal absorb out of order: "
                     "base_pos=%llu expected=%llu\n",
                     static_cast<unsigned long long>(base_pos),
                     static_cast<unsigned long long>(ctx->absorbed));
        return -1;
    }
    MetalRowLeafRuntime& runtime = Runtime();
    for (u32 offset = 0; offset < n_lanes; offset += ctx->max_lanes) {
        const u32 count = std::min(ctx->max_lanes, n_lanes - offset);
        const size_t bytes =
            static_cast<size_t>(count) * ctx->n_lde * sizeof(u64);
        std::memcpy(ctx->block.contents,
                    block + static_cast<u64>(offset) * ctx->n_lde, bytes);
        if (!DispatchAbsorb(runtime, *ctx, count, base_pos + offset)) {
            return -2;
        }
    }
    ctx->absorbed += n_lanes;
    return 0;
}

extern "C" int BtxGpuRowLeafFinalize(void* opaque, u64 total_vals,
                                     u64* out_digests)
{
    RowLeafCtx* ctx = static_cast<RowLeafCtx*>(opaque);
    if (ctx == nullptr || out_digests == nullptr) return -1;
    if (total_vals == 0 || total_vals != ctx->absorbed) {
        std::fprintf(stderr,
                     "[BTX_GPU_ROWLEAF] Metal finalize count mismatch: "
                     "total=%llu absorbed=%llu\n",
                     static_cast<unsigned long long>(total_vals),
                     static_cast<unsigned long long>(ctx->absorbed));
        BtxGpuRowLeafRelease(ctx);
        return -1;
    }
    const size_t bytes =
        static_cast<size_t>(ctx->n_lde) * kDigestWidth * sizeof(u64);
    const bool ok = DispatchFinalize(Runtime(), *ctx, total_vals);
    if (ok) std::memcpy(out_digests, ctx->digests.contents, bytes);
    BtxGpuRowLeafRelease(ctx);
    return ok ? 0 : -2;
}

extern "C" void BtxGpuRowLeafRelease(void* opaque)
{
    delete static_cast<RowLeafCtx*>(opaque);
}
