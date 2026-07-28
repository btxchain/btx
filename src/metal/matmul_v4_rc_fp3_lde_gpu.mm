// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal first-slice implementation of the Stage-3 Fp3 NTT/LDE.

#include <matmul/matmul_v4_rc_fp3_lde_gpu.h>

#include "matmul_v4_rc_fp3_lde_gpu_source.h"

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>
#include <string>

namespace {

using u32 = uint32_t;
using u64 = uint64_t;

struct alignas(8) PermuteParams {
    u32 n;
    u32 log_n;
};

struct alignas(8) StageParams {
    u32 n;
    u32 len;
    u32 root_stride;
    u32 reserved;
};

struct alignas(8) ScaleParams {
    u32 n;
    u32 reserved;
    u64 scale;
};

static_assert(sizeof(PermuteParams) == 8);
static_assert(sizeof(StageParams) == 16);
static_assert(sizeof(ScaleParams) == 16);

void Report(const char* where, const std::string& detail)
{
    std::fprintf(stderr, "[BTX_METAL_FP3_LDE] error in %s: %s\n",
                 where, detail.c_str());
}

bool IsPowerOfTwo(u32 n)
{
    return n != 0 && (n & (n - 1)) == 0;
}

u32 Log2Exact(u32 n)
{
    u32 log_n = 0;
    while (n > 1) {
        n >>= 1;
        ++log_n;
    }
    return log_n;
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
        [device newComputePipelineStateWithFunction:function
                                               error:&pipeline_error];
    if (pipeline == nil) {
        error = pipeline_error != nil
            ? [[pipeline_error localizedDescription] UTF8String]
            : std::string{"failed to create Metal pipeline "} +
                [name UTF8String];
    }
    return pipeline;
}

struct MetalFp3LdeRuntime {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> bit_reverse_pipeline{nil};
    id<MTLComputePipelineState> stage_pipeline{nil};
    id<MTLComputePipelineState> scale_pipeline{nil};
    std::string error;

    MetalFp3LdeRuntime()
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
#if defined(BTX_RC_FP3_LDE_METALLIB_PATH)
            NSString* path =
                [NSString stringWithUTF8String:BTX_RC_FP3_LDE_METALLIB_PATH];
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
                            kBtxRcFp3LdeMetalKernelSource]
                                  options:nil
                                    error:&library_error];
            }
            if (library == nil) {
                error = library_error != nil
                    ? [[library_error localizedDescription] UTF8String]
                    : "failed to compile Fp3 LDE Metal kernels";
                return;
            }
            bit_reverse_pipeline = MakePipeline(
                device, library, @"btx_rc_fp3_ntt_bit_reverse", error);
            if (bit_reverse_pipeline == nil) return;
            stage_pipeline = MakePipeline(
                device, library, @"btx_rc_fp3_ntt_stage", error);
            if (stage_pipeline == nil) return;
            scale_pipeline = MakePipeline(
                device, library, @"btx_rc_fp3_ntt_scale", error);
        }
    }

    bool Ready() const
    {
        return device != nil && queue != nil &&
            bit_reverse_pipeline != nil && stage_pipeline != nil &&
            scale_pipeline != nil;
    }
};

MetalFp3LdeRuntime& Runtime()
{
    static MetalFp3LdeRuntime runtime;
    return runtime;
}

struct Fp3LdeCtx {
    id<MTLBuffer> forward_roots{nil};
    id<MTLBuffer> inverse_roots{nil};
    id<MTLBuffer> work{nil};
    u32 n{0};
    u32 log_n{0};
    u64 inverse_n{0};
    NSUInteger work_bytes{0};
    std::atomic_flag busy = ATOMIC_FLAG_INIT;
};

class OperationGuard {
private:
    Fp3LdeCtx& m_ctx;
    bool m_acquired;

public:
    explicit OperationGuard(Fp3LdeCtx& ctx)
        : m_ctx(ctx),
          m_acquired(!m_ctx.busy.test_and_set(std::memory_order_acquire))
    {
    }

    ~OperationGuard()
    {
        if (m_acquired) {
            m_ctx.busy.clear(std::memory_order_release);
        }
    }

    explicit operator bool() const { return m_acquired; }
};

NSUInteger ThreadsPerGroup(id<MTLComputePipelineState> pipeline, u32 count)
{
    const NSUInteger execution_width =
        std::max<NSUInteger>(1, pipeline.threadExecutionWidth);
    NSUInteger threads = std::min<NSUInteger>(
        256, pipeline.maxTotalThreadsPerThreadgroup);
    threads = std::min<NSUInteger>(threads, count);
    if (threads >= execution_width) {
        threads = (threads / execution_width) * execution_width;
    }
    return std::max<NSUInteger>(1, threads);
}

void Dispatch(id<MTLComputeCommandEncoder> encoder,
              id<MTLComputePipelineState> pipeline, u32 count)
{
    const MTLSize grid = MTLSizeMake(count, 1, 1);
    const MTLSize group =
        MTLSizeMake(ThreadsPerGroup(pipeline, count), 1, 1);
    [encoder dispatchThreads:grid threadsPerThreadgroup:group];
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

bool EncodeTransform(Fp3LdeCtx& ctx, bool inverse)
{
    MetalFp3LdeRuntime& runtime = Runtime();
    @autoreleasepool {
        id<MTLCommandBuffer> command = [runtime.queue commandBuffer];
        id<MTLComputeCommandEncoder> encoder =
            [command computeCommandEncoder];
        if (command == nil || encoder == nil) {
            Report(inverse ? "Inverse" : "Forward",
                   "failed to create command encoder");
            return false;
        }

        const PermuteParams permute{ctx.n, ctx.log_n};
        [encoder setComputePipelineState:runtime.bit_reverse_pipeline];
        [encoder setBytes:&permute length:sizeof(permute) atIndex:0];
        [encoder setBuffer:ctx.work offset:0 atIndex:1];
        Dispatch(encoder, runtime.bit_reverse_pipeline, ctx.n);

        id<MTLBuffer> roots =
            inverse ? ctx.inverse_roots : ctx.forward_roots;
        for (u64 len64 = 2; len64 <= ctx.n; len64 <<= 1) {
            const u32 len = static_cast<u32>(len64);
            const StageParams stage{
                ctx.n, len, ctx.n / len, 0};
            [encoder setComputePipelineState:runtime.stage_pipeline];
            [encoder setBytes:&stage length:sizeof(stage) atIndex:0];
            [encoder setBuffer:ctx.work offset:0 atIndex:1];
            [encoder setBuffer:roots offset:0 atIndex:2];
            Dispatch(encoder, runtime.stage_pipeline, ctx.n / 2);
        }

        if (inverse) {
            const ScaleParams scale{ctx.n, 0, ctx.inverse_n};
            [encoder setComputePipelineState:runtime.scale_pipeline];
            [encoder setBytes:&scale length:sizeof(scale) atIndex:0];
            [encoder setBuffer:ctx.work offset:0 atIndex:1];
            Dispatch(encoder, runtime.scale_pipeline, ctx.n);
        }
        [encoder endEncoding];
        return CompleteCommand(command, inverse ? "Inverse" : "Forward");
    }
}

int Transform(Fp3LdeCtx* ctx, const u64* input, u32 input_count,
              bool inverse, u64* output)
{
    if (ctx == nullptr || output == nullptr || input_count > ctx->n ||
        (input_count != 0 && input == nullptr)) {
        return -1;
    }
    OperationGuard guard(*ctx);
    if (!guard) {
        Report(inverse ? "Inverse" : "Forward",
               "concurrent use of one transform context is not allowed");
        return -1;
    }
    std::memset(ctx->work.contents, 0, ctx->work_bytes);
    if (input_count != 0) {
        const size_t input_bytes =
            static_cast<size_t>(input_count) * 3 * sizeof(u64);
        std::memcpy(ctx->work.contents, input, input_bytes);
    }
    if (!EncodeTransform(*ctx, inverse)) return -2;
    std::memcpy(output, ctx->work.contents, ctx->work_bytes);
    return 0;
}

} // namespace

extern "C" int BtxMetalFp3LdeAvailable(void)
{
    return Runtime().Ready() ? 1 : 0;
}

extern "C" int BtxMetalFp3LdeBegin(
    u32 domain_size, const u64* forward_roots, u32 forward_root_count,
    const u64* inverse_roots, u32 inverse_root_count, u64 inverse_n,
    void** ctx_out)
{
    if (ctx_out == nullptr || !IsPowerOfTwo(domain_size)) return -1;
    *ctx_out = nullptr;
    const u32 required_roots = domain_size / 2;
    if (forward_root_count != required_roots ||
        inverse_root_count != required_roots ||
        (required_roots != 0 &&
         (forward_roots == nullptr || inverse_roots == nullptr))) {
        return -1;
    }

    MetalFp3LdeRuntime& runtime = Runtime();
    if (!runtime.Ready()) {
        Report("Begin", runtime.error);
        return -2;
    }

    NSUInteger work_bytes = 0;
    NSUInteger root_bytes = 0;
    if (!CheckedBytes(static_cast<u64>(domain_size) * 3, sizeof(u64),
                      work_bytes) ||
        !CheckedBytes(required_roots, sizeof(u64), root_bytes) ||
        work_bytes > runtime.device.maxBufferLength ||
        root_bytes > runtime.device.maxBufferLength) {
        Report("Begin", "requested domain exceeds Metal buffer limits");
        return -2;
    }

    Fp3LdeCtx* ctx = new (std::nothrow) Fp3LdeCtx();
    if (ctx == nullptr) return -2;
    ctx->n = domain_size;
    ctx->log_n = Log2Exact(domain_size);
    ctx->inverse_n = inverse_n;
    ctx->work_bytes = work_bytes;

    @autoreleasepool {
        ctx->work = [runtime.device
            newBufferWithLength:work_bytes
                        options:MTLResourceStorageModeShared];
        if (required_roots != 0) {
            ctx->forward_roots = [runtime.device
                newBufferWithBytes:forward_roots
                            length:root_bytes
                           options:MTLResourceStorageModeShared];
            ctx->inverse_roots = [runtime.device
                newBufferWithBytes:inverse_roots
                            length:root_bytes
                           options:MTLResourceStorageModeShared];
        }
    }
    if (ctx->work == nil ||
        (required_roots != 0 &&
         (ctx->forward_roots == nil || ctx->inverse_roots == nil))) {
        Report("Begin", "Metal buffer allocation failed");
        delete ctx;
        return -2;
    }
    *ctx_out = ctx;
    return 0;
}

extern "C" int BtxMetalFp3LdeForward(void* opaque, const u64* coeffs_aos,
                                     u32 coeff_count, u64* out_evals_aos)
{
    return Transform(static_cast<Fp3LdeCtx*>(opaque), coeffs_aos,
                     coeff_count, /*inverse=*/false, out_evals_aos);
}

extern "C" int BtxMetalFp3LdeInverse(void* opaque, const u64* evals_aos,
                                     u64* out_coeffs_aos)
{
    Fp3LdeCtx* ctx = static_cast<Fp3LdeCtx*>(opaque);
    if (ctx == nullptr) return -1;
    return Transform(ctx, evals_aos, ctx->n, /*inverse=*/true,
                     out_coeffs_aos);
}

extern "C" void BtxMetalFp3LdeRelease(void* opaque)
{
    delete static_cast<Fp3LdeCtx*>(opaque);
}

// Provider-neutral ABI used by BTX_GPU_LDE. Only compiled into Apple Metal
// builds that do not also link the CUDA provider (CMake excludes this TU's
// BtxGpu* symbols when CUDA ON by compiling the CUDA .cu instead and not
// defining these on CUDA hosts). On Metal-only builds these wrap Metal.
#if !defined(BTX_CUDA_FP3_LDE_PROVIDER)
extern "C" int BtxGpuFp3LdeAvailable(void)
{
    return BtxMetalFp3LdeAvailable();
}

extern "C" int BtxGpuFp3LdeBegin(u32 domain_size, const u64* forward_roots,
                                 u32 forward_root_count,
                                 const u64* inverse_roots,
                                 u32 inverse_root_count, u64 inverse_n,
                                 void** ctx_out)
{
    return BtxMetalFp3LdeBegin(domain_size, forward_roots, forward_root_count,
                               inverse_roots, inverse_root_count, inverse_n,
                               ctx_out);
}

extern "C" int BtxGpuFp3LdeForward(void* ctx, const u64* coeffs_aos,
                                   u32 coeff_count, u64* out_evals_aos)
{
    return BtxMetalFp3LdeForward(ctx, coeffs_aos, coeff_count, out_evals_aos);
}

extern "C" int BtxGpuFp3LdeInverse(void* ctx, const u64* evals_aos,
                                   u64* out_coeffs_aos)
{
    return BtxMetalFp3LdeInverse(ctx, evals_aos, out_coeffs_aos);
}

extern "C" void BtxGpuFp3LdeRelease(void* ctx)
{
    BtxMetalFp3LdeRelease(ctx);
}
#endif // !BTX_CUDA_FP3_LDE_PROVIDER
