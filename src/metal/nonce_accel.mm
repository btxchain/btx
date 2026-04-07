// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <metal/nonce_accel.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

constexpr const char* KERNEL_SOURCE = R"METAL(
#include <metal_stdlib>
using namespace metal;

kernel void nonce_prefilter(device const ulong* params [[buffer(0)]],
                            device ulong* out_nonces [[buffer(1)]],
                            device atomic_uint* out_count [[buffer(2)]],
                            uint gid [[thread_position_in_grid]])
{
    const ulong start_nonce = params[0];
    const ulong seed = params[1];
    const ulong threshold = params[2];
    const ulong batch_size_param = params[3];

    const ulong nonce = start_nonce + static_cast<ulong>(gid);

    ulong mixed = nonce ^ seed;
    mixed += 0x9e3779b97f4a7c15UL;
    mixed = (mixed ^ (mixed >> 30)) * 0xbf58476d1ce4e5b9UL;
    mixed = (mixed ^ (mixed >> 27)) * 0x94d049bb133111ebUL;
    mixed = mixed ^ (mixed >> 31);

    if (mixed <= threshold) {
        const uint idx = atomic_fetch_add_explicit(out_count, 1u, memory_order_relaxed);
        if ((ulong)idx < batch_size_param) {
            out_nonces[idx] = nonce;
        }
    }
}
)METAL";

struct MetalContext {
    bool ready{false};
    std::string error;
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> pipeline{nil};

    MetalContext()
    {
        @autoreleasepool {
            device = MTLCreateSystemDefaultDevice();
            if (device == nil) {
                error = "No Metal-compatible GPU device found";
                return;
            }

            queue = [device newCommandQueue];
            if (queue == nil) {
                error = "Failed to create Metal command queue";
                return;
            }

            NSError* library_error = nil;
            id<MTLLibrary> library = [device newLibraryWithSource:[NSString stringWithUTF8String:KERNEL_SOURCE]
                                                          options:nil
                                                            error:&library_error];
            if (library == nil) {
                error = library_error != nil ? [[library_error localizedDescription] UTF8String]
                                             : "Failed to compile Metal kernel source";
                return;
            }

            id<MTLFunction> function = [library newFunctionWithName:@"nonce_prefilter"];
            if (function == nil) {
                error = "Failed to load Metal kernel function";
                return;
            }

            NSError* pipeline_error = nil;
            pipeline = [device newComputePipelineStateWithFunction:function error:&pipeline_error];
            if (pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create Metal compute pipeline";
                return;
            }

            ready = true;
        }
    }
};

MetalContext& GetContext()
{
    static MetalContext context;
    return context;
}

} // namespace

namespace btx::metal {

NonceBatch GenerateNonceBatch(uint64_t start_nonce, uint32_t batch_size, uint64_t seed, uint64_t threshold)
{
    NonceBatch batch;
    if (batch_size == 0) {
        batch.available = true;
        return batch;
    }

    MetalContext& context = GetContext();
    if (!context.ready) {
        batch.error = context.error;
        return batch;
    }

    @autoreleasepool {
        id<MTLBuffer> params = [context.device newBufferWithLength:(sizeof(uint64_t) * 4)
                                                            options:MTLResourceStorageModeShared];
        id<MTLBuffer> out_nonces = [context.device newBufferWithLength:(sizeof(uint64_t) * batch_size)
                                                                options:MTLResourceStorageModeShared];
        id<MTLBuffer> out_count = [context.device newBufferWithLength:sizeof(uint32_t)
                                                               options:MTLResourceStorageModeShared];
        if (params == nil || out_nonces == nil || out_count == nil) {
            batch.error = "Failed to allocate Metal buffers";
            return batch;
        }

        uint64_t* params_ptr = static_cast<uint64_t*>(params.contents);
        params_ptr[0] = start_nonce;
        params_ptr[1] = seed;
        params_ptr[2] = threshold;
        params_ptr[3] = batch_size;

        std::memset(out_count.contents, 0, sizeof(uint32_t));

        id<MTLCommandBuffer> command = [context.queue commandBuffer];
        if (command == nil) {
            batch.error = "Failed to create Metal command buffer";
            return batch;
        }

        id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
        if (encoder == nil) {
            batch.error = "Failed to create Metal compute encoder";
            return batch;
        }

        [encoder setComputePipelineState:context.pipeline];
        [encoder setBuffer:params offset:0 atIndex:0];
        [encoder setBuffer:out_nonces offset:0 atIndex:1];
        [encoder setBuffer:out_count offset:0 atIndex:2];

        const NSUInteger max_threads = std::max<NSUInteger>(context.pipeline.maxTotalThreadsPerThreadgroup, 1);
        const NSUInteger thread_group_size = std::min<NSUInteger>(256, max_threads);
        const MTLSize grid = MTLSizeMake(batch_size, 1, 1);
        const MTLSize group = MTLSizeMake(thread_group_size, 1, 1);

        [encoder dispatchThreads:grid threadsPerThreadgroup:group];
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];

        if (command.status != MTLCommandBufferStatusCompleted) {
            NSString* description = command.error != nil ? [command.error localizedDescription] : @"unknown Metal command failure";
            batch.error = [description UTF8String];
            return batch;
        }

        uint32_t found = *static_cast<uint32_t*>(out_count.contents);
        found = std::min<uint32_t>(found, batch_size);

        const uint64_t* nonce_ptr = static_cast<const uint64_t*>(out_nonces.contents);
        batch.nonces.assign(nonce_ptr, nonce_ptr + found);
        std::sort(batch.nonces.begin(), batch.nonces.end());
        batch.available = true;
    }

    return batch;
}

} // namespace btx::metal
