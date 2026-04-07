// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <metal/oracle_accel.h>

#include <crypto/sha256.h>
#include <matmul/noise.h>
#include <matmul/transcript.h>
#include <span.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>

namespace {

constexpr const char* KERNEL_SOURCE = R"METAL(
#include <metal_stdlib>
using namespace metal;

constant uint MODULUS = 0x7fffffffu;

struct OracleParams {
    uint count;
};

inline uint rotr(uint x, uint n)
{
    return (x >> n) | (x << (32u - n));
}

inline uint sha_ch(uint x, uint y, uint z)
{
    return (x & y) ^ ((~x) & z);
}

inline uint sha_maj(uint x, uint y, uint z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint sha_bsig0(uint x)
{
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

inline uint sha_bsig1(uint x)
{
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

inline uint sha_ssig0(uint x)
{
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

inline uint sha_ssig1(uint x)
{
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

constant uint SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

inline void sha256_compress(thread uint state[8], thread uint w[64])
{
    for (uint t = 16; t < 64; ++t) {
        w[t] = sha_ssig1(w[t - 2]) + w[t - 7] + sha_ssig0(w[t - 15]) + w[t - 16];
    }

    uint a = state[0];
    uint b = state[1];
    uint c = state[2];
    uint d = state[3];
    uint e = state[4];
    uint f = state[5];
    uint g = state[6];
    uint h = state[7];

    for (uint t = 0; t < 64; ++t) {
        const uint t1 = h + sha_bsig1(e) + sha_ch(e, f, g) + SHA256_K[t] + w[t];
        const uint t2 = sha_bsig0(a) + sha_maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

inline void sha256_init(thread uint state[8])
{
    state[0] = 0x6a09e667u;
    state[1] = 0xbb67ae85u;
    state[2] = 0x3c6ef372u;
    state[3] = 0xa54ff53au;
    state[4] = 0x510e527fu;
    state[5] = 0x9b05688cu;
    state[6] = 0x1f83d9abu;
    state[7] = 0x5be0cd19u;
}

inline void set_byte(thread uint w[64], uint offset, uint byte)
{
    const uint word_index = offset >> 2u;
    const uint shift = (3u - (offset & 3u)) * 8u;
    w[word_index] |= (byte & 0xffu) << shift;
}

inline uint bswap32(uint x)
{
    return ((x & 0x000000ffu) << 24u) |
           ((x & 0x0000ff00u) << 8u) |
           ((x & 0x00ff0000u) >> 8u) |
           ((x & 0xff000000u) >> 24u);
}

inline uint candidate_from_seed_and_index(constant uchar* seed_internal, uint index, bool with_retry, uint retry)
{
    thread uint w[64];
    for (uint i = 0; i < 64; ++i) {
        w[i] = 0u;
    }

    for (uint i = 0; i < 32; ++i) {
        set_byte(w, i, seed_internal[31u - i]);
    }

    set_byte(w, 32u, index & 0xffu);
    set_byte(w, 33u, (index >> 8u) & 0xffu);
    set_byte(w, 34u, (index >> 16u) & 0xffu);
    set_byte(w, 35u, (index >> 24u) & 0xffu);

    uint message_len = 36u;
    if (with_retry) {
        set_byte(w, 36u, retry & 0xffu);
        set_byte(w, 37u, (retry >> 8u) & 0xffu);
        set_byte(w, 38u, (retry >> 16u) & 0xffu);
        set_byte(w, 39u, (retry >> 24u) & 0xffu);
        message_len = 40u;
    }

    set_byte(w, message_len, 0x80u);
    w[15] = message_len * 8u;

    thread uint state[8];
    sha256_init(state);
    sha256_compress(state, w);

    return bswap32(state[0]) & MODULUS;
}

inline uint fallback_candidate(constant uchar* seed_internal, uint index)
{
    thread uint w[64];
    for (uint i = 0; i < 64; ++i) {
        w[i] = 0u;
    }

    for (uint i = 0; i < 32; ++i) {
        set_byte(w, i, seed_internal[31u - i]);
    }

    set_byte(w, 32u, index & 0xffu);
    set_byte(w, 33u, (index >> 8u) & 0xffu);
    set_byte(w, 34u, (index >> 16u) & 0xffu);
    set_byte(w, 35u, (index >> 24u) & 0xffu);

    const uchar fallback_tag[15] = {
        'o', 'r', 'a', 'c', 'l', 'e', '-', 'f', 'a', 'l', 'l', 'b', 'a', 'c', 'k'
    };
    for (uint i = 0; i < 15; ++i) {
        set_byte(w, 36u + i, fallback_tag[i]);
    }

    set_byte(w, 51u, 0x80u);
    w[15] = 51u * 8u;

    thread uint state[8];
    sha256_init(state);
    sha256_compress(state, w);

    return bswap32(state[0]) % MODULUS;
}

inline uint from_oracle(constant uchar* seed_internal, uint index)
{
    for (uint retry = 0; retry < 256; ++retry) {
        const uint candidate = retry == 0
            ? candidate_from_seed_and_index(seed_internal, index, false, 0u)
            : candidate_from_seed_and_index(seed_internal, index, true, retry);
        if (candidate < MODULUS) {
            return candidate;
        }
    }
    return fallback_candidate(seed_internal, index);
}

kernel void generate_oracle_noise_vectors(constant OracleParams& p [[buffer(0)]],
                                          constant uchar* seed_el [[buffer(1)]],
                                          constant uchar* seed_er [[buffer(2)]],
                                          constant uchar* seed_fl [[buffer(3)]],
                                          constant uchar* seed_fr [[buffer(4)]],
                                          device uint* out_e_l [[buffer(5)]],
                                          device uint* out_e_r [[buffer(6)]],
                                          device uint* out_f_l [[buffer(7)]],
                                          device uint* out_f_r [[buffer(8)]],
                                          uint gid [[thread_position_in_grid]])
{
    if (gid >= p.count) {
        return;
    }
    out_e_l[gid] = from_oracle(seed_el, gid);
    out_e_r[gid] = from_oracle(seed_er, gid);
    out_f_l[gid] = from_oracle(seed_fl, gid);
    out_f_r[gid] = from_oracle(seed_fr, gid);
}

kernel void generate_oracle_vector(constant OracleParams& p [[buffer(0)]],
                                   constant uchar* seed_internal [[buffer(1)]],
                                   device uint* out [[buffer(2)]],
                                   uint gid [[thread_position_in_grid]])
{
    if (gid >= p.count) {
        return;
    }
    out[gid] = from_oracle(seed_internal, gid);
}
)METAL";

struct MetalContext {
    bool ready{false};
    bool using_precompiled_library{false};
    std::string error;
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> oracle_noise_pipeline{nil};
    id<MTLComputePipelineState> oracle_vector_pipeline{nil};
    std::mutex pool_mutex;
    id<MTLBuffer> pool_out_e_l{nil};
    id<MTLBuffer> pool_out_e_r{nil};
    id<MTLBuffer> pool_out_f_l{nil};
    id<MTLBuffer> pool_out_f_r{nil};
    id<MTLBuffer> pool_out_cv{nil};
    size_t pool_noise_bytes{0};
    size_t pool_compress_bytes{0};
    uint64_t pool_allocation_events{0};
    uint64_t pool_reuse_events{0};
    std::mutex profiling_mutex;
    btx::metal::MatMulInputGenerationProfile profile;

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
            id<MTLLibrary> library = nil;
#if defined(BTX_ORACLE_METALLIB_PATH)
            NSString* precompiled_path = [NSString stringWithUTF8String:BTX_ORACLE_METALLIB_PATH];
            if ([[NSFileManager defaultManager] fileExistsAtPath:precompiled_path]) {
                library_error = nil;
                NSURL* precompiled_url = [NSURL fileURLWithPath:precompiled_path];
                library = [device newLibraryWithURL:precompiled_url error:&library_error];
                using_precompiled_library = (library != nil);
            }
#endif
            if (library == nil) {
                library_error = nil;
                library = [device newLibraryWithSource:[NSString stringWithUTF8String:KERNEL_SOURCE]
                                               options:nil
                                                 error:&library_error];
                using_precompiled_library = false;
            }
            if (library == nil) {
                error = library_error != nil ? [[library_error localizedDescription] UTF8String]
                                             : "Failed to compile Metal oracle kernel source";
                return;
            }

            id<MTLFunction> oracle_noise_function = [library newFunctionWithName:@"generate_oracle_noise_vectors"];
            if (oracle_noise_function == nil) {
                error = "Failed to load Metal oracle noise kernel function";
                return;
            }

            NSError* pipeline_error = nil;
            oracle_noise_pipeline = [device newComputePipelineStateWithFunction:oracle_noise_function error:&pipeline_error];
            if (oracle_noise_pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create Metal oracle noise pipeline";
                return;
            }

            id<MTLFunction> oracle_vector_function = [library newFunctionWithName:@"generate_oracle_vector"];
            if (oracle_vector_function == nil) {
                error = "Failed to load Metal oracle vector kernel function";
                return;
            }

            pipeline_error = nil;
            oracle_vector_pipeline = [device newComputePipelineStateWithFunction:oracle_vector_function error:&pipeline_error];
            if (oracle_vector_pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create Metal oracle vector pipeline";
                return;
            }

            ready = true;
            profile.available = true;
            profile.library_source = using_precompiled_library ? "precompiled_metallib" : "inline_source_fallback";
            profile.reason = "oracle_profile_ready";
        }
    }
};

MetalContext& GetContext()
{
    static MetalContext context;
    return context;
}

NSUInteger SelectThreadGroupSize(id<MTLComputePipelineState> pipeline, NSUInteger preferred)
{
    if (pipeline == nil) return 1;
    const NSUInteger max_threads = std::max<NSUInteger>(pipeline.maxTotalThreadsPerThreadgroup, 1);
    return std::min<NSUInteger>(preferred, max_threads);
}

bool EnsureOutputBufferPool(MetalContext& context,
                            size_t noise_bytes,
                            size_t compress_bytes,
                            std::string& error)
{
    const bool needs_realloc = context.pool_out_e_l == nil ||
        context.pool_out_e_r == nil ||
        context.pool_out_f_l == nil ||
        context.pool_out_f_r == nil ||
        context.pool_out_cv == nil ||
        noise_bytes > context.pool_noise_bytes ||
        compress_bytes > context.pool_compress_bytes;
    if (!needs_realloc) {
        ++context.pool_reuse_events;
        return true;
    }

    id<MTLBuffer> out_e_l = [context.device newBufferWithLength:noise_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> out_e_r = [context.device newBufferWithLength:noise_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> out_f_l = [context.device newBufferWithLength:noise_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> out_f_r = [context.device newBufferWithLength:noise_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> out_cv = [context.device newBufferWithLength:compress_bytes options:MTLResourceStorageModeShared];
    if (out_e_l == nil || out_e_r == nil || out_f_l == nil || out_f_r == nil || out_cv == nil) {
        error = "Failed to allocate Metal output buffers for oracle generation";
        return false;
    }

    context.pool_out_e_l = out_e_l;
    context.pool_out_e_r = out_e_r;
    context.pool_out_f_l = out_f_l;
    context.pool_out_f_r = out_f_r;
    context.pool_out_cv = out_cv;
    context.pool_noise_bytes = noise_bytes;
    context.pool_compress_bytes = compress_bytes;
    ++context.pool_allocation_events;
    return true;
}

std::array<uint8_t, 32> ToCanonicalBytes(const uint256& value)
{
    std::array<uint8_t, 32> out;
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = value.data()[out.size() - 1 - i];
    }
    return out;
}

uint256 CanonicalBytesToUint256(const uint8_t* bytes)
{
    std::array<unsigned char, 32> internal;
    for (size_t i = 0; i < internal.size(); ++i) {
        internal[i] = bytes[internal.size() - 1 - i];
    }
    return uint256{Span<const unsigned char>{internal.data(), internal.size()}};
}

uint256 DeriveCompressionSeed(const uint256& sigma)
{
    const auto sigma_bytes = ToCanonicalBytes(sigma);
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const uint8_t*>(matmul::transcript::COMPRESS_TAG.data()), matmul::transcript::COMPRESS_TAG.size());
    hasher.Write(sigma_bytes.data(), sigma_bytes.size());

    uint8_t digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    return CanonicalBytesToUint256(digest);
}

} // namespace

namespace btx::metal {

MatMulInputGenerationProfile ProbeMatMulInputGenerationProfile()
{
    MatMulInputGenerationProfile profile;

    MetalContext& context = GetContext();
    if (!context.ready) {
        profile.available = false;
        profile.pool_initialized = false;
        profile.library_source = context.using_precompiled_library ? "precompiled_metallib" : "unavailable";
        profile.reason = context.error.empty() ? "Metal context initialization failed" : context.error;
        return profile;
    }

    std::lock_guard<std::mutex> pool_lock(context.pool_mutex);
    std::lock_guard<std::mutex> profiling_lock(context.profiling_mutex);
    profile = context.profile;
    profile.available = true;
    profile.pool_initialized = context.pool_out_e_l != nil &&
        context.pool_out_e_r != nil &&
        context.pool_out_f_l != nil &&
        context.pool_out_f_r != nil &&
        context.pool_out_cv != nil;
    profile.allocation_events = context.pool_allocation_events;
    profile.reuse_events = context.pool_reuse_events;
    if (profile.reason.empty()) {
        profile.reason = profile.pool_initialized ? "oracle_profile_ready" : "oracle_pool_uninitialized";
    }
    return profile;
}

MatMulInputGenerationResult GenerateMatMulInputsGPU(const MatMulInputGenerationRequest& request)
{
    MatMulInputGenerationResult result;

    MetalContext& context = GetContext();
    if (!context.ready) {
        result.available = false;
        result.success = false;
        result.error = context.error.empty() ? "Metal context initialization failed" : context.error;
        return result;
    }
    result.available = true;

    if (request.n == 0 || request.b == 0 || request.r == 0) {
        result.success = false;
        result.error = "invalid dimensions for GPU input generation";
        return result;
    }
    if (request.r > request.n) {
        result.success = false;
        result.error = "noise rank exceeds matrix dimension";
        return result;
    }
    if ((request.n % request.b) != 0) {
        result.success = false;
        result.error = "matrix dimension must be divisible by transcript block size";
        return result;
    }

    const uint64_t noise_words64 = static_cast<uint64_t>(request.n) * request.r;
    const uint64_t compress_words64 = static_cast<uint64_t>(request.b) * request.b;
    if (noise_words64 > std::numeric_limits<uint32_t>::max() ||
        compress_words64 > std::numeric_limits<uint32_t>::max()) {
        result.success = false;
        result.error = "input generation dimensions exceed supported bounds";
        return result;
    }

    const uint32_t noise_words = static_cast<uint32_t>(noise_words64);
    const uint32_t compress_words = static_cast<uint32_t>(compress_words64);

    const uint256 seed_el = matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_EL, request.sigma);
    const uint256 seed_er = matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_ER, request.sigma);
    const uint256 seed_fl = matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_FL, request.sigma);
    const uint256 seed_fr = matmul::noise::DeriveNoiseSeed(matmul::noise::TAG_FR, request.sigma);
    const uint256 seed_cv = DeriveCompressionSeed(request.sigma);

    double encode_noise_us{0.0};
    double encode_compress_us{0.0};
    double submit_wait_us{0.0};
    double gpu_generation_ms{0.0};

    @autoreleasepool {
        const size_t noise_bytes = static_cast<size_t>(noise_words) * sizeof(uint32_t);
        const size_t compress_bytes = static_cast<size_t>(compress_words) * sizeof(uint32_t);
        std::lock_guard<std::mutex> pool_lock(context.pool_mutex);

        if (!EnsureOutputBufferPool(context, noise_bytes, compress_bytes, result.error)) {
            result.success = false;
            return result;
        }

        id<MTLBuffer> out_e_l = context.pool_out_e_l;
        id<MTLBuffer> out_e_r = context.pool_out_e_r;
        id<MTLBuffer> out_f_l = context.pool_out_f_l;
        id<MTLBuffer> out_f_r = context.pool_out_f_r;
        id<MTLBuffer> out_cv = context.pool_out_cv;

        id<MTLCommandBuffer> command = nil;
        if ([context.queue respondsToSelector:@selector(commandBufferWithUnretainedReferences)]) {
            command = [context.queue commandBufferWithUnretainedReferences];
        }
        if (command == nil) {
            command = [context.queue commandBuffer];
        }
        if (command == nil) {
            result.success = false;
            result.error = "Failed to create Metal command buffer";
            return result;
        }

        struct OracleParams {
            uint32_t count;
        };

        id<MTLComputeCommandEncoder> noise_encoder = [command computeCommandEncoder];
        if (noise_encoder == nil) {
            result.success = false;
            result.error = "Failed to create Metal noise compute encoder";
            return result;
        }
        const OracleParams noise_params{noise_words};
        const auto encode_noise_start = std::chrono::steady_clock::now();
        [noise_encoder setComputePipelineState:context.oracle_noise_pipeline];
        [noise_encoder setBytes:&noise_params length:sizeof(noise_params) atIndex:0];
        [noise_encoder setBytes:seed_el.data() length:uint256::size() atIndex:1];
        [noise_encoder setBytes:seed_er.data() length:uint256::size() atIndex:2];
        [noise_encoder setBytes:seed_fl.data() length:uint256::size() atIndex:3];
        [noise_encoder setBytes:seed_fr.data() length:uint256::size() atIndex:4];
        [noise_encoder setBuffer:out_e_l offset:0 atIndex:5];
        [noise_encoder setBuffer:out_e_r offset:0 atIndex:6];
        [noise_encoder setBuffer:out_f_l offset:0 atIndex:7];
        [noise_encoder setBuffer:out_f_r offset:0 atIndex:8];
        const NSUInteger noise_group_size = SelectThreadGroupSize(context.oracle_noise_pipeline, 256);
        [noise_encoder dispatchThreads:MTLSizeMake(noise_words, 1, 1)
                 threadsPerThreadgroup:MTLSizeMake(noise_group_size, 1, 1)];
        [noise_encoder endEncoding];
        encode_noise_us = std::chrono::duration<double, std::micro>(
                              std::chrono::steady_clock::now() - encode_noise_start)
                              .count();

        id<MTLComputeCommandEncoder> compress_encoder = [command computeCommandEncoder];
        if (compress_encoder == nil) {
            result.success = false;
            result.error = "Failed to create Metal compress compute encoder";
            return result;
        }
        const OracleParams compress_params{compress_words};
        const auto encode_compress_start = std::chrono::steady_clock::now();
        [compress_encoder setComputePipelineState:context.oracle_vector_pipeline];
        [compress_encoder setBytes:&compress_params length:sizeof(compress_params) atIndex:0];
        [compress_encoder setBytes:seed_cv.data() length:uint256::size() atIndex:1];
        [compress_encoder setBuffer:out_cv offset:0 atIndex:2];
        const NSUInteger compress_group_size = SelectThreadGroupSize(context.oracle_vector_pipeline, 256);
        [compress_encoder dispatchThreads:MTLSizeMake(compress_words, 1, 1)
                    threadsPerThreadgroup:MTLSizeMake(compress_group_size, 1, 1)];
        [compress_encoder endEncoding];
        encode_compress_us = std::chrono::duration<double, std::micro>(
                                 std::chrono::steady_clock::now() - encode_compress_start)
                                 .count();

        const auto submit_wait_start = std::chrono::steady_clock::now();
        [command commit];
        [command waitUntilCompleted];
        submit_wait_us = std::chrono::duration<double, std::micro>(
                             std::chrono::steady_clock::now() - submit_wait_start)
                             .count();
        gpu_generation_ms = submit_wait_us / 1000.0;

        if (command.status != MTLCommandBufferStatusCompleted) {
            NSString* description = command.error != nil ? [command.error localizedDescription] : @"unknown Metal command failure";
            result.success = false;
            result.error = [description UTF8String];
            return result;
        }

        const auto* e_l_ptr = static_cast<const uint32_t*>(out_e_l.contents);
        const auto* e_r_ptr = static_cast<const uint32_t*>(out_e_r.contents);
        const auto* f_l_ptr = static_cast<const uint32_t*>(out_f_l.contents);
        const auto* f_r_ptr = static_cast<const uint32_t*>(out_f_r.contents);
        const auto* cv_ptr = static_cast<const uint32_t*>(out_cv.contents);

        result.noise_e_l.assign(e_l_ptr, e_l_ptr + noise_words);
        result.noise_e_r.assign(e_r_ptr, e_r_ptr + noise_words);
        result.noise_f_l.assign(f_l_ptr, f_l_ptr + noise_words);
        result.noise_f_r.assign(f_r_ptr, f_r_ptr + noise_words);
        result.compress_vec.assign(cv_ptr, cv_ptr + compress_words);
        result.success = true;

        {
            std::lock_guard<std::mutex> profiling_lock(context.profiling_mutex);
            context.profile.available = true;
            context.profile.pool_initialized = context.pool_out_e_l != nil &&
                context.pool_out_e_r != nil &&
                context.pool_out_f_l != nil &&
                context.pool_out_f_r != nil &&
                context.pool_out_cv != nil;
            ++context.profile.samples;
            context.profile.allocation_events = context.pool_allocation_events;
            context.profile.reuse_events = context.pool_reuse_events;
            context.profile.last_encode_noise_us = encode_noise_us;
            context.profile.last_encode_compress_us = encode_compress_us;
            context.profile.last_submit_wait_us = submit_wait_us;
            context.profile.last_gpu_generation_ms = gpu_generation_ms;
            context.profile.library_source = context.using_precompiled_library ? "precompiled_metallib" : "inline_source_fallback";
            context.profile.reason = "oracle_noise4_plus_compress";
        }

        return result;
    }
}

} // namespace btx::metal
