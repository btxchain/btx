// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Apple Metal RC Ozaki ExactPanels: Metal 4 mpp::tensor_ops::matmul2d
// (simdgroup / MPP) preferred after ExactGemmS8S8 self-qual; MSL ALU fallback.
// Native OCP MXFP4 remains fail-closed (not proven vs RC int64 Ozaki).

#include <metal/matmul_v4_rc_ozaki_accel.h>

#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>
#include <metal/matmul_v4_lt_accel.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

namespace matmul_v4::metal {
namespace {

std::mutex g_mu;
bool g_exact_ran{false};
bool g_exact_qualified{false};
bool g_mx_ran{false};
bool g_last_used_tensor_ops{false};
bool g_fused_ran{false};
bool g_fused_qualified{false};
std::string g_exact_backend;

static NSString* const kRcFusedLibrarySource = @R"MSL(
#include <metal_stdlib>
#if defined(__METAL_VERSION__) && (__METAL_VERSION__ >= 400) && \
    __has_include(<MetalPerformancePrimitives/MetalPerformancePrimitives.h>)
#include <MetalPerformancePrimitives/MetalPerformancePrimitives.h>
#define BTX_RC_HAVE_MPP 1
#endif
using namespace metal;

struct GemmParams {
    uint rows;
    uint inner;
    uint cols;
};

struct ExtractParams {
    uint rows;
    uint cols;
    uint add_residual;
    uint row_begin;
};

#if defined(BTX_RC_HAVE_MPP)
kernel void rc_fused_gemm_s8s8(
    constant GemmParams& p [[buffer(0)]],
    device int8_t* a [[buffer(1)]],
    device int8_t* b [[buffer(2)]],
    device int32_t* d [[buffer(3)]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    using namespace mpp;
    using namespace mpp::tensor_ops;
    constexpr auto desc = matmul2d_descriptor(32, 32);
    matmul2d<desc, execution_simdgroup> op;
    auto ma = tensor(
        a,
        dextents<int, 2>{(int)p.inner, (int)p.rows},
        array<int, 2>{1, (int)p.inner});
    auto mb = tensor(
        b,
        dextents<int, 2>{(int)p.cols, (int)p.inner},
        array<int, 2>{1, (int)p.cols});
    auto md = tensor(
        d,
        dextents<int, 2>{(int)p.cols, (int)p.rows},
        array<int, 2>{1, (int)p.cols});
    const int row0 = int(tgid.y * 32);
    const int col0 = int(tgid.x * 32);
    auto ta = ma.slice(0, row0);
    auto tb = mb.slice(col0, 0);
    auto td = md.slice(col0, row0);
    op.run(ta, tb, td);
}
#endif

kernel void rc_transpose_i8(
    device const int8_t* input [[buffer(0)]],
    device int8_t* output [[buffer(1)]],
    constant uint2& shape [[buffer(2)]],
    uint2 gid [[thread_position_in_grid]])
{
    if (gid.x >= shape.y || gid.y >= shape.x) return;
    output[ulong(gid.x) * ulong(shape.x) + gid.y] =
        input[ulong(gid.y) * ulong(shape.y) + gid.x];
}

inline uint rotl32(uint x, uint n)
{
    return (x << n) | (x >> (32 - n));
}

inline void qr(thread uint& a, thread uint& b, thread uint& c, thread uint& d)
{
    a += b; d = rotl32(d ^ a, 16);
    c += d; b = rotl32(b ^ c, 12);
    a += b; d = rotl32(d ^ a, 8);
    c += d; b = rotl32(b ^ c, 7);
}

inline uint read_le32(constant uchar* p)
{
    return uint(p[0]) | (uint(p[1]) << 8) |
           (uint(p[2]) << 16) | (uint(p[3]) << 24);
}

inline void chacha_block(
    constant uchar* key, uint row, uint block_col, uint counter,
    thread uint out[16])
{
    uint s[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        read_le32(key + 0), read_le32(key + 4),
        read_le32(key + 8), read_le32(key + 12),
        read_le32(key + 16), read_le32(key + 20),
        read_le32(key + 24), read_le32(key + 28),
        counter, block_col ^ 0x4D58424Cu, block_col, row
    };
    for (uint j = 0; j < 16; ++j) out[j] = s[j];
    for (uint round = 0; round < 10; ++round) {
        qr(out[0], out[4], out[8], out[12]);
        qr(out[1], out[5], out[9], out[13]);
        qr(out[2], out[6], out[10], out[14]);
        qr(out[3], out[7], out[11], out[15]);
        qr(out[0], out[5], out[10], out[15]);
        qr(out[1], out[6], out[11], out[12]);
        qr(out[2], out[7], out[8], out[13]);
        qr(out[3], out[4], out[9], out[14]);
    }
    for (uint j = 0; j < 16; ++j) out[j] += s[j];
}

constant uint kShaK[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
    0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
    0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
    0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
    0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
    0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

inline uint rotr32(uint x, uint n)
{
    return (x >> n) | (x << (32 - n));
}

inline void sha256_compress(thread uint state[8], thread uchar block[64])
{
    uint w[64];
    for (uint j = 0; j < 16; ++j) {
        const uint o = j * 4;
        w[j] = (uint(block[o]) << 24) | (uint(block[o + 1]) << 16) |
               (uint(block[o + 2]) << 8) | uint(block[o + 3]);
    }
    for (uint j = 16; j < 64; ++j) {
        const uint s0 = rotr32(w[j - 15], 7) ^ rotr32(w[j - 15], 18) ^
                        (w[j - 15] >> 3);
        const uint s1 = rotr32(w[j - 2], 17) ^ rotr32(w[j - 2], 19) ^
                        (w[j - 2] >> 10);
        w[j] = w[j - 16] + s0 + w[j - 7] + s1;
    }
    uint a=state[0], b=state[1], c=state[2], d=state[3];
    uint e=state[4], f=state[5], g=state[6], h=state[7];
    for (uint j = 0; j < 64; ++j) {
        const uint S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        const uint ch = (e & f) ^ ((~e) & g);
        const uint t1 = h + S1 + ch + kShaK[j] + w[j];
        const uint S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        const uint maj = (a & b) ^ (a & c) ^ (b & c);
        const uint t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

struct XofParams {
    uint blocks;
    uint domain;
};

kernel void rc_xof41_sha256(
    constant uchar* seed [[buffer(0)]],
    constant XofParams& p [[buffer(1)]],
    device uchar* hashes [[buffer(2)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= p.blocks) return;
    uint state[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    uchar block[64];
    for (uint j = 0; j < 64; ++j) block[j] = 0;
    for (uint j = 0; j < 32; ++j) block[j] = seed[j];
    block[32] = uchar(p.domain);
    const ulong counter = ulong(gid);
    for (uint j = 0; j < 8; ++j) {
        block[33 + j] = uchar(counter >> (j * 8));
    }
    block[41] = 0x80;
    block[62] = 0x01;
    block[63] = 0x48;
    sha256_compress(state, block);
    const ulong base = ulong(gid) * 32ul;
    for (uint j = 0; j < 8; ++j) {
        const uint word = state[j];
        hashes[base + j * 4 + 0] = uchar(word >> 24);
        hashes[base + j * 4 + 1] = uchar(word >> 16);
        hashes[base + j * 4 + 2] = uchar(word >> 8);
        hashes[base + j * 4 + 3] = uchar(word);
    }
}

struct Hash65Params {
    uint records;
    uint tag;
    uint payload_bytes;
};

kernel void rc_sha256d65(
    device const uchar* payloads [[buffer(0)]],
    constant Hash65Params& p [[buffer(1)]],
    device uchar* hashes [[buffer(2)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= p.records) return;
    uint first[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    const ulong base =
        ulong(gid) * ulong(p.payload_bytes);
    const ulong message_bytes =
        1ul + ulong(p.payload_bytes);
    const ulong padded_blocks =
        (message_bytes + 9ul + 63ul) / 64ul;
    const ulong padded_bytes = padded_blocks * 64ul;
    const ulong bit_length = message_bytes * 8ul;
    for (ulong block_index = 0;
         block_index < padded_blocks; ++block_index) {
        uchar block[64];
        for (uint j = 0; j < 64; ++j) {
            const ulong position =
                block_index * 64ul + ulong(j);
            if (position == 0) {
                block[j] = uchar(p.tag);
            } else if (position < message_bytes) {
                block[j] =
                    payloads[base + position - 1ul];
            } else if (position == message_bytes) {
                block[j] = 0x80;
            } else if (position >= padded_bytes - 8ul) {
                const uint shift =
                    uint((padded_bytes - 1ul - position) *
                         8ul);
                block[j] = uchar(bit_length >> shift);
            } else {
                block[j] = 0;
            }
        }
        sha256_compress(first, block);
    }

    uint second[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    uchar b2[64];
    for (uint j = 0; j < 64; ++j) b2[j] = 0;
    for (uint j = 0; j < 8; ++j) {
        const uint word = first[j];
        b2[j * 4 + 0] = uchar(word >> 24);
        b2[j * 4 + 1] = uchar(word >> 16);
        b2[j * 4 + 2] = uchar(word >> 8);
        b2[j * 4 + 3] = uchar(word);
    }
    b2[32] = 0x80;
    b2[62] = 0x01;
    sha256_compress(second, b2);
    const ulong out_base = ulong(gid) * 32ul;
    for (uint j = 0; j < 8; ++j) {
        const uint word = second[j];
        hashes[out_base + j * 4 + 0] = uchar(word >> 24);
        hashes[out_base + j * 4 + 1] = uchar(word >> 16);
        hashes[out_base + j * 4 + 2] = uchar(word >> 8);
        hashes[out_base + j * 4 + 3] = uchar(word);
    }
}

constant uchar kScaleTag[27] = {
    66,84,88,95,77,65,84,69,88,80,65,78,68,95,
    77,88,83,67,65,76,69,95,86,52,52,76,84
};

inline uint derive_scale(constant uchar* key, uint row, uint block_col)
{
    uint state[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
    };
    uchar b0[64];
    uchar b1[64];
    for (uint j = 0; j < 64; ++j) { b0[j] = 0; b1[j] = 0; }
    for (uint j = 0; j < 27; ++j) b0[j] = kScaleTag[j];
    for (uint j = 0; j < 32; ++j) b0[27 + j] = key[j];
    b0[59] = uchar(row);
    b0[60] = uchar(row >> 8);
    b0[61] = uchar(row >> 16);
    b0[62] = uchar(row >> 24);
    b0[63] = uchar(block_col);
    b1[0] = uchar(block_col >> 8);
    b1[1] = uchar(block_col >> 16);
    b1[2] = uchar(block_col >> 24);
    b1[3] = 0x80;
    b1[62] = 0x02;
    b1[63] = 0x18;
    sha256_compress(state, b0);
    sha256_compress(state, b1);
    return (state[0] >> 24) & 3u;
}

inline char decode_mantissa(uchar nibble, thread bool& accepted)
{
    accepted = true;
    switch (nibble & 15u) {
    case 0: return 0;
    case 2: return 1;
    case 4: return 2;
    case 5: return 3;
    case 6: return 4;
    case 7: return 6;
    case 10: return -1;
    case 12: return -2;
    case 13: return -3;
    case 14: return -4;
    case 15: return -6;
    default: accepted = false; return 0;
    }
}

struct MantissaStreamParams {
    uint blocks;
    uint output_count;
};

kernel void rc_mantissa_accept_counts(
    device const uchar* hashes [[buffer(0)]],
    constant MantissaStreamParams& p [[buffer(1)]],
    device uint* counts [[buffer(2)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= p.blocks) return;
    uint count = 0;
    const ulong base = ulong(gid) * 32ul;
    for (uint j = 0; j < 32; ++j) {
        const uchar byte = hashes[base + j];
        bool accepted = false;
        (void)decode_mantissa(byte, accepted);
        count += accepted ? 1u : 0u;
        (void)decode_mantissa(byte >> 4, accepted);
        count += accepted ? 1u : 0u;
    }
    counts[gid] = count;
}

kernel void rc_mantissa_fill(
    device const uchar* hashes [[buffer(0)]],
    device const uint* prefixes [[buffer(1)]],
    constant MantissaStreamParams& p [[buffer(2)]],
    device int8_t* output [[buffer(3)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= p.blocks) return;
    uint position = prefixes[gid];
    if (position >= p.output_count) return;
    const ulong base = ulong(gid) * 32ul;
    for (uint j = 0; j < 32; ++j) {
        const uchar byte = hashes[base + j];
        for (uint shift = 0; shift < 8; shift += 4) {
            bool accepted = false;
            const char value =
                decode_mantissa(byte >> shift, accepted);
            if (!accepted) continue;
            if (position < p.output_count) {
                output[position] = value;
            }
            ++position;
            if (position >= p.output_count) return;
        }
    }
}

struct OperandDequantParams {
    uint rows;
    uint columns;
    uint elements;
};

kernel void rc_operand_dequant(
    device int8_t* values [[buffer(0)]],
    device const uchar* scale_hashes [[buffer(1)]],
    constant OperandDequantParams& p [[buffer(2)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid >= p.elements) return;
    const uint blocks_per_row = p.columns / 32;
    const uint row = gid / p.columns;
    const uint column = gid - row * p.columns;
    const uint scale_index =
        row * blocks_per_row + column / 32;
    const uchar packed = scale_hashes[scale_index / 4];
    const uint scale =
        (packed >> ((scale_index & 3u) * 2u)) & 3u;
    values[gid] =
        int8_t(int(values[gid]) * int(1u << scale));
}

kernel void rc_fused_extract(
    device const int32_t* raw [[buffer(0)]],
    device const int8_t* residual [[buffer(1)]],
    device int8_t* output [[buffer(2)]],
    constant uchar* key [[buffer(3)]],
    constant ExtractParams& p [[buffer(4)]],
    uint tile [[thread_position_in_grid]])
{
    const uint blocks_per_row = p.cols / 32;
    const uint total_tiles = p.rows * blocks_per_row;
    if (tile >= total_tiles) return;
    const uint local_row = tile / blocks_per_row;
    const uint row = p.row_begin + local_row;
    const uint block_col = tile - local_row * blocks_per_row;
    const ulong base = ulong(local_row) * ulong(p.cols) + ulong(block_col) * 32ul;
    const uint scale = derive_scale(key, row, block_col);
    uint filled = 0;
    uint counter = 0;
    while (filled < 32) {
        uint words[16];
        chacha_block(key, row, block_col, counter, words);
        for (uint byte_index = 0; byte_index < 64 && filled < 32; ++byte_index) {
            const uchar byte = uchar(
                words[byte_index >> 2] >> ((byte_index & 3u) * 8u));
            for (uint lane = 0; lane < 2 && filled < 32; ++lane) {
                const uchar nibble = uchar((byte >> (lane * 4u)) & 15u);
                int value = raw[base + filled];
                if (p.add_residual != 0) value += int(residual[base + filled]);
                const uint raw_u = uint(value);
                const uchar mixed = uchar(
                    (uint(nibble) ^ ((raw_u * 0x9E3779B9u) >> 28)) & 15u);
                bool accepted = false;
                const char mantissa = decode_mantissa(mixed, accepted);
                if (accepted) {
                    output[base + filled] =
                        char(int(mantissa) * int(1u << scale));
                    ++filled;
                }
            }
        }
        ++counter;
    }
}
)MSL";

struct RcFusedMetalContext {
    id<MTLDevice> device{nil};
    id<MTLCommandQueue> queue{nil};
    id<MTLComputePipelineState> gemm{nil};
    id<MTLComputePipelineState> extract{nil};
    id<MTLComputePipelineState> transpose{nil};
    id<MTLComputePipelineState> xof{nil};
    id<MTLComputePipelineState> sha256d65{nil};
    id<MTLComputePipelineState> mantissa_counts{nil};
    id<MTLComputePipelineState> mantissa_fill{nil};
    id<MTLComputePipelineState> operand_dequant{nil};
    id<MTLBuffer> x{nil};
    id<MTLBuffer> w_up{nil};
    id<MTLBuffer> w_down{nil};
    id<MTLBuffer> raw{nil};
    id<MTLBuffer> h{nil};
    id<MTLBuffer> out{nil};
    id<MTLBuffer> xof_hashes{nil};
    id<MTLBuffer> hash65_payloads{nil};
    id<MTLBuffer> xof_counts{nil};
    id<MTLBuffer> xof_prefixes{nil};
    id<MTLBuffer> operand_values{nil};
    size_t x_bytes{0}, w_up_bytes{0}, w_down_bytes{0};
    size_t raw_bytes{0}, h_bytes{0}, out_bytes{0};
    size_t xof_hash_bytes{0};
    size_t hash65_payload_bytes{0};
    size_t xof_count_bytes{0};
    size_t xof_prefix_bytes{0};
    size_t operand_value_bytes{0};
    bool ready{false};
    std::mutex launch_mutex;

    bool Grow(id<MTLBuffer> __strong& buffer, size_t& have, size_t need)
    {
        if (buffer != nil && have >= need) return true;
        buffer = [device newBufferWithLength:need options:MTLResourceStorageModeShared];
        if (buffer == nil) { have = 0; return false; }
        have = need;
        return true;
    }

    bool Ensure(size_t xb, size_t upb, size_t downb, size_t rawb,
                size_t hb, size_t outb)
    {
        return Grow(x, x_bytes, xb) &&
               Grow(w_up, w_up_bytes, upb) &&
               Grow(w_down, w_down_bytes, downb) &&
               Grow(raw, raw_bytes, rawb) &&
               Grow(h, h_bytes, hb) &&
               Grow(out, out_bytes, outb);
    }
};

RcFusedMetalContext& FusedCtx()
{
    static RcFusedMetalContext ctx;
    static std::once_flag once;
    std::call_once(once, [] {
        @autoreleasepool {
            // MTLCreateSystemDefaultDevice() is restricted to interactive apps on
            // macOS 14+ and returns nil from CLI/daemon contexts, so a node started
            // with -daemon=1 silently lost its Metal backend and fell back to CPU
            // (reported by a Mac operator 2026-08-11: works with -daemon=0, falls
            // back with -daemon=1 and identical backend env). MTLCopyAllDevices()
            // is Apple's documented replacement that works in any context.
            NSArray<id<MTLDevice>>* allDevices = MTLCopyAllDevices();
            if (allDevices == nil || allDevices.count == 0) return;
            ctx.device = allDevices[0];
            if (ctx.device == nil) return;
            ctx.queue = [ctx.device newCommandQueue];
            if (ctx.queue == nil) return;
            MTLCompileOptions* options = [MTLCompileOptions new];
            options.languageVersion = static_cast<MTLLanguageVersion>(4 << 16);
            NSError* error = nil;
            id<MTLLibrary> library =
                [ctx.device newLibraryWithSource:kRcFusedLibrarySource
                                         options:options
                                           error:&error];
            if (library == nil) {
                NSLog(@"BTX RC fused Metal library compile failed: %@", error);
                return;
            }
            id<MTLFunction> gemm_fn =
                [library newFunctionWithName:@"rc_fused_gemm_s8s8"];
            id<MTLFunction> extract_fn =
                [library newFunctionWithName:@"rc_fused_extract"];
            id<MTLFunction> transpose_fn =
                [library newFunctionWithName:@"rc_transpose_i8"];
            id<MTLFunction> xof_fn =
                [library newFunctionWithName:@"rc_xof41_sha256"];
            id<MTLFunction> sha256d65_fn =
                [library newFunctionWithName:@"rc_sha256d65"];
            id<MTLFunction> mantissa_counts_fn =
                [library
                    newFunctionWithName:@"rc_mantissa_accept_counts"];
            id<MTLFunction> mantissa_fill_fn =
                [library newFunctionWithName:@"rc_mantissa_fill"];
            id<MTLFunction> operand_dequant_fn =
                [library newFunctionWithName:@"rc_operand_dequant"];
            if (gemm_fn == nil || extract_fn == nil ||
                transpose_fn == nil || xof_fn == nil ||
                sha256d65_fn == nil ||
                mantissa_counts_fn == nil ||
                mantissa_fill_fn == nil ||
                operand_dequant_fn == nil) {
                NSLog(@"BTX RC fused Metal functions missing");
                return;
            }
            ctx.gemm =
                [ctx.device newComputePipelineStateWithFunction:gemm_fn error:&error];
            ctx.extract =
                [ctx.device newComputePipelineStateWithFunction:extract_fn error:&error];
            ctx.transpose =
                [ctx.device newComputePipelineStateWithFunction:transpose_fn error:&error];
            ctx.xof =
                [ctx.device newComputePipelineStateWithFunction:xof_fn error:&error];
            ctx.sha256d65 =
                [ctx.device
                    newComputePipelineStateWithFunction:sha256d65_fn
                    error:&error];
            ctx.mantissa_counts =
                [ctx.device
                    newComputePipelineStateWithFunction:
                        mantissa_counts_fn
                    error:&error];
            ctx.mantissa_fill =
                [ctx.device
                    newComputePipelineStateWithFunction:
                        mantissa_fill_fn
                    error:&error];
            ctx.operand_dequant =
                [ctx.device
                    newComputePipelineStateWithFunction:
                        operand_dequant_fn
                    error:&error];
            if (ctx.gemm == nil || ctx.extract == nil ||
                ctx.transpose == nil || ctx.xof == nil ||
                ctx.sha256d65 == nil ||
                ctx.mantissa_counts == nil ||
                ctx.mantissa_fill == nil ||
                ctx.operand_dequant == nil) {
                NSLog(@"BTX RC fused Metal pipeline creation failed: %@", error);
            }
            ctx.ready =
                ctx.gemm != nil && ctx.extract != nil &&
                ctx.transpose != nil && ctx.xof != nil &&
                ctx.sha256d65 != nil &&
                ctx.mantissa_counts != nil &&
                ctx.mantissa_fill != nil &&
                ctx.operand_dequant != nil;
        }
    });
    return ctx;
}

struct FusedGemmParamsHost {
    uint32_t rows;
    uint32_t inner;
    uint32_t cols;
};

struct FusedExtractParamsHost {
    uint32_t rows;
    uint32_t cols;
    uint32_t add_residual;
    uint32_t row_begin;
};

struct FusedXofParamsHost {
    uint32_t blocks;
    uint32_t domain;
};

struct FusedMantissaParamsHost {
    uint32_t blocks;
    uint32_t output_count;
};

struct FusedOperandDequantParamsHost {
    uint32_t rows;
    uint32_t columns;
    uint32_t elements;
};

struct FusedHash65ParamsHost {
    uint32_t records;
    uint32_t tag;
    uint32_t payload_bytes;
};

bool LaunchRcHash65BatchRaw(
    RcFusedMetalContext& ctx,
    const unsigned char* payloads,
    uint32_t records,
    uint8_t tag,
    uint32_t payload_bytes_per_record,
    std::vector<uint256>& hashes)
{
    hashes.clear();
    if (records == 0) return true;
    if (payload_bytes_per_record == 0) return false;
    const size_t payload_bytes{
        static_cast<size_t>(records) *
        payload_bytes_per_record};
    const size_t hash_bytes{
        static_cast<size_t>(records) * 32};
    if (!ctx.Grow(
            ctx.hash65_payloads,
            ctx.hash65_payload_bytes,
            payload_bytes) ||
        !ctx.Grow(
            ctx.xof_hashes,
            ctx.xof_hash_bytes,
            hash_bytes)) {
        return false;
    }
    std::memcpy(
        [ctx.hash65_payloads contents],
        payloads, payload_bytes);
    @autoreleasepool {
        id<MTLCommandBuffer> command{[ctx.queue commandBuffer]};
        if (command == nil) return false;
        id<MTLComputeCommandEncoder> encoder{
            [command computeCommandEncoder]};
        if (encoder == nil) return false;
        const FusedHash65ParamsHost params{
            records, tag, payload_bytes_per_record};
        [encoder setComputePipelineState:ctx.sha256d65];
        [encoder setBuffer:ctx.hash65_payloads offset:0 atIndex:0];
        [encoder setBytes:&params length:sizeof(params) atIndex:1];
        [encoder setBuffer:ctx.xof_hashes offset:0 atIndex:2];
        const NSUInteger threads{
            std::min<NSUInteger>(
                256,
                ctx.sha256d65.maxTotalThreadsPerThreadgroup)};
        [encoder
            dispatchThreads:MTLSizeMake(records, 1, 1)
            threadsPerThreadgroup:MTLSizeMake(threads, 1, 1)];
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) {
            return false;
        }
    }
    static_assert(sizeof(uint256) == 32);
    hashes.resize(records);
    std::memcpy(
        hashes.data(), [ctx.xof_hashes contents], hash_bytes);
    return true;
}

bool LaunchRcExactReplayMerkleLeavesRaw(
    const unsigned char* leaf_payloads,
    uint32_t leaf_bytes,
    size_t leaf_count,
    std::vector<uint256>& leaf_hashes)
{
    leaf_hashes.clear();
    if (leaf_count == 0) return true;
    if (leaf_payloads == nullptr || leaf_bytes == 0) return false;
    auto& ctx{FusedCtx()};
    if (!ctx.ready) return false;
    std::lock_guard<std::mutex> lock{ctx.launch_mutex};
    const size_t records_per_batch{
        std::max<size_t>(
            1, (4u * 1024u * 1024u) / leaf_bytes)};
    leaf_hashes.reserve(leaf_count);
    for (size_t begin = 0; begin < leaf_count;
         begin += records_per_batch) {
        const size_t count{
            std::min(records_per_batch, leaf_count - begin)};
        std::vector<uint256> batch;
        if (!LaunchRcHash65BatchRaw(
                ctx, leaf_payloads +
                    begin * leaf_bytes,
                static_cast<uint32_t>(count), 0x00,
                leaf_bytes, batch)) {
            leaf_hashes.clear();
            return false;
        }
        leaf_hashes.insert(
            leaf_hashes.end(), batch.begin(), batch.end());
    }
    return true;
}

bool LaunchRcExactReplayMerkleRootRaw(
    const std::vector<uint256>& leaf_hashes,
    uint256& root)
{
    root.SetNull();
    if (leaf_hashes.empty() ||
        (leaf_hashes.size() &
         (leaf_hashes.size() - 1)) != 0) {
        return false;
    }
    auto& ctx{FusedCtx()};
    if (!ctx.ready) return false;
    std::lock_guard<std::mutex> lock{ctx.launch_mutex};
    constexpr size_t RECORDS_PER_BATCH{65536};
    const std::vector<uint256>* level{&leaf_hashes};
    std::vector<uint256> owned_level;
    while (level->size() > 1) {
        const size_t parent_count{level->size() / 2};
        std::vector<uint256> parent;
        parent.reserve(parent_count);
        const auto* payloads{
            reinterpret_cast<const unsigned char*>(
                level->data())};
        for (size_t begin = 0; begin < parent_count;
             begin += RECORDS_PER_BATCH) {
            const size_t count{
                std::min(
                    RECORDS_PER_BATCH,
                    parent_count - begin)};
            std::vector<uint256> batch;
            if (!LaunchRcHash65BatchRaw(
                    ctx, payloads + begin * 64,
                    static_cast<uint32_t>(count), 0x01,
                    64, batch)) {
                return false;
            }
            parent.insert(
                parent.end(), batch.begin(), batch.end());
        }
        owned_level = std::move(parent);
        level = &owned_level;
    }
    root = level->front();
    return true;
}

bool LaunchRcXofBlocksRaw(
    RcFusedMetalContext& ctx,
    const unsigned char seed_bytes[32],
    uint8_t domain,
    uint32_t blocks)
{
    if (blocks == 0) return true;
    const size_t hash_bytes{static_cast<size_t>(blocks) * 32};
    if (!ctx.Grow(
            ctx.xof_hashes, ctx.xof_hash_bytes, hash_bytes)) {
        return false;
    }
    @autoreleasepool {
        id<MTLCommandBuffer> command{[ctx.queue commandBuffer]};
        if (command == nil) return false;
        id<MTLComputeCommandEncoder> encoder{
            [command computeCommandEncoder]};
        if (encoder == nil) return false;
        const FusedXofParamsHost params{blocks, domain};
        [encoder setComputePipelineState:ctx.xof];
        [encoder setBytes:seed_bytes length:32 atIndex:0];
        [encoder setBytes:&params length:sizeof(params) atIndex:1];
        [encoder setBuffer:ctx.xof_hashes offset:0 atIndex:2];
        const NSUInteger threads{
            std::min<NSUInteger>(
                256, ctx.xof.maxTotalThreadsPerThreadgroup)};
        [encoder
            dispatchThreads:MTLSizeMake(blocks, 1, 1)
            threadsPerThreadgroup:MTLSizeMake(threads, 1, 1)];
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) {
            return false;
        }
    }
    return true;
}

bool LaunchRcExactReplayExpandMxRaw(
    const uint256& seed,
    uint32_t rows,
    uint32_t columns,
    std::vector<int8_t>& output)
{
    output.clear();
    if (rows == 0 || columns == 0 ||
        (rows % 32) != 0 || (columns % 32) != 0) {
        return false;
    }
    const uint64_t count64{
        static_cast<uint64_t>(rows) * columns};
    if (count64 > std::numeric_limits<size_t>::max() ||
        count64 > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    const size_t count{static_cast<size_t>(count64)};
    auto& ctx{FusedCtx()};
    if (!ctx.ready) return false;
    unsigned char seed_bytes[32];
    for (size_t i = 0; i < 32; ++i) {
        seed_bytes[i] = seed.data()[31 - i];
    }

    std::lock_guard<std::mutex> lock{ctx.launch_mutex};
    uint64_t mantissa_blocks{
        (count64 + 43) / 44};
    mantissa_blocks +=
        std::max<uint64_t>(64, mantissa_blocks / 128);
    uint64_t accepted_total{0};
    while (accepted_total < count64) {
        if (mantissa_blocks >
            std::numeric_limits<uint32_t>::max()) {
            return false;
        }
        const uint32_t blocks{
            static_cast<uint32_t>(mantissa_blocks)};
        const size_t counter_bytes{
            static_cast<size_t>(blocks) * sizeof(uint32_t)};
        if (!ctx.Grow(
                ctx.xof_counts, ctx.xof_count_bytes,
                counter_bytes) ||
            !ctx.Grow(
                ctx.xof_prefixes, ctx.xof_prefix_bytes,
                counter_bytes) ||
            !ctx.Grow(
                ctx.operand_values,
                ctx.operand_value_bytes, count) ||
            !LaunchRcXofBlocksRaw(
                ctx, seed_bytes, 0x6d,
                blocks)) {
            return false;
        }
        @autoreleasepool {
            id<MTLCommandBuffer> command{
                [ctx.queue commandBuffer]};
            if (command == nil) return false;
            id<MTLComputeCommandEncoder> encoder{
                [command computeCommandEncoder]};
            if (encoder == nil) return false;
            const FusedMantissaParamsHost params{
                blocks, static_cast<uint32_t>(count)};
            [encoder
                setComputePipelineState:ctx.mantissa_counts];
            [encoder setBuffer:ctx.xof_hashes
                       offset:0 atIndex:0];
            [encoder setBytes:&params
                       length:sizeof(params) atIndex:1];
            [encoder setBuffer:ctx.xof_counts
                       offset:0 atIndex:2];
            const NSUInteger threads{
                std::min<NSUInteger>(
                    256,
                    ctx.mantissa_counts
                        .maxTotalThreadsPerThreadgroup)};
            [encoder
                dispatchThreads:MTLSizeMake(blocks, 1, 1)
                threadsPerThreadgroup:
                    MTLSizeMake(threads, 1, 1)];
            [encoder endEncoding];
            [command commit];
            [command waitUntilCompleted];
            if (command.status !=
                MTLCommandBufferStatusCompleted) {
                return false;
            }
        }
        const auto* counts{
            static_cast<const uint32_t*>(
                [ctx.xof_counts contents])};
        auto* prefixes{
            static_cast<uint32_t*>(
                [ctx.xof_prefixes contents])};
        accepted_total = 0;
        for (uint32_t block = 0; block < blocks; ++block) {
            prefixes[block] =
                static_cast<uint32_t>(accepted_total);
            accepted_total += counts[block];
        }
        if (accepted_total < count64) {
            mantissa_blocks =
                std::max<uint64_t>(
                    mantissa_blocks + 64,
                    mantissa_blocks +
                        mantissa_blocks / 16);
        }
    }

    const uint32_t blocks{
        static_cast<uint32_t>(mantissa_blocks)};
    @autoreleasepool {
        id<MTLCommandBuffer> command{
            [ctx.queue commandBuffer]};
        if (command == nil) return false;
        id<MTLComputeCommandEncoder> encoder{
            [command computeCommandEncoder]};
        if (encoder == nil) return false;
        const FusedMantissaParamsHost params{
            blocks, static_cast<uint32_t>(count)};
        [encoder setComputePipelineState:ctx.mantissa_fill];
        [encoder setBuffer:ctx.xof_hashes
                   offset:0 atIndex:0];
        [encoder setBuffer:ctx.xof_prefixes
                   offset:0 atIndex:1];
        [encoder setBytes:&params
                   length:sizeof(params) atIndex:2];
        [encoder setBuffer:ctx.operand_values
                   offset:0 atIndex:3];
        const NSUInteger threads{
            std::min<NSUInteger>(
                256,
                ctx.mantissa_fill
                    .maxTotalThreadsPerThreadgroup)};
        [encoder
            dispatchThreads:MTLSizeMake(blocks, 1, 1)
            threadsPerThreadgroup:
                MTLSizeMake(threads, 1, 1)];
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status !=
            MTLCommandBufferStatusCompleted) {
            return false;
        }
    }

    const uint64_t scale_count64{
        static_cast<uint64_t>(rows) * (columns / 32)};
    const uint64_t scale_blocks{
        (scale_count64 + 127) / 128};
    if (scale_blocks > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    if (!LaunchRcXofBlocksRaw(
            ctx, seed_bytes, 0x65,
            static_cast<uint32_t>(scale_blocks))) {
        return false;
    }
    @autoreleasepool {
        id<MTLCommandBuffer> command{
            [ctx.queue commandBuffer]};
        if (command == nil) return false;
        id<MTLComputeCommandEncoder> encoder{
            [command computeCommandEncoder]};
        if (encoder == nil) return false;
        const FusedOperandDequantParamsHost params{
            rows, columns, static_cast<uint32_t>(count)};
        [encoder setComputePipelineState:ctx.operand_dequant];
        [encoder setBuffer:ctx.operand_values
                   offset:0 atIndex:0];
        [encoder setBuffer:ctx.xof_hashes
                   offset:0 atIndex:1];
        [encoder setBytes:&params
                   length:sizeof(params) atIndex:2];
        const NSUInteger threads{
            std::min<NSUInteger>(
                256,
                ctx.operand_dequant
                    .maxTotalThreadsPerThreadgroup)};
        [encoder
            dispatchThreads:MTLSizeMake(count, 1, 1)
            threadsPerThreadgroup:
                MTLSizeMake(threads, 1, 1)];
        [encoder endEncoding];
        [command commit];
        [command waitUntilCompleted];
        if (command.status !=
            MTLCommandBufferStatusCompleted) {
            return false;
        }
    }
    output.resize(count);
    std::memcpy(
        output.data(), [ctx.operand_values contents], count);
    return true;
}

bool LaunchRcExactReplayFusedFfnRaw(
    const std::vector<int8_t>& X,
    const std::vector<int8_t>& W_up,
    const std::vector<int8_t>& W_down,
    const uint256& prf_up,
    const uint256& prf_down,
    uint32_t row_begin,
    uint32_t rows,
    uint32_t d_model,
    uint32_t d_ff,
    std::vector<int8_t>& output)
{
    output.clear();
    if (rows == 0 || d_model == 0 || d_ff == 0 ||
        (d_model % 32) != 0 || (d_ff % 32) != 0 ||
        X.size() != static_cast<size_t>(rows) * d_model ||
        W_up.size() != static_cast<size_t>(d_model) * d_ff ||
        W_down.size() != static_cast<size_t>(d_ff) * d_model ||
        static_cast<uint64_t>(d_model) * 2304ull >=
            (uint64_t{1} << 31) ||
        static_cast<uint64_t>(d_ff) * 2304ull + 48ull >= (uint64_t{1} << 31)) {
        return false;
    }
    auto& ctx = FusedCtx();
    if (!ctx.ready) return false;

    const size_t x_bytes = X.size();
    const size_t up_bytes = W_up.size();
    const size_t down_bytes = W_down.size();
    const size_t h_bytes = static_cast<size_t>(rows) * d_ff;
    const size_t out_bytes = static_cast<size_t>(rows) * d_model;
    const size_t raw_bytes =
        std::max(h_bytes, out_bytes) * sizeof(int32_t);

    std::lock_guard<std::mutex> lock{ctx.launch_mutex};
    if (!ctx.Ensure(
            x_bytes, up_bytes, down_bytes, raw_bytes, h_bytes, out_bytes)) {
        return false;
    }
    std::memcpy([ctx.x contents], X.data(), x_bytes);
    std::memcpy([ctx.w_up contents], W_up.data(), up_bytes);
    std::memcpy([ctx.w_down contents], W_down.data(), down_bytes);

    @autoreleasepool {
        id<MTLCommandBuffer> command = [ctx.queue commandBuffer];
        if (command == nil) return false;

        auto encode_gemm = [&](id<MTLBuffer> a, id<MTLBuffer> b,
                               uint32_t inner, uint32_t cols) -> bool {
            id<MTLComputeCommandEncoder> encoder =
                [command computeCommandEncoder];
            if (encoder == nil) return false;
            const FusedGemmParamsHost params{rows, inner, cols};
            [encoder setComputePipelineState:ctx.gemm];
            [encoder setBytes:&params length:sizeof(params) atIndex:0];
            [encoder setBuffer:a offset:0 atIndex:1];
            [encoder setBuffer:b offset:0 atIndex:2];
            [encoder setBuffer:ctx.raw offset:0 atIndex:3];
            [encoder dispatchThreadgroups:
                MTLSizeMake((cols + 31) / 32, (rows + 31) / 32, 1)
                threadsPerThreadgroup:MTLSizeMake(32, 1, 1)];
            [encoder endEncoding];
            return true;
        };
        auto encode_extract = [&](id<MTLBuffer> destination,
                                  const uint256& key, uint32_t cols,
                                  bool residual) -> bool {
            id<MTLComputeCommandEncoder> encoder =
                [command computeCommandEncoder];
            if (encoder == nil) return false;
            const FusedExtractParamsHost params{
                rows, cols, residual ? 1u : 0u, row_begin};
            [encoder setComputePipelineState:ctx.extract];
            [encoder setBuffer:ctx.raw offset:0 atIndex:0];
            [encoder setBuffer:ctx.x offset:0 atIndex:1];
            [encoder setBuffer:destination offset:0 atIndex:2];
            [encoder setBytes:key.data() length:32 atIndex:3];
            [encoder setBytes:&params length:sizeof(params) atIndex:4];
            const NSUInteger threads =
                std::min<NSUInteger>(256, ctx.extract.maxTotalThreadsPerThreadgroup);
            [encoder dispatchThreads:
                MTLSizeMake(static_cast<NSUInteger>(rows) * (cols / 32), 1, 1)
                threadsPerThreadgroup:MTLSizeMake(threads, 1, 1)];
            [encoder endEncoding];
            return true;
        };

        if (!encode_gemm(ctx.x, ctx.w_up, d_model, d_ff) ||
            !encode_extract(ctx.h, prf_up, d_ff, false) ||
            !encode_gemm(ctx.h, ctx.w_down, d_ff, d_model) ||
            !encode_extract(ctx.out, prf_down, d_model, true)) {
            return false;
        }
        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) return false;
    }
    output.resize(static_cast<size_t>(rows) * d_model);
    std::memcpy(output.data(), [ctx.out contents], output.size());
    return true;
}

bool LaunchRcExactReplayFusedFfnChainRaw(
    const std::vector<int8_t>& X0,
    const std::vector<std::vector<int8_t>>& W_up,
    const std::vector<std::vector<int8_t>>& W_down,
    const std::vector<uint256>& prf_up,
    const std::vector<uint256>& prf_down,
    uint32_t rows,
    uint32_t d_model,
    uint32_t d_ff,
    std::vector<std::vector<int8_t>>& layer_outputs)
{
    layer_outputs.clear();
    const size_t layers{prf_up.size()};
    const bool shared_weights{W_up.size() == 1 && W_down.size() == 1};
    if (layers == 0 || prf_down.size() != layers ||
        (!shared_weights &&
         (W_up.size() != layers || W_down.size() != layers)) ||
        rows == 0 || d_model == 0 || d_ff == 0 ||
        (d_model % 32) != 0 || (d_ff % 32) != 0 ||
        X0.size() != static_cast<size_t>(rows) * d_model ||
        static_cast<uint64_t>(d_model) * 2304ull >=
            (uint64_t{1} << 31) ||
        static_cast<uint64_t>(d_ff) * 2304ull + 48ull >=
            (uint64_t{1} << 31)) {
        return false;
    }
    const size_t up_bytes{static_cast<size_t>(d_model) * d_ff};
    const size_t down_bytes{static_cast<size_t>(d_ff) * d_model};
    for (size_t l = 0; l < W_up.size(); ++l) {
        if (W_up[l].size() != up_bytes ||
            W_down[l].size() != down_bytes) {
            return false;
        }
    }

    auto& ctx{FusedCtx()};
    if (!ctx.ready) return false;
    const size_t activation_bytes{X0.size()};
    const size_t h_bytes{static_cast<size_t>(rows) * d_ff};
    const size_t raw_bytes{
        std::max(h_bytes, activation_bytes) * sizeof(int32_t)};

    std::lock_guard<std::mutex> lock{ctx.launch_mutex};
    if (!ctx.Grow(ctx.raw, ctx.raw_bytes, raw_bytes) ||
        !ctx.Grow(ctx.h, ctx.h_bytes, h_bytes)) {
        return false;
    }

    @autoreleasepool {
        // Immutable operands are uploaded exactly once. Activations remain in
        // shared Metal buffers across the complete chain; four-layer command
        // batches amortize submission while preserving cancellation points.
        std::vector<id<MTLBuffer>> activations(layers + 1, nil);
        activations[0] =
            [ctx.device newBufferWithBytes:X0.data()
                                   length:activation_bytes
                                  options:MTLResourceStorageModeShared];
        if (activations[0] == nil) return false;
        for (size_t l = 1; l <= layers; ++l) {
            activations[l] =
                [ctx.device newBufferWithLength:activation_bytes
                                        options:MTLResourceStorageModeShared];
            if (activations[l] == nil) return false;
        }

        std::vector<id<MTLBuffer>> up_buffers(W_up.size(), nil);
        std::vector<id<MTLBuffer>> down_buffers(W_down.size(), nil);
        for (size_t l = 0; l < W_up.size(); ++l) {
            up_buffers[l] =
                [ctx.device newBufferWithBytes:W_up[l].data()
                                       length:up_bytes
                                      options:MTLResourceStorageModeShared];
            down_buffers[l] =
                [ctx.device newBufferWithBytes:W_down[l].data()
                                       length:down_bytes
                                      options:MTLResourceStorageModeShared];
            if (up_buffers[l] == nil || down_buffers[l] == nil) {
                return false;
            }
        }

        constexpr size_t LAYERS_PER_COMMAND_BUFFER{4};
        for (size_t batch_begin = 0; batch_begin < layers;
             batch_begin += LAYERS_PER_COMMAND_BUFFER) {
            if (matmul::v4::rc::ExactReplayCancellationRequested()) {
                return false;
            }
            id<MTLCommandBuffer> command{[ctx.queue commandBuffer]};
            if (command == nil) return false;

            auto encode_gemm =
                [&](id<MTLBuffer> a, id<MTLBuffer> b,
                    uint32_t inner, uint32_t cols) -> bool {
                id<MTLComputeCommandEncoder> encoder{
                    [command computeCommandEncoder]};
                if (encoder == nil) return false;
                const FusedGemmParamsHost params{rows, inner, cols};
                [encoder setComputePipelineState:ctx.gemm];
                [encoder setBytes:&params
                           length:sizeof(params)
                          atIndex:0];
                [encoder setBuffer:a offset:0 atIndex:1];
                [encoder setBuffer:b offset:0 atIndex:2];
                [encoder setBuffer:ctx.raw offset:0 atIndex:3];
                [encoder
                    dispatchThreadgroups:
                        MTLSizeMake((cols + 31) / 32,
                                    (rows + 31) / 32, 1)
                    threadsPerThreadgroup:MTLSizeMake(32, 1, 1)];
                [encoder endEncoding];
                return true;
            };
            auto encode_extract =
                [&](id<MTLBuffer> residual,
                    id<MTLBuffer> destination,
                    const uint256& key, uint32_t cols,
                    bool add_residual) -> bool {
                id<MTLComputeCommandEncoder> encoder{
                    [command computeCommandEncoder]};
                if (encoder == nil) return false;
                const FusedExtractParamsHost params{
                    rows, cols, add_residual ? 1u : 0u, 0};
                [encoder setComputePipelineState:ctx.extract];
                [encoder setBuffer:ctx.raw offset:0 atIndex:0];
                [encoder setBuffer:residual offset:0 atIndex:1];
                [encoder setBuffer:destination offset:0 atIndex:2];
                [encoder setBytes:key.data() length:32 atIndex:3];
                [encoder setBytes:&params
                           length:sizeof(params)
                          atIndex:4];
                const NSUInteger threads{
                    std::min<NSUInteger>(
                        256,
                        ctx.extract.maxTotalThreadsPerThreadgroup)};
                [encoder
                    dispatchThreads:
                        MTLSizeMake(
                            static_cast<NSUInteger>(rows) *
                                (cols / 32),
                            1, 1)
                    threadsPerThreadgroup:
                        MTLSizeMake(threads, 1, 1)];
                [encoder endEncoding];
                return true;
            };

            const size_t batch_end{
                std::min(layers,
                         batch_begin +
                             LAYERS_PER_COMMAND_BUFFER)};
            for (size_t l = batch_begin; l < batch_end; ++l) {
                const size_t weight_index{
                    shared_weights ? 0 : l};
                if (!encode_gemm(
                        activations[l], up_buffers[weight_index],
                        d_model, d_ff) ||
                    !encode_extract(
                        activations[l], ctx.h, prf_up[l],
                        d_ff, false) ||
                    !encode_gemm(
                        ctx.h, down_buffers[weight_index],
                        d_ff, d_model) ||
                    !encode_extract(
                        activations[l], activations[l + 1],
                        prf_down[l], d_model, true)) {
                    return false;
                }
            }
            [command commit];
            [command waitUntilCompleted];
            if (command.status != MTLCommandBufferStatusCompleted) {
                return false;
            }
        }

        layer_outputs.assign(
            layers,
            std::vector<int8_t>(activation_bytes));
        for (size_t l = 0; l < layers; ++l) {
            std::memcpy(
                layer_outputs[l].data(),
                [activations[l + 1] contents],
                activation_bytes);
        }
    }
    return true;
}

bool LaunchRcExactReplayPhase1Raw(
    const std::vector<int8_t>& Q,
    const std::vector<int8_t>& K,
    const std::vector<int8_t>& V,
    const uint256& prf_s,
    const uint256& prf_z,
    uint32_t query_rows,
    uint32_t context_rows,
    uint32_t d_head,
    std::vector<int8_t>& output)
{
    output.clear();
    if (query_rows == 0 || context_rows == 0 || d_head == 0 ||
        (query_rows % 32) != 0 || (context_rows % 32) != 0 ||
        (d_head % 32) != 0 ||
        Q.size() != static_cast<size_t>(query_rows) * d_head ||
        K.size() != static_cast<size_t>(context_rows) * d_head ||
        V.size() != static_cast<size_t>(context_rows) * d_head ||
        static_cast<uint64_t>(context_rows) * 2304ull >=
            (uint64_t{1} << 31)) {
        return false;
    }
    auto& ctx = FusedCtx();
    if (!ctx.ready) return false;

    const size_t q_bytes = Q.size();
    const size_t k_bytes = K.size();
    const size_t v_bytes = V.size();
    const size_t s_bytes =
        static_cast<size_t>(query_rows) * context_rows;
    const size_t z_bytes =
        static_cast<size_t>(query_rows) * d_head;
    const size_t kt_or_s_bytes = std::max(k_bytes, s_bytes);
    const size_t raw_bytes =
        std::max(s_bytes, z_bytes) * sizeof(int32_t);

    std::lock_guard<std::mutex> lock{ctx.launch_mutex};
    if (!ctx.Ensure(
            q_bytes, k_bytes, v_bytes, raw_bytes,
            kt_or_s_bytes, z_bytes)) {
        return false;
    }
    std::memcpy([ctx.x contents], Q.data(), q_bytes);
    std::memcpy([ctx.w_up contents], K.data(), k_bytes);
    std::memcpy([ctx.w_down contents], V.data(), v_bytes);

    @autoreleasepool {
        id<MTLCommandBuffer> command = [ctx.queue commandBuffer];
        if (command == nil) return false;

        {
            id<MTLComputeCommandEncoder> encoder =
                [command computeCommandEncoder];
            if (encoder == nil) return false;
            const uint32_t shape[2]{context_rows, d_head};
            [encoder setComputePipelineState:ctx.transpose];
            [encoder setBuffer:ctx.w_up offset:0 atIndex:0];
            [encoder setBuffer:ctx.h offset:0 atIndex:1];
            [encoder setBytes:shape length:sizeof(shape) atIndex:2];
            [encoder dispatchThreads:MTLSizeMake(d_head, context_rows, 1)
                threadsPerThreadgroup:MTLSizeMake(16, 16, 1)];
            [encoder endEncoding];
        }

        auto encode_gemm = [&](id<MTLBuffer> a, id<MTLBuffer> b,
                               uint32_t inner, uint32_t cols) -> bool {
            id<MTLComputeCommandEncoder> encoder =
                [command computeCommandEncoder];
            if (encoder == nil) return false;
            const FusedGemmParamsHost params{
                query_rows, inner, cols};
            [encoder setComputePipelineState:ctx.gemm];
            [encoder setBytes:&params length:sizeof(params) atIndex:0];
            [encoder setBuffer:a offset:0 atIndex:1];
            [encoder setBuffer:b offset:0 atIndex:2];
            [encoder setBuffer:ctx.raw offset:0 atIndex:3];
            [encoder dispatchThreadgroups:
                MTLSizeMake((cols + 31) / 32, (query_rows + 31) / 32, 1)
                threadsPerThreadgroup:MTLSizeMake(32, 1, 1)];
            [encoder endEncoding];
            return true;
        };
        auto encode_extract = [&](id<MTLBuffer> destination,
                                  const uint256& key, uint32_t cols) -> bool {
            id<MTLComputeCommandEncoder> encoder =
                [command computeCommandEncoder];
            if (encoder == nil) return false;
            const FusedExtractParamsHost params{
                query_rows, cols, 0, 0};
            [encoder setComputePipelineState:ctx.extract];
            [encoder setBuffer:ctx.raw offset:0 atIndex:0];
            [encoder setBuffer:ctx.x offset:0 atIndex:1];
            [encoder setBuffer:destination offset:0 atIndex:2];
            [encoder setBytes:key.data() length:32 atIndex:3];
            [encoder setBytes:&params length:sizeof(params) atIndex:4];
            const NSUInteger threads =
                std::min<NSUInteger>(
                    256, ctx.extract.maxTotalThreadsPerThreadgroup);
            [encoder dispatchThreads:
                MTLSizeMake(
                    static_cast<NSUInteger>(query_rows) * (cols / 32), 1, 1)
                threadsPerThreadgroup:MTLSizeMake(threads, 1, 1)];
            [encoder endEncoding];
            return true;
        };

        if (!encode_gemm(ctx.x, ctx.h, d_head, context_rows) ||
            !encode_extract(ctx.h, prf_s, context_rows) ||
            !encode_gemm(ctx.h, ctx.w_down, context_rows, d_head) ||
            !encode_extract(ctx.out, prf_z, d_head)) {
            return false;
        }
        [command commit];
        [command waitUntilCompleted];
        if (command.status != MTLCommandBufferStatusCompleted) return false;
    }
    output.resize(static_cast<size_t>(query_rows) * d_head);
    std::memcpy(output.data(), [ctx.out contents], output.size());
    return true;
}

[[nodiscard]] bool DenseInt64(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                              uint32_t rows, uint32_t inner, uint32_t cols,
                              std::vector<int64_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            int64_t acc = 0;
            for (uint32_t k = 0; k < inner; ++k) {
                acc += static_cast<int64_t>(left[static_cast<size_t>(r) * inner + k]) *
                       static_cast<int64_t>(right[static_cast<size_t>(k) * cols + c]);
            }
            out[static_cast<size_t>(r) * cols + c] = acc;
        }
    }
    return true;
}

/** Limb-split via Metal LaunchGemmS8S8 (TensorOps or ALU) → int64 accumulate. */
[[nodiscard]] bool LaunchMetalOzakiExactPanels(const std::vector<int8_t>& left,
                                               const std::vector<int8_t>& right, uint32_t rows,
                                               uint32_t inner, uint32_t cols,
                                               std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "metal_rc_ozaki: degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "metal_rc_ozaki: size mismatch";
        return false;
    }
    if (!IsMatMulLTMetalAvailable()) {
        if (error) *error = "requires Apple silicon + Metal";
        return false;
    }

    constexpr uint32_t kChunk = matmul::v4::rc::kRCOzakiExactChunk;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    bool any_tensor = false;
    for (uint32_t k0 = 0; k0 < inner; k0 += kChunk) {
        const uint32_t len = std::min(kChunk, inner - k0);
        std::vector<int8_t> Lpanel(static_cast<size_t>(rows) * len);
        std::vector<int8_t> Rpanel(static_cast<size_t>(len) * cols);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t t = 0; t < len; ++t) {
                Lpanel[static_cast<size_t>(r) * len + t] =
                    left[static_cast<size_t>(r) * inner + (k0 + t)];
            }
        }
        for (uint32_t t = 0; t < len; ++t) {
            for (uint32_t c = 0; c < cols; ++c) {
                Rpanel[static_cast<size_t>(t) * cols + c] =
                    right[static_cast<size_t>(k0 + t) * cols + c];
            }
        }
        std::vector<int32_t> partial;
        if (!LaunchGemmS8S8(Lpanel, Rpanel, rows, len, cols, partial) ||
            partial.size() != out.size()) {
            if (error) *error = "metal_rc_ozaki: LaunchGemmS8S8 declined";
            out.clear();
            return false;
        }
        if (LtLastS8S8UsedTensorOps()) any_tensor = true;
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
    }
    g_last_used_tensor_ops = any_tensor;
    if (error) error->clear();
    return true;
}

[[nodiscard]] bool ExactShapeMatches(uint32_t rows, uint32_t inner, uint32_t cols, uint32_t seed,
                                     std::string* error)
{
    std::vector<int8_t> left(static_cast<size_t>(rows) * inner);
    std::vector<int8_t> right(static_cast<size_t>(inner) * cols);
    for (size_t i = 0; i < left.size(); ++i) {
        left[i] = static_cast<int8_t>((static_cast<int32_t>(i + seed) % 97) - 48);
    }
    for (size_t i = 0; i < right.size(); ++i) {
        right[i] = static_cast<int8_t>((static_cast<int32_t>(i * 3 + seed) % 95) - 47);
    }
    std::vector<int64_t> cpu;
    if (!matmul::v4::rc::RcOzakiCpuLimbSplitGemmS8S8Int64(left, right, rows, inner, cols, cpu)) {
        if (error) *error = "cpu Ozaki ExactPanels oracle failed";
        return false;
    }
    std::vector<int64_t> device;
    if (!LaunchMetalOzakiExactPanels(left, right, rows, inner, cols, device, error)) return false;
    if (device != cpu) {
        if (error) *error = "Metal ExactPanels != CPU Ozaki oracle";
        return false;
    }
    return true;
}

} // namespace

bool IsRcOzakiMetalCompiled()
{
    return true;
}

std::string RcOzakiMetalDeficit()
{
    if (IsRcOzakiMetalExactPanelsQualified()) return {};
    if (!IsMatMulLTMetalAvailable()) return "requires Apple silicon + Metal";
    return "requires Apple Metal RC Ozaki ExactPanels self-qual "
           "(rc_metal_ozaki_exact_panels_device_qualify)";
}

bool HostReferenceRcOzakiExactPanelsGemmS8S8Int64(const std::vector<int8_t>& left,
                                                 const std::vector<int8_t>& right, uint32_t rows,
                                                 uint32_t inner, uint32_t cols,
                                                 std::vector<int64_t>& out, std::string* error)
{
    if (!matmul::v4::rc::RcOzakiCpuLimbSplitGemmS8S8Int64(left, right, rows, inner, cols, out)) {
        if (error) *error = "metal_rc_ozaki_host_limb_split_failed";
        return false;
    }
    std::vector<int64_t> dense;
    if (!DenseInt64(left, right, rows, inner, cols, dense)) {
        if (error) *error = "metal_rc_ozaki_dense_oracle_failed";
        out.clear();
        return false;
    }
    if (out != dense) {
        if (error) *error = "metal_rc_ozaki_host_mismatch_vs_int64_oracle";
        out.clear();
        return false;
    }
    if (error) error->clear();
    return true;
}

bool IsRcOzakiMetalExactPanelsAttempted()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_exact_ran;
}

bool IsRcOzakiMetalExactPanelsQualified()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_exact_qualified;
}

std::string RcOzakiMetalExactPanelsBackend()
{
    std::lock_guard<std::mutex> lock(g_mu);
    // Honest INT8 labels only — never OCP MXFP4.
    return g_exact_backend;
}

bool SelfQualifyRcOzakiMetalExactPanelsOnce()
{
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (g_exact_ran) return g_exact_qualified;
    }
    std::string err;
    const bool ok = IsMatMulLTMetalAvailable() && ExactShapeMatches(8, 8, 8, 1u, &err) &&
                    ExactShapeMatches(16, 8192, 16, 7u, &err) &&
                    ExactShapeMatches(8, 4096, 8, 3u, &err);
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_exact_ran) {
        g_exact_ran = true;
        g_exact_qualified = ok;
        if (ok) {
            // Prefer last launch provenance; fall back to TensorOps-capable label.
            g_exact_backend = g_last_used_tensor_ops ? "metal_int8_mpp_tensorops"
                                                    : "metal_int8_msl_alu";
        } else {
            g_exact_backend.clear();
        }
    }
    return g_exact_qualified;
}

bool TryLaunchRcOzakiMetalExactPanelsGemmS8S8Int64(const std::vector<int8_t>& left,
                                                  const std::vector<int8_t>& right, uint32_t rows,
                                                  uint32_t inner, uint32_t cols,
                                                  std::vector<int64_t>& out, std::string* error)
{
    if (!SelfQualifyRcOzakiMetalExactPanelsOnce() || !IsRcOzakiMetalExactPanelsQualified()) {
        out.clear();
        if (error) *error = RcOzakiMetalDeficit();
        return false;
    }
    return LaunchMetalOzakiExactPanels(left, right, rows, inner, cols, out, error);
}

bool IsRcExactReplayFusedMetalQualified()
{
    std::lock_guard<std::mutex> lock(g_mu);
    return g_fused_qualified;
}

bool SelfQualifyRcExactReplayFusedMetalOnce()
{
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (g_fused_ran) return g_fused_qualified;
    }

    constexpr uint32_t rows = 32;
    constexpr uint32_t d_model = 32;
    // Exercise the production contraction boundaries, not just toy shapes:
    // down-projection K=16384 and Phase-1 S·V K=8192 both exceed 2^24's
    // floating-exact window while remaining inside the consensus int32 bound.
    constexpr uint32_t d_ff = 16384;
    std::vector<int8_t> X(static_cast<size_t>(rows) * d_model);
    std::vector<int8_t> W_up(static_cast<size_t>(d_model) * d_ff);
    std::vector<int8_t> W_down(static_cast<size_t>(d_ff) * d_model);
    for (size_t i = 0; i < X.size(); ++i) {
        X[i] = matmul::v4::lt::FoldInt32ToEmax48(
            static_cast<int32_t>(i * 7u) - 301);
    }
    for (size_t i = 0; i < W_up.size(); ++i) {
        W_up[i] = matmul::v4::lt::FoldInt32ToEmax48(
            static_cast<int32_t>(i * 11u) + 17);
    }
    for (size_t i = 0; i < W_down.size(); ++i) {
        W_down[i] = matmul::v4::lt::FoldInt32ToEmax48(
            static_cast<int32_t>(i * 13u) - 91);
    }
    uint256 prf_up;
    uint256 prf_down;
    for (uint32_t i = 0; i < 32; ++i) {
        prf_up.data()[i] = static_cast<unsigned char>(0x21u + i * 3u);
        prf_down.data()[i] = static_cast<unsigned char>(0x91u - i * 2u);
    }

    const auto raw_up =
        matmul::v4::lt::ExactGemmS8S8(
            X, W_up, rows, d_model, d_ff);
    std::vector<int8_t> H(raw_up.size());
    matmul::v4::rc::ExtractMXMatrixInt32(
        prf_up, raw_up.data(), rows, d_ff, H.data());
    auto raw_down =
        matmul::v4::lt::ExactGemmS8S8(
            H, W_down, rows, d_ff, d_model);
    for (size_t i = 0; i < raw_down.size(); ++i) {
        raw_down[i] += static_cast<int32_t>(X[i]);
    }
    std::vector<int8_t> expected(raw_down.size());
    matmul::v4::rc::ExtractMXMatrixInt32(
        prf_down, raw_down.data(), rows, d_model, expected.data());

    std::vector<int8_t> device;
    const bool ffn_ok =
        LaunchRcExactReplayFusedFfnRaw(
            X, W_up, W_down, prf_up, prf_down,
            /*row_begin=*/0, rows, d_model, d_ff, device) &&
        device == expected;
    const auto raw_up_2 =
        matmul::v4::lt::ExactGemmS8S8(
            expected, W_up, rows, d_model, d_ff);
    std::vector<int8_t> h_2(raw_up_2.size());
    matmul::v4::rc::ExtractMXMatrixInt32(
        prf_up, raw_up_2.data(), rows, d_ff, h_2.data());
    auto raw_down_2 =
        matmul::v4::lt::ExactGemmS8S8(
            h_2, W_down, rows, d_ff, d_model);
    for (size_t i = 0; i < raw_down_2.size(); ++i) {
        raw_down_2[i] += static_cast<int32_t>(expected[i]);
    }
    std::vector<int8_t> expected_2(raw_down_2.size());
    matmul::v4::rc::ExtractMXMatrixInt32(
        prf_down, raw_down_2.data(), rows, d_model,
        expected_2.data());
    std::vector<std::vector<int8_t>> chain_device;
    const bool chain_ok{
        LaunchRcExactReplayFusedFfnChainRaw(
            X, {W_up}, {W_down}, {prf_up, prf_up},
            {prf_down, prf_down}, rows, d_model, d_ff,
            chain_device) &&
        chain_device.size() == 2 &&
        chain_device[0] == expected &&
        chain_device[1] == expected_2};

    constexpr uint32_t context_rows = 8192;
    std::vector<int8_t> Q = X;
    std::vector<int8_t> K(
        static_cast<size_t>(context_rows) * d_model);
    std::vector<int8_t> V(K.size());
    for (size_t i = 0; i < K.size(); ++i) {
        K[i] = matmul::v4::lt::FoldInt32ToEmax48(
            static_cast<int32_t>(i * 19u) + 5);
        V[i] = matmul::v4::lt::FoldInt32ToEmax48(
            static_cast<int32_t>(i * 23u) - 47);
    }
    std::vector<int8_t> Kt(
        static_cast<size_t>(d_model) * context_rows);
    for (uint32_t r = 0; r < context_rows; ++r) {
        for (uint32_t d = 0; d < d_model; ++d) {
            Kt[static_cast<size_t>(d) * context_rows + r] =
                K[static_cast<size_t>(r) * d_model + d];
        }
    }
    const auto raw_qk = matmul::v4::lt::ExactGemmS8S8(
        Q, Kt, rows, d_model, context_rows);
    std::vector<int8_t> S(raw_qk.size());
    matmul::v4::rc::ExtractMXMatrixInt32(
        prf_up, raw_qk.data(), rows, context_rows, S.data());
    const auto raw_sv = matmul::v4::lt::ExactGemmS8S8(
        S, V, rows, context_rows, d_model);
    std::vector<int8_t> expected_z(raw_sv.size());
    matmul::v4::rc::ExtractMXMatrixInt32(
        prf_down, raw_sv.data(), rows, d_model, expected_z.data());
    std::vector<int8_t> device_z;
    const bool phase1_ok =
        LaunchRcExactReplayPhase1Raw(
            Q, K, V, prf_up, prf_down,
            rows, context_rows, d_model, device_z) &&
        device_z == expected_z;
    uint256 xof_seed;
    for (uint32_t i = 0; i < 32; ++i) {
        xof_seed.data()[i] =
            static_cast<unsigned char>(0xa7u - i * 3u);
    }
    constexpr uint32_t xof_rows{64};
    constexpr uint32_t xof_columns{128};
    const auto expected_xof{
        matmul::v4::rc::ExpandMxDequantInt8(
            xof_seed, xof_rows, xof_columns)};
    std::vector<int8_t> device_xof;
    const bool xof_ok{
        LaunchRcExactReplayExpandMxRaw(
            xof_seed, xof_rows, xof_columns, device_xof) &&
        device_xof == expected_xof};
    const auto qualify_merkle =
        [](uint32_t leaf_bytes) {
            std::vector<int8_t> merkle_stream(
                static_cast<size_t>(3) * leaf_bytes);
            for (size_t i = 0; i < merkle_stream.size();
                 ++i) {
                merkle_stream[i] =
                    static_cast<int8_t>(
                        i * 29u + 0x53u);
            }
            const auto expected_leaves{
                matmul::v4::rc::BuildTileTreeLeaves(
                    merkle_stream, leaf_bytes)};
            std::vector<uint256> device_leaves;
            if (!LaunchRcExactReplayMerkleLeavesRaw(
                    reinterpret_cast<const unsigned char*>(
                        merkle_stream.data()),
                    leaf_bytes, 3, device_leaves) ||
                device_leaves.size() != 3 ||
                !std::equal(
                    device_leaves.begin(),
                    device_leaves.end(),
                    expected_leaves.begin())) {
                return false;
            }
            device_leaves.push_back(expected_leaves.back());
            uint256 device_root;
            return LaunchRcExactReplayMerkleRootRaw(
                       device_leaves, device_root) &&
                device_root ==
                matmul::v4::rc::BuildTileTreeRoot(
                    merkle_stream, leaf_bytes);
        };
    const bool merkle_ok{
        qualify_merkle(64) && qualify_merkle(1024)};
    const bool ok =
        ffn_ok && chain_ok && phase1_ok &&
        xof_ok && merkle_ok;

    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_fused_ran) {
        g_fused_ran = true;
        g_fused_qualified = ok;
    }
    return g_fused_qualified;
}

bool LaunchRcExactReplayFusedFfn(
    const std::vector<int8_t>& X,
    const std::vector<int8_t>& W_up,
    const std::vector<int8_t>& W_down,
    const uint256& prf_up,
    const uint256& prf_down,
    uint32_t row_begin,
    uint32_t rows,
    uint32_t d_model,
    uint32_t d_ff,
    std::vector<int8_t>& out)
{
    if (!SelfQualifyRcExactReplayFusedMetalOnce() ||
        !IsRcExactReplayFusedMetalQualified()) {
        out.clear();
        return false;
    }
    return LaunchRcExactReplayFusedFfnRaw(
        X, W_up, W_down, prf_up, prf_down,
        row_begin, rows, d_model, d_ff, out);
}

bool LaunchRcExactReplayFusedFfnChain(
    const std::vector<int8_t>& X0,
    const std::vector<std::vector<int8_t>>& W_up,
    const std::vector<std::vector<int8_t>>& W_down,
    const std::vector<uint256>& prf_up,
    const std::vector<uint256>& prf_down,
    uint32_t rows,
    uint32_t d_model,
    uint32_t d_ff,
    std::vector<std::vector<int8_t>>& layer_outputs)
{
    if (!SelfQualifyRcExactReplayFusedMetalOnce() ||
        !IsRcExactReplayFusedMetalQualified()) {
        layer_outputs.clear();
        return false;
    }
    return LaunchRcExactReplayFusedFfnChainRaw(
        X0, W_up, W_down, prf_up, prf_down,
        rows, d_model, d_ff, layer_outputs);
}

bool LaunchRcExactReplayExpandMx(
    const uint256& seed,
    uint32_t rows,
    uint32_t columns,
    std::vector<int8_t>& output)
{
    if (!SelfQualifyRcExactReplayFusedMetalOnce() ||
        !IsRcExactReplayFusedMetalQualified()) {
        output.clear();
        return false;
    }
    return LaunchRcExactReplayExpandMxRaw(
        seed, rows, columns, output);
}

bool LaunchRcExactReplayMerkleLeaves(
    const unsigned char* leaf_payloads,
    uint32_t leaf_bytes,
    size_t leaf_count,
    std::vector<uint256>& leaf_hashes)
{
    if (!SelfQualifyRcExactReplayFusedMetalOnce() ||
        !IsRcExactReplayFusedMetalQualified()) {
        leaf_hashes.clear();
        return false;
    }
    return LaunchRcExactReplayMerkleLeavesRaw(
        leaf_payloads, leaf_bytes, leaf_count, leaf_hashes);
}

bool LaunchRcExactReplayMerkleRoot(
    const std::vector<uint256>& leaf_hashes,
    uint256& root)
{
    if (!SelfQualifyRcExactReplayFusedMetalOnce() ||
        !IsRcExactReplayFusedMetalQualified()) {
        root.SetNull();
        return false;
    }
    return LaunchRcExactReplayMerkleRootRaw(
        leaf_hashes, root);
}

bool LaunchRcExactReplayPhase1(
    const std::vector<int8_t>& Q,
    const std::vector<int8_t>& K,
    const std::vector<int8_t>& V,
    const uint256& prf_s,
    const uint256& prf_z,
    uint32_t query_rows,
    uint32_t context_rows,
    uint32_t d_head,
    std::vector<int8_t>& out_z)
{
    if (!SelfQualifyRcExactReplayFusedMetalOnce() ||
        !IsRcExactReplayFusedMetalQualified()) {
        out_z.clear();
        return false;
    }
    return LaunchRcExactReplayPhase1Raw(
        Q, K, V, prf_s, prf_z,
        query_rows, context_rows, d_head, out_z);
}

bool IsRcOzakiMetalMxfp4Qualified()
{
    return false;
}

std::string RcOzakiMetalMxfp4Backend()
{
    return {};
}

std::string RcOzakiMetalMxfp4ArchKey()
{
    return {};
}

bool SelfQualifyRcOzakiMetalMxfp4Once()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_mx_ran = true;
    // Apple MX·E8M0 / FP8 matmul2d is floating dequant — not RC OCP MXFP4.
    // Never set native qualified from INT8 ExactPanels.
    return false;
}

bool TryLaunchRcOzakiMetalMxfp4GemmS8S8Int64(const std::vector<int8_t>& /*left*/,
                                            const std::vector<int8_t>& /*right*/, uint32_t /*rows*/,
                                            uint32_t /*inner*/, uint32_t /*cols*/,
                                            std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (error) {
        *error = "metal_rc_ozaki_mxfp4_unavailable: no OCP MXFP4 RC tensor path on Metal "
                 "(INT8 ExactPanels ≠ native MX float)";
    }
    return false;
}

void ResetRcOzakiMetalQualForTest()
{
    std::lock_guard<std::mutex> lock(g_mu);
    g_exact_ran = false;
    g_exact_qualified = false;
    g_mx_ran = false;
    g_fused_ran = false;
    g_fused_qualified = false;
    g_last_used_tensor_ops = false;
    g_exact_backend.clear();
}

} // namespace matmul_v4::metal
