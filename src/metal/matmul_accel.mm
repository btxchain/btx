// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <metal/matmul_accel.h>

#include <crypto/common.h>
#include <hash.h>
#include <matmul/transcript.h>
#include <span.h>

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <sys/sysctl.h>
#include <unistd.h>

namespace {

constexpr const char* KERNEL_SOURCE = R"METAL(
#include <metal_stdlib>
using namespace metal;

constant uint MODULUS = 0x7fffffffu;
constant uint MAX_BLOCK_ELEMENTS = 256u;
constant uint FC_SPEC_N [[function_constant(0)]];
constant uint FC_SPEC_B [[function_constant(1)]];
constant uint FC_SPEC_R [[function_constant(2)]];
constant uint FC_SPEC_NBLOCKS [[function_constant(3)]];

struct KernelParams {
    uint n;
    uint b;
    uint r;
    uint N;
};

struct HashParams {
    uint compressed_words;
};

inline uint reduce64(ulong x)
{
    const ulong fold1 = (x & (ulong)MODULUS) + (x >> 31);
    const uint lo = (uint)(fold1 & (ulong)MODULUS);
    const uint hi = (uint)(fold1 >> 31);
    uint result = lo + hi;
    const uint ge_mask = result >= MODULUS ? 0xffffffffu : 0u;
    result -= MODULUS & ge_mask;
    return result;
}

inline uint add_mod(uint a, uint b)
{
    uint s = a + b;
    const uint ge_mask = s >= MODULUS ? 0xffffffffu : 0u;
    s -= MODULUS & ge_mask;
    return s;
}

inline uint mul_mod(uint a, uint b)
{
    return reduce64((ulong)a * (ulong)b);
}

inline uint dot_step(uint acc, uint a, uint b)
{
    return reduce64((ulong)acc + ((ulong)a * (ulong)b));
}

inline uint reduce_simdgroup_add_mod(uint value, uint simd_size)
{
    for (uint offset = simd_size >> 1u; offset > 0u; offset >>= 1u) {
        value = add_mod(value, simd_shuffle_xor(value, offset));
    }
    return value;
}

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

inline uint MessageByteAt(device const uint* compressed, uint64_t msg_len_bytes, uint64_t total_bytes, uint64_t offset)
{
    if (offset < msg_len_bytes) {
        const uint64_t word_index = offset >> 2;
        const uint lane = (uint)(offset & 3u);
        const uint word = compressed[word_index];
        return (word >> (lane * 8u)) & 0xffu;
    }

    if (offset == msg_len_bytes) {
        return 0x80u;
    }

    if (offset >= (total_bytes - 8u)) {
        const uint64_t bit_len = msg_len_bytes * 8u;
        const uint shift = (uint)((total_bytes - 1u - offset) * 8u);
        return (uint)((bit_len >> shift) & 0xffu);
    }

    return 0u;
}

inline uint FinalEllMessageByteAt(device const uint* compressed, uint N, uint64_t msg_len_bytes, uint64_t total_bytes, uint64_t offset)
{
    if (offset < msg_len_bytes) {
        const uint64_t word_index = offset >> 2;
        const uint lane = (uint)(offset & 3u);
        const uint64_t physical_index = word_index * (uint64_t)N + (uint64_t)(N - 1u);
        const uint word = compressed[physical_index];
        return (word >> (lane * 8u)) & 0xffu;
    }

    if (offset == msg_len_bytes) {
        return 0x80u;
    }

    if (offset >= (total_bytes - 8u)) {
        const uint64_t bit_len = msg_len_bytes * 8u;
        const uint shift = (uint)((total_bytes - 1u - offset) * 8u);
        return (uint)((bit_len >> shift) & 0xffu);
    }

    return 0u;
}

inline void sha256_stream_words(device const uint* compressed, uint words, thread uint out_state[8])
{
    out_state[0] = 0x6a09e667u;
    out_state[1] = 0xbb67ae85u;
    out_state[2] = 0x3c6ef372u;
    out_state[3] = 0xa54ff53au;
    out_state[4] = 0x510e527fu;
    out_state[5] = 0x9b05688cu;
    out_state[6] = 0x1f83d9abu;
    out_state[7] = 0x5be0cd19u;

    const uint64_t msg_len_bytes = (uint64_t)words * 4u;
    const uint64_t total_blocks = (msg_len_bytes + 9u + 63u) / 64u;
    const uint64_t total_bytes = total_blocks * 64u;

    thread uint w[64];
    for (uint64_t block = 0; block < total_blocks; ++block) {
        const uint64_t base = block * 64u;
        for (uint i = 0; i < 16; ++i) {
            const uint64_t off = base + (uint64_t)i * 4u;
            const uint b0 = MessageByteAt(compressed, msg_len_bytes, total_bytes, off + 0u);
            const uint b1 = MessageByteAt(compressed, msg_len_bytes, total_bytes, off + 1u);
            const uint b2 = MessageByteAt(compressed, msg_len_bytes, total_bytes, off + 2u);
            const uint b3 = MessageByteAt(compressed, msg_len_bytes, total_bytes, off + 3u);
            w[i] = (b0 << 24u) | (b1 << 16u) | (b2 << 8u) | b3;
        }
        sha256_compress(out_state, w);
    }
}

inline void sha256_stream_final_ell_words(device const uint* compressed, uint N, uint words, thread uint out_state[8])
{
    out_state[0] = 0x6a09e667u;
    out_state[1] = 0xbb67ae85u;
    out_state[2] = 0x3c6ef372u;
    out_state[3] = 0xa54ff53au;
    out_state[4] = 0x510e527fu;
    out_state[5] = 0x9b05688cu;
    out_state[6] = 0x1f83d9abu;
    out_state[7] = 0x5be0cd19u;

    const uint64_t msg_len_bytes = (uint64_t)words * 4u;
    const uint64_t total_blocks = (msg_len_bytes + 9u + 63u) / 64u;
    const uint64_t total_bytes = total_blocks * 64u;

    thread uint w[64];
    for (uint64_t block = 0; block < total_blocks; ++block) {
        const uint64_t base = block * 64u;
        for (uint i = 0; i < 16; ++i) {
            const uint64_t off = base + (uint64_t)i * 4u;
            const uint b0 = FinalEllMessageByteAt(compressed, N, msg_len_bytes, total_bytes, off + 0u);
            const uint b1 = FinalEllMessageByteAt(compressed, N, msg_len_bytes, total_bytes, off + 1u);
            const uint b2 = FinalEllMessageByteAt(compressed, N, msg_len_bytes, total_bytes, off + 2u);
            const uint b3 = FinalEllMessageByteAt(compressed, N, msg_len_bytes, total_bytes, off + 3u);
            w[i] = (b0 << 24u) | (b1 << 16u) | (b2 << 8u) | b3;
        }
        sha256_compress(out_state, w);
    }
}

inline void sha256_double_digest(thread uint first_state[8], thread uint out_state[8])
{
    out_state[0] = 0x6a09e667u;
    out_state[1] = 0xbb67ae85u;
    out_state[2] = 0x3c6ef372u;
    out_state[3] = 0xa54ff53au;
    out_state[4] = 0x510e527fu;
    out_state[5] = 0x9b05688cu;
    out_state[6] = 0x1f83d9abu;
    out_state[7] = 0x5be0cd19u;

    thread uint w[64];
    for (uint i = 0; i < 8; ++i) {
        w[i] = first_state[i];
    }
    w[8] = 0x80000000u;
    for (uint i = 9; i < 15; ++i) {
        w[i] = 0u;
    }
    w[15] = 256u;
    sha256_compress(out_state, w);
}

kernel void build_perturbed(
    constant KernelParams& p [[buffer(0)]],
    device const uint* matrix_a [[buffer(1)]],
    device const uint* matrix_b [[buffer(2)]],
    device const uint* e_l [[buffer(3)]],
    device const uint* e_r [[buffer(4)]],
    device const uint* f_l [[buffer(5)]],
    device const uint* f_r [[buffer(6)]],
    device uint* a_prime [[buffer(7)]],
    device uint* b_prime [[buffer(8)]],
    uint gid [[thread_position_in_grid]])
{
    const uint nn = p.n * p.n;
    if (gid >= nn) {
        return;
    }

    const uint row = gid / p.n;
    const uint col = gid - row * p.n;

    uint e_acc = 0;
    uint f_acc = 0;
    for (uint k = 0; k < p.r; ++k) {
        const uint el = e_l[row * p.r + k];
        const uint er = e_r[k * p.n + col];
        e_acc = add_mod(e_acc, mul_mod(el, er));

        const uint fl = f_l[row * p.r + k];
        const uint fr = f_r[k * p.n + col];
        f_acc = add_mod(f_acc, mul_mod(fl, fr));
    }

    a_prime[gid] = add_mod(matrix_a[gid], e_acc);
    b_prime[gid] = add_mod(matrix_b[gid], f_acc);
}

kernel void build_prefix(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device uint* c_prefix [[buffer(3)]],
    uint gid [[thread_position_in_grid]])
{
    const uint nn = p.n * p.n;
    if (gid >= nn) {
        return;
    }

    const uint row = gid / p.n;
    const uint col = gid - row * p.n;

    uint c_acc = 0;
    for (uint ell = 0; ell < p.N; ++ell) {
        const uint k_base = ell * p.b;

        uint product = 0;
        for (uint k = 0; k < p.b; ++k) {
            const uint a = a_prime[row * p.n + (k_base + k)];
            const uint b = b_prime[(k_base + k) * p.n + col];
            product = dot_step(product, a, b);
        }

        c_acc = add_mod(c_acc, product);
        c_prefix[ell * nn + gid] = c_acc;
    }
}

kernel void fused_final_compress(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device const uint* compress_vec [[buffer(3)]],
    device uint* compressed [[buffer(4)]],
    uint tid [[thread_index_in_threadgroup]],
    uint simd_size [[threads_per_simdgroup]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    const uint block_elements = p.b * p.b;
    if (block_elements == 0 || block_elements > MAX_BLOCK_ELEMENTS || tid >= block_elements) {
        return;
    }

    const uint tile_i = tgid.y;
    const uint tile_j = tgid.x;
    if (tile_i >= p.N || tile_j >= p.N) {
        return;
    }

    const uint br = tid / p.b;
    const uint bc = tid - br * p.b;
    const uint row = tile_i * p.b + br;
    const uint col = tile_j * p.b + bc;

    threadgroup uint weighted_terms[MAX_BLOCK_ELEMENTS];
    const uint weight = compress_vec[tid];
    uint c_acc = 0;
    for (uint ell = 0; ell < p.N; ++ell) {
        const uint k_base = ell * p.b;

        uint product = 0;
        for (uint k = 0; k < p.b; ++k) {
            const uint a = a_prime[row * p.n + (k_base + k)];
            const uint b = b_prime[(k_base + k) * p.n + col];
            product = dot_step(product, a, b);
        }

        c_acc = add_mod(c_acc, product);
    }

    weighted_terms[tid] = mul_mod(c_acc, weight);
    threadgroup_barrier(mem_flags::mem_threadgroup);

    const uint simd_lane = tid % simd_size;
    const uint simd_group = tid / simd_size;
    uint reduced = reduce_simdgroup_add_mod(weighted_terms[tid], simd_size);
    if (simd_lane == 0u) {
        weighted_terms[simd_group] = reduced;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    const uint group_count = (block_elements + simd_size - 1u) / simd_size;
    if (simd_group == 0u) {
        reduced = tid < group_count ? weighted_terms[tid] : 0u;
        reduced = reduce_simdgroup_add_mod(reduced, simd_size);
        if (tid == 0u) {
            compressed[tile_i * p.N + tile_j] = reduced;
        }
    }
}

kernel void compress_prefix(
    constant KernelParams& p [[buffer(0)]],
    device const uint* c_prefix [[buffer(1)]],
    device const uint* compress_vec [[buffer(2)]],
    device uint* compressed [[buffer(3)]],
    uint gid [[thread_position_in_grid]])
{
    const uint n3 = p.N * p.N * p.N;
    if (gid >= n3) {
        return;
    }

    const uint i = gid / (p.N * p.N);
    const uint rem = gid - i * (p.N * p.N);
    const uint j = rem / p.N;
    const uint ell = rem - j * p.N;

    const uint row_base = i * p.b;
    const uint col_base = j * p.b;
    const uint nn = p.n * p.n;

    uint acc = 0;
    uint v_idx = 0;
    for (uint br = 0; br < p.b; ++br) {
        const uint row = row_base + br;
        for (uint bc = 0; bc < p.b; ++bc) {
            const uint col = col_base + bc;
            const uint value = c_prefix[ell * nn + row * p.n + col];
            const uint weight = compress_vec[v_idx++];
            acc = dot_step(acc, value, weight);
        }
    }

    compressed[gid] = acc;
}

kernel void build_perturbed_specialized(
    constant KernelParams& p [[buffer(0)]],
    device const uint* matrix_a [[buffer(1)]],
    device const uint* matrix_b [[buffer(2)]],
    device const uint* e_l [[buffer(3)]],
    device const uint* e_r [[buffer(4)]],
    device const uint* f_l [[buffer(5)]],
    device const uint* f_r [[buffer(6)]],
    device uint* a_prime [[buffer(7)]],
    device uint* b_prime [[buffer(8)]],
    uint gid [[thread_position_in_grid]])
{
    const uint n = FC_SPEC_N;
    const uint r = FC_SPEC_R;
    if (p.n != n || p.r != r) {
        return;
    }

    const uint nn = n * n;
    if (gid >= nn) {
        return;
    }

    const uint row = gid / n;
    const uint col = gid - row * n;

    uint e_acc = 0;
    uint f_acc = 0;
    for (uint k = 0; k < FC_SPEC_R; ++k) {
        const uint el = e_l[row * r + k];
        const uint er = e_r[k * n + col];
        e_acc = add_mod(e_acc, mul_mod(el, er));

        const uint fl = f_l[row * r + k];
        const uint fr = f_r[k * n + col];
        f_acc = add_mod(f_acc, mul_mod(fl, fr));
    }

    a_prime[gid] = add_mod(matrix_a[gid], e_acc);
    b_prime[gid] = add_mod(matrix_b[gid], f_acc);
}

kernel void build_prefix_specialized(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device uint* c_prefix [[buffer(3)]],
    uint gid [[thread_position_in_grid]])
{
    const uint n = FC_SPEC_N;
    const uint b = FC_SPEC_B;
    const uint N = FC_SPEC_NBLOCKS;
    if (p.n != n || p.b != b || p.N != N) {
        return;
    }

    const uint nn = n * n;
    if (gid >= nn) {
        return;
    }

    const uint row = gid / n;
    const uint col = gid - row * n;

    uint c_acc = 0;
    for (uint ell = 0; ell < FC_SPEC_NBLOCKS; ++ell) {
        const uint k_base = ell * b;

        uint product = 0;
        for (uint k = 0; k < FC_SPEC_B; ++k) {
            const uint a = a_prime[row * n + (k_base + k)];
            const uint b_val = b_prime[(k_base + k) * n + col];
            product = dot_step(product, a, b_val);
        }

        c_acc = add_mod(c_acc, product);
        c_prefix[ell * nn + gid] = c_acc;
    }
}

kernel void fused_final_compress_specialized(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device const uint* compress_vec [[buffer(3)]],
    device uint* compressed [[buffer(4)]],
    uint tid [[thread_index_in_threadgroup]],
    uint simd_size [[threads_per_simdgroup]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    const uint n = FC_SPEC_N;
    const uint b = FC_SPEC_B;
    const uint N = FC_SPEC_NBLOCKS;
    if (p.n != n || p.b != b || p.N != N) {
        return;
    }

    const uint block_elements = FC_SPEC_B * FC_SPEC_B;
    if (block_elements == 0 || block_elements > MAX_BLOCK_ELEMENTS || tid >= block_elements) {
        return;
    }

    const uint tile_i = tgid.y;
    const uint tile_j = tgid.x;
    if (tile_i >= N || tile_j >= N) {
        return;
    }

    const uint br = tid / b;
    const uint bc = tid - br * b;
    const uint row = tile_i * b + br;
    const uint col = tile_j * b + bc;

    threadgroup uint weighted_terms[MAX_BLOCK_ELEMENTS];
    const uint weight = compress_vec[tid];
    uint c_acc = 0;
    for (uint ell = 0; ell < FC_SPEC_NBLOCKS; ++ell) {
        const uint k_base = ell * b;

        uint product = 0;
        for (uint k = 0; k < FC_SPEC_B; ++k) {
            const uint a = a_prime[row * n + (k_base + k)];
            const uint b_val = b_prime[(k_base + k) * n + col];
            product = dot_step(product, a, b_val);
        }

        c_acc = add_mod(c_acc, product);
    }

    weighted_terms[tid] = mul_mod(c_acc, weight);
    threadgroup_barrier(mem_flags::mem_threadgroup);

    const uint simd_lane = tid % simd_size;
    const uint simd_group = tid / simd_size;
    uint reduced = reduce_simdgroup_add_mod(weighted_terms[tid], simd_size);
    if (simd_lane == 0u) {
        weighted_terms[simd_group] = reduced;
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    const uint group_count = (block_elements + simd_size - 1u) / simd_size;
    if (simd_group == 0u) {
        reduced = tid < group_count ? weighted_terms[tid] : 0u;
        reduced = reduce_simdgroup_add_mod(reduced, simd_size);
        if (tid == 0u) {
            compressed[tile_i * N + tile_j] = reduced;
        }
    }
}

kernel void compress_prefix_specialized(
    constant KernelParams& p [[buffer(0)]],
    device const uint* c_prefix [[buffer(1)]],
    device const uint* compress_vec [[buffer(2)]],
    device uint* compressed [[buffer(3)]],
    uint gid [[thread_position_in_grid]])
{
    const uint n = FC_SPEC_N;
    const uint b = FC_SPEC_B;
    const uint N = FC_SPEC_NBLOCKS;
    if (p.n != n || p.b != b || p.N != N) {
        return;
    }

    const uint n3 = N * N * N;
    if (gid >= n3) {
        return;
    }

    const uint i = gid / (N * N);
    const uint rem = gid - i * (N * N);
    const uint j = rem / N;
    const uint ell = rem - j * N;

    const uint row_base = i * b;
    const uint col_base = j * b;
    const uint nn = n * n;

    uint acc = 0;
    uint v_idx = 0;
    for (uint br = 0; br < FC_SPEC_B; ++br) {
        const uint row = row_base + br;
        for (uint bc = 0; bc < FC_SPEC_B; ++bc) {
            const uint col = col_base + bc;
            const uint value = c_prefix[ell * nn + row * n + col];
            const uint weight = compress_vec[v_idx++];
            acc = dot_step(acc, value, weight);
        }
    }

    compressed[gid] = acc;
}

kernel void fused_prefix_compress_specialized(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device const uint* compress_vec [[buffer(3)]],
    device uint* compressed [[buffer(4)]],
    uint tid [[thread_index_in_threadgroup]],
    uint simd_size [[threads_per_simdgroup]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    const uint n = FC_SPEC_N;
    const uint b = FC_SPEC_B;
    const uint N = FC_SPEC_NBLOCKS;
    if (p.n != n || p.b != b || p.N != N) {
        return;
    }

    const uint block_elements = FC_SPEC_B * FC_SPEC_B;
    if (block_elements == 0 || block_elements > MAX_BLOCK_ELEMENTS || tid >= block_elements) {
        return;
    }

    const uint tile_i = tgid.y;
    const uint tile_j = tgid.x;
    if (tile_i >= N || tile_j >= N) {
        return;
    }

    const uint br = tid / b;
    const uint bc = tid - br * b;
    const uint row = tile_i * b + br;
    const uint col = tile_j * b + bc;

    threadgroup uint weighted_terms[MAX_BLOCK_ELEMENTS];
    const uint weight = compress_vec[tid];
    uint c_acc = 0;

    for (uint ell = 0; ell < FC_SPEC_NBLOCKS; ++ell) {
        const uint k_base = ell * b;

        uint product = 0;
        for (uint k = 0; k < FC_SPEC_B; ++k) {
            const uint a = a_prime[row * n + (k_base + k)];
            const uint b_val = b_prime[(k_base + k) * n + col];
            product = dot_step(product, a, b_val);
        }

        c_acc = add_mod(c_acc, product);
        weighted_terms[tid] = mul_mod(c_acc, weight);
        threadgroup_barrier(mem_flags::mem_threadgroup);

        const uint simd_lane = tid % simd_size;
        const uint simd_group = tid / simd_size;
        uint reduced = reduce_simdgroup_add_mod(weighted_terms[tid], simd_size);
        if (simd_lane == 0u) {
            weighted_terms[simd_group] = reduced;
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);

        const uint group_count = (block_elements + simd_size - 1u) / simd_size;
        if (simd_group == 0u) {
            reduced = tid < group_count ? weighted_terms[tid] : 0u;
            reduced = reduce_simdgroup_add_mod(reduced, simd_size);
            if (tid == 0u) {
                compressed[(tile_i * N + tile_j) * N + ell] = reduced;
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
}

inline uint block_dot_product_manual(constant KernelParams& p,
                                     device const uint* a_prime,
                                     device const uint* b_prime,
                                     threadgroup uint tile_a[16][16],
                                     threadgroup uint tile_b[16][16],
                                     uint row,
                                     uint col,
                                     uint ell,
                                     uint2 tid)
{
    const uint k_base = ell * p.b;

    uint a_value = 0;
    uint b_value = 0;
    if (tid.x < p.b && tid.y < p.b) {
        a_value = a_prime[row * p.n + (k_base + tid.x)];
        b_value = b_prime[(k_base + tid.y) * p.n + col];
    }
    tile_a[tid.y][tid.x] = a_value;
    tile_b[tid.y][tid.x] = b_value;
    threadgroup_barrier(mem_flags::mem_threadgroup);

    uint product = 0;
    for (uint k = 0; k < p.b; ++k) {
        const uint a = tile_a[tid.y][k];
        const uint b = tile_b[k][tid.x];
        product = dot_step(product, a, b);
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);
    return product;
}

inline uint block_dot_product_prepared(constant KernelParams& p,
                                       device const uint* a_prime,
                                       device const uint* b_prime,
                                       threadgroup uint tile_a[16][16],
                                       threadgroup uint tile_b[16][16],
                                       uint row,
                                       uint col,
                                       uint ell,
                                       uint2 tid)
{
#if defined(__METAL_VERSION__) && (__METAL_VERSION__ >= 400) && defined(BTX_ENABLE_COOPERATIVE_TENSOR_INT_EXPERIMENT)
    // Cooperative integer tensors are not yet enabled for this path.
    return block_dot_product_manual(p, a_prime, b_prime, tile_a, tile_b, row, col, ell, tid);
#else
    return block_dot_product_manual(p, a_prime, b_prime, tile_a, tile_b, row, col, ell, tid);
#endif
}

kernel void build_prefix_tiled(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device uint* c_prefix [[buffer(3)]],
    uint2 gid [[thread_position_in_grid]],
    uint2 tid [[thread_position_in_threadgroup]])
{
    const uint row = gid.y;
    const uint col = gid.x;
    if (row >= p.n || col >= p.n) {
        return;
    }

    threadgroup uint tile_a[16][16];
    threadgroup uint tile_b[16][16];

    uint c_acc = 0;
    for (uint ell = 0; ell < p.N; ++ell) {
        const uint product = block_dot_product_prepared(p, a_prime, b_prime, tile_a, tile_b, row, col, ell, tid);

        c_acc = add_mod(c_acc, product);
        c_prefix[ell * (p.n * p.n) + row * p.n + col] = c_acc;
    }
}

kernel void fused_prefix_compress(
    constant KernelParams& p [[buffer(0)]],
    device const uint* a_prime [[buffer(1)]],
    device const uint* b_prime [[buffer(2)]],
    device const uint* compress_vec [[buffer(3)]],
    device uint* compressed [[buffer(4)]],
    uint tid [[thread_index_in_threadgroup]],
    uint simd_size [[threads_per_simdgroup]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    const uint block_elements = p.b * p.b;
    if (block_elements == 0 || block_elements > MAX_BLOCK_ELEMENTS || tid >= block_elements) {
        return;
    }

    const uint tile_i = tgid.y;
    const uint tile_j = tgid.x;
    if (tile_i >= p.N || tile_j >= p.N) {
        return;
    }

    const uint br = tid / p.b;
    const uint bc = tid - br * p.b;
    const uint row = tile_i * p.b + br;
    const uint col = tile_j * p.b + bc;

    threadgroup uint weighted_terms[MAX_BLOCK_ELEMENTS];
    const uint weight = compress_vec[tid];
    uint c_acc = 0;

    for (uint ell = 0; ell < p.N; ++ell) {
        const uint k_base = ell * p.b;

        uint product = 0;
        for (uint k = 0; k < p.b; ++k) {
            const uint a = a_prime[row * p.n + (k_base + k)];
            const uint b = b_prime[(k_base + k) * p.n + col];
            product = dot_step(product, a, b);
        }

        c_acc = add_mod(c_acc, product);
        weighted_terms[tid] = mul_mod(c_acc, weight);
        threadgroup_barrier(mem_flags::mem_threadgroup);

        const uint simd_lane = tid % simd_size;
        const uint simd_group = tid / simd_size;
        uint reduced = reduce_simdgroup_add_mod(weighted_terms[tid], simd_size);
        if (simd_lane == 0u) {
            weighted_terms[simd_group] = reduced;
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);

        const uint group_count = (block_elements + simd_size - 1u) / simd_size;
        if (simd_group == 0u) {
            reduced = tid < group_count ? weighted_terms[tid] : 0u;
            reduced = reduce_simdgroup_add_mod(reduced, simd_size);
            if (tid == 0u) {
                compressed[(tile_i * p.N + tile_j) * p.N + ell] = reduced;
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }
}

kernel void transcript_sha256(
    device const uint* compressed [[buffer(0)]],
    constant HashParams& hp [[buffer(1)]],
    device uchar* hash_output [[buffer(2)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid != 0) {
        return;
    }

    thread uint first_state[8];
    sha256_stream_words(compressed, hp.compressed_words, first_state);

    thread uint final_state[8];
    sha256_double_digest(first_state, final_state);

    for (uint i = 0; i < 8; ++i) {
        const uint word = final_state[i];
        hash_output[i * 4 + 0] = (uchar)((word >> 24u) & 0xffu);
        hash_output[i * 4 + 1] = (uchar)((word >> 16u) & 0xffu);
        hash_output[i * 4 + 2] = (uchar)((word >> 8u) & 0xffu);
        hash_output[i * 4 + 3] = (uchar)(word & 0xffu);
    }
}

kernel void product_compressed_sha256(
    device const uint* compressed [[buffer(0)]],
    constant KernelParams& kp [[buffer(1)]],
    device uchar* hash_output [[buffer(2)]],
    uint gid [[thread_position_in_grid]])
{
    if (gid != 0) {
        return;
    }

    const uint final_words = kp.N * kp.N;
    thread uint first_state[8];
    sha256_stream_final_ell_words(compressed, kp.N, final_words, first_state);

    thread uint final_state[8];
    sha256_double_digest(first_state, final_state);

    for (uint i = 0; i < 8; ++i) {
        const uint word = final_state[i];
        hash_output[i * 4 + 0] = (uchar)((word >> 24u) & 0xffu);
        hash_output[i * 4 + 1] = (uchar)((word >> 16u) & 0xffu);
        hash_output[i * 4 + 2] = (uchar)((word >> 8u) & 0xffu);
        hash_output[i * 4 + 3] = (uchar)(word & 0xffu);
    }
}

)METAL";

constexpr uint32_t FC_INDEX_N = 0;
constexpr uint32_t FC_INDEX_B = 1;
constexpr uint32_t FC_INDEX_R = 2;
constexpr uint32_t FC_INDEX_NBLOCKS = 3;

struct SpecializedKernelShape {
    uint32_t n;
    uint32_t b;
    uint32_t r;
    uint32_t N;
    const char* label;
};

constexpr std::array<SpecializedKernelShape, 3> SPECIALIZED_KERNEL_SHAPES{{
    {512, 16, 8, 32, "mainnet_512_16_8"},
    {256, 8, 4, 32, "testnet_256_8_4"},
    {64, 4, 2, 16, "regtest_64_4_2"},
}};

// Keep the default auto pool conservative enough for Apple Silicon mining while
// still matching the solver fanout policy on hosts that benefit from multiple
// in-flight Metal solves. Explicit env overrides still take precedence.
constexpr uint32_t DEFAULT_METAL_POOL_SLOT_COUNT{1};
constexpr uint32_t MAX_METAL_POOL_SLOT_COUNT{8};

struct SpecializedKernelPipelines {
    SpecializedKernelShape shape{};
    id<MTLComputePipelineState> build_perturbed_pipeline{nil};
    id<MTLComputePipelineState> build_prefix_pipeline{nil};
    id<MTLComputePipelineState> fused_final_compress_pipeline{nil};
    id<MTLComputePipelineState> compress_prefix_pipeline{nil};
    id<MTLComputePipelineState> fused_prefix_compress_pipeline{nil};
    bool available{false};
};

int32_t ResolveApplePerformanceLogicalCpuCount()
{
    const char* override_env = std::getenv("BTX_MATMUL_APPLE_PERFLEVEL0_LOGICALCPU_OVERRIDE");
    if (override_env != nullptr && override_env[0] != '\0') {
        char* override_end{nullptr};
        const long parsed_override = std::strtol(override_env, &override_end, 10);
        if (override_end != override_env && *override_end == '\0') {
            return static_cast<int32_t>(parsed_override);
        }
    }

    int32_t perf_level0_logicalcpu{0};
    size_t perf_level0_size{sizeof(perf_level0_logicalcpu)};
    if (sysctlbyname("hw.perflevel0.logicalcpu",
                     &perf_level0_logicalcpu,
                     &perf_level0_size,
                     nullptr,
                     0) == 0 &&
        perf_level0_size == sizeof(perf_level0_logicalcpu) &&
        perf_level0_logicalcpu > 0) {
        return perf_level0_logicalcpu;
    }
    return 0;
}

bool IsHighPerfAppleMetalHost(int32_t perf_level0_logicalcpu)
{
    return perf_level0_logicalcpu >= 10;
}

bool IsConservativeAppleMetalHost(int32_t perf_level0_logicalcpu)
{
    return perf_level0_logicalcpu > 0 && perf_level0_logicalcpu <= 4;
}

uint32_t ResolveMetalAutoPoolSlotCount()
{
    const char* solver_threads_env = std::getenv("BTX_MATMUL_SOLVER_THREADS");
    if (solver_threads_env != nullptr && solver_threads_env[0] != '\0') {
        char* solver_threads_end{nullptr};
        const long parsed_solver_threads = std::strtol(solver_threads_env, &solver_threads_end, 10);
        if (solver_threads_end != solver_threads_env &&
            *solver_threads_end == '\0' &&
            parsed_solver_threads > 0) {
            return static_cast<uint32_t>(std::clamp<long>(
                parsed_solver_threads,
                1,
                MAX_METAL_POOL_SLOT_COUNT));
        }
    }

    const int32_t perf_level0_logicalcpu = ResolveApplePerformanceLogicalCpuCount();
    if (perf_level0_logicalcpu > 0) {
        if (IsHighPerfAppleMetalHost(perf_level0_logicalcpu)) {
            return 5;
        }

        if (IsConservativeAppleMetalHost(perf_level0_logicalcpu)) {
            return 1;
        }

        return static_cast<uint32_t>(std::clamp<int32_t>(
            perf_level0_logicalcpu - 1,
            1,
            4));
    }

    return DEFAULT_METAL_POOL_SLOT_COUNT;
}

uint32_t ResolveMetalPoolSlotCount()
{
    const char* env = std::getenv("BTX_MATMUL_METAL_POOL_SLOTS");
    if (env == nullptr || env[0] == '\0') {
        return ResolveMetalAutoPoolSlotCount();
    }

    char* end{nullptr};
    const long parsed = std::strtol(env, &end, 10);
    if (end == env || *end != '\0' || parsed <= 0) {
        return DEFAULT_METAL_POOL_SLOT_COUNT;
    }
    return static_cast<uint32_t>(std::clamp<long>(parsed, 1, MAX_METAL_POOL_SLOT_COUNT));
}

bool ParseTruthyEnv(const char* name, bool default_value)
{
    const char* env = std::getenv(name);
    if (env == nullptr || env[0] == '\0') {
        return default_value;
    }

    if (std::strcmp(env, "0") == 0 ||
        std::strcmp(env, "false") == 0 ||
        std::strcmp(env, "FALSE") == 0 ||
        std::strcmp(env, "off") == 0 ||
        std::strcmp(env, "OFF") == 0) {
        return false;
    }
    return true;
}

bool ShouldPrewarmMetalPoolSlots()
{
    return ParseTruthyEnv("BTX_MATMUL_METAL_POOL_PREWARM", true);
}

struct MetalPoolSlot {
    id<MTLCommandQueue> queue{nil};
    id<MTLBuffer> params_buffer{nil};
    id<MTLBuffer> hash_params_buffer{nil};
    id<MTLBuffer> matrix_a_stage_buffer{nil};
    id<MTLBuffer> matrix_b_stage_buffer{nil};
    id<MTLBuffer> e_l_buffer{nil};
    id<MTLBuffer> e_r_buffer{nil};
    id<MTLBuffer> f_l_buffer{nil};
    id<MTLBuffer> f_r_buffer{nil};
    id<MTLBuffer> compress_buffer{nil};
    id<MTLBuffer> a_prime_buffer{nil};
    id<MTLBuffer> b_prime_buffer{nil};
    id<MTLBuffer> prefix_buffer{nil};
    id<MTLBuffer> compressed_buffer{nil};
    id<MTLBuffer> transcript_hash_buffer{nil};
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    size_t matrix_bytes{0};
    size_t noise_bytes{0};
    size_t compress_bytes{0};
    size_t prefix_bytes{0};
    size_t compressed_bytes{0};
    size_t hash_bytes{0};
    bool in_use{false};
};

struct MetalContext {
    bool ready{false};
    std::string error;
    id<MTLDevice> device{nil};
    id<MTLComputePipelineState> build_perturbed_pipeline{nil};
    id<MTLComputePipelineState> build_prefix_pipeline{nil};
    id<MTLComputePipelineState> fused_final_compress_pipeline{nil};
    id<MTLComputePipelineState> compress_prefix_pipeline{nil};
    id<MTLComputePipelineState> build_prefix_tiled_pipeline{nil};
    id<MTLComputePipelineState> fused_prefix_compress_pipeline{nil};
    id<MTLComputePipelineState> transcript_sha256_pipeline{nil};
    id<MTLComputePipelineState> product_compressed_sha256_pipeline{nil};
    std::array<SpecializedKernelPipelines, SPECIALIZED_KERNEL_SHAPES.size()> specialized_pipelines{};
    uint32_t specialized_pipeline_count{0};
    std::string specialized_pipeline_reason;
    bool using_precompiled_library{false};
    bool capture_supported{false};
    std::mutex pool_mutex;
    std::condition_variable pool_cv;
    std::vector<MetalPoolSlot> pool_slots;
    uint32_t pool_last_n{0};
    uint32_t pool_last_b{0};
    uint32_t pool_last_r{0};
    uint32_t pool_next_slot{0};
    uint32_t pool_active_slots{0};
    uint32_t pool_high_water_slots{0};
    uint64_t pool_allocation_events{0};
    uint64_t pool_reuse_events{0};
    uint64_t pool_wait_events{0};
    uint64_t pool_completed_submissions{0};
    uint32_t pool_inflight_submissions{0};
    uint32_t pool_peak_inflight_submissions{0};
    std::mutex profiling_mutex;
    btx::metal::MatMulProfilingStats profiling_stats;
    std::mutex resident_base_mutex;
    id<MTLBuffer> resident_matrix_a_buffer{nil};
    id<MTLBuffer> resident_matrix_b_buffer{nil};
    uint32_t resident_matrix_n{0};
    uint64_t resident_data_fingerprint{0};

    MetalContext()
    {
        @autoreleasepool {
            device = MTLCreateSystemDefaultDevice();
            if (device == nil) {
                error = "No Metal-compatible GPU device found";
                return;
            }
            capture_supported = [MTLCaptureManager sharedCaptureManager] != nil;
            pool_slots.resize(ResolveMetalPoolSlotCount());
            for (auto& slot : pool_slots) {
                slot.queue = [device newCommandQueue];
                if (slot.queue == nil) {
                    error = "Failed to create Metal command queue";
                    return;
                }
            }

            NSError* library_error = nil;
            id<MTLLibrary> library = nil;
#if defined(BTX_MATMUL_METALLIB_PATH)
            NSString* precompiled_path = [NSString stringWithUTF8String:BTX_MATMUL_METALLIB_PATH];
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
                                             : "Failed to compile Metal MatMul kernel source";
                return;
            }

            id<MTLFunction> build_perturbed_function = [library newFunctionWithName:@"build_perturbed"];
            if (build_perturbed_function == nil) {
                error = "Failed to load Metal kernel function: build_perturbed";
                return;
            }

            NSError* pipeline_error = nil;
            build_perturbed_pipeline = [device newComputePipelineStateWithFunction:build_perturbed_function error:&pipeline_error];
            if (build_perturbed_pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create build_perturbed pipeline";
                return;
            }

            id<MTLFunction> build_prefix_function = [library newFunctionWithName:@"build_prefix"];
            if (build_prefix_function == nil) {
                error = "Failed to load Metal kernel function: build_prefix";
                return;
            }

            pipeline_error = nil;
            build_prefix_pipeline = [device newComputePipelineStateWithFunction:build_prefix_function error:&pipeline_error];
            if (build_prefix_pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create build_prefix pipeline";
                return;
            }

            id<MTLFunction> fused_final_compress_function = [library newFunctionWithName:@"fused_final_compress"];
            if (fused_final_compress_function == nil) {
                error = "Failed to load Metal kernel function: fused_final_compress";
                return;
            }

            pipeline_error = nil;
            fused_final_compress_pipeline = [device newComputePipelineStateWithFunction:fused_final_compress_function error:&pipeline_error];
            if (fused_final_compress_pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create fused_final_compress pipeline";
                return;
            }

            id<MTLFunction> compress_prefix_function = [library newFunctionWithName:@"compress_prefix"];
            if (compress_prefix_function == nil) {
                error = "Failed to load Metal kernel function: compress_prefix";
                return;
            }

            pipeline_error = nil;
            compress_prefix_pipeline = [device newComputePipelineStateWithFunction:compress_prefix_function error:&pipeline_error];
            if (compress_prefix_pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create compress_prefix pipeline";
                return;
            }

            id<MTLFunction> build_prefix_tiled_function = [library newFunctionWithName:@"build_prefix_tiled"];
            if (build_prefix_tiled_function == nil) {
                error = "Failed to load Metal kernel function: build_prefix_tiled";
                return;
            }

            pipeline_error = nil;
            build_prefix_tiled_pipeline = [device newComputePipelineStateWithFunction:build_prefix_tiled_function error:&pipeline_error];
            if (build_prefix_tiled_pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create build_prefix_tiled pipeline";
                return;
            }

            id<MTLFunction> fused_prefix_compress_function = [library newFunctionWithName:@"fused_prefix_compress"];
            if (fused_prefix_compress_function == nil) {
                error = "Failed to load Metal kernel function: fused_prefix_compress";
                return;
            }

            pipeline_error = nil;
            fused_prefix_compress_pipeline = [device newComputePipelineStateWithFunction:fused_prefix_compress_function error:&pipeline_error];
            if (fused_prefix_compress_pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create fused_prefix_compress pipeline";
                return;
            }

            id<MTLFunction> transcript_sha256_function = [library newFunctionWithName:@"transcript_sha256"];
            if (transcript_sha256_function == nil) {
                error = "Failed to load Metal kernel function: transcript_sha256";
                return;
            }

            pipeline_error = nil;
            transcript_sha256_pipeline = [device newComputePipelineStateWithFunction:transcript_sha256_function error:&pipeline_error];
            if (transcript_sha256_pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create transcript_sha256 pipeline";
                return;
            }

            id<MTLFunction> product_compressed_sha256_function = [library newFunctionWithName:@"product_compressed_sha256"];
            if (product_compressed_sha256_function == nil) {
                error = "Failed to load Metal kernel function: product_compressed_sha256";
                return;
            }

            pipeline_error = nil;
            product_compressed_sha256_pipeline = [device newComputePipelineStateWithFunction:product_compressed_sha256_function error:&pipeline_error];
            if (product_compressed_sha256_pipeline == nil) {
                error = pipeline_error != nil ? [[pipeline_error localizedDescription] UTF8String]
                                              : "Failed to create product_compressed_sha256 pipeline";
                return;
            }

            auto make_specialized_function = [&](NSString* function_name,
                                                 const SpecializedKernelShape& shape,
                                                 std::string& out_error) -> id<MTLFunction> {
                MTLFunctionConstantValues* values = [[MTLFunctionConstantValues alloc] init];
                const uint32_t n = shape.n;
                const uint32_t b = shape.b;
                const uint32_t r = shape.r;
                const uint32_t N = shape.N;
                [values setConstantValue:&n type:MTLDataTypeUInt atIndex:FC_INDEX_N];
                [values setConstantValue:&b type:MTLDataTypeUInt atIndex:FC_INDEX_B];
                [values setConstantValue:&r type:MTLDataTypeUInt atIndex:FC_INDEX_R];
                [values setConstantValue:&N type:MTLDataTypeUInt atIndex:FC_INDEX_NBLOCKS];

                NSError* fn_error = nil;
                id<MTLFunction> function = [library newFunctionWithName:function_name constantValues:values error:&fn_error];
                if (function == nil) {
                    out_error = fn_error != nil ? [[fn_error localizedDescription] UTF8String]
                                                : "Failed to create specialized Metal function";
                }
                return function;
            };

            auto make_specialized_pipeline = [&](NSString* function_name,
                                                 const SpecializedKernelShape& shape,
                                                 std::string& out_error) -> id<MTLComputePipelineState> {
                id<MTLFunction> function = make_specialized_function(function_name, shape, out_error);
                if (function == nil) {
                    return nil;
                }

                NSError* local_pipeline_error = nil;
                id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:function error:&local_pipeline_error];
                if (pipeline == nil) {
                    out_error = local_pipeline_error != nil ? [[local_pipeline_error localizedDescription] UTF8String]
                                                            : "Failed to create specialized Metal pipeline";
                }
                return pipeline;
            };

            specialized_pipeline_count = 0;
            specialized_pipeline_reason = "function_constant_specialization_unavailable";
            for (size_t i = 0; i < SPECIALIZED_KERNEL_SHAPES.size(); ++i) {
                auto& entry = specialized_pipelines[i];
                entry = SpecializedKernelPipelines{};
                entry.shape = SPECIALIZED_KERNEL_SHAPES[i];

                std::string local_error;
                entry.build_perturbed_pipeline = make_specialized_pipeline(@"build_perturbed_specialized", entry.shape, local_error);
                if (entry.build_perturbed_pipeline == nil) {
                    specialized_pipeline_reason = local_error.empty() ? "build_perturbed_specialized_unavailable" : local_error;
                    continue;
                }

                entry.build_prefix_pipeline = make_specialized_pipeline(@"build_prefix_specialized", entry.shape, local_error);
                if (entry.build_prefix_pipeline == nil) {
                    specialized_pipeline_reason = local_error.empty() ? "build_prefix_specialized_unavailable" : local_error;
                    continue;
                }

                entry.fused_final_compress_pipeline = make_specialized_pipeline(@"fused_final_compress_specialized", entry.shape, local_error);
                if (entry.fused_final_compress_pipeline == nil) {
                    specialized_pipeline_reason = local_error.empty() ? "fused_final_compress_specialized_unavailable" : local_error;
                    continue;
                }

                entry.compress_prefix_pipeline = make_specialized_pipeline(@"compress_prefix_specialized", entry.shape, local_error);
                if (entry.compress_prefix_pipeline == nil) {
                    specialized_pipeline_reason = local_error.empty() ? "compress_prefix_specialized_unavailable" : local_error;
                    continue;
                }

                entry.fused_prefix_compress_pipeline = make_specialized_pipeline(@"fused_prefix_compress_specialized", entry.shape, local_error);
                if (entry.fused_prefix_compress_pipeline == nil) {
                    specialized_pipeline_reason = local_error.empty() ? "fused_prefix_compress_specialized_unavailable" : local_error;
                    continue;
                }

                entry.available = true;
                ++specialized_pipeline_count;
            }
            if (specialized_pipeline_count > 0) {
                specialized_pipeline_reason = "function_constant_specialization_ready";
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

const SpecializedKernelPipelines* FindSpecializedPipelines(const MetalContext& context,
                                                           uint32_t n,
                                                           uint32_t b,
                                                           uint32_t r,
                                                           uint32_t N)
{
    for (const auto& entry : context.specialized_pipelines) {
        if (!entry.available) {
            continue;
        }
        if (entry.shape.n == n && entry.shape.b == b && entry.shape.r == r && entry.shape.N == N) {
            return &entry;
        }
    }
    return nullptr;
}

bool IsPoolSlotInitialized(const MetalPoolSlot& slot, bool require_prefix_buffer)
{
    return slot.params_buffer != nil &&
        slot.hash_params_buffer != nil &&
        slot.matrix_a_stage_buffer != nil &&
        slot.matrix_b_stage_buffer != nil &&
        slot.e_l_buffer != nil &&
        slot.e_r_buffer != nil &&
        slot.f_l_buffer != nil &&
        slot.f_r_buffer != nil &&
        slot.compress_buffer != nil &&
        slot.a_prime_buffer != nil &&
        slot.b_prime_buffer != nil &&
        (!require_prefix_buffer || slot.prefix_buffer != nil) &&
        slot.compressed_buffer != nil &&
        slot.transcript_hash_buffer != nil;
}

bool DoesPoolSlotSatisfyRequest(const MetalPoolSlot& slot,
                                const btx::metal::MatMulDigestRequest& request,
                                size_t matrix_bytes,
                                size_t noise_bytes,
                                size_t compress_bytes,
                                size_t prefix_bytes,
                                size_t compressed_bytes,
                                size_t hash_bytes,
                                bool require_prefix_buffer)
{
    return IsPoolSlotInitialized(slot, require_prefix_buffer) &&
        slot.n == request.n &&
        slot.b == request.b &&
        slot.r == request.r &&
        slot.matrix_bytes >= matrix_bytes &&
        slot.noise_bytes >= noise_bytes &&
        slot.compress_bytes >= compress_bytes &&
        (!require_prefix_buffer || slot.prefix_bytes >= prefix_bytes) &&
        slot.compressed_bytes >= compressed_bytes &&
        slot.hash_bytes >= hash_bytes;
}

bool AllocateBufferPoolSlot(MetalContext& context,
                            MetalPoolSlot& slot,
                            size_t matrix_bytes,
                            size_t noise_bytes,
                            size_t compress_bytes,
                            size_t prefix_bytes,
                            size_t compressed_bytes,
                            size_t hash_bytes,
                            bool require_prefix_buffer,
                            std::string& error)
{
    id<MTLBuffer> params_buffer = [context.device newBufferWithLength:sizeof(uint32_t) * 4
                                                               options:MTLResourceStorageModeShared];
    id<MTLBuffer> hash_params_buffer = [context.device newBufferWithLength:sizeof(uint32_t)
                                                                    options:MTLResourceStorageModeShared];
    id<MTLBuffer> matrix_a_stage_buffer = [context.device newBufferWithLength:matrix_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> matrix_b_stage_buffer = [context.device newBufferWithLength:matrix_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> e_l_buffer = [context.device newBufferWithLength:noise_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> e_r_buffer = [context.device newBufferWithLength:noise_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> f_l_buffer = [context.device newBufferWithLength:noise_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> f_r_buffer = [context.device newBufferWithLength:noise_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> compress_buffer = [context.device newBufferWithLength:compress_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> a_prime_buffer = [context.device newBufferWithLength:matrix_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> b_prime_buffer = [context.device newBufferWithLength:matrix_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> prefix_buffer = require_prefix_buffer
        ? [context.device newBufferWithLength:prefix_bytes options:MTLResourceStorageModeShared]
        : slot.prefix_buffer;
    id<MTLBuffer> compressed_buffer = [context.device newBufferWithLength:compressed_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> transcript_hash_buffer = [context.device newBufferWithLength:hash_bytes options:MTLResourceStorageModeShared];
    if (params_buffer == nil || hash_params_buffer == nil || matrix_a_stage_buffer == nil || matrix_b_stage_buffer == nil ||
        e_l_buffer == nil || e_r_buffer == nil || f_l_buffer == nil || f_r_buffer == nil ||
        compress_buffer == nil || a_prime_buffer == nil || b_prime_buffer == nil ||
        (require_prefix_buffer && prefix_buffer == nil) ||
        compressed_buffer == nil || transcript_hash_buffer == nil) {
        error = "Failed to allocate Metal buffer pool slot for MatMul digest";
        return false;
    }

    slot.params_buffer = params_buffer;
    slot.hash_params_buffer = hash_params_buffer;
    slot.matrix_a_stage_buffer = matrix_a_stage_buffer;
    slot.matrix_b_stage_buffer = matrix_b_stage_buffer;
    slot.e_l_buffer = e_l_buffer;
    slot.e_r_buffer = e_r_buffer;
    slot.f_l_buffer = f_l_buffer;
    slot.f_r_buffer = f_r_buffer;
    slot.compress_buffer = compress_buffer;
    slot.a_prime_buffer = a_prime_buffer;
    slot.b_prime_buffer = b_prime_buffer;
    slot.prefix_buffer = prefix_buffer;
    slot.compressed_buffer = compressed_buffer;
    slot.transcript_hash_buffer = transcript_hash_buffer;
    slot.matrix_bytes = matrix_bytes;
    slot.noise_bytes = noise_bytes;
    slot.compress_bytes = compress_bytes;
    slot.prefix_bytes = require_prefix_buffer ? prefix_bytes : slot.prefix_bytes;
    slot.compressed_bytes = compressed_bytes;
    slot.hash_bytes = hash_bytes;
    return true;
}

bool EnsureBufferPoolSlot(MetalContext& context,
                          MetalPoolSlot& slot,
                          const btx::metal::MatMulDigestRequest& request,
                          size_t matrix_bytes,
                          size_t noise_bytes,
                          size_t compress_bytes,
                          size_t prefix_bytes,
                          size_t compressed_bytes,
                          size_t hash_bytes,
                          bool require_prefix_buffer,
                          std::string& error)
{
    if (DoesPoolSlotSatisfyRequest(slot,
                                   request,
                                   matrix_bytes,
                                   noise_bytes,
                                   compress_bytes,
                                   prefix_bytes,
                                   compressed_bytes,
                                   hash_bytes,
                                   require_prefix_buffer)) {
        ++context.pool_reuse_events;
        context.pool_last_n = request.n;
        context.pool_last_b = request.b;
        context.pool_last_r = request.r;
        return true;
    }

    if (!AllocateBufferPoolSlot(context,
                                slot,
                                matrix_bytes,
                                noise_bytes,
                                compress_bytes,
                                prefix_bytes,
                                compressed_bytes,
                                hash_bytes,
                                require_prefix_buffer,
                                error)) {
        return false;
    }
    slot.n = request.n;
    slot.b = request.b;
    slot.r = request.r;
    context.pool_last_n = request.n;
    context.pool_last_b = request.b;
    context.pool_last_r = request.r;
    ++context.pool_allocation_events;
    return true;
}

void PrewarmAvailableBufferPoolSlots(MetalContext& context,
                                     const btx::metal::MatMulDigestRequest& request,
                                     size_t selected_slot_index,
                                     size_t matrix_bytes,
                                     size_t noise_bytes,
                                     size_t compress_bytes,
                                     size_t prefix_bytes,
                                     size_t compressed_bytes,
                                     size_t hash_bytes,
                                     bool require_prefix_buffer)
{
    if (!ShouldPrewarmMetalPoolSlots() || context.pool_slots.size() <= 1) {
        return;
    }

    std::string ignored_error;
    for (size_t slot_index = 0; slot_index < context.pool_slots.size(); ++slot_index) {
        if (slot_index == selected_slot_index) {
            continue;
        }

        auto& slot = context.pool_slots[slot_index];
        if (slot.in_use ||
            DoesPoolSlotSatisfyRequest(slot,
                                       request,
                                       matrix_bytes,
                                       noise_bytes,
                                       compress_bytes,
                                       prefix_bytes,
                                       compressed_bytes,
                                       hash_bytes,
                                       require_prefix_buffer)) {
            continue;
        }

        if (!EnsureBufferPoolSlot(context,
                                  slot,
                                  request,
                                  matrix_bytes,
                                  noise_bytes,
                                  compress_bytes,
                                  prefix_bytes,
                                  compressed_bytes,
                                  hash_bytes,
                                  require_prefix_buffer,
                                  ignored_error)) {
            return;
        }
    }
}

struct BufferPoolLease {
    MetalContext* context{nullptr};
    MetalPoolSlot* slot{nullptr};
    size_t slot_index{0};

    BufferPoolLease(MetalContext* context_in, MetalPoolSlot* slot_in, size_t slot_index_in)
        : context(context_in), slot(slot_in), slot_index(slot_index_in)
    {
    }

    BufferPoolLease(const BufferPoolLease&) = delete;
    BufferPoolLease& operator=(const BufferPoolLease&) = delete;

    BufferPoolLease(BufferPoolLease&& other) noexcept
        : context(other.context), slot(other.slot), slot_index(other.slot_index)
    {
        other.context = nullptr;
        other.slot = nullptr;
    }

    ~BufferPoolLease()
    {
        Release();
    }

    void Release()
    {
        if (context == nullptr || slot == nullptr) {
            return;
        }
        {
            std::lock_guard<std::mutex> lock(context->pool_mutex);
            if (slot->in_use) {
                slot->in_use = false;
                if (context->pool_active_slots > 0) {
                    --context->pool_active_slots;
                }
            }
        }
        context->pool_cv.notify_one();
        context = nullptr;
        slot = nullptr;
    }
};

template <typename Result>
struct AsyncDigestSubmissionState {
    MetalContext* context{nullptr};
    std::mutex mutex;
    std::condition_variable cv;
    bool completed{false};
    Result result{};
    std::optional<BufferPoolLease> lease;
    CFMutableArrayRef retained_inputs{nullptr};
    double encode_build_perturbed_us{0.0};
    double encode_fused_prefix_compress_us{0.0};
    double encode_transcript_sha256_us{0.0};
    double submit_wait_us{0.0};
    double gpu_execution_ms{0.0};
    double cpu_finalize_us{0.0};
    bool any_zero_copy_input{false};

    ~AsyncDigestSubmissionState()
    {
        if (retained_inputs != nullptr) {
            CFRelease(retained_inputs);
            retained_inputs = nullptr;
        }
    }
};

struct AsyncSingleDigestState final : public AsyncDigestSubmissionState<btx::metal::MatMulDigestResult> {
    bool use_legacy_pipeline{false};
    bool use_product_digest{false};
    uint32_t n{0};
    uint32_t b{0};
    uint32_t N{0};
    uint256 sigma;
    uint64_t compressed_words{0};
    id<MTLBuffer> a_prime_buffer{nil};
    id<MTLBuffer> b_prime_buffer{nil};
    id<MTLBuffer> prefix_buffer{nil};
    id<MTLBuffer> compressed_buffer{nil};
    id<MTLBuffer> transcript_hash_buffer{nil};
};

struct AsyncBatchDigestState final : public AsyncDigestSubmissionState<btx::metal::MatMulDigestBatchResult> {
    uint32_t batch_size{0};
    bool use_product_digest{false};
    uint32_t n{0};
    uint32_t b{0};
    uint32_t N{0};
    uint64_t compressed_words{0};
    std::vector<uint256> sigmas;
    id<MTLBuffer> compressed_buffer{nil};
    id<MTLBuffer> transcript_hash_buffer{nil};
};

CFMutableArrayRef CreateRetainedInputArray(CFIndex capacity)
{
    return CFArrayCreateMutable(kCFAllocatorDefault, capacity, &kCFTypeArrayCallBacks);
}

void RetainTemporaryInputBuffer(CFMutableArrayRef array, id<MTLBuffer> buffer)
{
    if (array == nullptr || buffer == nil) {
        return;
    }
    CFArrayAppendValue(array, (__bridge const void*)buffer);
}

id<MTLBuffer> WrapSharedNoCopyBuffer(id<MTLDevice> device, const void* bytes, size_t length);

bool FinalizeProductCommittedDigestFromFinalSliceBuffer(id<MTLBuffer> compressed_buffer,
                                                        size_t word_offset,
                                                        uint32_t blocks_per_axis,
                                                        uint32_t n,
                                                        uint32_t b,
                                                        const uint256& sigma,
                                                        uint256& out_digest,
                                                        std::string& error)
{
    if (compressed_buffer == nil) {
        error = "product digest finalize missing Metal compressed buffer";
        return false;
    }
    const auto* const compressed_words = static_cast<const matmul::field::Element*>(compressed_buffer.contents);
    if (compressed_words == nullptr) {
        error = "product digest finalize missing Metal compressed buffer contents";
        return false;
    }

    try {
        if (blocks_per_axis == 0) {
            error = "product digest finalize requires non-zero blocks_per_axis";
            return false;
        }
        const size_t final_word_count = static_cast<size_t>(blocks_per_axis) * blocks_per_axis;
        const size_t final_ell = static_cast<size_t>(blocks_per_axis - 1);
        std::vector<matmul::field::Element> final_words;
        final_words.reserve(final_word_count);
        for (size_t word_index = 0; word_index < final_word_count; ++word_index) {
            final_words.push_back(
                compressed_words[word_offset + (word_index * static_cast<size_t>(blocks_per_axis)) + final_ell]);
        }
        out_digest = matmul::transcript::ComputeProductCommittedDigestFromWords(
            Span<const matmul::field::Element>{final_words.data(), final_words.size()},
            sigma,
            n,
            b);
        return true;
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
}

template <typename State>
void FinalizeAsyncSubmissionState(const std::shared_ptr<State>& state,
                                  const char* profiling_reason)
{
    if (state == nullptr || state->context == nullptr) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(state->context->pool_mutex);
        if (state->context->pool_inflight_submissions > 0) {
            --state->context->pool_inflight_submissions;
        }
        ++state->context->pool_completed_submissions;
    }

    if (state->lease.has_value()) {
        state->lease->Release();
        state->lease.reset();
    }

    {
        std::lock_guard<std::mutex> lock(state->context->profiling_mutex);
        state->context->profiling_stats.available = true;
        state->context->profiling_stats.capture_supported = state->context->capture_supported;
        ++state->context->profiling_stats.samples;
        state->context->profiling_stats.last_encode_build_perturbed_us = state->encode_build_perturbed_us;
        state->context->profiling_stats.last_encode_fused_prefix_compress_us = state->encode_fused_prefix_compress_us;
        state->context->profiling_stats.last_encode_transcript_sha256_us = state->encode_transcript_sha256_us;
        state->context->profiling_stats.last_submit_wait_us = state->submit_wait_us;
        state->context->profiling_stats.last_gpu_execution_ms = state->gpu_execution_ms;
        state->context->profiling_stats.last_cpu_finalize_us = state->cpu_finalize_us;
        state->context->profiling_stats.last_zero_copy_inputs = state->any_zero_copy_input;
        state->context->profiling_stats.last_async_submission = true;
        state->context->profiling_stats.reason = profiling_reason;
    }

    {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->completed = true;
    }
    state->cv.notify_all();
}

std::optional<BufferPoolLease> AcquireBufferPoolLease(MetalContext& context,
                                                      const btx::metal::MatMulDigestRequest& request,
                                                      size_t matrix_bytes,
                                                      size_t noise_bytes,
                                                      size_t compress_bytes,
                                                      size_t prefix_bytes,
                                                      size_t compressed_bytes,
                                                      size_t hash_bytes,
                                                      bool require_prefix_buffer,
                                                      std::string& error)
{
    std::unique_lock<std::mutex> lock(context.pool_mutex);
    if (context.pool_slots.empty()) {
        error = "No Metal buffer pool slots are configured";
        return std::nullopt;
    }

    bool waited{false};
    // Cap the number of wait iterations to prevent indefinite blocking
    // when all pool slots are occupied (e.g. by parallel solver threads).
    // After the deadline the caller falls back to CPU, which also lets
    // the mining loop re-check its abort flag on tip-change or shutdown.
    constexpr uint32_t kMaxWaitRounds = 40; // 40 * 50ms = 2 seconds
    uint32_t wait_rounds{0};
    while (true) {
        for (size_t offset = 0; offset < context.pool_slots.size(); ++offset) {
            const size_t slot_index = (context.pool_next_slot + offset) % context.pool_slots.size();
            auto& slot = context.pool_slots[slot_index];
            if (slot.in_use) {
                continue;
            }
            if (!EnsureBufferPoolSlot(context,
                                      slot,
                                      request,
                                      matrix_bytes,
                                      noise_bytes,
                                      compress_bytes,
                                      prefix_bytes,
                                      compressed_bytes,
                                      hash_bytes,
                                      require_prefix_buffer,
                                      error)) {
                return std::nullopt;
            }

            PrewarmAvailableBufferPoolSlots(context,
                                            request,
                                            slot_index,
                                            matrix_bytes,
                                            noise_bytes,
                                            compress_bytes,
                                            prefix_bytes,
                                            compressed_bytes,
                                            hash_bytes,
                                            require_prefix_buffer);

            slot.in_use = true;
            ++context.pool_active_slots;
            context.pool_high_water_slots = std::max(context.pool_high_water_slots, context.pool_active_slots);
            context.pool_next_slot = static_cast<uint32_t>((slot_index + 1) % context.pool_slots.size());
            if (waited) {
                ++context.pool_wait_events;
            }
            return BufferPoolLease{&context, &slot, slot_index};
        }

        waited = true;
        if (++wait_rounds > kMaxWaitRounds) {
            error = "Metal buffer pool exhausted after timeout";
            return std::nullopt;
        }
        context.pool_cv.wait_for(lock, std::chrono::milliseconds{50});
    }
}

bool BuildKernelParams(const btx::metal::MatMulDigestRequest& request,
                       uint32_t& out_N,
                       uint64_t& out_matrix_words,
                       uint64_t& out_noise_words,
                       uint64_t& out_prefix_words,
                       uint64_t& out_compressed_words,
                       std::string& error)
{
    if (request.n == 0 || request.b == 0 || request.r == 0) {
        error = "invalid MatMul request dimensions";
        return false;
    }
    if (request.r > request.n) {
        error = "noise rank exceeds matrix dimension";
        return false;
    }
    if ((request.n % request.b) != 0) {
        error = "matrix dimension must be divisible by transcript block size";
        return false;
    }
    if ((static_cast<uint64_t>(request.b) * request.b) > 256) {
        error = "transcript block size exceeds fused kernel threadgroup capacity";
        return false;
    }

    const uint64_t n = request.n;
    const uint64_t b = request.b;
    const uint64_t N = n / b;

    if (N > std::numeric_limits<uint32_t>::max()) {
        error = "invalid block decomposition";
        return false;
    }

    const uint64_t matrix_words = n * n;
    const uint64_t noise_words = n * request.r;
    const uint64_t prefix_words = N * matrix_words;
    const uint64_t compressed_words = N * N * N;

    if (matrix_words > std::numeric_limits<uint32_t>::max() ||
        prefix_words > std::numeric_limits<uint32_t>::max() ||
        compressed_words > std::numeric_limits<uint32_t>::max()) {
        error = "matrix dimensions exceed supported Metal launch bounds";
        return false;
    }

    if (request.use_uploaded_base_matrices) {
        if (request.matrix_a != nullptr || request.matrix_b != nullptr) {
            error = "explicit base matrix buffers are not allowed when using uploaded matrices";
            return false;
        }
    } else if (request.matrix_a == nullptr || request.matrix_b == nullptr) {
        error = "missing MatMul base matrix buffer";
        return false;
    }

    if (request.noise_e_l == nullptr || request.noise_e_r == nullptr ||
        request.noise_f_l == nullptr || request.noise_f_r == nullptr ||
        request.compress_vec == nullptr) {
        error = "missing MatMul input buffer";
        return false;
    }

    out_N = static_cast<uint32_t>(N);
    out_matrix_words = matrix_words;
    out_noise_words = noise_words;
    out_prefix_words = prefix_words;
    out_compressed_words = compressed_words;
    return true;
}

NSUInteger SelectThreadGroupSize(id<MTLComputePipelineState> pipeline, NSUInteger preferred)
{
    const NSUInteger max_threads = std::max<NSUInteger>(pipeline.maxTotalThreadsPerThreadgroup, 1);
    const NSUInteger requested = std::max<NSUInteger>(preferred, 1);
    return std::min<NSUInteger>(requested, max_threads);
}

id<MTLBuffer> WrapSharedNoCopyBuffer(id<MTLDevice> device, const void* bytes, size_t length)
{
    if (device == nil || bytes == nullptr || length == 0) {
        return nil;
    }
    // Metal's newBufferWithBytesNoCopy requires a page-aligned pointer and
    // internally rounds the length up to the page boundary.  When malloc'd
    // memory (e.g. std::vector) coincidentally sits on a page boundary but
    // the allocation is smaller than a page, Metal's page-rounded view can
    // extend past the actual allocation, causing non-deterministic GPU reads.
    // Guard: require both pointer alignment AND length >= page_size so that
    // only properly VM-backed, full-page-or-larger allocations use zero-copy.
    const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGE_SIZE));
    if (reinterpret_cast<uintptr_t>(bytes) % page_size != 0 || length < page_size) {
        return nil;
    }
    return [device newBufferWithBytesNoCopy:const_cast<void*>(bytes)
                                      length:length
                                     options:MTLResourceStorageModeShared
                                 deallocator:nil];
}

struct BufferBinding {
    id<MTLBuffer> buffer{nil};
    NSUInteger offset{0};
};

template <size_t N>
void SetEncoderBindings(id<MTLComputeCommandEncoder> encoder, const std::array<BufferBinding, N>& bindings)
{
    std::array<id<MTLBuffer>, N> buffers{};
    std::array<NSUInteger, N> offsets{};
    for (NSUInteger i = 0; i < bindings.size(); ++i) {
        buffers[i] = bindings[i].buffer;
        offsets[i] = bindings[i].offset;
    }
    [encoder setBuffers:buffers.data() offsets:offsets.data() withRange:NSMakeRange(0, bindings.size())];
}

template <size_t N>
bool EncodeComputeBindings(id<MTLCommandBuffer> command,
                           id<MTLComputePipelineState> pipeline,
                           NSUInteger grid_size,
                           NSUInteger preferred_thread_group_size,
                           const std::array<BufferBinding, N>& bindings,
                           std::string& error)
{
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    if (encoder == nil) {
        error = "Failed to create Metal compute encoder";
        return false;
    }

    [encoder setComputePipelineState:pipeline];
    SetEncoderBindings(encoder, bindings);

    const NSUInteger thread_group_size = SelectThreadGroupSize(pipeline, preferred_thread_group_size);
    const MTLSize grid = MTLSizeMake(grid_size, 1, 1);
    const MTLSize group = MTLSizeMake(thread_group_size, 1, 1);

    [encoder dispatchThreads:grid threadsPerThreadgroup:group];
    [encoder endEncoding];
    return true;
}

template <size_t N>
bool EncodeComputeThreadgroupsBindings(id<MTLCommandBuffer> command,
                                       id<MTLComputePipelineState> pipeline,
                                       NSUInteger threadgroups_width,
                                       NSUInteger threadgroups_height,
                                       NSUInteger threads_per_group,
                                       const std::array<BufferBinding, N>& bindings,
                                       std::string& error)
{
    id<MTLComputeCommandEncoder> encoder = [command computeCommandEncoder];
    if (encoder == nil) {
        error = "Failed to create Metal compute encoder";
        return false;
    }

    [encoder setComputePipelineState:pipeline];
    SetEncoderBindings(encoder, bindings);

    const NSUInteger group_threads = std::max<NSUInteger>(threads_per_group, 1);
    const NSUInteger max_threads = std::max<NSUInteger>(pipeline.maxTotalThreadsPerThreadgroup, 1);
    if (group_threads > max_threads) {
        [encoder endEncoding];
        error = "Requested threadgroup size exceeds pipeline limit";
        return false;
    }

    const MTLSize group_count = MTLSizeMake(std::max<NSUInteger>(threadgroups_width, 1), std::max<NSUInteger>(threadgroups_height, 1), 1);
    const MTLSize group_size = MTLSizeMake(group_threads, 1, 1);
    [encoder dispatchThreadgroups:group_count threadsPerThreadgroup:group_size];
    [encoder endEncoding];
    return true;
}

id<MTLCommandBuffer> CreatePerformanceCommandBuffer(id<MTLCommandQueue> queue)
{
    if (queue == nil) {
        return nil;
    }
    // The Metal context owns the queue, pipelines, and pooled buffers for the
    // entire command lifetime, so unretained command buffers safely trim CPU
    // bookkeeping in the hot digest paths.
    return [queue commandBufferWithUnretainedReferences];
}

enum class MetalTranscriptPipelineMode {
    AUTO,
    FUSED,
    LEGACY,
};

MetalTranscriptPipelineMode ResolveMetalTranscriptPipelineMode()
{
    const char* env = std::getenv("BTX_MATMUL_METAL_PIPELINE");
    if (env == nullptr || env[0] == '\0' || std::strcmp(env, "auto") == 0) {
        return MetalTranscriptPipelineMode::AUTO;
    }
    if (std::strcmp(env, "legacy") == 0) {
        return MetalTranscriptPipelineMode::LEGACY;
    }
    if (std::strcmp(env, "fused") == 0) {
        return MetalTranscriptPipelineMode::FUSED;
    }
    return MetalTranscriptPipelineMode::AUTO;
}

bool ShouldUseLegacyTranscriptPipeline(const btx::metal::MatMulDigestRequest& request, const MetalContext& context)
{
    const bool legacy_available = context.build_prefix_pipeline != nil && context.compress_prefix_pipeline != nil;
    const bool fused_available = context.fused_prefix_compress_pipeline != nil && context.transcript_sha256_pipeline != nil;

    if (request.digest_mode == btx::metal::MatMulDigestMode::PRODUCT_COMMITTED) {
        return false;
    }

    switch (ResolveMetalTranscriptPipelineMode()) {
    case MetalTranscriptPipelineMode::LEGACY:
        return legacy_available;
    case MetalTranscriptPipelineMode::FUSED:
        return !fused_available && legacy_available;
    case MetalTranscriptPipelineMode::AUTO:
        if (!legacy_available) return false;
        if (!fused_available) return true;
        // Large production dimensions regress on fused+GPU hash on M1 class devices.
        return request.n >= 128;
    }

    return false;
}

enum class FunctionConstantSpecializationMode {
    AUTO,
    ENABLED,
    DISABLED,
};

FunctionConstantSpecializationMode ResolveFunctionConstantSpecializationMode()
{
    const char* env = std::getenv("BTX_MATMUL_METAL_FUNCTION_CONSTANTS");
    if (env == nullptr || env[0] == '\0' || std::strcmp(env, "auto") == 0) {
        return FunctionConstantSpecializationMode::AUTO;
    }
    if (std::strcmp(env, "1") == 0 || std::strcmp(env, "on") == 0 || std::strcmp(env, "true") == 0) {
        return FunctionConstantSpecializationMode::ENABLED;
    }
    if (std::strcmp(env, "0") == 0 || std::strcmp(env, "off") == 0 || std::strcmp(env, "false") == 0) {
        return FunctionConstantSpecializationMode::DISABLED;
    }
    return FunctionConstantSpecializationMode::AUTO;
}

bool ShouldUseFunctionConstantSpecialization(uint32_t n, bool use_legacy_pipeline)
{
    switch (ResolveFunctionConstantSpecializationMode()) {
    case FunctionConstantSpecializationMode::ENABLED:
        return true;
    case FunctionConstantSpecializationMode::DISABLED:
        return false;
    case FunctionConstantSpecializationMode::AUTO:
        // Host profiling shows mixed specialization behavior by transcript path.
        // Legacy prefix/compress benefits for production sizes, while fused+GPU-hash
        // still regresses for n=512 on M1-class devices.
        if (use_legacy_pipeline) {
            if (n >= 256) return true;
            return n <= 64;
        }
        if (n == 512) return false;
        if (n == 256) return true;
        return n <= 64;
    }
    return false;
}

} // namespace

namespace btx::metal {

bool ShouldUseFunctionConstantSpecializationPolicy(uint32_t n, bool use_legacy_pipeline)
{
    return ShouldUseFunctionConstantSpecialization(n, use_legacy_pipeline);
}

MatMulAccelerationProbe ProbeMatMulDigestAcceleration()
{
    MatMulAccelerationProbe probe;
    const MetalContext& context = GetContext();
    probe.available = context.ready;
    probe.reason = context.ready ? "runtime_probe_ok"
                                 : (context.error.empty() ? "runtime_probe_failed" : context.error);
    return probe;
}

// Compute a lightweight data fingerprint for safe cache invalidation.
// Uses dimension + sampled data points so we never compare dangling pointers.
uint64_t ComputeMatrixDataFingerprint(uint32_t n,
                                       const matmul::field::Element* matrix_a,
                                       const matmul::field::Element* matrix_b)
{
    const uint64_t nn = static_cast<uint64_t>(n) * n;
    // Mix dimension, first word, last word, and middle words of both matrices.
    uint64_t fp = static_cast<uint64_t>(n);
    if (nn > 0) {
        fp ^= static_cast<uint64_t>(matrix_a[0]) * 0x9E3779B97F4A7C15ULL;
        fp ^= static_cast<uint64_t>(matrix_b[0]) * 0x517CC1B727220A95ULL;
        fp ^= static_cast<uint64_t>(matrix_a[nn - 1]) * 0x6C62272E07BB0142ULL;
        fp ^= static_cast<uint64_t>(matrix_b[nn - 1]) * 0x62B821756295C58DULL;
        if (nn > 2) {
            const uint64_t mid = nn / 2;
            fp ^= static_cast<uint64_t>(matrix_a[mid]) * 0x3C6EF372FE94F82BULL;
            fp ^= static_cast<uint64_t>(matrix_b[mid]) * 0x27BB2EE687B0B0FDULL;
        }
    }
    return fp;
}

MatMulBaseMatricesResult UploadBaseMatrices(const MatMulBaseMatricesRequest& request)
{
    MatMulBaseMatricesResult result;

    MetalContext& context = GetContext();
    if (!context.ready) {
        result.available = false;
        result.success = false;
        result.error = context.error.empty() ? "Metal context initialization failed" : context.error;
        return result;
    }
    result.available = true;

    if (request.n == 0 || request.matrix_a == nullptr || request.matrix_b == nullptr) {
        result.success = false;
        result.error = "invalid base matrix upload request";
        return result;
    }

    const uint64_t matrix_words = static_cast<uint64_t>(request.n) * request.n;
    if (matrix_words > std::numeric_limits<uint32_t>::max()) {
        result.success = false;
        result.error = "base matrix dimensions exceed supported Metal upload bounds";
        return result;
    }
    const size_t matrix_bytes = static_cast<size_t>(matrix_words * sizeof(uint32_t));

    // Use a data fingerprint instead of raw pointer comparison to detect
    // when the caller's matrix data has changed.  Raw pointer comparison
    // is unsafe because a freed matrix allocation can be reused at the
    // same address with different data (use-after-free cache stale hit).
    const uint64_t fingerprint = ComputeMatrixDataFingerprint(request.n, request.matrix_a, request.matrix_b);

    std::lock_guard<std::mutex> lock(context.resident_base_mutex);
    if (context.resident_matrix_a_buffer != nil &&
        context.resident_matrix_b_buffer != nil &&
        context.resident_matrix_n == request.n &&
        context.resident_data_fingerprint == fingerprint) {
        result.success = true;
        return result;
    }

    // Reuse existing resident buffers when the matrix dimension is unchanged.
    // This avoids repeated per-block Metal buffer allocation churn during
    // mining while preserving uploaded-base functionality.
    if (context.resident_matrix_a_buffer != nil &&
        context.resident_matrix_b_buffer != nil &&
        context.resident_matrix_n == request.n) {
        std::memcpy(context.resident_matrix_a_buffer.contents, request.matrix_a, matrix_bytes);
        std::memcpy(context.resident_matrix_b_buffer.contents, request.matrix_b, matrix_bytes);
        context.resident_data_fingerprint = fingerprint;
        result.success = true;
        return result;
    }

    id<MTLBuffer> matrix_a_buffer = [context.device newBufferWithLength:matrix_bytes options:MTLResourceStorageModeShared];
    id<MTLBuffer> matrix_b_buffer = [context.device newBufferWithLength:matrix_bytes options:MTLResourceStorageModeShared];
    if (matrix_a_buffer == nil || matrix_b_buffer == nil) {
        result.success = false;
        result.error = "failed to allocate resident Metal base matrix buffers";
        return result;
    }

    std::memcpy(matrix_a_buffer.contents, request.matrix_a, matrix_bytes);
    std::memcpy(matrix_b_buffer.contents, request.matrix_b, matrix_bytes);

    context.resident_matrix_a_buffer = matrix_a_buffer;
    context.resident_matrix_b_buffer = matrix_b_buffer;
    context.resident_matrix_n = request.n;
    context.resident_data_fingerprint = fingerprint;

    result.success = true;
    return result;
}

MatMulBufferPoolStats ProbeMatMulBufferPool()
{
    MatMulBufferPoolStats stats;

    MetalContext& context = GetContext();
    if (!context.ready) {
        stats.available = false;
        stats.initialized = false;
        stats.reason = context.error.empty() ? "Metal context initialization failed" : context.error;
        return stats;
    }
    stats.available = true;

    std::lock_guard<std::mutex> lock(context.pool_mutex);
    stats.slot_count = static_cast<uint32_t>(context.pool_slots.size());
    stats.active_slots = context.pool_active_slots;
    stats.high_water_slots = context.pool_high_water_slots;
    stats.inflight_submissions = context.pool_inflight_submissions;
    stats.peak_inflight_submissions = context.pool_peak_inflight_submissions;
    stats.initialized = std::any_of(context.pool_slots.begin(), context.pool_slots.end(), [](const MetalPoolSlot& slot) {
        return IsPoolSlotInitialized(slot, /*require_prefix_buffer=*/false) || IsPoolSlotInitialized(slot, /*require_prefix_buffer=*/true);
    });
    stats.allocation_events = context.pool_allocation_events;
    stats.reuse_events = context.pool_reuse_events;
    stats.wait_events = context.pool_wait_events;
    stats.completed_submissions = context.pool_completed_submissions;
    stats.n = context.pool_last_n;
    stats.b = context.pool_last_b;
    stats.r = context.pool_last_r;
    stats.reason = stats.initialized ? "buffer_pool_slots_ready" : "buffer_pool_uninitialized";
    return stats;
}

MatMulDispatchConfig ProbeMatMulDispatchConfig()
{
    MatMulDispatchConfig config;

    MetalContext& context = GetContext();
    if (!context.ready) {
        config.available = false;
        config.reason = context.error.empty() ? "Metal context initialization failed" : context.error;
        return config;
    }
    config.available = true;

    config.build_perturbed_threads = SelectThreadGroupSize(context.build_perturbed_pipeline, 256);
    config.build_prefix_threads = SelectThreadGroupSize(context.build_prefix_tiled_pipeline, 256);
    config.compress_prefix_threads = SelectThreadGroupSize(context.fused_prefix_compress_pipeline, 256);
    config.reason = "dispatch_probe_ok";
    return config;
}

MatMulKernelProfile ProbeMatMulKernelProfile()
{
    MatMulKernelProfile profile;

    MetalContext& context = GetContext();
    if (!context.ready) {
        profile.available = false;
        profile.reason = context.error.empty() ? "Metal context initialization failed" : context.error;
        return profile;
    }

    profile.available = true;
    profile.tiled_build_prefix = context.build_prefix_tiled_pipeline != nil;
    profile.fused_prefix_compress = context.fused_prefix_compress_pipeline != nil;
    profile.gpu_transcript_hash = context.transcript_sha256_pipeline != nil;
    profile.function_constant_specialization = context.specialized_pipeline_count > 0;
    profile.cooperative_tensor_prepared = true;
    profile.cooperative_tensor_active = false;
    profile.uses_prefix_buffer = false;
    profile.specialized_shape_count = context.specialized_pipeline_count;
    profile.build_prefix_threadgroup_width = 16;
    profile.build_prefix_threadgroup_height = 16;
    profile.fused_prefix_threadgroup_threads = SelectThreadGroupSize(context.fused_prefix_compress_pipeline, 256);
    profile.specialization_reason = context.specialized_pipeline_reason;
    profile.cooperative_tensor_reason = "simdgroup_uint32_reduce_active_integer_cooperative_tensor_unavailable";
    profile.library_source = context.using_precompiled_library ? "precompiled_metallib" : "inline_source_fallback";
    profile.reason = profile.function_constant_specialization
        ? "tiled_fused_gpuhash_pipeline_with_function_constants"
        : "tiled_fused_gpuhash_pipeline";
    return profile;
}

MatMulProfilingStats ProbeMatMulProfilingStats()
{
    MatMulProfilingStats stats;

    MetalContext& context = GetContext();
    if (!context.ready) {
        stats.available = false;
        stats.reason = context.error.empty() ? "Metal context initialization failed" : context.error;
        return stats;
    }

    std::lock_guard<std::mutex> lock(context.profiling_mutex);
    stats = context.profiling_stats;
    stats.available = true;
    stats.capture_supported = context.capture_supported;
    if (stats.reason.empty()) {
        stats.reason = "profiling_probe_ok";
    }
    return stats;
}

namespace {

template <typename State>
void RecordAsyncSubmissionStart(MetalContext& context, const std::shared_ptr<State>& state)
{
    state->context = &context;
    std::lock_guard<std::mutex> lock(context.pool_mutex);
    ++context.pool_inflight_submissions;
    context.pool_peak_inflight_submissions =
        std::max(context.pool_peak_inflight_submissions, context.pool_inflight_submissions);
}

} // namespace

MatMulDigestSubmission SubmitCanonicalTranscriptDigest(const MatMulDigestRequest& request)
{
    MatMulDigestSubmission submission;

    MetalContext& context = GetContext();
    if (!context.ready) {
        submission.available = false;
        submission.error = context.error.empty() ? "Metal context initialization failed" : context.error;
        return submission;
    }
    submission.available = true;

    uint32_t N{0};
    uint64_t matrix_words{0};
    uint64_t noise_words{0};
    uint64_t prefix_words{0};
    uint64_t compressed_words{0};
    if (!BuildKernelParams(request, N, matrix_words, noise_words, prefix_words, compressed_words, submission.error)) {
        return submission;
    }

    struct KernelParams {
        uint32_t n;
        uint32_t b;
        uint32_t r;
        uint32_t N;
    } params{request.n, request.b, request.r, N};
    struct HashParams {
        uint32_t compressed_words;
    } hash_params{static_cast<uint32_t>(compressed_words)};
    const bool use_product_digest = request.digest_mode == MatMulDigestMode::PRODUCT_COMMITTED;
    const bool use_legacy_pipeline = use_product_digest || ShouldUseLegacyTranscriptPipeline(request, context);
    const SpecializedKernelPipelines* specialized = nullptr;
    if (ShouldUseFunctionConstantSpecialization(request.n, use_legacy_pipeline || use_product_digest)) {
        specialized = FindSpecializedPipelines(context, request.n, request.b, request.r, N);
    }
    id<MTLComputePipelineState> build_perturbed_pipeline =
        (specialized != nullptr && specialized->build_perturbed_pipeline != nil)
            ? specialized->build_perturbed_pipeline
            : context.build_perturbed_pipeline;
    id<MTLComputePipelineState> build_prefix_pipeline =
        (specialized != nullptr && specialized->build_prefix_pipeline != nil)
            ? specialized->build_prefix_pipeline
            : context.build_prefix_pipeline;
    id<MTLComputePipelineState> compress_prefix_pipeline =
        (specialized != nullptr && specialized->compress_prefix_pipeline != nil)
            ? specialized->compress_prefix_pipeline
            : context.compress_prefix_pipeline;
    id<MTLComputePipelineState> fused_prefix_compress_pipeline =
        (specialized != nullptr && specialized->fused_prefix_compress_pipeline != nil)
            ? specialized->fused_prefix_compress_pipeline
            : context.fused_prefix_compress_pipeline;

    auto state = std::make_shared<AsyncSingleDigestState>();
    state->result.available = true;

    @autoreleasepool {
        const size_t matrix_bytes = matrix_words * sizeof(uint32_t);
        const size_t noise_bytes = noise_words * sizeof(uint32_t);
        const size_t compress_bytes = static_cast<size_t>(request.b) * request.b * sizeof(uint32_t);
        const size_t prefix_bytes = prefix_words * sizeof(uint32_t);
        const size_t compressed_bytes = compressed_words * sizeof(uint32_t);
        constexpr size_t hash_bytes = 32;

        auto pool_lease = AcquireBufferPoolLease(context,
                                                 request,
                                                 matrix_bytes,
                                                 noise_bytes,
                                                 compress_bytes,
                                                 prefix_bytes,
                                                 compressed_bytes,
                                                 hash_bytes,
                                                 /*require_prefix_buffer=*/use_legacy_pipeline,
                                                 submission.error);
        if (!pool_lease.has_value()) {
            return submission;
        }
        state->lease.emplace(std::move(pool_lease.value()));

        MetalPoolSlot& pool_slot = *state->lease->slot;
        id<MTLBuffer> params_buffer = pool_slot.params_buffer;
        id<MTLBuffer> hash_params_buffer = pool_slot.hash_params_buffer;
        id<MTLBuffer> matrix_a_buffer = pool_slot.matrix_a_stage_buffer;
        id<MTLBuffer> matrix_b_buffer = pool_slot.matrix_b_stage_buffer;
        id<MTLBuffer> e_l_buffer = pool_slot.e_l_buffer;
        id<MTLBuffer> e_r_buffer = pool_slot.e_r_buffer;
        id<MTLBuffer> f_l_buffer = pool_slot.f_l_buffer;
        id<MTLBuffer> f_r_buffer = pool_slot.f_r_buffer;
        id<MTLBuffer> compress_buffer = pool_slot.compress_buffer;
        id<MTLBuffer> a_prime_buffer = pool_slot.a_prime_buffer;
        id<MTLBuffer> b_prime_buffer = pool_slot.b_prime_buffer;
        id<MTLBuffer> prefix_buffer = pool_slot.prefix_buffer;
        id<MTLBuffer> compressed_buffer = pool_slot.compressed_buffer;
        id<MTLBuffer> transcript_hash_buffer = pool_slot.transcript_hash_buffer;
        state->retained_inputs = CreateRetainedInputArray(6);

        if (request.use_uploaded_base_matrices) {
            std::lock_guard<std::mutex> lock(context.resident_base_mutex);
            if (context.resident_matrix_a_buffer == nil || context.resident_matrix_b_buffer == nil || context.resident_matrix_n != request.n) {
                submission.error = "uploaded base matrices are unavailable or stale for requested dimension";
                return submission;
            }
            matrix_a_buffer = context.resident_matrix_a_buffer;
            matrix_b_buffer = context.resident_matrix_b_buffer;
        } else {
            id<MTLBuffer> matrix_a_no_copy = WrapSharedNoCopyBuffer(context.device, request.matrix_a, matrix_bytes);
            id<MTLBuffer> matrix_b_no_copy = WrapSharedNoCopyBuffer(context.device, request.matrix_b, matrix_bytes);
            if (matrix_a_no_copy != nil && matrix_b_no_copy != nil) {
                matrix_a_buffer = matrix_a_no_copy;
                matrix_b_buffer = matrix_b_no_copy;
                state->any_zero_copy_input = true;
                RetainTemporaryInputBuffer(state->retained_inputs, matrix_a_no_copy);
                RetainTemporaryInputBuffer(state->retained_inputs, matrix_b_no_copy);
            } else {
                std::memcpy(matrix_a_buffer.contents, request.matrix_a, matrix_bytes);
                std::memcpy(matrix_b_buffer.contents, request.matrix_b, matrix_bytes);
            }
        }

        auto copy_or_wrap = [&](const matmul::field::Element* source,
                                id<MTLBuffer> staging_buffer,
                                size_t bytes) -> id<MTLBuffer> {
            id<MTLBuffer> no_copy = WrapSharedNoCopyBuffer(context.device, source, bytes);
            if (no_copy != nil) {
                state->any_zero_copy_input = true;
                RetainTemporaryInputBuffer(state->retained_inputs, no_copy);
                return no_copy;
            }
            std::memcpy(staging_buffer.contents, source, bytes);
            return staging_buffer;
        };

        id<MTLBuffer> e_l_input_buffer = copy_or_wrap(request.noise_e_l, e_l_buffer, noise_bytes);
        id<MTLBuffer> e_r_input_buffer = copy_or_wrap(request.noise_e_r, e_r_buffer, noise_bytes);
        id<MTLBuffer> f_l_input_buffer = copy_or_wrap(request.noise_f_l, f_l_buffer, noise_bytes);
        id<MTLBuffer> f_r_input_buffer = copy_or_wrap(request.noise_f_r, f_r_buffer, noise_bytes);
        id<MTLBuffer> compress_input_buffer = WrapSharedNoCopyBuffer(context.device, request.compress_vec, compress_bytes);
        if (compress_input_buffer == nil) {
            compress_input_buffer = compress_buffer;
            std::memcpy(compress_input_buffer.contents, request.compress_vec, compress_bytes);
        } else {
            state->any_zero_copy_input = true;
            RetainTemporaryInputBuffer(state->retained_inputs, compress_input_buffer);
        }

        std::memcpy(params_buffer.contents, &params, sizeof(params));
        std::memcpy(hash_params_buffer.contents, &hash_params, sizeof(hash_params));
        id<MTLCommandBuffer> command = CreatePerformanceCommandBuffer(pool_slot.queue);
        if (command == nil) {
            submission.error = "Failed to create Metal command buffer";
            return submission;
        }

        std::string encode_error;
        const std::array<BufferBinding, 9> buffers_1{{
            {params_buffer, 0},
            {matrix_a_buffer, 0},
            {matrix_b_buffer, 0},
            {e_l_input_buffer, 0},
            {e_r_input_buffer, 0},
            {f_l_input_buffer, 0},
            {f_r_input_buffer, 0},
            {a_prime_buffer, 0},
            {b_prime_buffer, 0},
        }};
        const auto encode_build_start = std::chrono::steady_clock::now();
        if (!EncodeComputeBindings(command,
                                   build_perturbed_pipeline,
                                   static_cast<NSUInteger>(matrix_words),
                                   256,
                                   buffers_1,
                                   encode_error)) {
            submission.error = encode_error;
            return submission;
        }
        state->encode_build_perturbed_us = std::chrono::duration<double, std::micro>(
                                               std::chrono::steady_clock::now() - encode_build_start)
                                               .count();

        if (use_legacy_pipeline) {
            const std::array<BufferBinding, 4> buffers_2{{
                {params_buffer, 0},
                {a_prime_buffer, 0},
                {b_prime_buffer, 0},
                {prefix_buffer, 0},
            }};
            const auto encode_prefix_start = std::chrono::steady_clock::now();
            if (!EncodeComputeBindings(command,
                                       build_prefix_pipeline,
                                       static_cast<NSUInteger>(matrix_words),
                                       256,
                                       buffers_2,
                                       encode_error)) {
                submission.error = encode_error;
                return submission;
            }
            const double encode_prefix_us = std::chrono::duration<double, std::micro>(
                                                std::chrono::steady_clock::now() - encode_prefix_start)
                                                .count();

            const std::array<BufferBinding, 4> buffers_3{{
                {params_buffer, 0},
                {prefix_buffer, 0},
                {compress_input_buffer, 0},
                {compressed_buffer, 0},
            }};
            const auto encode_compress_start = std::chrono::steady_clock::now();
            if (!EncodeComputeBindings(command,
                                       compress_prefix_pipeline,
                                       static_cast<NSUInteger>(compressed_words),
                                       256,
                                       buffers_3,
                                       encode_error)) {
                submission.error = encode_error;
                return submission;
            }
            const double encode_compress_us = std::chrono::duration<double, std::micro>(
                                                  std::chrono::steady_clock::now() - encode_compress_start)
                                                  .count();
            state->encode_fused_prefix_compress_us = encode_prefix_us + encode_compress_us;
        } else {
            const NSUInteger block_elements = static_cast<NSUInteger>(request.b) * request.b;
            const std::array<BufferBinding, 5> buffers_2{{
                {params_buffer, 0},
                {a_prime_buffer, 0},
                {b_prime_buffer, 0},
                {compress_input_buffer, 0},
                {compressed_buffer, 0},
            }};
            const auto encode_fused_start = std::chrono::steady_clock::now();
            if (!EncodeComputeThreadgroupsBindings(command,
                                                   fused_prefix_compress_pipeline,
                                                   static_cast<NSUInteger>(N),
                                                   static_cast<NSUInteger>(N),
                                                   block_elements,
                                                   buffers_2,
                                                   encode_error)) {
                submission.error = encode_error;
                return submission;
            }
            state->encode_fused_prefix_compress_us = std::chrono::duration<double, std::micro>(
                                                         std::chrono::steady_clock::now() - encode_fused_start)
                                                         .count();

            const std::array<BufferBinding, 3> buffers_3{{
                {compressed_buffer, 0},
                {hash_params_buffer, 0},
                {transcript_hash_buffer, 0},
            }};
            const auto encode_hash_start = std::chrono::steady_clock::now();
            if (!EncodeComputeBindings(command,
                                       context.transcript_sha256_pipeline,
                                       1,
                                       1,
                                       buffers_3,
                                       encode_error)) {
                submission.error = encode_error;
                return submission;
            }
            state->encode_transcript_sha256_us = std::chrono::duration<double, std::micro>(
                                                     std::chrono::steady_clock::now() - encode_hash_start)
                                                     .count();
        }

        state->use_legacy_pipeline = use_legacy_pipeline;
        state->use_product_digest = use_product_digest;
        state->n = request.n;
        state->b = request.b;
        state->N = N;
        state->sigma = request.sigma;
        state->compressed_words = compressed_words;
        state->compressed_buffer = compressed_buffer;
        state->transcript_hash_buffer = transcript_hash_buffer;

        RecordAsyncSubmissionStart(context, state);
        const auto submit_wait_start = std::chrono::steady_clock::now();
        [command addCompletedHandler:^(id<MTLCommandBuffer> completed) {
            @autoreleasepool {
                state->submit_wait_us = std::chrono::duration<double, std::micro>(
                                            std::chrono::steady_clock::now() - submit_wait_start)
                                            .count();
                state->gpu_execution_ms = state->submit_wait_us / 1000.0;
                state->result.available = true;

                if (completed.status != MTLCommandBufferStatusCompleted) {
                    NSString* description = completed.error != nil ? [completed.error localizedDescription] : @"unknown Metal command failure";
                    state->result.success = false;
                    state->result.error = [description UTF8String];
                    FinalizeAsyncSubmissionState(state, "profiling_samples_ready_async_error");
                    return;
                }

                const auto finalize_start = std::chrono::steady_clock::now();
                if (state->use_product_digest) {
                    if (!FinalizeProductCommittedDigestFromFinalSliceBuffer(
                            state->compressed_buffer,
                            /*word_offset=*/0,
                            state->N,
                            state->n,
                            state->b,
                            state->sigma,
                            state->result.digest,
                            state->result.error)) {
                        state->result.success = false;
                        FinalizeAsyncSubmissionState(state, "profiling_samples_ready_async_error");
                        return;
                    }
                } else if (state->use_legacy_pipeline) {
                    const uint32_t* compressed_ptr = static_cast<const uint32_t*>(state->compressed_buffer.contents);
                    CHash256 hasher;
                    for (uint64_t idx = 0; idx < state->compressed_words; ++idx) {
                        uint8_t le[4];
                        WriteLE32(le, compressed_ptr[idx]);
                        hasher.Write(le);
                    }
                    hasher.Finalize(state->result.digest);
                } else {
                    std::array<unsigned char, 32> digest_bytes{};
                    std::memcpy(digest_bytes.data(), state->transcript_hash_buffer.contents, digest_bytes.size());
                    state->result.digest = uint256{Span<const unsigned char>{digest_bytes.data(), digest_bytes.size()}};
                }
                state->cpu_finalize_us = std::chrono::duration<double, std::micro>(
                                             std::chrono::steady_clock::now() - finalize_start)
                                             .count();
                state->result.success = true;
                FinalizeAsyncSubmissionState(state, "profiling_samples_ready_async");
            }
        }];
        [command commit];
    }

    submission.submitted = true;
    submission.opaque = state;
    return submission;
}

bool IsCanonicalTranscriptDigestSubmissionReady(const MatMulDigestSubmission& submission)
{
    if (!submission.submitted || !submission.opaque) {
        return false;
    }
    auto state = std::static_pointer_cast<AsyncSingleDigestState>(submission.opaque);
    std::lock_guard<std::mutex> lock(state->mutex);
    return state->completed;
}

MatMulDigestResult WaitForCanonicalTranscriptDigestSubmission(MatMulDigestSubmission&& submission)
{
    MatMulDigestResult result;
    result.available = submission.available;
    if (!submission.submitted || !submission.opaque) {
        result.success = false;
        result.error = submission.error.empty() ? "Metal digest submission was not started" : submission.error;
        return result;
    }

    auto state = std::static_pointer_cast<AsyncSingleDigestState>(submission.opaque);
    std::unique_lock<std::mutex> lock(state->mutex);
    state->cv.wait(lock, [&state] { return state->completed; });
    return state->result;
}

MatMulDigestResult ComputeCanonicalTranscriptDigest(const MatMulDigestRequest& request)
{
    auto submission = SubmitCanonicalTranscriptDigest(request);
    return WaitForCanonicalTranscriptDigestSubmission(std::move(submission));
}

MatMulDigestBatchSubmission SubmitCanonicalTranscriptDigestBatch(const MatMulDigestBatchRequest& request)
{
    MatMulDigestBatchSubmission submission;

    MetalContext& context = GetContext();
    if (!context.ready) {
        submission.available = false;
        submission.error = context.error.empty() ? "Metal context initialization failed" : context.error;
        return submission;
    }
    submission.available = true;

    if (request.batch_size == 0) {
        submission.error = "invalid MatMul batch request: batch_size must be non-zero";
        return submission;
    }
    const bool use_product_digest = request.digest_mode == MatMulDigestMode::PRODUCT_COMMITTED;
    if (use_product_digest && request.sigmas == nullptr) {
        submission.error = "invalid MatMul batch request: missing per-batch sigma values";
        return submission;
    }
    if (request.noise_e_l == nullptr || request.noise_e_r == nullptr ||
        request.noise_f_l == nullptr || request.noise_f_r == nullptr ||
        request.compress_vec == nullptr) {
        submission.error = "invalid MatMul batch request: missing batch input pointers";
        return submission;
    }

    for (uint32_t i = 0; i < request.batch_size; ++i) {
        if (request.noise_e_l[i] == nullptr || request.noise_e_r[i] == nullptr ||
            request.noise_f_l[i] == nullptr || request.noise_f_r[i] == nullptr ||
            request.compress_vec[i] == nullptr) {
            submission.error = "invalid MatMul batch request: null per-batch input pointer";
            return submission;
        }
    }

    MatMulDigestRequest validation_request{
        .n = request.n,
        .b = request.b,
        .r = request.r,
        .digest_mode = request.digest_mode,
        .sigma = use_product_digest ? request.sigmas[0] : uint256{},
        .matrix_a = request.matrix_a,
        .matrix_b = request.matrix_b,
        .use_uploaded_base_matrices = request.use_uploaded_base_matrices,
        .noise_e_l = request.noise_e_l[0],
        .noise_e_r = request.noise_e_r[0],
        .noise_f_l = request.noise_f_l[0],
        .noise_f_r = request.noise_f_r[0],
        .compress_vec = request.compress_vec[0],
    };

    uint32_t N{0};
    uint64_t matrix_words{0};
    uint64_t noise_words{0};
    uint64_t prefix_words{0};
    uint64_t compressed_words{0};
    if (!BuildKernelParams(validation_request, N, matrix_words, noise_words, prefix_words, compressed_words, submission.error)) {
        return submission;
    }

    struct KernelParams {
        uint32_t n;
        uint32_t b;
        uint32_t r;
        uint32_t N;
    } params{request.n, request.b, request.r, N};
    struct HashParams {
        uint32_t compressed_words;
    } hash_params{static_cast<uint32_t>(compressed_words)};
    const SpecializedKernelPipelines* specialized = nullptr;
    if (ShouldUseFunctionConstantSpecialization(request.n, /*use_legacy_pipeline=*/use_product_digest)) {
        specialized = FindSpecializedPipelines(context, request.n, request.b, request.r, N);
    }
    id<MTLComputePipelineState> build_perturbed_pipeline =
        (specialized != nullptr && specialized->build_perturbed_pipeline != nil)
            ? specialized->build_perturbed_pipeline
            : context.build_perturbed_pipeline;
    id<MTLComputePipelineState> fused_prefix_compress_pipeline =
        (specialized != nullptr && specialized->fused_prefix_compress_pipeline != nil)
            ? specialized->fused_prefix_compress_pipeline
            : context.fused_prefix_compress_pipeline;

    auto state = std::make_shared<AsyncBatchDigestState>();
    state->result.available = true;
    state->batch_size = request.batch_size;

    @autoreleasepool {
        const size_t matrix_bytes = matrix_words * sizeof(uint32_t);
        const size_t noise_bytes = noise_words * sizeof(uint32_t);
        const size_t compress_bytes = static_cast<size_t>(request.b) * request.b * sizeof(uint32_t);
        const size_t prefix_bytes = prefix_words * sizeof(uint32_t);
        const size_t compressed_bytes = compressed_words * sizeof(uint32_t);
        constexpr size_t kHashBytesPerDigest = 32;
        const size_t staged_matrix_bytes = use_product_digest
            ? static_cast<size_t>(request.batch_size) * matrix_bytes
            : matrix_bytes;
        const size_t staged_noise_bytes = static_cast<size_t>(request.batch_size) * noise_bytes;
        const size_t staged_compress_bytes = static_cast<size_t>(request.batch_size) * compress_bytes;
        const size_t staged_prefix_bytes = prefix_bytes;
        const size_t staged_compressed_bytes = use_product_digest
            ? static_cast<size_t>(request.batch_size) * compressed_bytes
            : compressed_bytes;
        const size_t hash_bytes = static_cast<size_t>(request.batch_size) * kHashBytesPerDigest;

        auto pool_lease = AcquireBufferPoolLease(context,
                                                 validation_request,
                                                 staged_matrix_bytes,
                                                 staged_noise_bytes,
                                                 staged_compress_bytes,
                                                 staged_prefix_bytes,
                                                 staged_compressed_bytes,
                                                 hash_bytes,
                                                 /*require_prefix_buffer=*/false,
                                                 submission.error);
        if (!pool_lease.has_value()) {
            return submission;
        }
        state->lease.emplace(std::move(pool_lease.value()));

        MetalPoolSlot& pool_slot = *state->lease->slot;
        id<MTLBuffer> params_buffer = pool_slot.params_buffer;
        id<MTLBuffer> hash_params_buffer = pool_slot.hash_params_buffer;
        id<MTLBuffer> matrix_a_buffer = pool_slot.matrix_a_stage_buffer;
        id<MTLBuffer> matrix_b_buffer = pool_slot.matrix_b_stage_buffer;
        id<MTLBuffer> e_l_stage_buffer = pool_slot.e_l_buffer;
        id<MTLBuffer> e_r_stage_buffer = pool_slot.e_r_buffer;
        id<MTLBuffer> f_l_stage_buffer = pool_slot.f_l_buffer;
        id<MTLBuffer> f_r_stage_buffer = pool_slot.f_r_buffer;
        id<MTLBuffer> compress_stage_buffer = pool_slot.compress_buffer;
        id<MTLBuffer> a_prime_buffer = pool_slot.a_prime_buffer;
        id<MTLBuffer> b_prime_buffer = pool_slot.b_prime_buffer;
        id<MTLBuffer> compressed_buffer = pool_slot.compressed_buffer;
        id<MTLBuffer> transcript_hash_buffer = pool_slot.transcript_hash_buffer;
        state->retained_inputs = CreateRetainedInputArray(static_cast<CFIndex>(request.batch_size * 5 + 2));

        if (request.use_uploaded_base_matrices) {
            std::lock_guard<std::mutex> lock(context.resident_base_mutex);
            if (context.resident_matrix_a_buffer == nil || context.resident_matrix_b_buffer == nil || context.resident_matrix_n != request.n) {
                submission.error = "uploaded base matrices are unavailable or stale for requested dimension";
                return submission;
            }
            matrix_a_buffer = context.resident_matrix_a_buffer;
            matrix_b_buffer = context.resident_matrix_b_buffer;
        } else {
            id<MTLBuffer> matrix_a_no_copy = WrapSharedNoCopyBuffer(context.device, request.matrix_a, matrix_bytes);
            id<MTLBuffer> matrix_b_no_copy = WrapSharedNoCopyBuffer(context.device, request.matrix_b, matrix_bytes);
            if (matrix_a_no_copy != nil && matrix_b_no_copy != nil) {
                matrix_a_buffer = matrix_a_no_copy;
                matrix_b_buffer = matrix_b_no_copy;
                state->any_zero_copy_input = true;
                RetainTemporaryInputBuffer(state->retained_inputs, matrix_a_no_copy);
                RetainTemporaryInputBuffer(state->retained_inputs, matrix_b_no_copy);
            } else {
                std::memcpy(matrix_a_buffer.contents, request.matrix_a, matrix_bytes);
                std::memcpy(matrix_b_buffer.contents, request.matrix_b, matrix_bytes);
            }
        }

        std::memcpy(params_buffer.contents, &params, sizeof(params));
        std::memcpy(hash_params_buffer.contents, &hash_params, sizeof(hash_params));
        id<MTLCommandBuffer> command = CreatePerformanceCommandBuffer(pool_slot.queue);
        if (command == nil) {
            submission.error = "Failed to create Metal command buffer";
            return submission;
        }

        std::string encode_error;
        const NSUInteger block_elements = static_cast<NSUInteger>(request.b) * request.b;

        for (uint32_t i = 0; i < request.batch_size; ++i) {
            auto make_input_binding = [&](const matmul::field::Element* source,
                                          id<MTLBuffer> staging_buffer,
                                          size_t bytes,
                                          size_t stage_index) -> BufferBinding {
                id<MTLBuffer> no_copy = WrapSharedNoCopyBuffer(context.device, source, bytes);
                if (no_copy != nil) {
                    state->any_zero_copy_input = true;
                    RetainTemporaryInputBuffer(state->retained_inputs, no_copy);
                    return BufferBinding{no_copy, 0};
                }
                if (staging_buffer == nil) {
                    return BufferBinding{};
                }
                const size_t offset = stage_index * bytes;
                std::memcpy(static_cast<unsigned char*>(staging_buffer.contents) + offset, source, bytes);
                return BufferBinding{staging_buffer, static_cast<NSUInteger>(offset)};
            };

            const BufferBinding e_l_input = make_input_binding(request.noise_e_l[i], e_l_stage_buffer, noise_bytes, i);
            const BufferBinding e_r_input = make_input_binding(request.noise_e_r[i], e_r_stage_buffer, noise_bytes, i);
            const BufferBinding f_l_input = make_input_binding(request.noise_f_l[i], f_l_stage_buffer, noise_bytes, i);
            const BufferBinding f_r_input = make_input_binding(request.noise_f_r[i], f_r_stage_buffer, noise_bytes, i);
            const BufferBinding compress_input = make_input_binding(request.compress_vec[i], compress_stage_buffer, compress_bytes, i);
            if (e_l_input.buffer == nil || e_r_input.buffer == nil || f_l_input.buffer == nil ||
                f_r_input.buffer == nil || compress_input.buffer == nil) {
                submission.error = "Failed to allocate Metal batch input buffers";
                return submission;
            }
            const size_t matrix_offset = use_product_digest ? static_cast<size_t>(i) * matrix_bytes : 0;
            const size_t compressed_offset = use_product_digest ? static_cast<size_t>(i) * compressed_bytes : 0;

            const std::array<BufferBinding, 9> buffers_1{{
                {params_buffer, 0},
                {matrix_a_buffer, 0},
                {matrix_b_buffer, 0},
                e_l_input,
                e_r_input,
                f_l_input,
                f_r_input,
                {a_prime_buffer, static_cast<NSUInteger>(matrix_offset)},
                {b_prime_buffer, static_cast<NSUInteger>(matrix_offset)},
            }};
            const auto encode_build_start = std::chrono::steady_clock::now();
            if (!EncodeComputeBindings(command,
                                       build_perturbed_pipeline,
                                       static_cast<NSUInteger>(matrix_words),
                                       256,
                                       buffers_1,
                                       encode_error)) {
                submission.error = encode_error;
                return submission;
            }
            state->encode_build_perturbed_us += std::chrono::duration<double, std::micro>(
                                                    std::chrono::steady_clock::now() - encode_build_start)
                                                    .count();

            if (use_product_digest) {
                const std::array<BufferBinding, 5> buffers_2{{
                    {params_buffer, 0},
                    {a_prime_buffer, static_cast<NSUInteger>(matrix_offset)},
                    {b_prime_buffer, static_cast<NSUInteger>(matrix_offset)},
                    compress_input,
                    {compressed_buffer, static_cast<NSUInteger>(compressed_offset)},
                }};
                const auto encode_product_start = std::chrono::steady_clock::now();
                if (!EncodeComputeThreadgroupsBindings(command,
                                           fused_prefix_compress_pipeline,
                                           static_cast<NSUInteger>(N),
                                           static_cast<NSUInteger>(N),
                                           block_elements,
                                           buffers_2,
                                           encode_error)) {
                    submission.error = encode_error;
                    return submission;
                }
                state->encode_fused_prefix_compress_us += std::chrono::duration<double, std::micro>(
                                                             std::chrono::steady_clock::now() - encode_product_start)
                                                             .count();
            } else {
                const std::array<BufferBinding, 5> buffers_2{{
                    {params_buffer, 0},
                    {a_prime_buffer, 0},
                    {b_prime_buffer, 0},
                    compress_input,
                    {compressed_buffer, 0},
                }};
                const auto encode_fused_start = std::chrono::steady_clock::now();
                if (!EncodeComputeThreadgroupsBindings(command,
                                                       fused_prefix_compress_pipeline,
                                                       static_cast<NSUInteger>(N),
                                                       static_cast<NSUInteger>(N),
                                                       block_elements,
                                                       buffers_2,
                                                       encode_error)) {
                    submission.error = encode_error;
                    return submission;
                }
                state->encode_fused_prefix_compress_us += std::chrono::duration<double, std::micro>(
                                                              std::chrono::steady_clock::now() - encode_fused_start)
                                                              .count();

                id<MTLComputeCommandEncoder> hash_encoder = [command computeCommandEncoder];
                if (hash_encoder == nil) {
                    submission.error = "Failed to create Metal compute encoder";
                    return submission;
                }
                [hash_encoder setComputePipelineState:context.transcript_sha256_pipeline];
                const std::array<BufferBinding, 3> hash_bindings{{
                    {compressed_buffer, 0},
                    {hash_params_buffer, 0},
                    {transcript_hash_buffer, static_cast<NSUInteger>(i) * kHashBytesPerDigest},
                }};
                SetEncoderBindings(hash_encoder, hash_bindings);

                const NSUInteger hash_group_size = SelectThreadGroupSize(context.transcript_sha256_pipeline, 1);
                const MTLSize hash_grid = MTLSizeMake(1, 1, 1);
                const MTLSize hash_group = MTLSizeMake(hash_group_size, 1, 1);
                const auto encode_hash_start = std::chrono::steady_clock::now();
                [hash_encoder dispatchThreads:hash_grid threadsPerThreadgroup:hash_group];
                [hash_encoder endEncoding];
                state->encode_transcript_sha256_us += std::chrono::duration<double, std::micro>(
                                                          std::chrono::steady_clock::now() - encode_hash_start)
                                                          .count();
            }
        }

        state->use_product_digest = use_product_digest;
        state->n = request.n;
        state->b = request.b;
        state->N = N;
        state->compressed_words = compressed_words;
        if (use_product_digest) {
            state->sigmas.assign(request.sigmas, request.sigmas + request.batch_size);
        }
        state->compressed_buffer = compressed_buffer;
        state->transcript_hash_buffer = transcript_hash_buffer;

        RecordAsyncSubmissionStart(context, state);
        const auto submit_wait_start = std::chrono::steady_clock::now();
        [command addCompletedHandler:^(id<MTLCommandBuffer> completed) {
            @autoreleasepool {
                state->submit_wait_us = std::chrono::duration<double, std::micro>(
                                            std::chrono::steady_clock::now() - submit_wait_start)
                                            .count();
                state->gpu_execution_ms = state->submit_wait_us / 1000.0;
                state->result.available = true;

                if (completed.status != MTLCommandBufferStatusCompleted) {
                    NSString* description = completed.error != nil ? [completed.error localizedDescription] : @"unknown Metal command failure";
                    state->result.success = false;
                    state->result.error = [description UTF8String];
                    FinalizeAsyncSubmissionState(state, "profiling_samples_ready_batch_async_error");
                    return;
                }

                const auto finalize_start = std::chrono::steady_clock::now();
                state->result.digests.reserve(state->batch_size);
                if (state->use_product_digest) {
                    for (uint32_t i = 0; i < state->batch_size; ++i) {
                        uint256 digest;
                        std::string finalize_error;
                        if (!FinalizeProductCommittedDigestFromFinalSliceBuffer(
                                state->compressed_buffer,
                                static_cast<size_t>(i) * state->compressed_words,
                                state->N,
                                state->n,
                                state->b,
                                state->sigmas[i],
                                digest,
                                finalize_error)) {
                            state->result.success = false;
                            state->result.error = finalize_error;
                            FinalizeAsyncSubmissionState(state, "profiling_samples_ready_batch_async_error");
                            return;
                        }
                        state->result.digests.push_back(digest);
                    }
                } else {
                    const auto* hash_ptr = static_cast<const unsigned char*>(state->transcript_hash_buffer.contents);
                    for (uint32_t i = 0; i < state->batch_size; ++i) {
                        state->result.digests.emplace_back(Span<const unsigned char>{
                            hash_ptr + (static_cast<size_t>(i) * kHashBytesPerDigest),
                            kHashBytesPerDigest,
                        });
                    }
                }
                state->cpu_finalize_us = std::chrono::duration<double, std::micro>(
                                             std::chrono::steady_clock::now() - finalize_start)
                                             .count();
                state->result.success = true;
                FinalizeAsyncSubmissionState(state, "profiling_samples_ready_batch_async");
            }
        }];
        [command commit];
    }

    submission.submitted = true;
    submission.opaque = state;
    return submission;
}

bool IsCanonicalTranscriptDigestBatchSubmissionReady(const MatMulDigestBatchSubmission& submission)
{
    if (!submission.submitted || !submission.opaque) {
        return false;
    }
    auto state = std::static_pointer_cast<AsyncBatchDigestState>(submission.opaque);
    std::lock_guard<std::mutex> lock(state->mutex);
    return state->completed;
}

MatMulDigestBatchResult WaitForCanonicalTranscriptDigestBatchSubmission(MatMulDigestBatchSubmission&& submission)
{
    MatMulDigestBatchResult result;
    result.available = submission.available;
    if (!submission.submitted || !submission.opaque) {
        result.success = false;
        result.error = submission.error.empty() ? "Metal batch digest submission was not started" : submission.error;
        return result;
    }

    auto state = std::static_pointer_cast<AsyncBatchDigestState>(submission.opaque);
    std::unique_lock<std::mutex> lock(state->mutex);
    state->cv.wait(lock, [&state] { return state->completed; });
    return state->result;
}

MatMulDigestBatchResult ComputeCanonicalTranscriptDigestBatch(const MatMulDigestBatchRequest& request)
{
    auto submission = SubmitCanonicalTranscriptDigestBatch(request);
    return WaitForCanonicalTranscriptDigestBatchSubmission(std::move(submission));
}

} // namespace btx::metal
