// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_accel.h>

#include <arith_uint256.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <cuda/cuda_context.h>
#include <cuda/matmul_v4_lt_device_mx.h>
#include <cuda/matmul_v4_lt_mx_native.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <matmul/int8_field.h>
#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>
#include <primitives/block.h>
#include <span.h>
#include <uint256.h>

#include <cuda_runtime.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

// ===========================================================================
// NVIDIA backend for MatMul v4.4 ENC-DR-LT ("MatExpand") mining.
//
// Lever-B MX Extract (normative): E8M0 scales on 32-col blocks + tile ChaCha
// M11 mantissas (`BTX_MATEXPAND_MXPRF_V44LT` / `MXSCALE`). Device twin must
// match CPU ExtractDequantMatExpand / AccelReplica bit-exactly.
//
// Hot path (when a calibrated CUDA device is present):
 //   persistent device-resident loop over MatExpand → project → combine.
 //   When IsLtImmaGemmAvailable(), direct s8xs8 stages use cuBLASLt IMMA;
 //   Bhat*V prefers exact MX scale-partitioned INT8 (four exponent-masked
 //   GEMMs, bit-identical to ComputeProjectedRightMxBlockScaleLT). Dense
 //   dequant INT8 is the fallback. The host-vector projection entry may try
 //   native MXFP8 / MXFP4 only after multi-shape self-qual vs the CPU oracle;
 //   the resident Q* loop reports only the exact INT8 lane it actually runs.
 //   Float accumulate is never labeled ExactGemm. Y*H uses four radix-256
 //   IMMA products, and combine uses nine base-64 Karatsuba products.
 //   TryLaunchLtImmaGemmS32S8 itself still honestly declines because cuBLASLt
 //   has no direct s32xs8 recipe. When IMMA declines, scalar tiled DeviceGemm*
 //   + CUDA-graph replay serve the same buffers — never labeled IMMA.
 //   Consensus-seeded Q* calls also generate W via the exact counter-mode SHA
 //   chunks of Chat in parallel; only digest/status records cross to the host.
 //
 // Fail-closed fallback:
 //   host ExactGemm* / WindowSketchMinerLT (bit-exact MX scale-partitioned
 //   B̂·V on CPU). That host path is the safety net when the device declines.
 //
 // Availability requires a one-time bit-identity self-test of the GEMM kernels
 // AND a two-header device-resident digest differential, plus multi-shape MX
 // projection checks vs ComputeProjectedRightMxBlockScaleLT.
// ===========================================================================

namespace matmul_v4::cuda {

namespace {

// Domain tags MUST match src/matmul/matmul_v4_lt.cpp (anonymous-namespace twins).
constexpr char kMatExpandGTag[] = "BTX_MATEXPAND_G_V44LT";
constexpr char kMatExpandHTag[] = "BTX_MATEXPAND_H_V44LT";
constexpr char kMatExpandWTag[] = "BTX_MATEXPAND_W_V44LT";
constexpr char kMatExpandWATag[] = "BTX_MATEXPAND_WA_V44LT";
constexpr size_t kDigestBytes = 32;
constexpr size_t kMaxConsensusBatch = matmul::v4::lt::kConsensusQStarMax;

// Optional force-dense Bhat·V (disables production exact-MX preference).
// Legacy BTX_MATMUL_V4_LT_LOGICAL_MX=1 is accepted as a no-op (MX is default).
bool ForceDenseBhatProjection()
{
    const char* value = std::getenv("BTX_MATMUL_V4_LT_DENSE_BHAT");
    return value != nullptr &&
           (std::strcmp(value, "1") == 0 || std::strcmp(value, "true") == 0 ||
            std::strcmp(value, "yes") == 0);
}

thread_local matmul::v4::lt::MxLaneProvenance g_lt_last_mx_prov{};
thread_local bool g_lt_exact_mx_selftest_ok = false;

uint256 DeriveTaggedSeed(const char* tag, size_t taglen, const uint256& hash)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    hasher.Write(hash.data(), uint256::size());
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

// Minimal device SHA-256 used by the nonce-bound W XOF and by the final
// SHA256d(tag || sigma || LE64(Chat...)). Keeping both users on one primitive
// makes the batch self-test cover byte order, padding, and digest emission.
__device__ __constant__ uint32_t kDeviceSha256K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

__device__ __forceinline__ uint32_t DeviceShaRotr(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (32U - n));
}

__device__ __forceinline__ void DeviceSha256Init(uint32_t state[8])
{
    state[0] = 0x6a09e667U; state[1] = 0xbb67ae85U;
    state[2] = 0x3c6ef372U; state[3] = 0xa54ff53aU;
    state[4] = 0x510e527fU; state[5] = 0x9b05688cU;
    state[6] = 0x1f83d9abU; state[7] = 0x5be0cd19U;
}

__device__ __forceinline__ void DeviceSha256Compress(uint32_t state[8],
                                                      const uint8_t block[64])
{
    // Sixteen-word circular schedule keeps the parallel W-XOF kernel in
    // registers. A 64-word local array spills to local memory on SM100/120 and
    // turns projector generation into a memory lane rather than SHA compute.
    uint32_t wv[16];
#pragma unroll
    for (int i = 0; i < 16; ++i) {
        const int p = i * 4;
        wv[i] = (static_cast<uint32_t>(block[p]) << 24) |
                (static_cast<uint32_t>(block[p + 1]) << 16) |
                (static_cast<uint32_t>(block[p + 2]) << 8) |
                static_cast<uint32_t>(block[p + 3]);
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
#pragma unroll
    for (int i = 0; i < 64; ++i) {
        if (i >= 16) {
            const uint32_t x = wv[(i + 1) & 15];  // W[i-15]
            const uint32_t y = wv[(i + 14) & 15]; // W[i-2]
            const uint32_t ss0 = DeviceShaRotr(x, 7) ^ DeviceShaRotr(x, 18) ^ (x >> 3);
            const uint32_t ss1 = DeviceShaRotr(y, 17) ^ DeviceShaRotr(y, 19) ^ (y >> 10);
            wv[i & 15] = wv[i & 15] + ss0 + wv[(i + 9) & 15] + ss1;
        }
        const uint32_t wi = wv[i & 15];
        const uint32_t s1 = DeviceShaRotr(e, 6) ^ DeviceShaRotr(e, 11) ^ DeviceShaRotr(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = h + s1 + ch + kDeviceSha256K[i] + wi;
        const uint32_t s0 = DeviceShaRotr(a, 2) ^ DeviceShaRotr(a, 13) ^ DeviceShaRotr(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ __forceinline__ uint8_t DeviceWordByte(const uint32_t words[8], uint32_t i)
{
    return static_cast<uint8_t>((words[i / 4] >> (8U * (i % 4))) & 0xffU);
}

__device__ __forceinline__ void DeviceShaStateBytes(const uint32_t state[8], uint8_t out[32])
{
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        out[4 * i] = static_cast<uint8_t>(state[i] >> 24);
        out[4 * i + 1] = static_cast<uint8_t>(state[i] >> 16);
        out[4 * i + 2] = static_cast<uint8_t>(state[i] >> 8);
        out[4 * i + 3] = static_cast<uint8_t>(state[i]);
    }
}

// ---------------------------------------------------------------------------
// Device kernels: exact GEMMs + ExtractDequant + F_q combine.
// ---------------------------------------------------------------------------

__global__ void DeviceGemmS8S8Tiled(const int8_t* __restrict__ A,
                                    const int8_t* __restrict__ B,
                                    int32_t* __restrict__ D,
                                    int M, int N, int K)
{
    const int col = blockIdx.x * blockDim.x + threadIdx.x;
    const int row = blockIdx.y * blockDim.y + threadIdx.y;
    if (row >= M || col >= N) return;
    int32_t acc = 0;
    const size_t arow = static_cast<size_t>(row) * K;
    for (int k = 0; k < K; ++k) {
        acc += static_cast<int32_t>(A[arow + k]) * static_cast<int32_t>(B[static_cast<size_t>(k) * N + col]);
    }
    D[static_cast<size_t>(row) * N + col] = acc;
}

__global__ void DeviceGemmS32S8Tiled(const int32_t* __restrict__ A,
                                     const int8_t* __restrict__ B,
                                     int32_t* __restrict__ D,
                                     int M, int N, int K)
{
    const int col = blockIdx.x * blockDim.x + threadIdx.x;
    const int row = blockIdx.y * blockDim.y + threadIdx.y;
    if (row >= M || col >= N) return;
    int64_t acc = 0;
    const size_t arow = static_cast<size_t>(row) * K;
    for (int k = 0; k < K; ++k) {
        acc += static_cast<int64_t>(A[arow + k]) * static_cast<int64_t>(B[static_cast<size_t>(k) * N + col]);
    }
    D[static_cast<size_t>(row) * N + col] = static_cast<int32_t>(acc);
}

__device__ __forceinline__ uint32_t DeviceRotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

__device__ __forceinline__ void DeviceChaChaQuarter(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    a += b; d = DeviceRotl32(d ^ a, 16);
    c += d; b = DeviceRotl32(b ^ c, 12);
    a += b; d = DeviceRotl32(d ^ a, 8);
    c += d; b = DeviceRotl32(b ^ c, 7);
}

// Bit-identical to matmul_v4_lt.cpp MatExpandMxTileKeystream (full 64-byte block).
// nonce_first = bj ⊕ 'MXBL'; nonce_second = (i<<32)|bj; counter = remix.
__device__ __forceinline__ void DeviceMatExpandMxTileKeystream(const uint32_t key[8],
                                                              uint32_t i, uint32_t bj,
                                                              uint32_t remix, uint8_t out64[64])
{
    constexpr uint32_t kLaneMxBl = 0x4D58424Cu; // 'MXBL'
    uint32_t x0 = 0x61707865u, x1 = 0x3320646eu, x2 = 0x79622d32u, x3 = 0x6b206574u;
    uint32_t x4 = key[0], x5 = key[1], x6 = key[2], x7 = key[3];
    uint32_t x8 = key[4], x9 = key[5], x10 = key[6], x11 = key[7];
    uint32_t x12 = remix;
    uint32_t x13 = bj ^ kLaneMxBl;
    const uint64_t nonce_second = (static_cast<uint64_t>(i) << 32) | static_cast<uint64_t>(bj);
    uint32_t x14 = static_cast<uint32_t>(nonce_second);
    uint32_t x15 = static_cast<uint32_t>(nonce_second >> 32);

    const uint32_t j4 = x4, j5 = x5, j6 = x6, j7 = x7;
    const uint32_t j8 = x8, j9 = x9, j10 = x10, j11 = x11;
    const uint32_t j12 = x12, j13 = x13, j14 = x14, j15 = x15;

#pragma unroll
    for (int r = 0; r < 10; ++r) {
        DeviceChaChaQuarter(x0, x4, x8, x12);
        DeviceChaChaQuarter(x1, x5, x9, x13);
        DeviceChaChaQuarter(x2, x6, x10, x14);
        DeviceChaChaQuarter(x3, x7, x11, x15);
        DeviceChaChaQuarter(x0, x5, x10, x15);
        DeviceChaChaQuarter(x1, x6, x11, x12);
        DeviceChaChaQuarter(x2, x7, x8, x13);
        DeviceChaChaQuarter(x3, x4, x9, x14);
    }

    x0 += 0x61707865u; x1 += 0x3320646eu; x2 += 0x79622d32u; x3 += 0x6b206574u;
    x4 += j4; x5 += j5; x6 += j6; x7 += j7;
    x8 += j8; x9 += j9; x10 += j10; x11 += j11;
    x12 += j12; x13 += j13; x14 += j14; x15 += j15;

    const uint32_t words[16] = {x0, x1, x2, x3, x4, x5, x6, x7,
                                x8, x9, x10, x11, x12, x13, x14, x15};
#pragma unroll
    for (int w = 0; w < 16; ++w) {
        out64[w * 4 + 0] = static_cast<uint8_t>(words[w] & 0xff);
        out64[w * 4 + 1] = static_cast<uint8_t>((words[w] >> 8) & 0xff);
        out64[w * 4 + 2] = static_cast<uint8_t>((words[w] >> 16) & 0xff);
        out64[w * 4 + 3] = static_cast<uint8_t>((words[w] >> 24) & 0xff);
    }
}

// Bit-identical to matmul::v4::bmx4::SampleMantissaNibble (E2M1 M11 table).
__device__ __forceinline__ int8_t DeviceSampleMantissaNibble(uint8_t nibble, bool& accepted)
{
    const uint8_t nib = nibble & 0x0F;
    const uint8_t sign = (nib >> 3) & 1;
    const uint8_t exp = (nib >> 1) & 3;
    const uint8_t man = nib & 1;
    int mag = 0;
    bool integer = true;
    switch (exp) {
    case 0: mag = 0; integer = (man == 0); break;
    case 1: mag = 1; integer = (man == 0); break;
    case 2: mag = (man == 0) ? 2 : 3; break;
    case 3: mag = (man == 0) ? 4 : 6; break;
    default: break;
    }
    if (!integer || (sign && mag == 0)) {
        accepted = false;
        return 0;
    }
    accepted = true;
    return static_cast<int8_t>(sign ? -mag : mag);
}

// One SHA-256 block exactly matching ExpandMantissaStream:
// SHA256(reverse(seed bytes) || 'm' || LE64(counter)). The 41-byte message and
// its padding fit one compression block.
__device__ __forceinline__ void DeviceMantissaXofBlock(const uint32_t seed_words[8],
                                                       uint64_t counter, uint8_t out[32])
{
    uint8_t block[64];
#pragma unroll
    for (int i = 0; i < 64; ++i) block[i] = 0;
#pragma unroll
    for (uint32_t i = 0; i < 32; ++i) {
        block[i] = DeviceWordByte(seed_words, 31U - i);
    }
    block[32] = 0x6d; // BMX4C mantissa XOF domain 'm'
#pragma unroll
    for (uint32_t i = 0; i < 8; ++i) {
        block[33 + i] = static_cast<uint8_t>(counter >> (8U * i));
    }
    block[41] = 0x80;
    constexpr uint64_t kBitLength = 41U * 8U;
#pragma unroll
    for (uint32_t i = 0; i < 8; ++i) {
        block[56 + i] = static_cast<uint8_t>(kBitLength >> (8U * (7U - i)));
    }
    uint32_t state[8];
    DeviceSha256Init(state);
    DeviceSha256Compress(state, block);
    DeviceShaStateBytes(state, out);
}

__global__ void DeviceGenerateMantissaXofBlocks(uint8_t* __restrict__ hashes,
                                                uint32_t* __restrict__ accepted,
                                                size_t blocks,
                                                uint32_t s0, uint32_t s1, uint32_t s2,
                                                uint32_t s3, uint32_t s4, uint32_t s5,
                                                uint32_t s6, uint32_t s7)
{
    const size_t block_index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (block_index >= blocks) return;
    const uint32_t seed_words[8] = {s0, s1, s2, s3, s4, s5, s6, s7};
    uint8_t digest[32];
    DeviceMantissaXofBlock(seed_words, static_cast<uint64_t>(block_index), digest);
    uint32_t count = 0;
#pragma unroll
    for (int i = 0; i < 32; ++i) {
        hashes[block_index * 32 + i] = digest[i];
        bool ok = false;
        (void)DeviceSampleMantissaNibble(digest[i] & 0x0f, ok);
        count += ok ? 1U : 0U;
        (void)DeviceSampleMantissaNibble(digest[i] >> 4, ok);
        count += ok ? 1U : 0U;
    }
    accepted[block_index] = count;
}

// The scan is deliberately deterministic and tiny relative to MatExpand. It
// runs on-device, so no candidate incurs a host readback or synchronization.
__global__ void DeviceScanMantissaCounts(const uint32_t* __restrict__ accepted,
                                         uint32_t* __restrict__ offsets,
                                         size_t blocks, size_t required,
                                         int* __restrict__ status)
{
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    size_t prefix = 0;
    for (size_t i = 0; i < blocks; ++i) {
        offsets[i] = static_cast<uint32_t>(prefix);
        prefix += accepted[i];
    }
    *status = prefix >= required ? 1 : 0;
}

__global__ void DeviceScatterMantissaXof(const uint8_t* __restrict__ hashes,
                                         const uint32_t* __restrict__ offsets,
                                         size_t blocks, size_t required,
                                         const int* __restrict__ status,
                                         int8_t* __restrict__ out)
{
    const size_t block_index = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (block_index >= blocks || *status == 0) return;
    size_t pos = offsets[block_index];
#pragma unroll
    for (int i = 0; i < 32; ++i) {
        const uint8_t byte = hashes[block_index * 32 + i];
        bool ok = false;
        int8_t value = DeviceSampleMantissaNibble(byte & 0x0f, ok);
        if (ok) {
            if (pos < required) out[pos] = value;
            ++pos;
        }
        value = DeviceSampleMantissaNibble(byte >> 4, ok);
        if (ok) {
            if (pos < required) out[pos] = value;
            ++pos;
        }
    }
}

__device__ __noinline__ void DeviceSha256dSketchOne(const uint64_t* __restrict__ chat,
                                                     size_t words,
                                                     uint32_t s0, uint32_t s1, uint32_t s2,
                                                     uint32_t s3, uint32_t s4, uint32_t s5,
                                                     uint32_t s6, uint32_t s7,
                                                     uint8_t* __restrict__ digest_out)
{
    constexpr uint8_t kTag[13] = {'B', 'T', 'X', '_', 'M', 'A', 'T',
                                  'M', 'U', 'L', '_', 'V', '4'};
    constexpr size_t kPrefixBytes = sizeof(kTag) + 32;
    const uint32_t sigma_words[8] = {s0, s1, s2, s3, s4, s5, s6, s7};
    const auto* chat_bytes = reinterpret_cast<const uint8_t*>(chat);
    const size_t message_bytes = kPrefixBytes + words * sizeof(uint64_t);
    const size_t padded_bytes = (message_bytes + 9U + 63U) & ~size_t{63};
    const uint64_t message_bits = static_cast<uint64_t>(message_bytes) * 8U;

    uint32_t state[8];
    DeviceSha256Init(state);
    for (size_t base = 0; base < padded_bytes; base += 64) {
        uint8_t block[64];
#pragma unroll
        for (uint32_t j = 0; j < 64; ++j) {
            const size_t p = base + j;
            uint8_t byte = 0;
            if (p < sizeof(kTag)) {
                byte = kTag[p];
            } else if (p < kPrefixBytes) {
                byte = DeviceWordByte(sigma_words, static_cast<uint32_t>(p - sizeof(kTag)));
            } else if (p < message_bytes) {
                byte = chat_bytes[p - kPrefixBytes];
            } else if (p == message_bytes) {
                byte = 0x80;
            } else if (p >= padded_bytes - 8U) {
                byte = static_cast<uint8_t>(message_bits >> (8U * (padded_bytes - 1U - p)));
            }
            block[j] = byte;
        }
        DeviceSha256Compress(state, block);
    }

    uint8_t middle[32];
    DeviceShaStateBytes(state, middle);
    uint8_t final_block[64];
#pragma unroll
    for (uint32_t i = 0; i < 64; ++i) final_block[i] = 0;
#pragma unroll
    for (uint32_t i = 0; i < 32; ++i) final_block[i] = middle[i];
    final_block[32] = 0x80;
    final_block[62] = 0x01; // 32 bytes == 256 bits
    DeviceSha256Init(state);
    DeviceSha256Compress(state, final_block);
    DeviceShaStateBytes(state, digest_out);
}

__global__ void DeviceSha256dSketchBatch(const uint64_t* __restrict__ chats,
                                         size_t words_per_chat,
                                         const uint8_t* __restrict__ sigmas,
                                         size_t count,
                                         uint8_t* __restrict__ digests)
{
    const size_t candidate = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (candidate >= count) return;
    const uint8_t* sigma = sigmas + candidate * kDigestBytes;
    uint32_t sw[8];
#pragma unroll
    for (int i = 0; i < 8; ++i) {
        const size_t p = static_cast<size_t>(i) * 4;
        sw[i] = static_cast<uint32_t>(sigma[p]) |
                (static_cast<uint32_t>(sigma[p + 1]) << 8) |
                (static_cast<uint32_t>(sigma[p + 2]) << 16) |
                (static_cast<uint32_t>(sigma[p + 3]) << 24);
    }
    DeviceSha256dSketchOne(chats + candidate * words_per_chat, words_per_chat,
                           sw[0], sw[1], sw[2], sw[3], sw[4], sw[5], sw[6], sw[7],
                           digests + candidate * kDigestBytes);
}

// Lever-B MX Extract: one thread per (i, bj) tile. The E8M0 scale is derived
// on-device, avoiding n*(n/32) host SHA-256 calls and an H2D upload per nonce.
__global__ void DeviceExtractDequantMatExpandMx(const int32_t* __restrict__ B32,
                                                int8_t* __restrict__ Bhat,
                                                int8_t* __restrict__ Mu,
                                                uint8_t* __restrict__ Scales,
                                                uint32_t n, uint32_t k0, uint32_t k1, uint32_t k2,
                                                uint32_t k3, uint32_t k4, uint32_t k5, uint32_t k6,
                                                uint32_t k7)
{
    constexpr uint32_t kBlk = 32;
    const uint32_t nblk = n / kBlk;
    const uint32_t tile = blockIdx.x * blockDim.x + threadIdx.x;
    const uint32_t ntiles = n * nblk;
    if (tile >= ntiles) return;

    const uint32_t i = tile / nblk;
    const uint32_t bj = tile % nblk;
    const uint32_t key[8] = {k0, k1, k2, k3, k4, k5, k6, k7};
    const int32_t* raw32 = B32 + static_cast<size_t>(i) * n + static_cast<size_t>(bj) * kBlk;

    int8_t mu[kBlk];
    uint32_t remix = 0;
    uint32_t filled = 0;
    while (filled < kBlk) {
        uint8_t ks[64];
        DeviceMatExpandMxTileKeystream(key, i, bj, remix, ks);
        for (int b = 0; b < 64 && filled < kBlk; ++b) {
            const uint8_t byte = ks[b];
            for (int shift = 0; shift < 8 && filled < kBlk; shift += 4) {
                const uint8_t nibble = static_cast<uint8_t>((byte >> shift) & 0x0F);
                const uint32_t raw_u = static_cast<uint32_t>(raw32[filled]);
                const uint8_t mixed = static_cast<uint8_t>(
                    (nibble ^ static_cast<uint8_t>((raw_u * 0x9E3779B9u) >> 28)) & 0x0F);
                bool accepted = false;
                const int8_t m = DeviceSampleMantissaNibble(mixed, accepted);
                if (accepted) {
                    mu[filled++] = m;
                }
            }
        }
        ++remix;
    }

    const uint8_t e = matmul_v4::lt_device::DeriveMatExpandMxScale(key, i, bj);
    if (Scales != nullptr) Scales[tile] = e;
    const int32_t scale = int32_t{1} << e;
    const size_t base = static_cast<size_t>(i) * n + static_cast<size_t>(bj) * kBlk;
    int8_t* dense_out = Bhat != nullptr ? Bhat + base : nullptr;
    int8_t* mu_out = Mu != nullptr ? Mu + base : nullptr;
    for (uint32_t t = 0; t < kBlk; ++t) {
        if (mu_out != nullptr) mu_out[t] = mu[t];
        if (dense_out != nullptr) {
            dense_out[t] = static_cast<int8_t>(static_cast<int32_t>(mu[t]) * scale);
        }
    }
}

// Build the e-th exact scale partition without materializing dense Bhat.
// Each μ value is copied only when its row/32-column tile has exponent e;
// otherwise it is zero. Four ordinary signed-INT8 tensor GEMMs followed by
// exact power-of-two accumulation reproduce (μ*2^scale)*V bit-for-bit. This is
// an MX-layout IMMA lowering, not a claim of native OCP-MXFP4 instructions.
__global__ void DeviceBuildMxExponentPlane(const int8_t* __restrict__ Mu,
                                           const uint8_t* __restrict__ Scales,
                                           int8_t* __restrict__ Plane,
                                           size_t count, uint32_t n, uint32_t exponent)
{
    constexpr uint32_t kBlk = 32;
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    const uint32_t row = static_cast<uint32_t>(idx / n);
    const uint32_t col = static_cast<uint32_t>(idx % n);
    const uint32_t nblk = n / kBlk;
    const uint8_t e = Scales[static_cast<size_t>(row) * nblk + col / kBlk];
    Plane[idx] = e == exponent ? Mu[idx] : int8_t{0};
}

__global__ void DeviceAccumulateMxProjection(const int32_t* __restrict__ Product,
                                             int32_t* __restrict__ Q,
                                             size_t count, uint32_t exponent)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    const int64_t term = static_cast<int64_t>(Product[idx]) * (int64_t{1} << exponent);
    auto* q_bits = reinterpret_cast<uint32_t*>(Q);
    const uint32_t prior = exponent == 0 ? 0U : q_bits[idx];
    q_bits[idx] = prior + static_cast<uint32_t>(term);
}

// Exact s32 -> four signed-byte planes. The low three unsigned bytes are
// recentered into [-128,127], while the high byte remains signed:
//
// x = sum_l plane_l(x)*256^l + 128*(1 + 256 + 65536).
//
// Four self-qualified s8xs8 IMMA products plus the row-independent correction
// therefore reproduce Y*H for every int32 bit pattern, with defined modulo-2^32
// intermediate accumulation and the consensus-bounded signed final result.
__global__ void DeviceExtractRadix256Plane(const int32_t* __restrict__ input,
                                           int8_t* __restrict__ plane,
                                           size_t count, uint32_t limb)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    const uint32_t bits = static_cast<uint32_t>(input[idx]);
    const uint32_t byte = (bits >> (8U * limb)) & 0xffU;
    const int32_t digit = limb < 3
        ? static_cast<int32_t>(byte) - 128
        : (byte < 128 ? static_cast<int32_t>(byte) : static_cast<int32_t>(byte) - 256);
    plane[idx] = static_cast<int8_t>(digit);
}

__global__ void DeviceColumnSumsS8(const int8_t* __restrict__ matrix,
                                   int32_t* __restrict__ sums, int rows, int cols)
{
    const int col = blockIdx.x * blockDim.x + threadIdx.x;
    if (col >= cols) return;
    int32_t sum = 0;
    for (int row = 0; row < rows; ++row) {
        sum += static_cast<int32_t>(matrix[static_cast<size_t>(row) * cols + col]);
    }
    sums[col] = sum;
}

__global__ void DeviceAccumulateRadix256(const int32_t* __restrict__ limb_product,
                                         int32_t* __restrict__ output,
                                         const int32_t* __restrict__ rhs_column_sums,
                                         size_t count, int cols, uint32_t limb)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    constexpr int64_t kLowByteBias = 128ll * (1ll + 256ll + 65536ll);
    int64_t term = static_cast<int64_t>(limb_product[idx]) * (int64_t{1} << (8U * limb));
    if (limb == 3) {
        term += kLowByteBias * static_cast<int64_t>(rhs_column_sums[idx % cols]);
    }
    auto* output_bits = reinterpret_cast<uint32_t*>(output);
    const uint32_t prior = limb == 0 ? 0U : output_bits[idx];
    output_bits[idx] = prior + static_cast<uint32_t>(term);
}

static_assert(matmul::v4::bmx4::kCombineLimbs == 4 &&
              matmul::v4::bmx4::kCombineLimbBase == 64,
              "LT CUDA combine kernels pin the BMX4-C four-limb base-64 encoding");

// Emits one of the nine exact Karatsuba planes in the CPU helper's order.
// Each output is in [-128,127], so it is a legal signed-byte IMMA operand.
__global__ void DeviceBuildKaratsubaPlane(const int32_t* __restrict__ input,
                                          int8_t* __restrict__ plane,
                                          size_t count, uint32_t plane_index)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    int32_t x = input[idx];
    const int32_t d0 = ((x + 32) & 63) - 32;
    x = (x - d0) / 64;
    const int32_t d1 = ((x + 32) & 63) - 32;
    x = (x - d1) / 64;
    const int32_t d2 = ((x + 32) & 63) - 32;
    const int32_t d3 = (x - d2) / 64;
    int32_t value = 0;
    switch (plane_index) {
    case 0: value = d0; break;
    case 1: value = d1; break;
    case 2: value = d0 + d1; break;
    case 3: value = d2; break;
    case 4: value = d3; break;
    case 5: value = d2 + d3; break;
    case 6: value = d0 + d2; break;
    case 7: value = d1 + d3; break;
    case 8: value = d0 + d1 + d2 + d3; break;
    }
    plane[idx] = static_cast<int8_t>(value);
}

// F_q = 2^61-1 helpers (device twin of matmul::int8_field).
__device__ __forceinline__ uint64_t DeviceFqReduce(unsigned __int128 x)
{
    constexpr uint64_t q = (uint64_t{1} << 61) - 1;
    const uint64_t lo = static_cast<uint64_t>(x & q);
    const uint64_t hi = static_cast<uint64_t>(x >> 61);
    uint64_t s = lo + hi;
    s = (s & q) + (s >> 61);
    if (s >= q) s -= q;
    return s;
}

__device__ __forceinline__ uint64_t DeviceFqFromInt64(int64_t x)
{
    constexpr uint64_t q = (uint64_t{1} << 61) - 1;
    if (x >= 0) return DeviceFqReduce(static_cast<unsigned __int128>(static_cast<uint64_t>(x)));
    const uint64_t magnitude = static_cast<uint64_t>(-(x + 1)) + 1;
    const uint64_t r = DeviceFqReduce(static_cast<unsigned __int128>(magnitude));
    return r == 0 ? 0 : (q - r);
}

__device__ __forceinline__ uint64_t DeviceFqAdd(uint64_t a, uint64_t b)
{
    constexpr uint64_t q = (uint64_t{1} << 61) - 1;
    const uint64_t sum = a + b;
    return sum >= q ? sum - q : sum;
}

__device__ __forceinline__ uint64_t DeviceFqMul(uint64_t a, uint64_t b)
{
    return DeviceFqReduce(static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b));
}

__global__ void DeviceAccumulateCombinePlane(const int32_t* __restrict__ product,
                                             uint64_t* __restrict__ chat,
                                             uint64_t weight, size_t count)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    chat[idx] = DeviceFqAdd(chat[idx],
                            DeviceFqMul(weight, DeviceFqFromInt64(product[idx])));
}

void Karatsuba9FqWeights(uint64_t (&weights)[9])
{
    using matmul::int8_field::FqAdd;
    using matmul::int8_field::FqNeg;
    const uint64_t w[7] = {
        uint64_t{1} << 0, uint64_t{1} << 6, uint64_t{1} << 12, uint64_t{1} << 18,
        uint64_t{1} << 24, uint64_t{1} << 30, uint64_t{1} << 36,
    };
    weights[0] = FqAdd(FqAdd(w[0], FqNeg(w[1])), FqAdd(FqNeg(w[2]), w[3]));
    weights[1] = FqAdd(FqAdd(FqNeg(w[1]), w[2]), FqAdd(w[3], FqNeg(w[4])));
    weights[2] = FqAdd(w[1], FqNeg(w[3]));
    weights[3] = FqAdd(FqAdd(FqNeg(w[2]), w[3]), FqAdd(w[4], FqNeg(w[5])));
    weights[4] = FqAdd(FqAdd(w[3], FqNeg(w[4])), FqAdd(FqNeg(w[5]), w[6]));
    weights[5] = FqAdd(FqNeg(w[3]), w[5]);
    weights[6] = FqAdd(w[2], FqNeg(w[3]));
    weights[7] = FqAdd(FqNeg(w[3]), w[4]);
    weights[8] = w[3];
}

static_assert(uint64_t{288} * 288 * 29'127 * 29'127 * 29'127 < (uint64_t{1} << 63),
              "BMX4C deferred combine must fit signed int64 at the construction limit");

// Chat[a,c] = sum_k P[a,k]*Q[k,c] (mod q). BMX4C pins
// |P|,|Q| <= 288*n, hence at the largest public n=8192 the entire signed dot
// product is bounded by 288^2*n^3 < 2^56. Accumulate exactly in int64 and do
// one field reduction per output, matching the CPU deferred-combine oracle.
// The previous kernel performed a 128-bit Mersenne reduction on every MAC.
// Shared K tiles also remove the 16-way redundant P/Q global loads in a block.
__global__ void DeviceCombineModQ(const int32_t* __restrict__ P,
                                  const int32_t* __restrict__ Q,
                                  uint64_t* __restrict__ Chat,
                                  int n, int m)
{
    constexpr int kOutputTile = 16;
    constexpr int kReductionTile = 32;
    __shared__ int32_t p_tile[kOutputTile][kReductionTile];
    __shared__ int32_t q_tile[kReductionTile][kOutputTile];

    const int tx = threadIdx.x;
    const int ty = threadIdx.y;
    const int c0 = static_cast<int>(blockIdx.x) * kOutputTile;
    const int a0 = static_cast<int>(blockIdx.y) * kOutputTile;
    const int c = c0 + tx;
    const int a = a0 + ty;
    const int tid = ty * kOutputTile + tx;
    int64_t acc = 0;

    for (int k0 = 0; k0 < n; k0 += kReductionTile) {
        for (int linear = tid; linear < kOutputTile * kReductionTile;
             linear += kOutputTile * kOutputTile) {
            const int row = linear / kReductionTile;
            const int kk = linear % kReductionTile;
            const int ga = a0 + row;
            const int gk = k0 + kk;
            p_tile[row][kk] = (ga < m && gk < n)
                ? P[static_cast<size_t>(ga) * n + gk]
                : 0;
        }
        for (int linear = tid; linear < kReductionTile * kOutputTile;
             linear += kOutputTile * kOutputTile) {
            const int kk = linear / kOutputTile;
            const int col = linear % kOutputTile;
            const int gk = k0 + kk;
            const int gc = c0 + col;
            q_tile[kk][col] = (gk < n && gc < m)
                ? Q[static_cast<size_t>(gk) * m + gc]
                : 0;
        }
        __syncthreads();
        if (a < m && c < m) {
#pragma unroll
            for (int kk = 0; kk < kReductionTile; ++kk) {
                acc += static_cast<int64_t>(p_tile[ty][kk]) *
                       static_cast<int64_t>(q_tile[kk][tx]);
            }
        }
        __syncthreads();
    }
    if (a < m && c < m) Chat[static_cast<size_t>(a) * m + c] = DeviceFqFromInt64(acc);
}

// ---------------------------------------------------------------------------
// Persistent cross-call device pool + CUDA graphs for stable GEMM stages.
// ---------------------------------------------------------------------------

struct LtCudaResidentPool {
    std::mutex mu;
    int device{-1};
    cudaStream_t stream{nullptr};

    uint32_t n{0};
    uint32_t m{0};
    uint32_t w{0};
    uint256 template_hash{};
    bool template_bound{false};
    bool graphs_ready{false};
    bool imma_s8s8{false};
    // Prefer exact MX scale-partitioned B̂·V (μ + E8M0) over dense dequant.
    bool mx_partitioned{false};
    bool used_exact_mx_this_batch{false};
    matmul::v4::lt::MxLaneProvenance mx_prov{};

    // Template-resident
    int8_t* dG{nullptr};
    int8_t* dH{nullptr};
    int8_t* dU{nullptr};
    int8_t* dV{nullptr};
    int8_t* dAhat{nullptr};
    int32_t* dP{nullptr};

    // Per-nonce working set (reused across calls)
    int8_t* dW{nullptr};
    int32_t* dY{nullptr};
    int32_t* dB32{nullptr};
    int8_t* dBhat{nullptr}; // MX mantissa μ when mx_partitioned; else dense Bhat
    uint8_t* dScales{nullptr}; // n*(n/32) E8M0 codes for exact MX projection
    int32_t* dQ{nullptr};
    uint64_t* dChat{nullptr};

    // Device W-XOF staging is dimension-scoped. Batch outputs remain only
    // 32-byte digests plus one fail-closed status word per candidate.
    uint8_t* dWHashes{nullptr};
    uint32_t* dWAccepted{nullptr};
    uint32_t* dWOffsets{nullptr};
    size_t w_xof_blocks{0};
    uint8_t* dBatchDigests{nullptr};
    uint8_t* dBatchSigmas{nullptr};
    int* dBatchStatus{nullptr};
    uint64_t* dChatBatch{nullptr};
    size_t chat_batch_slots{0};
    size_t batch_capacity{0};

    // Generic LaunchGemm scratch (cross-call reuse; minimizes alloc churn)
    int8_t* dGemmS8L{nullptr};
    int8_t* dGemmS8R{nullptr};
    int32_t* dGemmS32L{nullptr};
    int32_t* dGemmOut{nullptr};
    size_t gemm_s8l_bytes{0};
    size_t gemm_s8r_bytes{0};
    size_t gemm_s32l_bytes{0};
    size_t gemm_out_bytes{0};

    cudaGraph_t matexpand_graph{nullptr};
    cudaGraphExec_t matexpand_exec{nullptr};
    cudaGraph_t project_right_graph{nullptr};
    cudaGraphExec_t project_right_exec{nullptr};

    ~LtCudaResidentPool() { Release(); }

    void ReleaseGraphs()
    {
        if (matexpand_exec) { cudaGraphExecDestroy(matexpand_exec); matexpand_exec = nullptr; }
        if (matexpand_graph) { cudaGraphDestroy(matexpand_graph); matexpand_graph = nullptr; }
        if (project_right_exec) { cudaGraphExecDestroy(project_right_exec); project_right_exec = nullptr; }
        if (project_right_graph) { cudaGraphDestroy(project_right_graph); project_right_graph = nullptr; }
        graphs_ready = false;
    }

    void Release()
    {
        ReleaseGraphs();
        auto free_p = [](auto*& p) {
            if (p) { cudaFree(p); p = nullptr; }
        };
        free_p(dG); free_p(dH); free_p(dU); free_p(dV); free_p(dAhat); free_p(dP);
        free_p(dW); free_p(dY); free_p(dB32); free_p(dBhat); free_p(dQ); free_p(dChat);
        free_p(dScales);
        free_p(dWHashes); free_p(dWAccepted); free_p(dWOffsets);
        free_p(dBatchDigests); free_p(dBatchSigmas); free_p(dBatchStatus); free_p(dChatBatch);
        w_xof_blocks = chat_batch_slots = batch_capacity = 0;
        free_p(dGemmS8L); free_p(dGemmS8R); free_p(dGemmS32L); free_p(dGemmOut);
        gemm_s8l_bytes = gemm_s8r_bytes = gemm_s32l_bytes = gemm_out_bytes = 0;
        if (stream) { cudaStreamDestroy(stream); stream = nullptr; }
        template_bound = false;
        imma_s8s8 = false;
        mx_partitioned = false;
        used_exact_mx_this_batch = false;
        mx_prov = {};
        n = m = w = 0;
        device = -1;
    }

    [[nodiscard]] bool EnsureScratch(size_t s8l, size_t s8r, size_t s32l, size_t out)
    {
        auto grow = [](auto*& p, size_t& have, size_t need) -> bool {
            if (need <= have) return true;
            if (p) { cudaFree(p); p = nullptr; have = 0; }
            if (need == 0) return true;
            if (cudaMalloc(reinterpret_cast<void**>(&p), need) != cudaSuccess) return false;
            have = need;
            return true;
        };
        return grow(dGemmS8L, gemm_s8l_bytes, s8l) &&
               grow(dGemmS8R, gemm_s8r_bytes, s8r) &&
               grow(dGemmS32L, gemm_s32l_bytes, s32l) &&
               grow(dGemmOut, gemm_out_bytes, out);
    }

    [[nodiscard]] bool EnsureBatchCapacity(size_t count)
    {
        if (count <= batch_capacity) return true;
        if (dBatchDigests) { cudaFree(dBatchDigests); dBatchDigests = nullptr; }
        if (dBatchSigmas) { cudaFree(dBatchSigmas); dBatchSigmas = nullptr; }
        if (dBatchStatus) { cudaFree(dBatchStatus); dBatchStatus = nullptr; }
        if (dChatBatch) { cudaFree(dChatBatch); dChatBatch = nullptr; }
        chat_batch_slots = 0;
        batch_capacity = 0;
        const size_t chat_bytes = static_cast<size_t>(m) * m * sizeof(uint64_t);
        size_t free_bytes = 0;
        size_t total_bytes = 0;
        if (cudaMemGetInfo(&free_bytes, &total_bytes) != cudaSuccess || chat_bytes == 0) return false;
        constexpr size_t kMaxChatBatchBytes = size_t{128} << 20;
        const size_t budget = std::min(kMaxChatBatchBytes,
                                       std::min(free_bytes / 8U, total_bytes / 16U));
        chat_batch_slots = std::min(count, std::max<size_t>(1, budget / chat_bytes));
        if (chat_batch_slots > std::numeric_limits<size_t>::max() / chat_bytes) return false;
        if (cudaMalloc(reinterpret_cast<void**>(&dBatchDigests), count * kDigestBytes) != cudaSuccess ||
            cudaMalloc(reinterpret_cast<void**>(&dBatchSigmas), count * kDigestBytes) != cudaSuccess ||
            cudaMalloc(reinterpret_cast<void**>(&dBatchStatus), count * sizeof(int)) != cudaSuccess ||
            cudaMalloc(reinterpret_cast<void**>(&dChatBatch), chat_batch_slots * chat_bytes) != cudaSuccess) {
            if (dBatchDigests) { cudaFree(dBatchDigests); dBatchDigests = nullptr; }
            if (dBatchSigmas) { cudaFree(dBatchSigmas); dBatchSigmas = nullptr; }
            if (dBatchStatus) { cudaFree(dBatchStatus); dBatchStatus = nullptr; }
            if (dChatBatch) { cudaFree(dChatBatch); dChatBatch = nullptr; }
            chat_batch_slots = 0;
            return false;
        }
        batch_capacity = count;
        return true;
    }

    [[nodiscard]] bool EnsureDims(uint32_t n_in, uint32_t m_in)
    {
        const uint32_t w_in = matmul::v4::lt::kMatExpandPanelW;
        if (stream != nullptr && n == n_in && m == m_in && w == w_in) {
            return true;
        }
        Release();

        const btx::cuda::CudaRuntimeProbe runtime = btx::cuda::ProbeCudaRuntime();
        if (runtime.device_index >= 0) {
            if (cudaSetDevice(runtime.device_index) != cudaSuccess) return false;
            device = runtime.device_index;
        } else {
            if (cudaGetDevice(&device) != cudaSuccess) return false;
        }
        if (cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking) != cudaSuccess) return false;

        // Production default: exact MX scale-partitioned B̂·V (CPU-oracle
        // identical). Opt out with BTX_MATMUL_V4_LT_DENSE_BHAT=1. Native MXFP8/
        // MXFP4 may qualify only after matmul_v4_lt_mx_native.cu self-qual.
        mx_partitioned = (n_in % matmul::v4::lt::kMatExpandMxBlockLen == 0) &&
                         !ForceDenseBhatProjection();
        used_exact_mx_this_batch = false;
        // Resident provenance describes execution, not process-wide native-lane
        // capability. EnqueueOneHeader sets the exact lane it actually uses.
        mx_prov = {};

        n = n_in;
        m = m_in;
        w = w_in;
        const size_t nn = static_cast<size_t>(n) * n;
        const size_t nw = static_cast<size_t>(n) * w;
        const size_t wn = static_cast<size_t>(w) * n;
        const size_t mn = static_cast<size_t>(m) * n;
        const size_t nm = static_cast<size_t>(n) * m;
        const size_t mm = static_cast<size_t>(m) * m;
        // Each counter block supplies at most 64 and on average 44 accepted
        // mantissas. One block per 32 required outputs is a conservative fixed
        // budget; a device status word makes the vanishingly unlikely short
        // prefix an explicit fail-closed decline.
        w_xof_blocks = (nw + 31U) / 32U;
        const size_t nscales = static_cast<size_t>(n) *
            (n / matmul::v4::lt::kMatExpandMxBlockLen);

        auto mall = [](void** p, size_t bytes) {
            return bytes == 0 || cudaMalloc(p, bytes) == cudaSuccess;
        };
        if (!mall(reinterpret_cast<void**>(&dG), nn) ||
            !mall(reinterpret_cast<void**>(&dH), wn) ||
            !mall(reinterpret_cast<void**>(&dU), mn) ||
            !mall(reinterpret_cast<void**>(&dV), nm) ||
            !mall(reinterpret_cast<void**>(&dAhat), nn) ||
            !mall(reinterpret_cast<void**>(&dP), mn * sizeof(int32_t)) ||
            !mall(reinterpret_cast<void**>(&dW), nw) ||
            !mall(reinterpret_cast<void**>(&dY), nw * sizeof(int32_t)) ||
            !mall(reinterpret_cast<void**>(&dB32), nn * sizeof(int32_t)) ||
            !mall(reinterpret_cast<void**>(&dBhat), nn) ||
            !mall(reinterpret_cast<void**>(&dQ), nm * sizeof(int32_t)) ||
            !mall(reinterpret_cast<void**>(&dChat), mm * sizeof(uint64_t)) ||
            !mall(reinterpret_cast<void**>(&dScales), mx_partitioned ? nscales : 0) ||
            !mall(reinterpret_cast<void**>(&dWHashes), w_xof_blocks * 32U) ||
            !mall(reinterpret_cast<void**>(&dWAccepted), w_xof_blocks * sizeof(uint32_t)) ||
            !mall(reinterpret_cast<void**>(&dWOffsets), w_xof_blocks * sizeof(uint32_t))) {
            Release();
            return false;
        }
        return true;
    }

    [[nodiscard]] bool LaunchDeviceW(const uint256& seed_w, int* status)
    {
        const size_t required = static_cast<size_t>(n) * w;
        uint32_t sw[8];
        for (int i = 0; i < 8; ++i) {
            sw[i] = ReadLE32(seed_w.data() + static_cast<size_t>(i) * 4);
        }
        constexpr unsigned kThreads = 256;
        const unsigned blocks = static_cast<unsigned>((w_xof_blocks + kThreads - 1) / kThreads);
        DeviceGenerateMantissaXofBlocks<<<blocks, kThreads, 0, stream>>>(
            dWHashes, dWAccepted, w_xof_blocks,
            sw[0], sw[1], sw[2], sw[3], sw[4], sw[5], sw[6], sw[7]);
        if (cudaGetLastError() != cudaSuccess) return false;
        DeviceScanMantissaCounts<<<1, 1, 0, stream>>>(
            dWAccepted, dWOffsets, w_xof_blocks, required, status);
        if (cudaGetLastError() != cudaSuccess) return false;
        DeviceScatterMantissaXof<<<blocks, kThreads, 0, stream>>>(
            dWHashes, dWOffsets, w_xof_blocks, required, status, dW);
        return cudaGetLastError() == cudaSuccess;
    }

    [[nodiscard]] bool LaunchDeviceDigestBatch(size_t count,
                                               const uint8_t* sigmas,
                                               uint8_t* digests)
    {
        if (count == 0 || count > chat_batch_slots) return false;
        // SHA-256 is serial within one Chat transcript, but candidates are
        // independent. One thread per staged candidate lets a bounded chunk
        // occupy the GPU instead of serializing Q* single-thread kernels.
        constexpr unsigned kThreads = 64;
        const unsigned blocks = static_cast<unsigned>((count + kThreads - 1) / kThreads);
        DeviceSha256dSketchBatch<<<blocks, kThreads, 0, stream>>>(
            dChatBatch, static_cast<size_t>(m) * m, sigmas, count, digests);
        return cudaGetLastError() == cudaSuccess;
    }

    [[nodiscard]] bool LaunchMxExtract(int8_t* dDenseOut, int8_t* dMuOut,
                                       uint8_t* dScalesOut, const uint256& prf_key)
    {
        const uint32_t nblk = n / matmul::v4::lt::kMatExpandMxBlockLen;
        uint32_t kw[8];
        for (int t = 0; t < 8; ++t) kw[t] = ReadLE32(prf_key.data() + static_cast<size_t>(t) * 4);
        const uint32_t ntiles = n * nblk;
        const int extract_threads = 256;
        const int extract_blocks = static_cast<int>((ntiles + extract_threads - 1) / extract_threads);
        DeviceExtractDequantMatExpandMx<<<extract_blocks, extract_threads, 0, stream>>>(
            dB32, dDenseOut, dMuOut, dScalesOut, n,
            kw[0], kw[1], kw[2], kw[3], kw[4], kw[5], kw[6], kw[7]);
        return cudaGetLastError() == cudaSuccess;
    }

    [[nodiscard]] bool CaptureGraphsScalar()
    {
        ReleaseGraphs();
        const dim3 block(16, 16, 1);
        {
            const dim3 grid_y((w + block.x - 1) / block.x, (n + block.y - 1) / block.y, 1);
            const dim3 grid_b((n + block.x - 1) / block.x, (n + block.y - 1) / block.y, 1);
            if (cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal) != cudaSuccess) return false;
            DeviceGemmS8S8Tiled<<<grid_y, block, 0, stream>>>(dG, dW, dY, (int)n, (int)w, (int)n);
            DeviceGemmS32S8Tiled<<<grid_b, block, 0, stream>>>(dY, dH, dB32, (int)n, (int)n, (int)w);
            if (cudaStreamEndCapture(stream, &matexpand_graph) != cudaSuccess) { matexpand_graph = nullptr; return false; }
            if (cudaGraphInstantiate(&matexpand_exec, matexpand_graph, nullptr, nullptr, 0) != cudaSuccess) { ReleaseGraphs(); return false; }
        }
        {
            const dim3 grid_q((m + block.x - 1) / block.x, (n + block.y - 1) / block.y, 1);
            if (cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal) != cudaSuccess) { ReleaseGraphs(); return false; }
            DeviceGemmS8S8Tiled<<<grid_q, block, 0, stream>>>(dBhat, dV, dQ, (int)n, (int)m, (int)n);
            if (cudaStreamEndCapture(stream, &project_right_graph) != cudaSuccess) { project_right_graph = nullptr; ReleaseGraphs(); return false; }
            if (cudaGraphInstantiate(&project_right_exec, project_right_graph, nullptr, nullptr, 0) != cudaSuccess) { ReleaseGraphs(); return false; }
        }
        graphs_ready = true;
        return true;
    }

    [[nodiscard]] bool LaunchMatExpandImma()
    {
        if (!TryLaunchLtImmaGemmS8S8Device(dG, dW, dY, n, w, n, stream)) return false;
        const size_t yw = static_cast<size_t>(n) * w;
        const size_t nn = static_cast<size_t>(n) * n;
        if (!EnsureScratch(yw, 0, static_cast<size_t>(n) * sizeof(int32_t),
                           nn * sizeof(int32_t))) {
            return false;
        }

        constexpr unsigned kElemThreads = 256;
        const unsigned yw_blocks = static_cast<unsigned>((yw + kElemThreads - 1) / kElemThreads);
        const unsigned out_blocks = static_cast<unsigned>((nn + kElemThreads - 1) / kElemThreads);
        const unsigned col_blocks = (n + kElemThreads - 1) / kElemThreads;
        DeviceColumnSumsS8<<<col_blocks, kElemThreads, 0, stream>>>(
            dH, dGemmS32L, static_cast<int>(w), static_cast<int>(n));
        if (cudaGetLastError() != cudaSuccess) return false;

        for (uint32_t limb = 0; limb < 4; ++limb) {
            DeviceExtractRadix256Plane<<<yw_blocks, kElemThreads, 0, stream>>>(
                dY, dGemmS8L, yw, limb);
            if (cudaGetLastError() != cudaSuccess) return false;
            if (!TryLaunchLtImmaGemmS8S8Device(dGemmS8L, dH, dGemmOut,
                                               n, n, w, stream)) {
                return false;
            }
            DeviceAccumulateRadix256<<<out_blocks, kElemThreads, 0, stream>>>(
                dGemmOut, dB32, dGemmS32L, nn, static_cast<int>(n), limb);
            if (cudaGetLastError() != cudaSuccess) return false;
        }
        return true;
    }

    [[nodiscard]] bool LaunchProjectRightDenseImma()
    {
        return TryLaunchLtImmaGemmS8S8Device(dBhat, dV, dQ, n, m, n, stream);
    }

    // Exact MX-layout lowering: four exponent-masked M11 planes × s8xs8 GEMM
    // + exact 2^e accumulate. Bit-identical to
    // ComputeProjectedRightMxBlockScaleLT / ComputeProjectedRightMxScalePartitionedGemmLT.
    // Prefer IMMA library GEMMs; fall back to tiled DeviceGemmS8S8.
    [[nodiscard]] bool LaunchProjectRightMxExact()
    {
        const size_t nn = static_cast<size_t>(n) * n;
        const size_t nm = static_cast<size_t>(n) * m;
        if (dScales == nullptr || !EnsureScratch(nn, 0, 0, nm * sizeof(int32_t))) {
            return false;
        }

        constexpr unsigned kElemThreads = 256;
        const unsigned plane_blocks = static_cast<unsigned>((nn + kElemThreads - 1) /
                                                             kElemThreads);
        const unsigned out_blocks = static_cast<unsigned>((nm + kElemThreads - 1) /
                                                           kElemThreads);
        const dim3 gemm_block(16, 16, 1);
        const dim3 gemm_grid((m + gemm_block.x - 1) / gemm_block.x,
                             (n + gemm_block.y - 1) / gemm_block.y, 1);
        for (uint32_t exponent = 0;
             exponent < matmul::v4::bmx4::kNumScaleCodes; ++exponent) {
            DeviceBuildMxExponentPlane<<<plane_blocks, kElemThreads, 0, stream>>>(
                dBhat, dScales, dGemmS8L, nn, n, exponent);
            if (cudaGetLastError() != cudaSuccess) return false;
            bool gemm_ok = false;
            if (imma_s8s8) {
                gemm_ok = TryLaunchLtImmaGemmS8S8Device(dGemmS8L, dV, dGemmOut,
                                                        n, m, n, stream);
            }
            if (!gemm_ok) {
                DeviceGemmS8S8Tiled<<<gemm_grid, gemm_block, 0, stream>>>(
                    dGemmS8L, dV, dGemmOut, static_cast<int>(n), static_cast<int>(m),
                    static_cast<int>(n));
                if (cudaGetLastError() != cudaSuccess) return false;
            }
            DeviceAccumulateMxProjection<<<out_blocks, kElemThreads, 0, stream>>>(
                dGemmOut, dQ, nm, exponent);
            if (cudaGetLastError() != cudaSuccess) return false;
        }
        return true;
    }

    [[nodiscard]] bool LaunchProjectRightMxImma()
    {
        return LaunchProjectRightMxExact();
    }

    [[nodiscard]] bool LaunchProjectLeftImma()
    {
        return TryLaunchLtImmaGemmS8S8Device(dU, dAhat, dP, m, n, n, stream);
    }

    [[nodiscard]] bool LaunchCombineImma()
    {
        const size_t mn = static_cast<size_t>(m) * n;
        const size_t nm = static_cast<size_t>(n) * m;
        const size_t mm = static_cast<size_t>(m) * m;
        if (!EnsureScratch(mn, nm, 0, mm * sizeof(int32_t))) return false;

        constexpr unsigned kElemThreads = 256;
        const unsigned p_blocks = static_cast<unsigned>((mn + kElemThreads - 1) / kElemThreads);
        const unsigned q_blocks = static_cast<unsigned>((nm + kElemThreads - 1) / kElemThreads);
        const unsigned out_blocks = static_cast<unsigned>((mm + kElemThreads - 1) / kElemThreads);
        if (cudaMemsetAsync(dChat, 0, mm * sizeof(uint64_t), stream) != cudaSuccess) return false;

        uint64_t weights[9];
        Karatsuba9FqWeights(weights);
        for (uint32_t plane = 0; plane < 9; ++plane) {
            DeviceBuildKaratsubaPlane<<<p_blocks, kElemThreads, 0, stream>>>(
                dP, dGemmS8L, mn, plane);
            if (cudaGetLastError() != cudaSuccess) return false;
            DeviceBuildKaratsubaPlane<<<q_blocks, kElemThreads, 0, stream>>>(
                dQ, dGemmS8R, nm, plane);
            if (cudaGetLastError() != cudaSuccess) return false;
            if (!TryLaunchLtImmaGemmS8S8Device(dGemmS8L, dGemmS8R, dGemmOut,
                                               m, m, n, stream)) {
                return false;
            }
            DeviceAccumulateCombinePlane<<<out_blocks, kElemThreads, 0, stream>>>(
                dGemmOut, dChat, weights[plane], mm);
            if (cudaGetLastError() != cudaSuccess) return false;
        }
        return true;
    }

    [[nodiscard]] bool BindTemplate(const CBlockHeader& tmpl, uint32_t n_in, uint32_t m_in)
    {
        if (!EnsureDims(n_in, m_in)) return false;
        const uint256 th = matmul::v4::ComputeTemplateHash(tmpl);
        const bool want_imma = IsLtImmaGemmAvailable();
        if (template_bound && template_hash == th && imma_s8s8 == want_imma && (imma_s8s8 || graphs_ready)) return true;

        namespace bx = matmul::v4::bmx4;
        const uint256 seed_g = DeriveTaggedSeed(kMatExpandGTag, sizeof(kMatExpandGTag) - 1, th);
        const uint256 seed_h = DeriveTaggedSeed(kMatExpandHTag, sizeof(kMatExpandHTag) - 1, th);
        const uint256 seed_wa = DeriveTaggedSeed(kMatExpandWATag, sizeof(kMatExpandWATag) - 1, th);
        const auto [seed_u, seed_v] = matmul::v4::lt::DeriveProjectorSeedsBMX4CLT(tmpl);

        const std::vector<int8_t> G = bx::ExpandProjectorBMX4C(seed_g, n, n);
        const std::vector<int8_t> H = bx::ExpandProjectorBMX4C(seed_h, w, n);
        const std::vector<int8_t> W_a = bx::ExpandProjectorBMX4C(seed_wa, n, w);
        const std::vector<int8_t> U = bx::ExpandProjectorBMX4C(seed_u, m, n);
        const std::vector<int8_t> V = bx::ExpandProjectorBMX4C(seed_v, n, m);

        const size_t nn = static_cast<size_t>(n) * n;
        const size_t nw = static_cast<size_t>(n) * w;
        const size_t wn = static_cast<size_t>(w) * n;
        const size_t mn = static_cast<size_t>(m) * n;
        const size_t nm = static_cast<size_t>(n) * m;

        if (cudaMemcpyAsync(dG, G.data(), nn, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;
        if (cudaMemcpyAsync(dH, H.data(), wn, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;
        if (cudaMemcpyAsync(dW, W_a.data(), nw, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;
        if (cudaMemcpyAsync(dU, U.data(), mn, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;
        if (cudaMemcpyAsync(dV, V.data(), nm, cudaMemcpyHostToDevice, stream) != cudaSuccess) return false;

        imma_s8s8 = want_imma;
        if (imma_s8s8) {
            ReleaseGraphs();
            if (!LaunchMatExpandImma()) {
                imma_s8s8 = false;
                if (!CaptureGraphsScalar()) return false;
                if (cudaGraphLaunch(matexpand_exec, stream) != cudaSuccess) return false;
            }
        } else {
            if (!CaptureGraphsScalar()) return false;
            if (cudaGraphLaunch(matexpand_exec, stream) != cudaSuccess) return false;
        }

        const uint256 prf_a = matmul::v4::lt::DeriveMatExpandPrfKey(seed_wa);
        if (!LaunchMxExtract(dAhat, nullptr, nullptr, prf_a)) return false;

        if (imma_s8s8) {
            if (!LaunchProjectLeftImma()) {
                imma_s8s8 = false;
                const dim3 block(16, 16, 1);
                const dim3 grid_p((n + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
                DeviceGemmS8S8Tiled<<<grid_p, block, 0, stream>>>(dU, dAhat, dP, (int)m, (int)n, (int)n);
                if (cudaGetLastError() != cudaSuccess) return false;
                if (!graphs_ready && !CaptureGraphsScalar()) return false;
            }
        } else {
            const dim3 block(16, 16, 1);
            const dim3 grid_p((n + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
            DeviceGemmS8S8Tiled<<<grid_p, block, 0, stream>>>(dU, dAhat, dP, (int)m, (int)n, (int)n);
            if (cudaGetLastError() != cudaSuccess) return false;
        }
        if (cudaStreamSynchronize(stream) != cudaSuccess) return false;
        template_hash = th;
        template_bound = true;
        return true;
    }

    [[nodiscard]] bool EnqueueOneHeader(const CBlockHeader& header, int* status)
    {
        if (!template_bound) return false;
        if (!imma_s8s8 && !graphs_ready) return false;
        if (matmul::v4::ComputeTemplateHash(header) != template_hash) return false;

        const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);
        const uint256 seed_w = DeriveTaggedSeed(kMatExpandWTag, sizeof(kMatExpandWTag) - 1, header_hash);
        if (!LaunchDeviceW(seed_w, status)) return false;

        if (imma_s8s8) {
            if (!LaunchMatExpandImma()) return false;
        } else {
            if (cudaGraphLaunch(matexpand_exec, stream) != cudaSuccess) return false;
        }

        const uint256 prf = matmul::v4::lt::DeriveMatExpandPrfKey(seed_w);
        // Production default: extract MX components and project via exact
        // scale-partitioned INT8. Dense dequant + single GEMM only when forced
        // or when the MX buffers were not allocated.
        const bool use_mx = mx_partitioned && dScales != nullptr;
        if (use_mx) {
            if (!LaunchMxExtract(nullptr, dBhat, dScales, prf)) return false;
        } else {
            if (!LaunchMxExtract(dBhat, nullptr, nullptr, prf)) return false;
        }

        if (use_mx) {
            if (!LaunchProjectRightMxExact()) return false;
            used_exact_mx_this_batch = true;
            mx_prov.exact_mx_scale_partitioned = true;
        } else if (imma_s8s8) {
            if (!LaunchProjectRightDenseImma()) return false;
        } else {
            if (cudaGraphLaunch(project_right_exec, stream) != cudaSuccess) return false;
        }

        if (imma_s8s8) {
            if (!LaunchCombineImma()) return false;
        } else {
            const dim3 block(16, 16, 1);
            const dim3 grid_c((m + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
            DeviceCombineModQ<<<grid_c, block, 0, stream>>>(dP, dQ, dChat, (int)n, (int)m);
            if (cudaGetLastError() != cudaSuccess) return false;
        }

        return true;
    }
};

LtCudaResidentPool& Pool()
{
    static LtCudaResidentPool pool;
    return pool;
}

[[nodiscard]] bool CudaOkLaunchGemmS8S8(const std::vector<int8_t>& left,
                                        const std::vector<int8_t>& right,
                                        uint32_t rows, uint32_t k, uint32_t cols,
                                        std::vector<int32_t>& out)
{
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }
    const size_t lhs_bytes = static_cast<size_t>(rows) * k * sizeof(int8_t);
    const size_t rhs_bytes = static_cast<size_t>(k) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);

    auto& pool = Pool();
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.EnsureScratch(lhs_bytes, rhs_bytes, 0, out_bytes)) return false;
    if (cudaMemcpy(pool.dGemmS8L, left.data(), lhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) {
        return false;
    }
    if (cudaMemcpy(pool.dGemmS8R, right.data(), rhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) {
        return false;
    }

    const dim3 block(16, 16, 1);
    const dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y, 1);
    DeviceGemmS8S8Tiled<<<grid, block>>>(pool.dGemmS8L, pool.dGemmS8R, pool.dGemmOut,
                                         static_cast<int>(rows), static_cast<int>(cols),
                                         static_cast<int>(k));
    if (cudaGetLastError() != cudaSuccess) return false;
    if (cudaDeviceSynchronize() != cudaSuccess) return false;

    out.assign(static_cast<size_t>(rows) * cols, 0);
    return cudaMemcpy(out.data(), pool.dGemmOut, out_bytes, cudaMemcpyDeviceToHost) == cudaSuccess;
}

[[nodiscard]] bool CudaOkLaunchGemmS32S8(const std::vector<int32_t>& left,
                                         const std::vector<int8_t>& right,
                                         uint32_t rows, uint32_t k, uint32_t cols,
                                         std::vector<int32_t>& out)
{
    if (rows == 0 || k == 0 || cols == 0) { out.clear(); return true; }
    const size_t lhs_bytes = static_cast<size_t>(rows) * k * sizeof(int32_t);
    const size_t rhs_bytes = static_cast<size_t>(k) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);

    auto& pool = Pool();
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.EnsureScratch(0, rhs_bytes, lhs_bytes, out_bytes)) return false;
    if (cudaMemcpy(pool.dGemmS32L, left.data(), lhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) {
        return false;
    }
    if (cudaMemcpy(pool.dGemmS8R, right.data(), rhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) {
        return false;
    }

    const dim3 block(16, 16, 1);
    const dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y, 1);
    DeviceGemmS32S8Tiled<<<grid, block>>>(pool.dGemmS32L, pool.dGemmS8R, pool.dGemmOut,
                                          static_cast<int>(rows), static_cast<int>(cols),
                                          static_cast<int>(k));
    if (cudaGetLastError() != cudaSuccess) return false;
    if (cudaDeviceSynchronize() != cudaSuccess) return false;

    out.assign(static_cast<size_t>(rows) * cols, 0);
    return cudaMemcpy(out.data(), pool.dGemmOut, out_bytes, cudaMemcpyDeviceToHost) == cudaSuccess;
}

thread_local bool g_lt_device_gemm_failed = false;
thread_local bool g_lt_last_s8s8_imma = false;

bool BackendGemmS8S8(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                     uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (TryLaunchLtImmaGemmS8S8(L, R, rows, inner, cols, out)) {
        g_lt_last_s8s8_imma = true;
        return true;
    }
    g_lt_last_s8s8_imma = false;
    if (CudaOkLaunchGemmS8S8(L, R, rows, inner, cols, out)) return true;
    g_lt_device_gemm_failed = true;
    return false;
}

bool BackendGemmS32S8(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                      uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (TryLaunchLtImmaGemmS32S8(L, R, rows, inner, cols, out)) return true;
    if (CudaOkLaunchGemmS32S8(L, R, rows, inner, cols, out)) return true;
    g_lt_device_gemm_failed = true;
    return false;
}

[[nodiscard]] bool SelfTestGemmKernelsOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        constexpr uint32_t kDim = 24;
        std::vector<int8_t> left(static_cast<size_t>(kDim) * kDim);
        std::vector<int8_t> right(static_cast<size_t>(kDim) * kDim);
        std::vector<int32_t> mid(static_cast<size_t>(kDim) * kDim);
        for (uint32_t i = 0; i < kDim * kDim; ++i) {
            left[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 7 - 101);
            right[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 11 + 53);
            mid[i] = static_cast<int32_t>(left[i]) * 997 - 12345;
        }

        const std::vector<int32_t> cpu_s8s8 = matmul::v4::lt::ExactGemmS8S8(left, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu_s8s8;
        bool s8_ok = false;
        if (IsLtImmaGemmAvailable()) {
            s8_ok = TryLaunchLtImmaGemmS8S8(left, right, kDim, kDim, kDim, gpu_s8s8) && gpu_s8s8 == cpu_s8s8;
        }
        if (!s8_ok) {
            if (!CudaOkLaunchGemmS8S8(left, right, kDim, kDim, kDim, gpu_s8s8) || gpu_s8s8 != cpu_s8s8) {
                return;
            }
        }

        const std::vector<int32_t> cpu_s32s8 = matmul::v4::lt::ExactGemmS32S8(mid, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu_s32s8;
        if (!CudaOkLaunchGemmS32S8(mid, right, kDim, kDim, kDim, gpu_s32s8) || gpu_s32s8 != cpu_s32s8) {
            return;
        }

        // Exact MX scale-partitioned B̂·V vs CPU oracle on n multiple of 32.
        {
            constexpr uint32_t kMxN = 32;
            constexpr uint32_t kMxM = 16;
            const uint32_t nblk = kMxN / matmul::v4::lt::kMatExpandMxBlockLen;
            std::vector<int8_t> mu(static_cast<size_t>(kMxN) * kMxN);
            std::vector<uint8_t> scales(static_cast<size_t>(kMxN) * nblk);
            std::vector<int8_t> V(static_cast<size_t>(kMxN) * kMxM);
            for (uint32_t i = 0; i < kMxN * kMxN; ++i) {
                static constexpr int8_t kM11[] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
                mu[i] = kM11[i % 11];
            }
            for (uint32_t i = 0; i < kMxN * nblk; ++i) {
                scales[i] = static_cast<uint8_t>(i & 3U);
            }
            for (uint32_t i = 0; i < kMxN * kMxM; ++i) {
                V[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 3 - 17);
            }
            // Native lanes may succeed only when globally self-qualified and
            // oracle-identical. A qualified claim without oracle match aborts.
            {
                std::vector<int32_t> native_out;
                matmul::v4::lt::MxLaneProvenance native_prov{};
                if (TryLaunchNativeMxfp4ProjectedRight(mu, scales, V, kMxN, kMxM, native_out,
                                                       &native_prov)) {
                    if (!native_prov.native_mxfp4_qualified ||
                        !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, kMxN, kMxM,
                                                                      native_out)) {
                        return;
                    }
                } else if (native_prov.native_mxfp4_qualified) {
                    return;
                }
                native_out.clear();
                native_prov = {};
                if (TryLaunchNativeFp8ProjectedRight(mu, scales, V, kMxN, kMxM, native_out,
                                                     &native_prov)) {
                    if (!native_prov.native_fp8_qualified ||
                        !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, kMxN, kMxM,
                                                                      native_out)) {
                        return;
                    }
                } else if (native_prov.native_fp8_qualified) {
                    return;
                }
            }
            matmul::v4::lt::ExactGemmBackend gemm;
            gemm.gemm_s8s8 = &BackendGemmS8S8;
            gemm.gemm_s32s8 = &BackendGemmS32S8;
            const auto partitioned =
                matmul::v4::lt::ComputeProjectedRightMxScalePartitionedGemmLT(
                    mu, scales, V, kMxN, kMxM, gemm);
            if (partitioned.empty() ||
                !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, kMxN, kMxM,
                                                              partitioned)) {
                return;
            }
            std::vector<int32_t> launched;
            matmul::v4::lt::MxLaneProvenance mx_prov{};
            if (!LaunchProjectedRightMx(mu, scales, V, kMxN, kMxM, launched, &mx_prov) ||
                !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, kMxN, kMxM,
                                                              launched) ||
                !HasQualifiedLtCudaMxProjectionLane(mx_prov)) {
                return;
            }
        }

        // Full-pipeline bit-identity: a real two-header batch with distinct
        // nonce-bound seeds. This catches the legacy template+nonce bug as
        // well as device W-XOF, Chat SHA256d, and batch ordering drift.
        constexpr uint32_t kN = 64;
        uint32_t m = 0;
        if (!matmul::v4::lt::ValidateDimsBMX4CLT(kN, m)) return;

        CBlockHeader header;
        header.nVersion = 0x20000004;
        header.nTime = 1'770'000'000;
        header.nBits = 0x207fffff;
        header.nNonce64 = 42;
        header.nNonce = 42;
        header.matmul_dim = static_cast<uint16_t>(kN);
        // Distinct non-zero seeds so DeriveSigma / projectors are well-defined.
        for (int i = 0; i < 32; ++i) {
            header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
            header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
            header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
            header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
        }

        std::array<CBlockHeader, 2> headers{header, header};
        headers[1].nNonce64 = 43;
        headers[1].nNonce = 43;
        for (int i = 0; i < 32; ++i) {
            headers[1].seed_a.data()[i] = static_cast<unsigned char>(0x33 + (i & 7));
            headers[1].seed_b.data()[i] = static_cast<unsigned char>(0x44 + (i & 7));
        }
        std::array<uint256, 2> cpu_digests{};
        for (size_t i = 0; i < headers.size(); ++i) {
            std::vector<unsigned char> cpu_payload;
            if (!matmul::v4::lt::ComputeDigestBMX4CLT(
                    headers[i], kN, cpu_digests[i], cpu_payload)) {
                return;
            }
        }

        auto& pool = Pool();
        std::lock_guard<std::mutex> lock(pool.mu);
        if (!pool.BindTemplate(header, kN, m) ||
            !pool.EnsureBatchCapacity(headers.size())) {
            if (pool.stream != nullptr) (void)cudaStreamSynchronize(pool.stream);
            return;
        }
        auto drain = [&]() {
            if (pool.stream != nullptr) (void)cudaStreamSynchronize(pool.stream);
        };
        std::array<std::array<unsigned char, kDigestBytes>, 2> sigmas{};
        for (size_t i = 0; i < headers.size(); ++i) {
            const uint256 sigma = matmul::v4::DeriveSigma(headers[i]);
            std::copy(sigma.data(), sigma.data() + kDigestBytes, sigmas[i].begin());
        }
        const size_t chat_words = static_cast<size_t>(m) * m;
        if (cudaMemcpyAsync(pool.dBatchSigmas, sigmas.data(), sizeof(sigmas),
                            cudaMemcpyHostToDevice, pool.stream) != cudaSuccess) {
            drain();
            return;
        }
        for (size_t i = 0; i < headers.size(); ++i) {
            if (!pool.EnqueueOneHeader(headers[i], pool.dBatchStatus + i) ||
                cudaMemcpyAsync(pool.dChatBatch + i * chat_words, pool.dChat,
                                chat_words * sizeof(uint64_t), cudaMemcpyDeviceToDevice,
                                pool.stream) != cudaSuccess) {
                drain();
                return;
            }
        }
        if (!pool.LaunchDeviceDigestBatch(headers.size(), pool.dBatchSigmas,
                                          pool.dBatchDigests)) {
            drain();
            return;
        }
        std::array<std::array<unsigned char, kDigestBytes>, 2> digest_bytes{};
        std::array<int, 2> device_status{};
        if (cudaMemcpyAsync(digest_bytes.data(), pool.dBatchDigests, sizeof(digest_bytes),
                            cudaMemcpyDeviceToHost, pool.stream) != cudaSuccess ||
            cudaMemcpyAsync(device_status.data(), pool.dBatchStatus, sizeof(device_status),
                            cudaMemcpyDeviceToHost, pool.stream) != cudaSuccess ||
            cudaStreamSynchronize(pool.stream) != cudaSuccess) {
            drain();
            return;
        }
        for (size_t i = 0; i < headers.size(); ++i) {
            if (device_status[i] != 1 ||
                uint256{Span<const unsigned char>{digest_bytes[i].data(), kDigestBytes}} !=
                    cpu_digests[i]) {
                return;
            }
        }

        ok = true;
        g_lt_exact_mx_selftest_ok = true;
    });
    return ok;
}

[[nodiscard]] bool MineDeviceResident(const std::vector<CBlockHeader>& headers,
                                      uint32_t n, uint32_t m,
                                      std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
                                      size_t max_chat_chunk_slots =
                                          std::numeric_limits<size_t>::max(),
                                      size_t* chunks_out = nullptr)
{
    if (chunks_out != nullptr) *chunks_out = 0;
    // Bound every allocation before EnsureBatchCapacity. A vector larger than
    // consensus Q* is malformed for this ABI and must fail closed.
    if (headers.empty() || headers.size() > kMaxConsensusBatch) return false;
    // Peak-performance default: Blackwell must run qualified native MXFP4/FP8.
    // Without it, decline resident GPU LT (host ExactGemm fallback) so operators
    // cannot silently ship sub-peak INT8 rates as silicon evidence.
    if (LtPeakMxBlocksDeviceResident()) {
        return false;
    }
    auto& pool = Pool();
    std::lock_guard<std::mutex> lock(pool.mu);
    pool.used_exact_mx_this_batch = false;
    pool.mx_prov = {};
    if (!pool.BindTemplate(headers.front(), n, m) ||
        !pool.EnsureBatchCapacity(headers.size())) {
        if (pool.stream != nullptr) (void)cudaStreamSynchronize(pool.stream);
        return false;
    }
    auto drain_and_fail = [&]() {
        // A declined enqueue may leave earlier kernels/copies in the nonblocking
        // pool stream. Drain them before host fallback reuses pool scratch on
        // the default stream; this is a failure-only synchronization.
        if (pool.stream != nullptr) (void)cudaStreamSynchronize(pool.stream);
        out.clear();
        return false;
    };

    std::vector<std::array<unsigned char, kDigestBytes>> sigma_bytes(headers.size());
    for (size_t i = 0; i < headers.size(); ++i) {
        const uint256 sigma = matmul::v4::DeriveSigma(headers[i]);
        std::copy(sigma.data(), sigma.data() + kDigestBytes, sigma_bytes[i].begin());
    }
    if (cudaMemcpyAsync(pool.dBatchSigmas, sigma_bytes.data(),
                        headers.size() * kDigestBytes, cudaMemcpyHostToDevice,
                        pool.stream) != cudaSuccess) {
        return drain_and_fail();
    }

    const size_t chat_words = static_cast<size_t>(m) * m;
    const size_t chat_bytes = chat_words * sizeof(uint64_t);
    const size_t chat_chunk_slots = std::min(pool.chat_batch_slots, max_chat_chunk_slots);
    if (chat_chunk_slots == 0) return drain_and_fail();
    size_t completed_chunks = 0;
    for (size_t base = 0; base < headers.size(); base += chat_chunk_slots) {
        const size_t chunk = std::min(chat_chunk_slots, headers.size() - base);
        for (size_t slot = 0; slot < chunk; ++slot) {
            const size_t i = base + slot;
            if (!pool.EnqueueOneHeader(headers[i], pool.dBatchStatus + i) ||
                cudaMemcpyAsync(pool.dChatBatch + slot * chat_words, pool.dChat, chat_bytes,
                                cudaMemcpyDeviceToDevice, pool.stream) != cudaSuccess) {
                return drain_and_fail();
            }
        }
        if (!pool.LaunchDeviceDigestBatch(
                chunk, pool.dBatchSigmas + base * kDigestBytes,
                pool.dBatchDigests + base * kDigestBytes)) {
            return drain_and_fail();
        }
        ++completed_chunks;
    }

    std::vector<std::array<unsigned char, kDigestBytes>> digest_bytes(headers.size());
    std::vector<int> status(headers.size(), 0);
    if (cudaMemcpyAsync(digest_bytes.data(), pool.dBatchDigests,
                        headers.size() * kDigestBytes, cudaMemcpyDeviceToHost,
                        pool.stream) != cudaSuccess ||
        cudaMemcpyAsync(status.data(), pool.dBatchStatus,
                        headers.size() * sizeof(int), cudaMemcpyDeviceToHost,
                        pool.stream) != cudaSuccess ||
        cudaStreamSynchronize(pool.stream) != cudaSuccess) {
        return drain_and_fail();
    }

    out.resize(headers.size());
    for (size_t i = 0; i < headers.size(); ++i) {
        if (status[i] != 1) {
            return drain_and_fail();
        }
        out[i].nonce = headers[i].nNonce64;
        out[i].digest = uint256{Span<const unsigned char>{
            digest_bytes[i].data(), digest_bytes[i].size()}};
        out[i].target_match = false;
        out[i].backend_status = matmul::v4::bmx4::DigestOnlyBackendStatus::Ok;
    }
    g_lt_last_mx_prov = pool.mx_prov;
    g_lt_last_mx_prov.exact_mx_scale_partitioned = pool.used_exact_mx_this_batch;
    if (chunks_out != nullptr) *chunks_out = completed_chunks;
    return true;
}

[[nodiscard]] bool MineHostExactFallback(const std::vector<CBlockHeader>& headers,
                                         uint32_t n,
                                         bool try_device_gemms,
                                         std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    if (headers.empty()) return false;
    matmul::v4::lt::ExactGemmBackend backend;
    matmul::v4::lt::ExactMxProjectionBackend mx_proj;
    if (try_device_gemms) {
        backend.gemm_s8s8 = &BackendGemmS8S8;
        backend.gemm_s32s8 = &BackendGemmS32S8;
        mx_proj.project_right = &LaunchProjectedRightMx;
    }
    g_lt_device_gemm_failed = false;

    matmul::v4::lt::WindowSketchMinerLT miner(headers.front(), n, backend, mx_proj);
    if (!miner.Valid()) return false;

    const uint256 kNoTarget = ArithToUint256(~arith_uint256{});
    std::vector<matmul::v4::lt::DigestOnlyResultLT> results;
    if (!miner.MineWindow(headers, kNoTarget, results)) return false;

    const bool device_served =
        try_device_gemms && miner.UsingDeviceGemms() && !g_lt_device_gemm_failed;
    const auto status = device_served
                            ? matmul::v4::bmx4::DigestOnlyBackendStatus::Ok
                            : matmul::v4::bmx4::DigestOnlyBackendStatus::Fallback;
    for (auto& r : results) {
        r.target_match = false;
        r.backend_status = status;
    }
    out = std::move(results);
    return true;
}

} // namespace

bool LaunchGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                    uint32_t rows, uint32_t k, uint32_t cols,
                    std::vector<int32_t>& out)
{
    if (TryLaunchLtImmaGemmS8S8(left, right, rows, k, cols, out)) {
        g_lt_last_s8s8_imma = true;
        return true;
    }
    g_lt_last_s8s8_imma = false;
    return CudaOkLaunchGemmS8S8(left, right, rows, k, cols, out);
}

bool LaunchGemmS32S8(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
                     uint32_t rows, uint32_t k, uint32_t cols,
                     std::vector<int32_t>& out)
{
    if (TryLaunchLtImmaGemmS32S8(left, right, rows, k, cols, out)) {
        return true;
    }
    return CudaOkLaunchGemmS32S8(left, right, rows, k, cols, out);
}

bool IsMatMulLTCudaAvailable()
{
    const btx::cuda::CudaRuntimeProbe probe = btx::cuda::ProbeCudaRuntime();
    if (!probe.compiled || !probe.available) {
        return false;
    }
    // Always emit peak-path diagnostics once when CUDA is present, even if
    // ExactGemm self-test later declines (operators must see PEAK DEFICIT).
    DiagnoseLtPeakMxPathOnce();
    return SelfTestGemmKernelsOnce();
}

bool ComputeDigestsOnlyLTCuda(const CBlockHeader& tmpl, uint32_t n,
                              const uint64_t* nonces, size_t count,
                              std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    if (nonces == nullptr || count == 0) {
        return false;
    }

    std::vector<CBlockHeader> headers(count, tmpl);
    for (size_t i = 0; i < count; ++i) {
        headers[i].nNonce64 = nonces[i];
        headers[i].nNonce = static_cast<uint32_t>(nonces[i]);
    }
    return ComputeDigestsOnlyLTCuda(headers, n, out, nullptr);
}

bool ComputeDigestsOnlyLTCuda(
    const std::vector<CBlockHeader>& headers, uint32_t n,
    std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
    LtCudaBatchProvenance* provenance)
{
    out.clear();
    if (provenance != nullptr) *provenance = {};
    // Keep the hard bound at the public boundary too: an oversized request
    // must not silently turn into the host ExactGemm fallback after the
    // resident path declines it.
    if (headers.empty() || headers.size() > kMaxConsensusBatch) return false;

    uint32_t m = 0;
    if (!matmul::v4::lt::ValidateDimsBMX4CLT(n, m)) return false;
    const uint256 template_hash = matmul::v4::ComputeTemplateHash(headers.front());
    if (!std::all_of(headers.begin(), headers.end(), [&](const CBlockHeader& header) {
            return matmul::v4::ComputeTemplateHash(header) == template_hash;
        })) {
        return false;
    }

    // Prefer the persistent device-resident MatExpand→project→combine loop
    // over the complete consensus-seeded candidate vector. The resident path
    // does not materialize Q*m^2 Chat storage: each Chat is hashed before its
    // working buffer is reused, and all digest/status records cross at the
    // completion boundary.
    // Host ExactGemm / WindowSketchMinerLT is fail-closed fallback only.
    if (IsMatMulLTCudaAvailable()) {
        if (MineDeviceResident(headers, n, m, out)) {
            if (provenance != nullptr) {
                provenance->qstar_device_batched = headers.size() > 1;
                provenance->device_w_generation = true;
                provenance->device_digest = true;
                provenance->per_nonce_sync_absent = true;
                provenance->mx = g_lt_last_mx_prov;
            }
            return true;
        }
        // Device-resident path declined at runtime: fall back to host ExactGemm
        // (optionally still using per-call device GEMMs via ExactGemmBackend).
        return MineHostExactFallback(headers, n, /*try_device_gemms=*/true, out);
    }

    return MineHostExactFallback(headers, n, /*try_device_gemms=*/false, out);
}

bool RunMatMulLTCudaExtendedSelfTest(std::string& error)
{
    error.clear();
    if (!SelfTestGemmKernelsOnce()) {
        error = "baseline CUDA LT self-test declined";
        return false;
    }

    auto make_header = [](uint32_t n, uint64_t nonce, unsigned char salt) {
        CBlockHeader header;
        header.nVersion = 0x20000004;
        header.nTime = 1'770'000'123;
        header.nBits = 0x207fffff;
        header.nNonce64 = nonce;
        header.nNonce = static_cast<uint32_t>(nonce);
        header.matmul_dim = static_cast<uint16_t>(n);
        for (size_t i = 0; i < uint256::size(); ++i) {
            // Template fields remain identical across a batch. The two seeds
            // deliberately vary with the nonce to exercise the full-header
            // device W/projector path instead of the legacy template+nonce ABI.
            header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51U + (i & 3U));
            header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3U - (i & 3U));
            header.seed_a.data()[i] = static_cast<unsigned char>(salt + (i & 7U));
            header.seed_b.data()[i] = static_cast<unsigned char>(salt + 0x31U + (i & 7U));
        }
        return header;
    };

    auto compare_resident = [&](const std::vector<CBlockHeader>& headers,
                                uint32_t n, size_t forced_chat_slots,
                                size_t minimum_chunks, const char* label) {
        uint32_t m = 0;
        if (!matmul::v4::lt::ValidateDimsBMX4CLT(n, m)) {
            error = std::string{label} + ": invalid dimensions";
            return false;
        }

        std::vector<uint256> cpu_digests(headers.size());
        for (size_t i = 0; i < headers.size(); ++i) {
            std::vector<unsigned char> cpu_payload;
            if (!matmul::v4::lt::ComputeDigestBMX4CLT(
                    headers[i], n, cpu_digests[i], cpu_payload)) {
                error = std::string{label} + ": CPU reference declined";
                return false;
            }
        }

        std::vector<matmul::v4::lt::DigestOnlyResultLT> device_results;
        size_t chunks = 0;
        if (!MineDeviceResident(headers, n, m, device_results,
                                forced_chat_slots, &chunks)) {
            error = std::string{label} + ": resident CUDA path declined";
            return false;
        }
        if (chunks < minimum_chunks) {
            error = std::string{label} + ": bounded Chat staging did not roll over";
            return false;
        }
        if (device_results.size() != cpu_digests.size()) {
            error = std::string{label} + ": result count mismatch";
            return false;
        }
        for (size_t i = 0; i < device_results.size(); ++i) {
            if (device_results[i].backend_status !=
                    matmul::v4::bmx4::DigestOnlyBackendStatus::Ok ||
                device_results[i].digest != cpu_digests[i]) {
                error = std::string{label} + ": CPU/CUDA digest mismatch at candidate " +
                    std::to_string(i);
                return false;
            }
        }
        return true;
    };

    // Keep the production differential deliberately small. Two n=4096 CPU
    // references are already expensive enough that this check must remain an
    // explicit release/silicon qualification step, never a startup gate.
    constexpr uint32_t kProductionN = 4096;
    const std::vector<CBlockHeader> production_headers{
        make_header(kProductionN, 0x409600000001ULL, 0x19),
        make_header(kProductionN, 0x409600000002ULL, 0x2b)};
    if (!compare_resident(production_headers, kProductionN,
                          std::numeric_limits<size_t>::max(), 1,
                          "production n=4096 differential")) {
        return false;
    }

    // Independently force three complete nonce-bound headers through a two-Chat
    // staging window. This deterministically crosses the chunk rollover even on
    // devices with enough memory to stage the whole small test batch at once.
    constexpr uint32_t kRolloverN = 64;
    std::vector<CBlockHeader> rollover_headers;
    for (size_t i = 0; i < 3; ++i) {
        rollover_headers.push_back(make_header(
            kRolloverN, 0x6400000000ULL + i, static_cast<unsigned char>(0x40U + i * 9U)));
    }
    if (!compare_resident(rollover_headers, kRolloverN,
                          /*forced_chat_slots=*/2, /*minimum_chunks=*/2,
                          "forced multi-Chat rollover")) {
        return false;
    }

    return true;
}

bool LtLastS8S8UsedImma()
{
    return g_lt_last_s8s8_imma;
}

matmul::v4::lt::MxLaneProvenance LtLastMxProvenance()
{
    return g_lt_last_mx_prov;
}

bool IsLtExactMxScalePartitionedAvailable()
{
    return IsMatMulLTCudaAvailable() && g_lt_exact_mx_selftest_ok;
}

bool LaunchProjectedRightMx(const std::vector<int8_t>& mu,
                            const std::vector<uint8_t>& scales,
                            const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                            std::vector<int32_t>& out,
                            matmul::v4::lt::MxLaneProvenance* provenance)
{
    matmul::v4::lt::MxLaneProvenance local{};
    out.clear();
    if (n == 0 || m == 0 || (n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) {
        if (provenance) *provenance = local;
        g_lt_last_mx_prov = local;
        return false;
    }
    const uint32_t nblk = n / matmul::v4::lt::kMatExpandMxBlockLen;
    if (mu.size() != static_cast<size_t>(n) * n ||
        scales.size() != static_cast<size_t>(n) * nblk ||
        V.size() != static_cast<size_t>(n) * m) {
        if (provenance) *provenance = local;
        g_lt_last_mx_prov = local;
        return false;
    }

    // Prefer a qualified native path; otherwise exact INT8 scale partitions
    // only when peak policy allows (non-Blackwell, or ALLOW_EXACT_MX_FALLBACK).
    if (TryLaunchNativeMxfp4ProjectedRight(mu, scales, V, n, m, out, &local) &&
        matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
        local.native_mxfp4_qualified = true;
        local.exact_mx_scale_partitioned = false;
        if (provenance) *provenance = local;
        g_lt_last_mx_prov = local;
        return true;
    }
    local = {};
    if (TryLaunchNativeFp8ProjectedRight(mu, scales, V, n, m, out, &local) &&
        matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
        local.native_fp8_qualified = true;
        local.exact_mx_scale_partitioned = false;
        if (provenance) *provenance = local;
        g_lt_last_mx_prov = local;
        return true;
    }
    local = {};

    if (LtPeakMxBlocksDeviceResident()) {
        // Peak-capable + native unqualified + no fallback escape → decline.
        if (provenance) *provenance = local;
        g_lt_last_mx_prov = local;
        out.clear();
        return false;
    }

    matmul::v4::lt::ExactGemmBackend gemm;
    gemm.gemm_s8s8 = &LaunchGemmS8S8;
    gemm.gemm_s32s8 = &LaunchGemmS32S8;
    out = matmul::v4::lt::ComputeProjectedRightMxScalePartitionedGemmLT(mu, scales, V, n, m, gemm);
    if (out.empty() ||
        !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
        out = matmul::v4::lt::ComputeProjectedRightMxBlockScaleLT(mu, scales, V, n, m);
    }
    local.exact_mx_scale_partitioned = true;
    if (provenance) *provenance = local;
    g_lt_last_mx_prov = local;
    return !out.empty();
}

} // namespace matmul_v4::cuda
