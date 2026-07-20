// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_lt_accel.h>

#include <arith_uint256.h>
#include <cuda/matmul_v4_lt_device_mx.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/int8_field.h>
#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_lt_mx_exact.h>
#include <primitives/block.h>
#include <span.h>
#include <uint256.h>

#include <hip/hip_runtime.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

// ===========================================================================
// AMD ROCm/HIP backend for MatMul v4.4 ENC-DR-LT (MatExpand).
//
// Hot path: persistent device-resident MatExpand→Extract→project→combine.
//   B̂·V production default is exact MX scale-partitioned INT8 (four exponent
//   planes × MFMA/ALU + exact 2^e accumulate), bit-identical to
//   ComputeProjectedRightMxBlockScaleLT. Dense dequantized Bhat GEMM is the
//   fail-closed fallback (opt-in via BTX_MATMUL_V4_LT_DENSE_BHAT=1).
//   Native hipBLASLt/CDNA4 MXFP4/FP8 is attempted only behind self-qual vs the
//   CPU MX oracle; unqualified attempts never set native_*_qualified.
//   Y*H uses four radix-256 products and F_q combine uses nine Karatsuba/
//   base-64 products. These are exact signed-byte MFMA lowerings, never
//   mislabeled as native MXFP4 or s32xs8 instructions.
// Host ExactGemm / WindowSketchMinerLT is fail-closed fallback only.
// Target: gfx942 (MI300) / gfx950 (MI350/MI355) via BTX_HIP_ARCHITECTURES.
// ===========================================================================

namespace matmul_v4::hip {

namespace {

constexpr size_t kMaxConsensusBatch = matmul::v4::lt::kConsensusQStarMax;

constexpr char kMatExpandGTag[] = "BTX_MATEXPAND_G_V44LT";
constexpr char kMatExpandHTag[] = "BTX_MATEXPAND_H_V44LT";
constexpr char kMatExpandWTag[] = "BTX_MATEXPAND_W_V44LT";
constexpr char kMatExpandWATag[] = "BTX_MATEXPAND_WA_V44LT";
constexpr size_t kDigestRingSlots = 8;

// Opt-out of the production exact-MX partitioned projection (benchmark /
// A-B only). Default is scale-partitioned exact INT8.
bool DenseBhatProjectionForced()
{
    const char* value = std::getenv("BTX_MATMUL_V4_LT_DENSE_BHAT");
    return value != nullptr &&
           (std::strcmp(value, "1") == 0 || std::strcmp(value, "true") == 0 ||
            std::strcmp(value, "yes") == 0);
}

// Process-local MX honesty snapshot updated by LaunchProjectedRightMx /
// resident enqueue. Native flags live in matmul_v4_lt_mx_native.hip.
thread_local matmul::v4::lt::MxLaneProvenance g_lt_last_mx_provenance{};

uint256 DeriveTaggedSeed(const char* tag, size_t taglen, const uint256& hash)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    hasher.Write(hash.data(), uint256::size());
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

void Bmx4SeedStreamWords(const uint256& seed, uint32_t (&words)[8])
{
    // ExpandMantissaStream hashes SeedBytesLE(seed), which is the reverse of
    // uint256::data(). Pack that exact byte sequence for the device XOF.
    for (uint32_t w = 0; w < 8; ++w) {
        words[w] = 0;
        for (uint32_t p = 0; p < 4; ++p) {
            words[w] |= static_cast<uint32_t>(seed.data()[31U - (w * 4U + p)]) << (8U * p);
        }
    }
}

__global__ void DeviceGemmS8S8Tiled(const int8_t* __restrict__ A,
                                    const int8_t* __restrict__ B,
                                    int32_t* __restrict__ D,
                                    int M, int N, int K)
{
    __shared__ int8_t tile_a[16][16];
    __shared__ int8_t tile_b[16][16];
    const int col = blockIdx.x * blockDim.x + threadIdx.x;
    const int row = blockIdx.y * blockDim.y + threadIdx.y;
    int32_t acc = 0;
    for (int base = 0; base < K; base += 16) {
        const int ak = base + threadIdx.x;
        const int bk = base + threadIdx.y;
        tile_a[threadIdx.y][threadIdx.x] = (row < M && ak < K)
            ? A[static_cast<size_t>(row) * K + ak] : int8_t{0};
        tile_b[threadIdx.y][threadIdx.x] = (bk < K && col < N)
            ? B[static_cast<size_t>(bk) * N + col] : int8_t{0};
        __syncthreads();
#pragma unroll
        for (int k = 0; k < 16; ++k) {
            acc += static_cast<int32_t>(tile_a[threadIdx.y][k]) *
                   static_cast<int32_t>(tile_b[k][threadIdx.x]);
        }
        __syncthreads();
    }
    if (row < M && col < N) D[static_cast<size_t>(row) * N + col] = acc;
}

__global__ void DeviceGemmS32S8Tiled(const int32_t* __restrict__ A,
                                     const int8_t* __restrict__ B,
                                     int32_t* __restrict__ D,
                                     int M, int N, int K)
{
    __shared__ int32_t tile_a[16][16];
    __shared__ int8_t tile_b[16][16];
    const int col = blockIdx.x * blockDim.x + threadIdx.x;
    const int row = blockIdx.y * blockDim.y + threadIdx.y;
    int64_t acc = 0;
    for (int base = 0; base < K; base += 16) {
        const int ak = base + threadIdx.x;
        const int bk = base + threadIdx.y;
        tile_a[threadIdx.y][threadIdx.x] = (row < M && ak < K)
            ? A[static_cast<size_t>(row) * K + ak] : int32_t{0};
        tile_b[threadIdx.y][threadIdx.x] = (bk < K && col < N)
            ? B[static_cast<size_t>(bk) * N + col] : int8_t{0};
        __syncthreads();
#pragma unroll
        for (int k = 0; k < 16; ++k) {
            acc += static_cast<int64_t>(tile_a[threadIdx.y][k]) *
                   static_cast<int64_t>(tile_b[k][threadIdx.x]);
        }
        __syncthreads();
    }
    if (row < M && col < N) D[static_cast<size_t>(row) * N + col] = static_cast<int32_t>(acc);
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

// Compact device/host result image for a Q* batch.  The hot path never copies
// the m*m Chat field back to the host: each slot writes its SHA256d digest here
// and the whole batch is returned by one D2H transfer after all queued work.
struct alignas(4) DeviceDigestStatusLT {
    uint8_t digest[32];
    uint32_t ok;
};
static_assert(sizeof(DeviceDigestStatusLT) == 36);

__device__ __forceinline__ void DeviceBmx4MantissaBlock(
    const uint32_t seed_words[8], uint64_t counter, uint8_t digest[32])
{
    // SHA256(seed_bytes_le || 'm' || counter_LE64), exactly matching
    // ExpandMantissaStream.  The 41-byte message fits in one SHA block.
    uint32_t state[8];
    uint32_t block[16] = {};
    matmul_v4::lt_device::ShaInit(state);
#pragma unroll
    for (uint32_t p = 0; p < 32; ++p) {
        matmul_v4::lt_device::ShaSetByte(
            block, p, (seed_words[p >> 2U] >> (8U * (p & 3U))) & 0xffU);
    }
    matmul_v4::lt_device::ShaSetByte(block, 32, 0x6dU);
#pragma unroll
    for (uint32_t p = 0; p < 8; ++p) {
        matmul_v4::lt_device::ShaSetByte(block, 33 + p,
                                        (counter >> (8U * p)) & 0xffU);
    }
    matmul_v4::lt_device::ShaSetByte(block, 41, 0x80U);
    block[15] = 41U * 8U;
    matmul_v4::lt_device::ShaCompress(state, block);
#pragma unroll
    for (uint32_t w = 0; w < 8; ++w) {
        digest[w * 4 + 0] = static_cast<uint8_t>(state[w] >> 24U);
        digest[w * 4 + 1] = static_cast<uint8_t>(state[w] >> 16U);
        digest[w * 4 + 2] = static_cast<uint8_t>(state[w] >> 8U);
        digest[w * 4 + 3] = static_cast<uint8_t>(state[w]);
    }
}

__global__ void DeviceGenerateProjectorBlocks(uint8_t* __restrict__ hashes,
                                              uint8_t* __restrict__ counts,
                                              uint32_t blocks,
                                              uint32_t k0, uint32_t k1,
                                              uint32_t k2, uint32_t k3,
                                              uint32_t k4, uint32_t k5,
                                              uint32_t k6, uint32_t k7)
{
    const uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= blocks) return;
    const uint32_t seed[8] = {k0, k1, k2, k3, k4, k5, k6, k7};
    uint8_t digest[32];
    DeviceBmx4MantissaBlock(seed, idx, digest);
    uint8_t accepted_count = 0;
#pragma unroll
    for (uint32_t b = 0; b < 32; ++b) {
        hashes[static_cast<size_t>(idx) * 32 + b] = digest[b];
        bool accepted = false;
        (void)DeviceSampleMantissaNibble(digest[b] & 0x0fU, accepted);
        accepted_count += accepted ? 1U : 0U;
        (void)DeviceSampleMantissaNibble(digest[b] >> 4U, accepted);
        accepted_count += accepted ? 1U : 0U;
    }
    counts[idx] = accepted_count;
}

// A single deterministic prefix thread is intentional.  At n=4096 this is
// only ~105k byte loads/adds, small beside MatExpand, and it avoids a rocPRIM
// dependency while pinning byte order exactly to the CPU streaming oracle.
__global__ void DevicePrefixProjectorBlocks(const uint8_t* __restrict__ counts,
                                            uint32_t* __restrict__ offsets,
                                            uint32_t blocks, size_t wanted,
                                            DeviceDigestStatusLT* result)
{
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    uint32_t sum = 0;
    for (uint32_t i = 0; i < blocks; ++i) {
        offsets[i] = sum;
        sum += counts[i];
    }
    result->ok = static_cast<size_t>(sum) >= wanted ? 1U : 0U;
}

__global__ void DeviceScatterProjectorBlocks(const uint8_t* __restrict__ hashes,
                                             const uint32_t* __restrict__ offsets,
                                             uint32_t blocks, size_t wanted,
                                             const DeviceDigestStatusLT* result,
                                             int8_t* __restrict__ out)
{
    const uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= blocks || result->ok == 0) return;
    size_t pos = offsets[idx];
    const uint8_t* hash = hashes + static_cast<size_t>(idx) * 32;
#pragma unroll
    for (uint32_t b = 0; b < 32; ++b) {
        const uint8_t nibs[2] = {static_cast<uint8_t>(hash[b] & 0x0fU),
                                 static_cast<uint8_t>(hash[b] >> 4U)};
#pragma unroll
        for (uint32_t half = 0; half < 2; ++half) {
            bool accepted = false;
            const int8_t value = DeviceSampleMantissaNibble(nibs[half], accepted);
            if (accepted) {
                if (pos < wanted) out[pos] = value;
                ++pos;
            }
        }
    }
}

__global__ void DeviceDigestChatSha256d(const uint64_t* __restrict__ chat,
                                        size_t words, DeviceDigestStatusLT* result,
                                        uint32_t s0, uint32_t s1, uint32_t s2,
                                        uint32_t s3, uint32_t s4, uint32_t s5,
                                        uint32_t s6, uint32_t s7)
{
    // SHA-256's compression chain is serial for one message, so one thread
    // owns one candidate. The pool overlaps up to kDigestRingSlots independent
    // candidates on separate streams with bounded Chat staging. This removes
    // the Q*m^2 host transfer but is not a claim that digest is tensor-bound;
    // a wavefront-cooperative SHA implementation remains a silicon benchmark
    // candidate if this stage dominates.
    if (blockIdx.x != 0 || threadIdx.x != 0 || result->ok == 0) return;
    constexpr char kTag[] = "BTX_MATMUL_V4";
    constexpr size_t kTagLen = sizeof(kTag) - 1;
    const uint32_t sigma[8] = {s0, s1, s2, s3, s4, s5, s6, s7};
    const size_t message_len = kTagLen + 32 + words * sizeof(uint64_t);
    const size_t sha_blocks = (message_len + 1 + 8 + 63) / 64;
    uint32_t state[8];
    matmul_v4::lt_device::ShaInit(state);
    for (size_t bi = 0; bi < sha_blocks; ++bi) {
        uint32_t block[16] = {};
#pragma unroll
        for (uint32_t p = 0; p < 64; ++p) {
            const size_t at = bi * 64 + p;
            uint8_t byte = 0;
            bool set = false;
            if (at < kTagLen) {
                byte = static_cast<uint8_t>(kTag[at]);
                set = true;
            } else if (at < kTagLen + 32) {
                const size_t q = at - kTagLen;
                byte = static_cast<uint8_t>((sigma[q >> 2U] >> (8U * (q & 3U))) & 0xffU);
                set = true;
            } else if (at < message_len) {
                const size_t q = at - kTagLen - 32;
                byte = static_cast<uint8_t>(chat[q >> 3U] >> (8U * (q & 7U)));
                set = true;
            } else if (at == message_len) {
                byte = 0x80U;
                set = true;
            }
            if (set) matmul_v4::lt_device::ShaSetByte(block, p, byte);
        }
        if (bi + 1 == sha_blocks) {
            const uint64_t bit_len = static_cast<uint64_t>(message_len) * 8U;
            block[14] = static_cast<uint32_t>(bit_len >> 32U);
            block[15] = static_cast<uint32_t>(bit_len);
        }
        matmul_v4::lt_device::ShaCompress(state, block);
    }

    // Second SHA-256 over the 32-byte first digest.
    uint32_t inner[8];
    uint32_t block[16] = {};
    matmul_v4::lt_device::ShaInit(inner);
#pragma unroll
    for (uint32_t w = 0; w < 8; ++w) {
#pragma unroll
        for (uint32_t p = 0; p < 4; ++p) {
            matmul_v4::lt_device::ShaSetByte(
                block, w * 4 + p, (state[w] >> (24U - 8U * p)) & 0xffU);
        }
    }
    matmul_v4::lt_device::ShaSetByte(block, 32, 0x80U);
    block[15] = 32U * 8U;
    matmul_v4::lt_device::ShaCompress(inner, block);
#pragma unroll
    for (uint32_t w = 0; w < 8; ++w) {
        result->digest[w * 4 + 0] = static_cast<uint8_t>(inner[w] >> 24U);
        result->digest[w * 4 + 1] = static_cast<uint8_t>(inner[w] >> 16U);
        result->digest[w * 4 + 2] = static_cast<uint8_t>(inner[w] >> 8U);
        result->digest[w * 4 + 3] = static_cast<uint8_t>(inner[w]);
    }
}

// Scale SHA-256 runs beside tile ChaCha on-device; no per-nonce host scale
// vector or transfer is part of the resident path.
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

// Exact MX-layout lowering for Bhat*V: four exponent-masked M11 matrices feed
// signed-INT8 MFMA and are accumulated with exact 2^e weights. This consumes
// the committed (μ, E8M0/32) representation directly; it is not native MXFP4.
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
// recentered into [-128,127]; the high byte remains signed. Therefore
//
//   x = sum_l plane_l(x) * 256^l + 128 * (1 + 256 + 65536).
//
// The row-independent correction is applied after the four exact s8xs8->s32
// GEMMs. This covers every int32 bit pattern, unlike a magnitude-specific
// decomposition, and preserves the consensus s32xs8 result exactly.
__global__ void DeviceExtractRadix256Plane(const int32_t* __restrict__ input,
                                           int8_t* __restrict__ plane,
                                           size_t count, uint32_t limb)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    const uint32_t bits = static_cast<uint32_t>(input[idx]);
    const uint32_t byte = (bits >> (8 * limb)) & 0xffu;
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
    const int64_t scale = int64_t{1} << (8 * limb);
    int64_t term = static_cast<int64_t>(limb_product[idx]) * scale;
    if (limb == 3) {
        term += kLowByteBias * static_cast<int64_t>(rhs_column_sums[idx % cols]);
    }
    // Accumulate by bit pattern so every intermediate is defined modulo 2^32.
    // Consensus MatExpand bounds make the final signed value fit int32.
    auto* output_bits = reinterpret_cast<uint32_t*>(output);
    const uint32_t prior = limb == 0 ? 0u : output_bits[idx];
    output_bits[idx] = prior + static_cast<uint32_t>(term);
}

static_assert(matmul::v4::bmx4::kCombineLimbs == 4 &&
              matmul::v4::bmx4::kCombineLimbBase == 64,
              "LT HIP combine kernels pin the BMX4-C four-limb base-64 encoding");

// Device twin of DecomposeLimbPlanesBMX4C + BuildKaratsubaPlanes. It emits one
// of the nine planes in the exact CPU order
// [d0,d1,d0+d1,d2,d3,d2+d3,d0+d2,d1+d3,d0+d1+d2+d3]. The maximum plane
// magnitude is 128, so every value remains a legal signed-byte tensor operand.
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
    default: value = 0; break;
    }
    plane[idx] = static_cast<int8_t>(value);
}

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

__device__ __forceinline__ uint64_t DeviceFqAdd(uint64_t a, uint64_t b)
{
    constexpr uint64_t q = (uint64_t{1} << 61) - 1;
    uint64_t s = a + b;
    if (s >= q) s -= q;
    return s;
}

__device__ __forceinline__ uint64_t DeviceFqMul(uint64_t a, uint64_t b)
{
    return DeviceFqReduce(static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b));
}

__device__ __forceinline__ uint64_t DeviceFqFromInt32(int32_t x)
{
    constexpr uint64_t q = (uint64_t{1} << 61) - 1;
    if (x >= 0) {
        return DeviceFqReduce(static_cast<unsigned __int128>(static_cast<uint64_t>(x)));
    }
    const uint64_t magnitude = static_cast<uint64_t>(-(static_cast<int64_t>(x) + 1)) + 1;
    uint64_t r = DeviceFqReduce(static_cast<unsigned __int128>(magnitude));
    return r == 0 ? 0 : (q - r);
}

__global__ void DeviceAccumulateCombineLimb(const int32_t* __restrict__ product,
                                            uint64_t* __restrict__ chat,
                                            uint64_t weight, size_t count)
{
    const size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    chat[idx] = DeviceFqAdd(chat[idx],
                            DeviceFqMul(weight, DeviceFqFromInt32(product[idx])));
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

__global__ void DeviceCombineModQ(const int32_t* __restrict__ P,
                                  const int32_t* __restrict__ Q,
                                  uint64_t* __restrict__ Chat,
                                  int n, int m)
{
    const int c = blockIdx.x * blockDim.x + threadIdx.x;
    const int a = blockIdx.y * blockDim.y + threadIdx.y;
    if (a >= m || c >= m) return;
    uint64_t acc = 0;
    const size_t prow = static_cast<size_t>(a) * n;
    for (int k = 0; k < n; ++k) {
        const int32_t p = P[prow + k];
        if (p == 0) continue;
        acc = DeviceFqAdd(acc, DeviceFqMul(DeviceFqFromInt32(p),
                                           DeviceFqFromInt32(Q[static_cast<size_t>(k) * m + c])));
    }
    Chat[static_cast<size_t>(a) * m + c] = acc;
}

struct LtHipResidentPool {
    std::mutex mu;
    hipStream_t stream{nullptr};
    uint32_t n{0}, m{0}, w{0};
    uint256 template_hash{};
    bool template_bound{false};
    bool graphs_ready{false};
    bool mfma_s8s8{false};
    // Production default: retain MX (μ, E8M0) and run scale-partitioned B̂·V.
    bool mx_partitioned{false};
    bool used_exact_mx_this_batch{false};

    int8_t *dG{nullptr}, *dH{nullptr}, *dU{nullptr}, *dV{nullptr}, *dAhat{nullptr};
    int32_t* dP{nullptr};
    int8_t *dW{nullptr}, *dBhat{nullptr}; // dense Bhat, or MX mantissa μ when partitioned
    int32_t *dY{nullptr}, *dB32{nullptr}, *dQ{nullptr};
    uint64_t* dChat{nullptr};
    uint64_t* dDigestChatRing{nullptr};
    uint8_t* dScales{nullptr}; // n*(n/32) E8M0 codes for exact MX projection
    uint8_t *dWXofHashes{nullptr}, *dWXofCounts{nullptr};
    uint32_t* dWXofOffsets{nullptr};
    uint32_t w_xof_blocks{0};
    DeviceDigestStatusLT* dBatchResults{nullptr};
    size_t batch_result_capacity{0};
    hipStream_t digest_streams[kDigestRingSlots]{};
    hipEvent_t digest_ready[kDigestRingSlots]{};
    hipEvent_t digest_done[kDigestRingSlots]{};
    bool digest_inflight[kDigestRingSlots]{};

    int8_t *dGemmS8L{nullptr}, *dGemmS8R{nullptr};
    int32_t *dGemmS32L{nullptr}, *dGemmOut{nullptr};
    size_t gemm_s8l_bytes{0}, gemm_s8r_bytes{0}, gemm_s32l_bytes{0}, gemm_out_bytes{0};

    hipGraph_t matexpand_graph{nullptr};
    hipGraphExec_t matexpand_exec{nullptr};
    hipGraph_t project_right_graph{nullptr};
    hipGraphExec_t project_right_exec{nullptr};

    ~LtHipResidentPool() { Release(); }

    void ReleaseGraphs()
    {
        if (matexpand_exec) { hipGraphExecDestroy(matexpand_exec); matexpand_exec = nullptr; }
        if (matexpand_graph) { hipGraphDestroy(matexpand_graph); matexpand_graph = nullptr; }
        if (project_right_exec) { hipGraphExecDestroy(project_right_exec); project_right_exec = nullptr; }
        if (project_right_graph) { hipGraphDestroy(project_right_graph); project_right_graph = nullptr; }
        graphs_ready = false;
    }

    void Release()
    {
        ReleaseGraphs();
        for (size_t i = 0; i < kDigestRingSlots; ++i) {
            if (digest_streams[i]) { hipStreamDestroy(digest_streams[i]); digest_streams[i] = nullptr; }
            if (digest_ready[i]) { hipEventDestroy(digest_ready[i]); digest_ready[i] = nullptr; }
            if (digest_done[i]) { hipEventDestroy(digest_done[i]); digest_done[i] = nullptr; }
            digest_inflight[i] = false;
        }
        auto free_p = [](auto*& p) { if (p) { hipFree(p); p = nullptr; } };
        free_p(dG); free_p(dH); free_p(dU); free_p(dV); free_p(dAhat); free_p(dP);
        free_p(dW); free_p(dY); free_p(dB32); free_p(dBhat); free_p(dQ); free_p(dChat);
        free_p(dDigestChatRing);
        free_p(dScales);
        free_p(dWXofHashes); free_p(dWXofCounts); free_p(dWXofOffsets);
        free_p(dBatchResults);
        w_xof_blocks = 0;
        batch_result_capacity = 0;
        free_p(dGemmS8L); free_p(dGemmS8R); free_p(dGemmS32L); free_p(dGemmOut);
        gemm_s8l_bytes = gemm_s8r_bytes = gemm_s32l_bytes = gemm_out_bytes = 0;
        if (stream) { hipStreamDestroy(stream); stream = nullptr; }
        template_bound = false;
        mfma_s8s8 = false;
        mx_partitioned = false;
        used_exact_mx_this_batch = false;
        n = m = w = 0;
    }

    [[nodiscard]] bool EnsureScratch(size_t s8l, size_t s8r, size_t s32l, size_t out)
    {
        auto grow = [](auto*& p, size_t& have, size_t need) -> bool {
            if (need <= have) return true;
            if (p) { hipFree(p); p = nullptr; have = 0; }
            if (need == 0) return true;
            if (hipMalloc(reinterpret_cast<void**>(&p), need) != hipSuccess) return false;
            have = need;
            return true;
        };
        return grow(dGemmS8L, gemm_s8l_bytes, s8l) &&
               grow(dGemmS8R, gemm_s8r_bytes, s8r) &&
               grow(dGemmS32L, gemm_s32l_bytes, s32l) &&
               grow(dGemmOut, gemm_out_bytes, out);
    }

    [[nodiscard]] bool EnsureBatchResults(size_t count)
    {
        if (count <= batch_result_capacity) return true;
        if (dBatchResults) {
            if (hipFree(dBatchResults) != hipSuccess) return false;
            dBatchResults = nullptr;
            batch_result_capacity = 0;
        }
        if (hipMalloc(reinterpret_cast<void**>(&dBatchResults),
                      count * sizeof(DeviceDigestStatusLT)) != hipSuccess) {
            return false;
        }
        batch_result_capacity = count;
        return true;
    }

    [[nodiscard]] bool EnsureDims(uint32_t n_in, uint32_t m_in)
    {
        const uint32_t w_in = matmul::v4::lt::kMatExpandPanelW;
        if (stream && n == n_in && m == m_in && w == w_in) return true;
        Release();
        if (hipStreamCreateWithFlags(&stream, hipStreamNonBlocking) != hipSuccess) return false;
        for (size_t i = 0; i < kDigestRingSlots; ++i) {
            if (hipStreamCreateWithFlags(&digest_streams[i], hipStreamNonBlocking) != hipSuccess ||
                hipEventCreateWithFlags(&digest_ready[i], hipEventDisableTiming) != hipSuccess ||
                hipEventCreateWithFlags(&digest_done[i], hipEventDisableTiming) != hipSuccess) {
                Release();
                return false;
            }
        }
        // Exact MX scale-partitioned B̂·V is the production default whenever
        // n is a multiple of the MX block length (always true for LT dims).
        // Dense dequant remains available via BTX_MATMUL_V4_LT_DENSE_BHAT=1.
        mx_partitioned = (n_in % matmul::v4::lt::kMatExpandMxBlockLen == 0) &&
                         !DenseBhatProjectionForced();
        used_exact_mx_this_batch = false;
        n = n_in; m = m_in; w = w_in;
        const size_t nn = static_cast<size_t>(n) * n;
        const size_t nw = static_cast<size_t>(n) * w;
        const size_t wn = static_cast<size_t>(w) * n;
        const size_t mn = static_cast<size_t>(m) * n;
        const size_t nm = static_cast<size_t>(n) * m;
        const size_t mm = static_cast<size_t>(m) * m;
        const size_t nscales = static_cast<size_t>(n) *
            (n / matmul::v4::lt::kMatExpandMxBlockLen);
        // 40 accepted mantissas/hash is below the 44/hash expectation.  The
        // 256-block reserve makes exhaustion negligible, while `ok` is still
        // checked after the batch so any short stream fails closed.
        const size_t xof_blocks_sz = (nw + 39U) / 40U + 256U;
        if (xof_blocks_sz > std::numeric_limits<uint32_t>::max()) {
            Release();
            return false;
        }
        w_xof_blocks = static_cast<uint32_t>(xof_blocks_sz);
        auto mall = [](void** p, size_t bytes) {
            return bytes == 0 || hipMalloc(p, bytes) == hipSuccess;
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
            !mall(reinterpret_cast<void**>(&dDigestChatRing),
                  kDigestRingSlots * mm * sizeof(uint64_t)) ||
            !mall(reinterpret_cast<void**>(&dScales), mx_partitioned ? nscales : 0) ||
            !mall(reinterpret_cast<void**>(&dWXofHashes), xof_blocks_sz * 32U) ||
            !mall(reinterpret_cast<void**>(&dWXofCounts), xof_blocks_sz) ||
            !mall(reinterpret_cast<void**>(&dWXofOffsets), xof_blocks_sz * sizeof(uint32_t))) {
            Release();
            return false;
        }
        return true;
    }

    [[nodiscard]] bool LaunchProjectorW(const uint256& seed_w,
                                        DeviceDigestStatusLT* result)
    {
        uint32_t sw[8];
        Bmx4SeedStreamWords(seed_w, sw);
        constexpr uint32_t threads = 256;
        const uint32_t blocks = (w_xof_blocks + threads - 1U) / threads;
        hipLaunchKernelGGL(DeviceGenerateProjectorBlocks,
                           dim3(blocks), dim3(threads), 0, stream,
                           dWXofHashes, dWXofCounts, w_xof_blocks,
                           sw[0], sw[1], sw[2], sw[3], sw[4], sw[5], sw[6], sw[7]);
        if (hipGetLastError() != hipSuccess) return false;
        hipLaunchKernelGGL(DevicePrefixProjectorBlocks,
                           dim3(1), dim3(1), 0, stream,
                           dWXofCounts, dWXofOffsets, w_xof_blocks,
                           static_cast<size_t>(n) * w, result);
        if (hipGetLastError() != hipSuccess) return false;
        hipLaunchKernelGGL(DeviceScatterProjectorBlocks,
                           dim3(blocks), dim3(threads), 0, stream,
                           dWXofHashes, dWXofOffsets, w_xof_blocks,
                           static_cast<size_t>(n) * w, result, dW);
        return hipGetLastError() == hipSuccess;
    }

    [[nodiscard]] bool LaunchChatDigest(const uint256& sigma,
                                        DeviceDigestStatusLT* result,
                                        size_t batch_index)
    {
        const size_t ring = batch_index % kDigestRingSlots;
        const size_t chat_words = static_cast<size_t>(m) * m;
        if (digest_inflight[ring] &&
            hipStreamWaitEvent(stream, digest_done[ring], 0) != hipSuccess) {
            return false;
        }
        uint64_t* staged_chat = dDigestChatRing + ring * chat_words;
        if (hipMemcpyAsync(staged_chat, dChat, chat_words * sizeof(uint64_t),
                           hipMemcpyDeviceToDevice, stream) != hipSuccess ||
            hipEventRecord(digest_ready[ring], stream) != hipSuccess ||
            hipStreamWaitEvent(digest_streams[ring], digest_ready[ring], 0) != hipSuccess) {
            return false;
        }
        uint32_t sw[8];
        for (uint32_t t = 0; t < 8; ++t) {
            sw[t] = ReadLE32(sigma.data() + static_cast<size_t>(t) * 4);
        }
        hipLaunchKernelGGL(DeviceDigestChatSha256d,
                           dim3(1), dim3(1), 0, digest_streams[ring],
                           staged_chat, chat_words, result,
                           sw[0], sw[1], sw[2], sw[3], sw[4], sw[5], sw[6], sw[7]);
        if (hipGetLastError() != hipSuccess ||
            hipEventRecord(digest_done[ring], digest_streams[ring]) != hipSuccess) {
            return false;
        }
        digest_inflight[ring] = true;
        return true;
    }

    [[nodiscard]] bool JoinDigestStreams()
    {
        for (size_t i = 0; i < kDigestRingSlots; ++i) {
            if (digest_inflight[i] && hipStreamWaitEvent(stream, digest_done[i], 0) != hipSuccess) {
                return false;
            }
        }
        return true;
    }

    void ResetDigestRing()
    {
        for (bool& inflight : digest_inflight) inflight = false;
    }

    [[nodiscard]] bool LaunchMxExtract(int8_t* dDenseOut, int8_t* dMuOut,
                                       uint8_t* dScalesOut, const uint256& prf_key)
    {
        const uint32_t nblk = n / matmul::v4::lt::kMatExpandMxBlockLen;
        uint32_t kw[8];
        for (int t = 0; t < 8; ++t) kw[t] = ReadLE32(prf_key.data() + static_cast<size_t>(t) * 4);
        const uint32_t ntiles = n * nblk;
        const int et = 256;
        const int eb = static_cast<int>((ntiles + et - 1) / et);
        hipLaunchKernelGGL(DeviceExtractDequantMatExpandMx, dim3(eb), dim3(et), 0, stream,
                           dB32, dDenseOut, dMuOut, dScalesOut, n,
                           kw[0], kw[1], kw[2], kw[3], kw[4], kw[5], kw[6], kw[7]);
        return hipGetLastError() == hipSuccess;
    }

    [[nodiscard]] bool CaptureGraphsScalar()
    {
        ReleaseGraphs();
        const dim3 block(16, 16, 1);
        {
            const dim3 grid_y((w + block.x - 1) / block.x, (n + block.y - 1) / block.y, 1);
            const dim3 grid_b((n + block.x - 1) / block.x, (n + block.y - 1) / block.y, 1);
            if (hipStreamBeginCapture(stream, hipStreamCaptureModeGlobal) != hipSuccess) return false;
            hipLaunchKernelGGL(DeviceGemmS8S8Tiled, grid_y, block, 0, stream,
                               dG, dW, dY, static_cast<int>(n), static_cast<int>(w), static_cast<int>(n));
            hipLaunchKernelGGL(DeviceGemmS32S8Tiled, grid_b, block, 0, stream,
                               dY, dH, dB32, static_cast<int>(n), static_cast<int>(n), static_cast<int>(w));
            if (hipStreamEndCapture(stream, &matexpand_graph) != hipSuccess) {
                matexpand_graph = nullptr;
                return false;
            }
            if (hipGraphInstantiate(&matexpand_exec, matexpand_graph, nullptr, nullptr, 0) != hipSuccess) {
                ReleaseGraphs();
                return false;
            }
        }
        {
            const dim3 grid_q((m + block.x - 1) / block.x, (n + block.y - 1) / block.y, 1);
            if (hipStreamBeginCapture(stream, hipStreamCaptureModeGlobal) != hipSuccess) {
                ReleaseGraphs();
                return false;
            }
            hipLaunchKernelGGL(DeviceGemmS8S8Tiled, grid_q, block, 0, stream,
                               dBhat, dV, dQ, static_cast<int>(n), static_cast<int>(m), static_cast<int>(n));
            if (hipStreamEndCapture(stream, &project_right_graph) != hipSuccess) {
                project_right_graph = nullptr;
                ReleaseGraphs();
                return false;
            }
            if (hipGraphInstantiate(&project_right_exec, project_right_graph, nullptr, nullptr, 0) !=
                hipSuccess) {
                ReleaseGraphs();
                return false;
            }
        }
        graphs_ready = true;
        return true;
    }

    [[nodiscard]] bool LaunchMatExpandMfma()
    {
        if (!TryLaunchLtMfmaGemmS8S8Device(dG, dW, dY, n, w, n, stream)) return false;
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
        hipLaunchKernelGGL(DeviceColumnSumsS8, dim3(col_blocks), dim3(kElemThreads), 0, stream,
                           dH, dGemmS32L, static_cast<int>(w), static_cast<int>(n));
        if (hipGetLastError() != hipSuccess) return false;

        for (uint32_t limb = 0; limb < 4; ++limb) {
            hipLaunchKernelGGL(DeviceExtractRadix256Plane, dim3(yw_blocks), dim3(kElemThreads), 0, stream,
                               dY, dGemmS8L, yw, limb);
            if (hipGetLastError() != hipSuccess) return false;
            if (!TryLaunchLtMfmaGemmS8S8Device(dGemmS8L, dH, dGemmOut,
                                               n, n, w, stream)) {
                return false;
            }
            hipLaunchKernelGGL(DeviceAccumulateRadix256, dim3(out_blocks), dim3(kElemThreads), 0, stream,
                               dGemmOut, dB32, dGemmS32L, nn, static_cast<int>(n), limb);
            if (hipGetLastError() != hipSuccess) return false;
        }
        return true;
    }

    [[nodiscard]] bool LaunchProjectRightDenseMfma()
    {
        return TryLaunchLtMfmaGemmS8S8Device(dBhat, dV, dQ, n, m, n, stream);
    }

    // Exact MX-layout lowering: four exponent-masked M11 planes × s8xs8 GEMM
    // + exact 2^e accumulate. Bit-identical to
    // ComputeProjectedRightMxBlockScaleLT / ComputeProjectedRightMxScalePartitionedGemmLT.
    // Prefer MFMA library GEMMs; fall back to tiled DeviceGemmS8S8.
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
            hipLaunchKernelGGL(DeviceBuildMxExponentPlane,
                               dim3(plane_blocks), dim3(kElemThreads), 0, stream,
                               dBhat, dScales, dGemmS8L, nn, n, exponent);
            if (hipGetLastError() != hipSuccess) return false;
            bool gemm_ok = false;
            if (mfma_s8s8) {
                gemm_ok = TryLaunchLtMfmaGemmS8S8Device(dGemmS8L, dV, dGemmOut,
                                                        n, m, n, stream);
            }
            if (!gemm_ok) {
                hipLaunchKernelGGL(DeviceGemmS8S8Tiled, gemm_grid, gemm_block, 0, stream,
                                   dGemmS8L, dV, dGemmOut,
                                   static_cast<int>(n), static_cast<int>(m),
                                   static_cast<int>(n));
                if (hipGetLastError() != hipSuccess) return false;
            }
            hipLaunchKernelGGL(DeviceAccumulateMxProjection,
                               dim3(out_blocks), dim3(kElemThreads), 0, stream,
                               dGemmOut, dQ, nm, exponent);
            if (hipGetLastError() != hipSuccess) return false;
        }
        return true;
    }

    [[nodiscard]] bool LaunchProjectRightMxMfma()
    {
        return LaunchProjectRightMxExact();
    }

    [[nodiscard]] bool LaunchProjectLeftMfma()
    {
        return TryLaunchLtMfmaGemmS8S8Device(dU, dAhat, dP, m, n, n, stream);
    }

    [[nodiscard]] bool LaunchCombineMfma()
    {
        const size_t mn = static_cast<size_t>(m) * n;
        const size_t nm = static_cast<size_t>(n) * m;
        const size_t mm = static_cast<size_t>(m) * m;
        if (!EnsureScratch(mn, nm, 0, mm * sizeof(int32_t))) {
            return false;
        }

        constexpr unsigned kElemThreads = 256;
        const unsigned p_blocks = static_cast<unsigned>((mn + kElemThreads - 1) / kElemThreads);
        const unsigned q_blocks = static_cast<unsigned>((nm + kElemThreads - 1) / kElemThreads);
        const unsigned out_blocks = static_cast<unsigned>((mm + kElemThreads - 1) / kElemThreads);
        if (hipMemsetAsync(dChat, 0, mm * sizeof(uint64_t), stream) != hipSuccess) {
            return false;
        }

        uint64_t weights[9];
        Karatsuba9FqWeights(weights);
        for (uint32_t r = 0; r < 9; ++r) {
            hipLaunchKernelGGL(DeviceBuildKaratsubaPlane,
                               dim3(p_blocks), dim3(kElemThreads), 0, stream,
                               dP, dGemmS8L, mn, r);
            if (hipGetLastError() != hipSuccess) return false;
            hipLaunchKernelGGL(DeviceBuildKaratsubaPlane,
                               dim3(q_blocks), dim3(kElemThreads), 0, stream,
                               dQ, dGemmS8R, nm, r);
            if (hipGetLastError() != hipSuccess) return false;
            if (!TryLaunchLtMfmaGemmS8S8Device(dGemmS8L, dGemmS8R, dGemmOut,
                                               m, m, n, stream)) {
                return false;
            }
            hipLaunchKernelGGL(DeviceAccumulateCombineLimb,
                               dim3(out_blocks), dim3(kElemThreads), 0, stream,
                               dGemmOut, dChat, weights[r], mm);
            if (hipGetLastError() != hipSuccess) return false;
        }
        return true;
    }

    [[nodiscard]] bool BindTemplate(const CBlockHeader& tmpl, uint32_t n_in, uint32_t m_in)
    {
        if (!EnsureDims(n_in, m_in)) return false;
        const uint256 th = matmul::v4::ComputeTemplateHash(tmpl);
        const bool want_mfma = IsLtMfmaGemmAvailable();
        if (template_bound && template_hash == th && mfma_s8s8 == want_mfma &&
            (mfma_s8s8 || graphs_ready)) {
            return true;
        }

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
        if (hipMemcpyAsync(dG, G.data(), nn, hipMemcpyHostToDevice, stream) != hipSuccess) return false;
        if (hipMemcpyAsync(dH, H.data(), wn, hipMemcpyHostToDevice, stream) != hipSuccess) return false;
        if (hipMemcpyAsync(dW, W_a.data(), nw, hipMemcpyHostToDevice, stream) != hipSuccess) return false;
        if (hipMemcpyAsync(dU, U.data(), mn, hipMemcpyHostToDevice, stream) != hipSuccess) return false;
        if (hipMemcpyAsync(dV, V.data(), nm, hipMemcpyHostToDevice, stream) != hipSuccess) return false;

        mfma_s8s8 = want_mfma;
        if (mfma_s8s8) {
            ReleaseGraphs();
            if (!LaunchMatExpandMfma()) {
                mfma_s8s8 = false;
                if (!CaptureGraphsScalar()) return false;
                if (hipGraphLaunch(matexpand_exec, stream) != hipSuccess) return false;
            }
        } else {
            if (!CaptureGraphsScalar()) return false;
            if (hipGraphLaunch(matexpand_exec, stream) != hipSuccess) return false;
        }

        const uint256 prf_a = matmul::v4::lt::DeriveMatExpandPrfKey(seed_wa);
        if (!LaunchMxExtract(dAhat, nullptr, nullptr, prf_a)) return false;

        if (mfma_s8s8) {
            if (!LaunchProjectLeftMfma()) {
                mfma_s8s8 = false;
                const dim3 block(16, 16, 1);
                const dim3 grid_p((n + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
                hipLaunchKernelGGL(DeviceGemmS8S8Tiled, grid_p, block, 0, stream,
                                   dU, dAhat, dP, static_cast<int>(m), static_cast<int>(n),
                                   static_cast<int>(n));
                if (hipGetLastError() != hipSuccess) return false;
                if (!graphs_ready && !CaptureGraphsScalar()) return false;
            }
        } else {
            const dim3 block(16, 16, 1);
            const dim3 grid_p((n + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
            hipLaunchKernelGGL(DeviceGemmS8S8Tiled, grid_p, block, 0, stream,
                               dU, dAhat, dP, static_cast<int>(m), static_cast<int>(n),
                               static_cast<int>(n));
            if (hipGetLastError() != hipSuccess) return false;
        }
        if (hipStreamSynchronize(stream) != hipSuccess) return false;
        template_hash = th;
        template_bound = true;
        return true;
    }

    [[nodiscard]] bool EnqueueOneHeader(const CBlockHeader& header,
                                        DeviceDigestStatusLT* result,
                                        size_t batch_index)
    {
        if (!template_bound || result == nullptr) return false;
        if (!mfma_s8s8 && !graphs_ready) return false;
        if (matmul::v4::ComputeTemplateHash(header) != template_hash) return false;
        const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);
        const uint256 seed_w = DeriveTaggedSeed(kMatExpandWTag, sizeof(kMatExpandWTag) - 1, header_hash);
        if (!LaunchProjectorW(seed_w, result)) return false;

        if (mfma_s8s8) {
            if (!LaunchMatExpandMfma()) return false;
        } else {
            if (hipGraphLaunch(matexpand_exec, stream) != hipSuccess) return false;
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
        } else if (mfma_s8s8) {
            if (!LaunchProjectRightDenseMfma()) return false;
        } else {
            if (hipGraphLaunch(project_right_exec, stream) != hipSuccess) return false;
        }

        if (mfma_s8s8) {
            if (!LaunchCombineMfma()) return false;
        } else {
            const dim3 block(16, 16, 1);
            const dim3 grid_c((m + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
            hipLaunchKernelGGL(DeviceCombineModQ, grid_c, block, 0, stream,
                               dP, dQ, dChat, static_cast<int>(n), static_cast<int>(m));
            if (hipGetLastError() != hipSuccess) return false;
        }
        return LaunchChatDigest(matmul::v4::DeriveSigma(header), result, batch_index);
    }
};

LtHipResidentPool& Pool()
{
    static LtHipResidentPool pool;
    return pool;
}

[[nodiscard]] bool HipOkLaunchGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
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
    if (hipMemcpy(pool.dGemmS8L, left.data(), lhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;
    if (hipMemcpy(pool.dGemmS8R, right.data(), rhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;
    const dim3 block(16, 16, 1);
    const dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y, 1);
    hipLaunchKernelGGL(DeviceGemmS8S8Tiled, grid, block, 0, 0,
                       pool.dGemmS8L, pool.dGemmS8R, pool.dGemmOut,
                       static_cast<int>(rows), static_cast<int>(cols), static_cast<int>(k));
    if (hipGetLastError() != hipSuccess) return false;
    if (hipDeviceSynchronize() != hipSuccess) return false;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    return hipMemcpy(out.data(), pool.dGemmOut, out_bytes, hipMemcpyDeviceToHost) == hipSuccess;
}

[[nodiscard]] bool HipOkLaunchGemmS32S8(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
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
    if (hipMemcpy(pool.dGemmS32L, left.data(), lhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;
    if (hipMemcpy(pool.dGemmS8R, right.data(), rhs_bytes, hipMemcpyHostToDevice) != hipSuccess) return false;
    const dim3 block(16, 16, 1);
    const dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y, 1);
    hipLaunchKernelGGL(DeviceGemmS32S8Tiled, grid, block, 0, 0,
                       pool.dGemmS32L, pool.dGemmS8R, pool.dGemmOut,
                       static_cast<int>(rows), static_cast<int>(cols), static_cast<int>(k));
    if (hipGetLastError() != hipSuccess) return false;
    if (hipDeviceSynchronize() != hipSuccess) return false;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    return hipMemcpy(out.data(), pool.dGemmOut, out_bytes, hipMemcpyDeviceToHost) == hipSuccess;
}

thread_local bool g_lt_device_gemm_failed = false;
thread_local bool g_lt_last_s8s8_mfma = false;

bool BackendGemmS8S8(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                     uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (TryLaunchLtMfmaGemmS8S8(L, R, rows, inner, cols, out)) {
        g_lt_last_s8s8_mfma = true;
        return true;
    }
    g_lt_last_s8s8_mfma = false;
    if (HipOkLaunchGemmS8S8(L, R, rows, inner, cols, out)) return true;
    if (TryLaunchLtDeviceAluGemmS8S8(L, R, rows, inner, cols, out)) return true;
    g_lt_device_gemm_failed = true;
    return false;
}

bool BackendGemmS32S8(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                      uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (TryLaunchLtMfmaGemmS32S8(L, R, rows, inner, cols, out)) return true;
    if (HipOkLaunchGemmS32S8(L, R, rows, inner, cols, out)) return true;
    if (TryLaunchLtDeviceAluGemmS32S8(L, R, rows, inner, cols, out)) return true;
    g_lt_device_gemm_failed = true;
    return false;
}

// ---------------------------------------------------------------------------
// B̂·V: prefer self-qualified native MXFP4/FP8 (matmul_v4_lt_mx_native.hip);
// production default remains exact INT8 scale-partitioned MFMA until that
// path sets native_*_qualified.
// ---------------------------------------------------------------------------

[[nodiscard]] bool LaunchProjectedRightMxImpl(const std::vector<int8_t>& mu,
                                              const std::vector<uint8_t>& scales,
                                              const std::vector<int8_t>& V, uint32_t n,
                                              uint32_t m, std::vector<int32_t>& out,
                                              matmul::v4::lt::MxLaneProvenance* provenance)
{
    matmul::v4::lt::MxLaneProvenance local{};
    out.clear();
    if (n == 0 || m == 0 || (n % matmul::v4::lt::kMatExpandMxBlockLen) != 0) {
        if (provenance) *provenance = local;
        g_lt_last_mx_provenance = local;
        return false;
    }
    const uint32_t nblk = n / matmul::v4::lt::kMatExpandMxBlockLen;
    if (mu.size() != static_cast<size_t>(n) * n ||
        scales.size() != static_cast<size_t>(n) * nblk ||
        V.size() != static_cast<size_t>(n) * m) {
        if (provenance) *provenance = local;
        g_lt_last_mx_provenance = local;
        return false;
    }

    // Prefer a qualified native path; otherwise exact INT8 scale partitions.
    if (TryLaunchNativeMxfp4ProjectedRight(mu, scales, V, n, m, out, &local) &&
        matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
        local.exact_mx_scale_partitioned = false;
        if (provenance) *provenance = local;
        g_lt_last_mx_provenance = local;
        return true;
    }
    local = {};
    if (TryLaunchNativeFp8ProjectedRight(mu, scales, V, n, m, out, &local) &&
        matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
        local.exact_mx_scale_partitioned = false;
        if (provenance) *provenance = local;
        g_lt_last_mx_provenance = local;
        return true;
    }
    local = {};

    matmul::v4::lt::ExactGemmBackend gemm;
    gemm.gemm_s8s8 = &BackendGemmS8S8;
    gemm.gemm_s32s8 = &BackendGemmS32S8;
    out = matmul::v4::lt::ComputeProjectedRightMxScalePartitionedGemmLT(mu, scales, V, n, m, gemm);
    if (out.empty() ||
        !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, n, m, out)) {
        // Absolute fail-closed: CPU oracle loop (still exact).
        out = matmul::v4::lt::ComputeProjectedRightMxBlockScaleLT(mu, scales, V, n, m);
    }
    local.exact_mx_scale_partitioned = true;
    if (provenance) *provenance = local;
    g_lt_last_mx_provenance = local;
    return !out.empty();
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
        const auto cpu8 = matmul::v4::lt::ExactGemmS8S8(left, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu8;
        bool s8_ok = false;
        if (IsLtMfmaGemmAvailable()) {
            s8_ok = TryLaunchLtMfmaGemmS8S8(left, right, kDim, kDim, kDim, gpu8) && gpu8 == cpu8;
        }
        if (!s8_ok) {
            if (!HipOkLaunchGemmS8S8(left, right, kDim, kDim, kDim, gpu8) || gpu8 != cpu8) return;
        }
        const auto cpu32 = matmul::v4::lt::ExactGemmS32S8(mid, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu32;
        if (!HipOkLaunchGemmS32S8(mid, right, kDim, kDim, kDim, gpu32) || gpu32 != cpu32) return;

        // Exact MX scale-partitioned B̂·V vs CPU oracle on n multiple of 32.
        {
            constexpr uint32_t kMxN = 32;
            constexpr uint32_t kMxM = 16; // deep tile m = n/2 for LT, but any m works for Q
            const uint32_t nblk = kMxN / matmul::v4::lt::kMatExpandMxBlockLen;
            std::vector<int8_t> mu(static_cast<size_t>(kMxN) * kMxN);
            std::vector<uint8_t> scales(static_cast<size_t>(kMxN) * nblk);
            std::vector<int8_t> V(static_cast<size_t>(kMxN) * kMxM);
            for (uint32_t i = 0; i < kMxN * kMxN; ++i) {
                // M11 alphabet subset: {0,±1,±2,±3,±4,±6}
                static constexpr int8_t kM11[] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
                mu[i] = kM11[i % 11];
            }
            for (uint32_t i = 0; i < kMxN * nblk; ++i) {
                scales[i] = static_cast<uint8_t>(i & 3U);
            }
            for (uint32_t i = 0; i < kMxN * kMxM; ++i) {
                V[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * 3 - 17);
            }
            // Native may qualify only after oracle match; INT8 partitions remain
            // the production default when native stays fail-closed.
            {
                std::vector<int32_t> native_out;
                matmul::v4::lt::MxLaneProvenance native_prov{};
                if (TryLaunchNativeMxfp4ProjectedRight(mu, scales, V, kMxN, kMxM, native_out,
                                                       &native_prov) &&
                    native_prov.native_mxfp4_qualified &&
                    !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, kMxN, kMxM,
                                                                  native_out)) {
                    return;
                }
                if (TryLaunchNativeFp8ProjectedRight(mu, scales, V, kMxN, kMxM, native_out,
                                                     &native_prov) &&
                    native_prov.native_fp8_qualified &&
                    !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, kMxN, kMxM,
                                                                  native_out)) {
                    return;
                }
            }
            matmul::v4::lt::ExactGemmBackend gemm;
            gemm.gemm_s8s8 = &BackendGemmS8S8;
            gemm.gemm_s32s8 = &BackendGemmS32S8;
            const auto partitioned =
                matmul::v4::lt::ComputeProjectedRightMxScalePartitionedGemmLT(mu, scales, V, kMxN,
                                                                              kMxM, gemm);
            if (partitioned.empty() ||
                !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, kMxN, kMxM,
                                                              partitioned)) {
                return;
            }
            std::vector<int32_t> launched;
            matmul::v4::lt::MxLaneProvenance mx_prov{};
            if (!LaunchProjectedRightMxImpl(mu, scales, V, kMxN, kMxM, launched, &mx_prov) ||
                !matmul::v4::lt::MxProjectionMatchesCpuOracle(mu, scales, V, kMxN, kMxM,
                                                              launched) ||
                !(mx_prov.exact_mx_scale_partitioned || mx_prov.native_mxfp4_qualified ||
                  mx_prov.native_fp8_qualified)) {
                return;
            }
        }

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
        for (int i = 0; i < 32; ++i) {
            header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
            header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
            header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
            header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
        }
        CBlockHeader header2 = header;
        header2.nNonce64 = 43;
        header2.nNonce = 43;
        header2.seed_a.data()[0] ^= 0x5aU;
        header2.seed_b.data()[31] ^= 0xa5U;
        uint256 cpu_digest, cpu_digest2;
        std::vector<unsigned char> cpu_payload;
        if (!matmul::v4::lt::ComputeDigestBMX4CLT(header, kN, cpu_digest, cpu_payload)) return;
        if (!matmul::v4::lt::ComputeDigestBMX4CLT(header2, kN, cpu_digest2, cpu_payload)) return;
        auto& pool = Pool();
        std::lock_guard<std::mutex> lock(pool.mu);
        if (!pool.BindTemplate(header, kN, m)) return;
        if (!pool.EnsureBatchResults(2)) return;
        if (hipMemsetAsync(pool.dBatchResults, 0, 2 * sizeof(DeviceDigestStatusLT), pool.stream) !=
            hipSuccess) return;
        if (!pool.EnqueueOneHeader(header, pool.dBatchResults, 0)) return;
        if (!pool.EnqueueOneHeader(header2, pool.dBatchResults + 1, 1)) return;
        if (!pool.JoinDigestStreams()) return;
        DeviceDigestStatusLT gpu[2]{};
        if (hipMemcpyAsync(gpu, pool.dBatchResults, sizeof(gpu), hipMemcpyDeviceToHost,
                           pool.stream) != hipSuccess) return;
        if (hipStreamSynchronize(pool.stream) != hipSuccess || gpu[0].ok != 1U || gpu[1].ok != 1U) {
            return;
        }
        pool.ResetDigestRing();
        const uint256 gpu_digest{Span<const unsigned char>{gpu[0].digest, sizeof(gpu[0].digest)}};
        const uint256 gpu_digest2{Span<const unsigned char>{gpu[1].digest, sizeof(gpu[1].digest)}};
        if (gpu_digest != cpu_digest || gpu_digest2 != cpu_digest2) return;
        ok = true;
    });
    return ok;
}

[[nodiscard]] bool HipDeviceAvailable()
{
    int count = 0;
    return hipGetDeviceCount(&count) == hipSuccess && count > 0;
}

[[nodiscard]] bool MineHeadersDeviceResident(
    const std::vector<CBlockHeader>& headers, uint32_t n, uint32_t m,
    std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
    matmul_v4::hip::LtHipBatchProvenance* provenance)
{
    if (headers.empty() || headers.size() > kMaxConsensusBatch) return false;
    const uint256 template_hash = matmul::v4::ComputeTemplateHash(headers.front());
    for (const CBlockHeader& header : headers) {
        if (matmul::v4::ComputeTemplateHash(header) != template_hash) return false;
    }

    auto& pool = Pool();
    std::lock_guard<std::mutex> lock(pool.mu);
    pool.used_exact_mx_this_batch = false;
    if (!pool.BindTemplate(headers.front(), n, m) ||
        !pool.EnsureBatchResults(headers.size())) return false;
    if (hipMemsetAsync(pool.dBatchResults, 0,
                       headers.size() * sizeof(DeviceDigestStatusLT), pool.stream) != hipSuccess) {
        return false;
    }
    for (size_t i = 0; i < headers.size(); ++i) {
        if (!pool.EnqueueOneHeader(headers[i], pool.dBatchResults + i, i)) {
            (void)pool.JoinDigestStreams();
            (void)hipStreamSynchronize(pool.stream);
            pool.ResetDigestRing();
            out.clear();
            return false;
        }
    }

    if (!pool.JoinDigestStreams()) {
        (void)hipStreamSynchronize(pool.stream);
        pool.ResetDigestRing();
        out.clear();
        return false;
    }

    std::vector<DeviceDigestStatusLT> device_results(headers.size());
    if (hipMemcpyAsync(device_results.data(), pool.dBatchResults,
                       device_results.size() * sizeof(DeviceDigestStatusLT),
        hipMemcpyDeviceToHost, pool.stream) != hipSuccess ||
        hipStreamSynchronize(pool.stream) != hipSuccess) {
        (void)hipStreamSynchronize(pool.stream);
        pool.ResetDigestRing();
        out.clear();
        return false;
    }
    pool.ResetDigestRing();
    out.resize(headers.size());
    for (size_t i = 0; i < headers.size(); ++i) {
        if (device_results[i].ok != 1U) {
            out.clear();
            return false;
        }
        out[i].nonce = headers[i].nNonce64;
        out[i].digest = uint256{Span<const unsigned char>{device_results[i].digest,
                                                         sizeof(device_results[i].digest)}};
        out[i].target_match = false;
        out[i].backend_status = matmul::v4::bmx4::DigestOnlyBackendStatus::Ok;
    }
    if (provenance) {
        provenance->qstar_device_batched = headers.size() > 1;
        provenance->device_w_generation = true;
        provenance->device_digest = true;
        provenance->per_nonce_sync_absent = true;
        provenance->mx = ProbeLtHipMxNativeProvenance();
        provenance->mx.exact_mx_scale_partitioned = pool.used_exact_mx_this_batch;
        g_lt_last_mx_provenance = provenance->mx;
    }
    return true;
}

[[nodiscard]] bool MineDeviceResident(const CBlockHeader& tmpl, uint32_t n, uint32_t m,
                                      const uint64_t* nonces, size_t count,
                                      std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    std::vector<CBlockHeader> headers(count, tmpl);
    for (size_t i = 0; i < count; ++i) {
        headers[i].nNonce64 = nonces[i];
        headers[i].nNonce = static_cast<uint32_t>(nonces[i]);
    }
    return MineHeadersDeviceResident(headers, n, m, out, nullptr);
}

[[nodiscard]] bool MineHostExactFallback(const CBlockHeader& tmpl, uint32_t n,
                                         const uint64_t* nonces, size_t count,
                                         bool try_device_gemms,
                                         std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    matmul::v4::lt::ExactGemmBackend backend;
    matmul::v4::lt::ExactMxProjectionBackend mx_proj;
    if (try_device_gemms) {
        backend.gemm_s8s8 = &BackendGemmS8S8;
        backend.gemm_s32s8 = &BackendGemmS32S8;
        mx_proj.project_right = &LaunchProjectedRightMx;
    }
    g_lt_device_gemm_failed = false;
    matmul::v4::lt::WindowSketchMinerLT miner(tmpl, n, backend, mx_proj);
    if (!miner.Valid()) return false;
    const std::vector<uint64_t> nonce_vec(nonces, nonces + count);
    const uint256 kNoTarget = ArithToUint256(~arith_uint256{});
    std::vector<matmul::v4::lt::DigestOnlyResultLT> results;
    if (!miner.Mine(nonce_vec, kNoTarget, results, nullptr)) return false;
    const bool device_served =
        try_device_gemms && miner.UsingDeviceGemms() && !g_lt_device_gemm_failed;
    const auto status = device_served ? matmul::v4::bmx4::DigestOnlyBackendStatus::Ok
                                      : matmul::v4::bmx4::DigestOnlyBackendStatus::Fallback;
    for (auto& r : results) {
        r.target_match = false;
        r.backend_status = status;
    }
    out = std::move(results);
    return true;
}

[[nodiscard]] bool MineHostExactFallbackHeaders(
    const std::vector<CBlockHeader>& headers, uint32_t n, bool try_device_gemms,
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
    const auto status = device_served ? matmul::v4::bmx4::DigestOnlyBackendStatus::Ok
                                      : matmul::v4::bmx4::DigestOnlyBackendStatus::Fallback;
    for (auto& result : results) {
        result.target_match = false;
        result.backend_status = status;
    }
    out = std::move(results);
    return true;
}

} // namespace

bool LaunchGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                    uint32_t rows, uint32_t k, uint32_t cols,
                    std::vector<int32_t>& out)
{
    if (TryLaunchLtMfmaGemmS8S8(left, right, rows, k, cols, out)) {
        g_lt_last_s8s8_mfma = true;
        return true;
    }
    g_lt_last_s8s8_mfma = false;
    if (HipOkLaunchGemmS8S8(left, right, rows, k, cols, out)) return true;
    return TryLaunchLtDeviceAluGemmS8S8(left, right, rows, k, cols, out);
}

bool LaunchGemmS32S8(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
                     uint32_t rows, uint32_t k, uint32_t cols,
                     std::vector<int32_t>& out)
{
    if (TryLaunchLtMfmaGemmS32S8(left, right, rows, k, cols, out)) return true;
    if (HipOkLaunchGemmS32S8(left, right, rows, k, cols, out)) return true;
    return TryLaunchLtDeviceAluGemmS32S8(left, right, rows, k, cols, out);
}

bool LtLastS8S8UsedMfma()
{
    return g_lt_last_s8s8_mfma;
}

matmul::v4::lt::MxLaneProvenance LtLastMxProvenance()
{
    return g_lt_last_mx_provenance;
}

bool LaunchProjectedRightMx(const std::vector<int8_t>& mu, const std::vector<uint8_t>& scales,
                            const std::vector<int8_t>& V, uint32_t n, uint32_t m,
                            std::vector<int32_t>& out,
                            matmul::v4::lt::MxLaneProvenance* provenance)
{
    return LaunchProjectedRightMxImpl(mu, scales, V, n, m, out, provenance);
}

bool IsMatMulLTHipAvailable()
{
    if (!HipDeviceAvailable()) return false;
    return SelfTestGemmKernelsOnce();
}

bool ComputeDigestsOnlyLTHip(const CBlockHeader& tmpl, uint32_t n,
                             const uint64_t* nonces, size_t count,
                             std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    out.clear();
    if (nonces == nullptr || count == 0) return false;
    uint32_t m = 0;
    if (!matmul::v4::lt::ValidateDimsBMX4CLT(n, m)) return false;

    if (IsMatMulLTHipAvailable()) {
        if (MineDeviceResident(tmpl, n, m, nonces, count, out)) return true;
        return MineHostExactFallback(tmpl, n, nonces, count, /*try_device_gemms=*/true, out);
    }
    return MineHostExactFallback(tmpl, n, nonces, count, /*try_device_gemms=*/false, out);
}

bool ComputeDigestsOnlyLTHip(
    const std::vector<CBlockHeader>& headers, uint32_t n,
    std::vector<matmul::v4::lt::DigestOnlyResultLT>& out,
    LtHipBatchProvenance* provenance)
{
    out.clear();
    if (provenance) *provenance = {};
    // Match CUDA's public fail-closed contract: requests larger than the
    // consensus Q* ceiling never enter either device allocation or host
    // fallback paths.
    if (headers.empty() || headers.size() > kMaxConsensusBatch) return false;
    uint32_t m = 0;
    if (!matmul::v4::lt::ValidateDimsBMX4CLT(n, m)) return false;

    if (IsMatMulLTHipAvailable()) {
        if (MineHeadersDeviceResident(headers, n, m, out, provenance)) return true;
        if (provenance) *provenance = {};
        return MineHostExactFallbackHeaders(headers, n, /*try_device_gemms=*/true, out);
    }
    return MineHostExactFallbackHeaders(headers, n, /*try_device_gemms=*/false, out);
}

} // namespace matmul_v4::hip
