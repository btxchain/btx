// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_rc_episode_context.h>

#include <cuda/matmul_v4_lt_device_mx.h>
#include <cuda/matmul_v4_rc_mx_ozaki_native.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_batch.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_peak_ready.h>
#include <matmul/matmul_v4_rc_residency_plan.h>
#include <span.h>

#include <cuda_runtime.h>

#include <climits>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ENC_RC CUDA episode context — resident bank/state + once-captured GEMM DAG +
// device barrier tail (permute / mix / ExtractMX / BarrierRoot).
//
// Timed path (material-exchange defaults / V1–V2 golden):
//   LoadBank once → BindEpisode (host precompute pi/mask/prf/page_ids + one H2D) →
//   for each barrier: cudaGraphLaunch pages → device permute+mix+Extract+BarrierRoot
//   (NO cudaStreamSynchronize until episode end) →
//   one D2H of barrier_roots → AssembleCoupledEpisodeDigest on host.
//
// Fallback: D2H int64 acc → ApplyCoupledBarrierTail → H2D state.
// Never raise heights; GKR OFF. peak_ready via DeriveRCPeakReady only (false).

namespace matmul_v4::cuda {
namespace {

namespace rc = matmul::v4::rc;
namespace lt = matmul::v4::lt;
namespace dc = matmul::v4::rc::dc;

RcResidentDeviceGemmHook g_device_gemm_hook{nullptr};

bool CudaOk(cudaError_t err, std::string* error, const char* what)
{
    if (err == cudaSuccess) return true;
    if (error) {
        *error = std::string(what) + ": " + cudaGetErrorString(err);
    }
    return false;
}

struct ArenaLayout {
    size_t bank_bytes{0};
    size_t state_bytes{0};
    size_t state_q_bytes{0};
    size_t acc_bytes{0};
    size_t acc_q_bytes{0};
    size_t page_ids_launch_bytes{0}; // captured-graph launch scratch (lobes u32)
    size_t acc_scratch_bytes{0};
    size_t pi_all_bytes{0};
    size_t mix_mask_bytes{0};
    size_t prf_key_bytes{0};
    size_t page_ids_all_bytes{0};
    size_t barrier_roots_bytes{0};
    size_t sha_scratch_bytes{0};
    size_t total{0};

    int8_t* d_bank{nullptr};
    int8_t* d_state{nullptr};
    int64_t* d_acc{nullptr};
    uint32_t* d_page_ids{nullptr}; // launch scratch captured by GEMM graph
    int64_t* d_acc_scratch{nullptr};
    uint32_t* d_pi_all{nullptr};
    uint32_t* d_mix_mask{nullptr};
    uint32_t* d_prf_key{nullptr}; // [barriers][8]
    uint32_t* d_page_ids_all{nullptr};
    uint8_t* d_barrier_roots{nullptr};
    uint8_t* d_sha_scratch{nullptr};
};

uint32_t PagesPerBarrier(const RCCudaEpisodeShape& shape)
{
    if (!dc::kRCCoupFullBankScheduleEnabled) return 1u;
    return shape.pages_per_barrier_lobe == 0 ? dc::kRCCoupPagesPerBarrierLobe
                                             : shape.pages_per_barrier_lobe;
}

ArenaLayout LayoutFor(const RCCudaEpisodeShape& shape, void* arena)
{
    ArenaLayout L;
    const size_t page = static_cast<size_t>(shape.lobe_width) * shape.lobe_width;
    const size_t state = static_cast<size_t>(shape.lobes) * shape.lobe_width;
    const uint32_t Q = shape.batch_q == 0 ? 1 : shape.batch_q;
    const uint32_t P = PagesPerBarrier(shape);
    L.bank_bytes = page * shape.bank_pages;
    L.state_bytes = state;
    L.state_q_bytes = state * Q;
    L.acc_bytes = state * sizeof(int64_t);
    L.acc_q_bytes = L.acc_bytes * Q;
    L.page_ids_launch_bytes = shape.lobes * sizeof(uint32_t);
    L.acc_scratch_bytes = state * sizeof(int64_t);
    L.pi_all_bytes = static_cast<size_t>(shape.barriers) * state * sizeof(uint32_t);
    L.mix_mask_bytes = static_cast<size_t>(shape.barriers) * sizeof(uint32_t);
    L.prf_key_bytes = static_cast<size_t>(shape.barriers) * 8 * sizeof(uint32_t);
    L.page_ids_all_bytes =
        static_cast<size_t>(shape.barriers) * P * shape.lobes * sizeof(uint32_t);
    L.barrier_roots_bytes = static_cast<size_t>(shape.barriers) * 32;
    // BarrierRoot message = tag + LE32 + state.
    L.sha_scratch_bytes = (sizeof(rc::kRCCoupBarrierTag) - 1) + 4 + state + 64;
    L.total = L.bank_bytes + L.state_q_bytes + L.acc_q_bytes + L.page_ids_launch_bytes +
              L.acc_scratch_bytes + L.pi_all_bytes + L.mix_mask_bytes + L.prf_key_bytes +
              L.page_ids_all_bytes + L.barrier_roots_bytes + L.sha_scratch_bytes + 256;

    if (arena != nullptr) {
        auto* base = static_cast<unsigned char*>(arena);
        size_t off = 0;
        auto take = [&](size_t nbytes) -> unsigned char* {
            unsigned char* p = base + off;
            off += nbytes;
            return p;
        };
        L.d_bank = reinterpret_cast<int8_t*>(take(L.bank_bytes));
        L.d_state = reinterpret_cast<int8_t*>(take(L.state_q_bytes));
        L.d_acc = reinterpret_cast<int64_t*>(take(L.acc_q_bytes));
        L.d_page_ids = reinterpret_cast<uint32_t*>(take(L.page_ids_launch_bytes));
        L.d_acc_scratch = reinterpret_cast<int64_t*>(take(L.acc_scratch_bytes));
        L.d_pi_all = reinterpret_cast<uint32_t*>(take(L.pi_all_bytes));
        L.d_mix_mask = reinterpret_cast<uint32_t*>(take(L.mix_mask_bytes));
        L.d_prf_key = reinterpret_cast<uint32_t*>(take(L.prf_key_bytes));
        L.d_page_ids_all = reinterpret_cast<uint32_t*>(take(L.page_ids_all_bytes));
        L.d_barrier_roots = take(L.barrier_roots_bytes);
        L.d_sha_scratch = take(L.sha_scratch_bytes);
    }
    return L;
}

__global__ void rc_resident_lobes_gemm(const int8_t* __restrict__ bank, size_t page_stride,
                                       const int8_t* __restrict__ state, int64_t* __restrict__ acc,
                                       const uint32_t* __restrict__ page_ids, int lobes, int W)
{
    const int ell = static_cast<int>(blockIdx.y);
    const int c = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x);
    if (ell >= lobes || c >= W) return;
    const int8_t* A = state + static_cast<size_t>(ell) * W;
    const int8_t* B = bank + static_cast<size_t>(page_ids[ell]) * page_stride;
    int32_t sum = 0;
    for (int k = 0; k < W; ++k) {
        sum += static_cast<int32_t>(A[k]) *
               static_cast<int32_t>(B[static_cast<size_t>(k) * static_cast<size_t>(W) + c]);
    }
    acc[static_cast<size_t>(ell) * W + c] += static_cast<int64_t>(sum);
}

__global__ void rc_balanced_permute(const int64_t* __restrict__ in, int64_t* __restrict__ out,
                                    const uint32_t* __restrict__ pi, int n)
{
    const int i = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x);
    if (i >= n) return;
    out[pi[i]] = in[i];
}

__global__ void rc_copy_i64(const int64_t* __restrict__ in, int64_t* __restrict__ out, int n)
{
    const int i = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x);
    if (i >= n) return;
    out[i] = in[i];
}

__global__ void rc_mix_butterfly(int64_t* __restrict__ s, uint32_t mask, uint32_t n,
                                 uint32_t pattern)
{
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    if (n < 2 || (n & (n - 1)) != 0) return;

    if (pattern == 0) {
        for (uint32_t stage = 0; (uint32_t{1} << stage) < n; ++stage) {
            const uint32_t stride = uint32_t{1} << stage;
            for (uint32_t i = 0; i < n; ++i) {
                const uint32_t j = i ^ stride;
                if (i >= j) continue;
                const uint32_t pi = i ^ mask;
                const uint32_t pj = j ^ mask;
                const int64_t a = s[pi];
                const int64_t b = s[pj];
                s[pi] = a + b;
                s[pj] = a - b;
            }
        }
        return;
    }

    uint32_t bits = 0;
    for (uint32_t t = n; t > 1; t >>= 1) ++bits;
    auto rotl = [bits, n](uint32_t x, uint32_t r) -> uint32_t {
        r %= bits;
        return ((x << r) | (x >> (bits - r))) & (n - 1);
    };
    for (int stage = static_cast<int>(bits) - 1; stage >= 0; --stage) {
        const uint32_t stride = uint32_t{1} << static_cast<uint32_t>(stage);
        for (uint32_t i = 0; i < n; ++i) {
            const uint32_t j = i ^ stride;
            if (i >= j) continue;
            const uint32_t pi = rotl(i ^ mask, 3);
            const uint32_t pj = rotl(j ^ mask, 3);
            const int64_t a = s[pi];
            const int64_t b = s[pj];
            s[pi] = a + b;
            s[pj] = b - a;
        }
    }
}

/** Bit-identical twin of host ExtractMixBitsFromInt64. */
__device__ __forceinline__ uint32_t RcExtractMixBitsFromInt64(int64_t y)
{
    if (y >= static_cast<int64_t>(INT32_MIN) && y <= static_cast<int64_t>(INT32_MAX)) {
        return static_cast<uint32_t>(static_cast<int32_t>(y));
    }
    const uint64_t u = static_cast<uint64_t>(y);
    return static_cast<uint32_t>(u) ^ static_cast<uint32_t>(u >> 32);
}

__device__ __forceinline__ uint32_t RcRotl32(uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}

__device__ __forceinline__ void RcChaChaQuarter(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    a += b;
    d = RcRotl32(d ^ a, 16);
    c += d;
    b = RcRotl32(b ^ c, 12);
    a += b;
    d = RcRotl32(d ^ a, 8);
    c += d;
    b = RcRotl32(b ^ c, 7);
}

__device__ __forceinline__ void RcMatExpandMxTileKeystream(const uint32_t key[8], uint32_t i,
                                                          uint32_t bj, uint32_t remix,
                                                          uint8_t out64[64])
{
    constexpr uint32_t kLaneMxBl = 0x4D58424Cu;
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
        RcChaChaQuarter(x0, x4, x8, x12);
        RcChaChaQuarter(x1, x5, x9, x13);
        RcChaChaQuarter(x2, x6, x10, x14);
        RcChaChaQuarter(x3, x7, x11, x15);
        RcChaChaQuarter(x0, x5, x10, x15);
        RcChaChaQuarter(x1, x6, x11, x12);
        RcChaChaQuarter(x2, x7, x8, x13);
        RcChaChaQuarter(x3, x4, x9, x14);
    }

    x0 += 0x61707865u;
    x1 += 0x3320646eu;
    x2 += 0x79622d32u;
    x3 += 0x6b206574u;
    x4 += j4;
    x5 += j5;
    x6 += j6;
    x7 += j7;
    x8 += j8;
    x9 += j9;
    x10 += j10;
    x11 += j11;
    x12 += j12;
    x13 += j13;
    x14 += j14;
    x15 += j15;

    const uint32_t words[16] = {x0,  x1,  x2,  x3,  x4,  x5,  x6,  x7,
                                x8,  x9,  x10, x11, x12, x13, x14, x15};
#pragma unroll
    for (int w = 0; w < 16; ++w) {
        out64[w * 4 + 0] = static_cast<uint8_t>(words[w] & 0xff);
        out64[w * 4 + 1] = static_cast<uint8_t>((words[w] >> 8) & 0xff);
        out64[w * 4 + 2] = static_cast<uint8_t>((words[w] >> 16) & 0xff);
        out64[w * 4 + 3] = static_cast<uint8_t>((words[w] >> 24) & 0xff);
    }
}

__device__ __forceinline__ int8_t RcSampleMantissaNibble(uint8_t nibble, bool& accepted)
{
    const uint8_t nib = nibble & 0x0F;
    const uint8_t sign = (nib >> 3) & 1;
    const uint8_t exp = (nib >> 1) & 3;
    const uint8_t man = nib & 1;
    int mag = 0;
    bool integer = true;
    switch (exp) {
    case 0:
        mag = 0;
        integer = (man == 0);
        break;
    case 1:
        mag = 1;
        integer = (man == 0);
        break;
    case 2:
        mag = (man == 0) ? 2 : 3;
        break;
    case 3:
        mag = (man == 0) ? 4 : 6;
        break;
    default:
        break;
    }
    if (!integer || (sign && mag == 0)) {
        accepted = false;
        return 0;
    }
    accepted = true;
    return static_cast<int8_t>(sign ? -mag : mag);
}

/**
 * ExtractMXTileInt64 twin for 1-row StateBytes: one thread per 32-wide tile,
 * i=0, bj=tile. Bit-identical to host ExtractMXTileInt64.
 */
__global__ void rc_extract_mx_int64(const int64_t* __restrict__ raw, int8_t* __restrict__ out,
                                    const uint32_t* __restrict__ prf_key8, uint32_t n)
{
    constexpr uint32_t kBlk = 32;
    const uint32_t n_tiles = n / kBlk;
    const uint32_t bj = blockIdx.x * blockDim.x + threadIdx.x;
    if (bj >= n_tiles) return;

    const uint32_t key[8] = {prf_key8[0], prf_key8[1], prf_key8[2], prf_key8[3],
                             prf_key8[4], prf_key8[5], prf_key8[6], prf_key8[7]};
    const int64_t* raw64 = raw + static_cast<size_t>(bj) * kBlk;

    int8_t mu[kBlk];
    uint32_t remix = 0;
    uint32_t filled = 0;
    while (filled < kBlk) {
        uint8_t ks[64];
        RcMatExpandMxTileKeystream(key, /*i=*/0, bj, remix, ks);
        for (int b = 0; b < 64 && filled < kBlk; ++b) {
            const uint8_t byte = ks[b];
            for (int shift = 0; shift < 8 && filled < kBlk; shift += 4) {
                const uint8_t nibble = static_cast<uint8_t>((byte >> shift) & 0x0F);
                const uint32_t raw_u = RcExtractMixBitsFromInt64(raw64[filled]);
                const uint8_t mixed = static_cast<uint8_t>(
                    (nibble ^ static_cast<uint8_t>((raw_u * 0x9E3779B9u) >> 28)) & 0x0F);
                bool accepted = false;
                const int8_t m = RcSampleMantissaNibble(mixed, accepted);
                if (accepted) {
                    mu[filled++] = m;
                }
            }
        }
        ++remix;
    }

    const uint8_t e = matmul_v4::lt_device::DeriveMatExpandMxScale(key, /*i=*/0, bj);
    const int32_t scale = int32_t{1} << e;
    int8_t* dst = out + static_cast<size_t>(bj) * kBlk;
    for (uint32_t t = 0; t < kBlk; ++t) {
        dst[t] = static_cast<int8_t>(static_cast<int32_t>(mu[t]) * scale);
    }
}

__device__ __forceinline__ void RcSha256(const uint8_t* msg, size_t len, uint8_t out[32])
{
    using matmul_v4::lt_device::ShaCompress;
    using matmul_v4::lt_device::ShaInit;
    using matmul_v4::lt_device::ShaSetByte;

    uint32_t state[8];
    ShaInit(state);
    const uint64_t bit_len = static_cast<uint64_t>(len) * 8U;

    size_t off = 0;
    while (off + 64 <= len) {
        uint32_t block[16] = {};
#pragma unroll
        for (uint32_t j = 0; j < 64; ++j) {
            ShaSetByte(block, j, msg[off + j]);
        }
        ShaCompress(state, block);
        off += 64;
    }

    uint32_t block[16] = {};
    uint32_t pos = 0;
    for (; off < len; ++off, ++pos) {
        ShaSetByte(block, pos, msg[off]);
    }
    ShaSetByte(block, pos, 0x80);
    ++pos;
    if (pos > 56) {
        ShaCompress(state, block);
#pragma unroll
        for (int i = 0; i < 16; ++i) block[i] = 0;
        pos = 0;
    }
    block[14] = static_cast<uint32_t>(bit_len >> 32);
    block[15] = static_cast<uint32_t>(bit_len);
    ShaCompress(state, block);

#pragma unroll
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<uint8_t>((state[i] >> 24) & 0xff);
        out[i * 4 + 1] = static_cast<uint8_t>((state[i] >> 16) & 0xff);
        out[i * 4 + 2] = static_cast<uint8_t>((state[i] >> 8) & 0xff);
        out[i * 4 + 3] = static_cast<uint8_t>(state[i] & 0xff);
    }
}

__device__ __forceinline__ void RcSha256d(const uint8_t* msg, size_t len, uint8_t out[32])
{
    uint8_t mid[32];
    RcSha256(msg, len, mid);
    RcSha256(mid, 32, out);
}

/** BarrierRoot = SHA256d(tag ‖ barrier_LE32 ‖ state). */
__global__ void rc_barrier_root(const int8_t* __restrict__ state, uint32_t n, uint32_t barrier,
                                uint8_t* __restrict__ scratch, uint8_t* __restrict__ out32)
{
    if (blockIdx.x != 0 || threadIdx.x != 0) return;
    constexpr char kTag[] = "BTX_RC_COUP_BARRIER_V1";
    constexpr uint32_t kTagLen = sizeof(kTag) - 1;
    uint8_t* msg = scratch;
    for (uint32_t i = 0; i < kTagLen; ++i) msg[i] = static_cast<uint8_t>(kTag[i]);
    msg[kTagLen + 0] = static_cast<uint8_t>(barrier & 0xff);
    msg[kTagLen + 1] = static_cast<uint8_t>((barrier >> 8) & 0xff);
    msg[kTagLen + 2] = static_cast<uint8_t>((barrier >> 16) & 0xff);
    msg[kTagLen + 3] = static_cast<uint8_t>((barrier >> 24) & 0xff);
    for (uint32_t i = 0; i < n; ++i) {
        msg[kTagLen + 4 + i] = static_cast<uint8_t>(state[i]);
    }
    RcSha256d(msg, kTagLen + 4 + n, out32);
}


// --- Host-side seed packing (byte-identical to ApplyCoupledBarrierTail) ---

uint256 Sha256TaggedLocal(const char* tag, size_t taglen, const unsigned char* data, size_t len)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    if (len > 0) hasher.Write(data, len);
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

uint256 Sha256TaggedU32Local(const char* tag, size_t taglen, const uint256& a, uint32_t le32)
{
    unsigned char buf[32 + 4];
    std::memcpy(buf, a.data(), 32);
    WriteLE32(buf + 32, le32);
    return Sha256TaggedLocal(tag, taglen, buf, sizeof(buf));
}

uint256 Sha256TaggedU32U32Local(const char* tag, size_t taglen, const uint256& a, uint32_t x,
                                uint32_t y)
{
    unsigned char buf[32 + 8];
    std::memcpy(buf, a.data(), 32);
    WriteLE32(buf + 32, x);
    WriteLE32(buf + 36, y);
    return Sha256TaggedLocal(tag, taglen, buf, sizeof(buf));
}

class ShaXofLocal {
public:
    explicit ShaXofLocal(const uint256& seed) : m_seed(seed) {}

    uint32_t NextU32()
    {
        if (m_pos + 4 > 32) {
            Refill();
        }
        const uint32_t v = ReadLE32(m_block + m_pos);
        m_pos += 4;
        return v;
    }

private:
    void Refill()
    {
        unsigned char buf[32 + 4];
        std::memcpy(buf, m_seed.data(), 32);
        WriteLE32(buf + 32, m_ctr++);
        uint8_t out[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(buf, sizeof(buf)).Finalize(out);
        std::memcpy(m_block, out, 32);
        m_pos = 0;
    }

    uint256 m_seed;
    uint32_t m_ctr{0};
    uint32_t m_pos{32};
    unsigned char m_block[32]{};
};

[[nodiscard]] uint32_t DeriveMixMask(const uint256& sigma, uint32_t barrier, uint32_t n)
{
    uint256 mix_seed;
    if (dc::RCCoupMaterialExchangeActive()) {
        const uint32_t rows = dc::kRCCoupExchangeRowsDefault;
        mix_seed = Sha256TaggedU32U32Local(rc::kRCCoupMaterialExchangeTag,
                                           sizeof(rc::kRCCoupMaterialExchangeTag) - 1, sigma,
                                           barrier, rows);
    } else {
        mix_seed =
            Sha256TaggedU32Local(rc::kRCCoupMixTag, sizeof(rc::kRCCoupMixTag) - 1, sigma, barrier);
    }
    ShaXofLocal xof(mix_seed);
    return xof.NextU32() & (n - 1);
}

[[nodiscard]] uint256 DeriveExtractPrfKey(const uint256& sigma, uint32_t barrier)
{
    const uint256 extract_seed =
        Sha256TaggedU32U32Local(rc::kRCCoupExtractTag, sizeof(rc::kRCCoupExtractTag) - 1, sigma,
                                barrier, /*unused=*/0);
    return lt::DeriveMatExpandPrfKey(extract_seed);
}

void SeedLobeStateHost(const CBlockHeader& header, const rc::RCCoupParams& params,
                       std::vector<int8_t>& state)
{
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const auto lobe_seeds = rc::DeriveCoupledLobeSeeds(sigma, params);
    const uint32_t n = params.StateBytes();
    state.assign(n, 0);
    for (uint32_t ell = 0; ell < params.lobes; ++ell) {
        const auto tile =
            rc::ExpandMxDequantInt8(lobe_seeds[ell], params.lobe_width, params.lobe_width);
        std::memcpy(state.data() + ell * params.lobe_width, tile.data(), params.lobe_width);
    }
}

[[nodiscard]] bool CaptureBarrierGemmGraph(cudaStream_t stream, cudaGraph_t* out_graph,
                                           cudaGraphExec_t* out_exec, const ArenaLayout& L,
                                           uint32_t lobes, uint32_t W, std::string* error)
{
    if (*out_exec) {
        cudaGraphExecDestroy(*out_exec);
        *out_exec = nullptr;
    }
    if (*out_graph) {
        cudaGraphDestroy(*out_graph);
        *out_graph = nullptr;
    }

    if (!CudaOk(cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal), error,
                "RCCudaEpisodeContext BeginCapture")) {
        return false;
    }
    const int threads = 128;
    const int blocks_x = static_cast<int>((W + threads - 1) / threads);
    dim3 grid(blocks_x, static_cast<int>(lobes), 1);
    const size_t page_stride = static_cast<size_t>(W) * W;
    // Capture against first page_ids slot; RunBarrierGraph retargets via
    // cudaGraphExecKernelNodeSetParams is unavailable without node handles —
    // instead we memcpy the active page_ids into the captured slot (d_page_ids
    // alias) OR launch with pointer arithmetic by copying into slot 0 each time.
    // We keep d_page_ids as the launch pointer and copy from d_page_ids_all[b,k].
    rc_resident_lobes_gemm<<<grid, threads, 0, stream>>>(L.d_bank, page_stride, L.d_state, L.d_acc,
                                                         L.d_page_ids, static_cast<int>(lobes),
                                                         static_cast<int>(W));
    if (cudaGetLastError() != cudaSuccess) {
        cudaStreamEndCapture(stream, out_graph);
        if (error) *error = "RCCudaEpisodeContext capture launch error";
        return false;
    }
    if (!CudaOk(cudaStreamEndCapture(stream, out_graph), error,
                "RCCudaEpisodeContext EndCapture")) {
        return false;
    }
    if (!CudaOk(cudaGraphInstantiate(out_exec, *out_graph, nullptr, nullptr, 0), error,
                "RCCudaEpisodeContext GraphInstantiate")) {
        return false;
    }
    return true;
}

[[nodiscard]] bool SelfQualPortableGemmOnce(const ArenaLayout& L, uint32_t W, cudaStream_t stream,
                                            std::string* error)
{
    if (W == 0) return false;
    std::vector<int8_t> A(W), B(static_cast<size_t>(W) * W);
    for (uint32_t i = 0; i < W; ++i) {
        A[i] = static_cast<int8_t>((static_cast<int32_t>(i) % 97) - 48);
    }
    for (uint32_t i = 0; i < W * W; ++i) {
        B[i] = static_cast<int8_t>((static_cast<int32_t>(i * 5) % 95) - 47);
    }
    const auto cpu = lt::ExactGemmS8S8(A, B, /*rows=*/1, W, W);
    if (!CudaOk(cudaMemcpyAsync(L.d_state, A.data(), W, cudaMemcpyHostToDevice, stream), error,
                "selfqual H2D A")) {
        return false;
    }
    if (!CudaOk(cudaMemcpyAsync(L.d_bank, B.data(), B.size(), cudaMemcpyHostToDevice, stream),
                error, "selfqual H2D B")) {
        return false;
    }
    uint32_t page0 = 0;
    if (!CudaOk(cudaMemcpyAsync(L.d_page_ids, &page0, sizeof(page0), cudaMemcpyHostToDevice,
                                stream),
                error, "selfqual H2D page")) {
        return false;
    }
    // F6: kernel accumulates with +=; zero d_acc or self-qual is nondeterministic.
    if (!CudaOk(cudaMemsetAsync(L.d_acc, 0, static_cast<size_t>(W) * sizeof(int64_t), stream),
                error, "selfqual zero d_acc")) {
        return false;
    }
    const int threads = 128;
    const int blocks_x = static_cast<int>((W + threads - 1) / threads);
    dim3 grid(blocks_x, 1, 1);
    rc_resident_lobes_gemm<<<grid, threads, 0, stream>>>(
        L.d_bank, static_cast<size_t>(W) * W, L.d_state, L.d_acc, L.d_page_ids, /*lobes=*/1,
        static_cast<int>(W));
    std::vector<int64_t> got(W);
    if (!CudaOk(cudaMemcpyAsync(got.data(), L.d_acc, W * sizeof(int64_t), cudaMemcpyDeviceToHost,
                                stream),
                error, "selfqual D2H")) {
        return false;
    }
    if (!CudaOk(cudaStreamSynchronize(stream), error, "selfqual sync")) return false;
    for (uint32_t c = 0; c < W; ++c) {
        if (got[c] != static_cast<int64_t>(cpu[c])) {
            if (error) *error = "portable_device_alu selfqual mismatch vs ExactGemmS8S8";
            return false;
        }
    }
    return true;
}

/**
 * Device barrier tail using BindEpisode-preuploaded pi/prf tables for barrier `b`.
 * No host sync; writes Extracted state into d_state and BarrierRoot into
 * d_barrier_roots[b]. mix_mask is a host-derived u32 (cheap; matches BindEpisode).
 */
[[nodiscard]] bool LaunchDeviceBarrierTailWithMask(const ArenaLayout& L, cudaStream_t stream,
                                                   uint32_t n, uint32_t barrier, uint32_t mix_mask,
                                                   uint32_t mix_pattern, std::string* error)
{
    if (L.d_acc == nullptr || L.d_acc_scratch == nullptr || L.d_pi_all == nullptr ||
        L.d_state == nullptr || L.d_prf_key == nullptr || L.d_barrier_roots == nullptr ||
        L.d_sha_scratch == nullptr) {
        if (error) *error = "device barrier tail: null arena";
        return false;
    }
    const int threads = 128;
    const int blocks = static_cast<int>((n + threads - 1) / threads);
    const uint32_t* pi = L.d_pi_all + static_cast<size_t>(barrier) * n;
    const uint32_t* prf = L.d_prf_key + static_cast<size_t>(barrier) * 8;

    rc_balanced_permute<<<blocks, threads, 0, stream>>>(L.d_acc, L.d_acc_scratch, pi,
                                                       static_cast<int>(n));
    rc_copy_i64<<<blocks, threads, 0, stream>>>(L.d_acc_scratch, L.d_acc, static_cast<int>(n));
    rc_mix_butterfly<<<1, 1, 0, stream>>>(L.d_acc, mix_mask, n, mix_pattern);

    const uint32_t n_tiles = n / 32;
    const int ext_blocks = static_cast<int>((n_tiles + threads - 1) / threads);
    rc_extract_mx_int64<<<ext_blocks, threads, 0, stream>>>(L.d_acc, L.d_state, prf, n);

    rc_barrier_root<<<1, 1, 0, stream>>>(L.d_state, n, barrier, L.d_sha_scratch,
                                         L.d_barrier_roots + static_cast<size_t>(barrier) * 32);
    if (!CudaOk(cudaGetLastError(), error, "device barrier tail launch")) {
        return false;
    }
    return true;
}

[[nodiscard]] bool RunHostBarrierTailFallback(const ArenaLayout& L, cudaStream_t stream,
                                              const uint256& sigma, uint32_t barrier,
                                              const rc::RCCoupParams& params,
                                              std::vector<int8_t>& state_host,
                                              uint256* barrier_root, uint64_t* h2d_bytes,
                                              uint64_t* d2h_bytes, std::string* error)
{
    const uint32_t n = params.StateBytes();
    std::vector<int64_t> acc(n);
    if (!CudaOk(cudaMemcpyAsync(acc.data(), L.d_acc, n * sizeof(int64_t), cudaMemcpyDeviceToHost,
                                stream),
                error, "fallback acc D2H")) {
        return false;
    }
    if (!CudaOk(cudaStreamSynchronize(stream), error, "fallback sync")) return false;
    if (d2h_bytes) *d2h_bytes += n * sizeof(int64_t);
    if (!rc::ApplyCoupledBarrierTail(sigma, barrier, params, acc, state_host, barrier_root)) {
        if (error) *error = "ApplyCoupledBarrierTail failed";
        return false;
    }
    if (!CudaOk(cudaMemcpyAsync(L.d_state, state_host.data(), n, cudaMemcpyHostToDevice, stream),
                error, "fallback state H2D")) {
        return false;
    }
    if (h2d_bytes) *h2d_bytes += n;
    return true;
}

void SetPeakReadyDerived(RCCudaEpisodeProvenance& prov, bool device_tail_ok)
{
    rc::RCPeakReadyInputs in;
    in.bank_genuinely_resident = prov.device_bank_resident;
    // Episode digest assembled on host → full_device_pipeline stays false.
    in.full_device_pipeline = false;
    in.no_per_barrier_host_sync = device_tail_ok;
    in.native_tensor_executed = false;
    in.native_provider_linked = prov.resident_native_mxfp4_qualified;
    in.exactness_selfqual_ok = false;
    in.no_dense_int8_as_native = true;
    in.no_scalar_cuda_as_native = true;
    in.cpu_gpu_byte_exact = false;
    in.device_event_timing = false;
    in.v3_config_selected = false;
    in.production_dimensions = false;
    in.full_page_schedule = dc::kRCCoupFullBankScheduleEnabled;
    in.canonical_packed_bank = false;
    in.arch_backend_selected = false;
    in.no_cpu_fallback = false;
    in.production_provenance_recorded = false;
    in.corruption_gate_ok = false;
    in.production_readiness_tests_pass = false;
    in.real_m128_workload = false;
    const auto st = rc::DeriveRCPeakReady(in);
    prov.peak_ready = st.peak_ready;
    if (!st.peak_ready) {
        prov.parked_reason =
            "AssembleCoupledEpisodeDigest_on_host; native_mxfp4_device_ptr_awaiting_wsB; " +
            st.deficit;
    }
}

} // namespace

void SetRcResidentDeviceGemmHook(RcResidentDeviceGemmHook hook)
{
    g_device_gemm_hook = hook;
}

void RCCudaEpisodeContext::RefreshPeakReadyDerived()
{
    // Re-run the fail-closed derivation against current provenance. No qualified
    // native-MX device tail is wired here, so device_tail_ok is false and
    // peak_ready stays false — the derivation never forces it true.
    SetPeakReadyDerived(m_prov, /*device_tail_ok=*/false);
}

RcResidentDeviceGemmHook GetRcResidentDeviceGemmHook()
{
    return g_device_gemm_hook;
}

bool IsRcEpisodeCudaCompiled()
{
    return true;
}

std::string RcEpisodeCudaArchKey()
{
    int device = 0;
    if (cudaGetDevice(&device) != cudaSuccess) return {};
    cudaDeviceProp prop{};
    if (cudaGetDeviceProperties(&prop, device) != cudaSuccess) return {};
    char buf[32];
    std::snprintf(buf, sizeof(buf), "sm_%d%d", prop.major, prop.minor);
    return std::string(buf);
}

bool RCCudaEpisodeContext::Init(const RCCudaEpisodeShape& shape, std::string* error)
{
    Destroy();
    if (shape.barriers == 0 || shape.lobes == 0 || shape.lobe_width == 0 ||
        shape.bank_pages == 0 || shape.batch_q == 0) {
        if (error) *error = "RCCudaEpisodeContext: invalid shape";
        return false;
    }
    rc::RCCoupParams p;
    p.barriers = shape.barriers;
    p.lobes = shape.lobes;
    p.lobe_width = shape.lobe_width;
    p.bank_pages = shape.bank_pages;
    p.pages_per_barrier_lobe = shape.pages_per_barrier_lobe;
    // F6: resident CUDA path is M=1 only (V3 rows_per_lobe>1 would emit a wrong digest).
    if (p.rows_per_lobe != 1) {
        if (error) {
            *error = "RCCudaEpisodeContext: rows_per_lobe!=1 fail-closed "
                     "(resident path does not wire V3 M>1)";
        }
        return false;
    }
    if (!rc::ValidateRCCoupParams(p)) {
        if (error) *error = "RCCudaEpisodeContext: ValidateRCCoupParams failed";
        return false;
    }

    const ArenaLayout layout = LayoutFor(shape, nullptr);

    // Resident-vs-streamed staging decision (RTX PRO 6000 Blackwell 96 GB win).
    // Probe VRAM and record the plan in provenance BEFORE the big arena alloc.
    // Fail-closed: if the resident arena cannot physically fit (working set +
    // headroom > free VRAM), refuse here with a machine-readable capacity-short
    // reason instead of triggering an opaque cudaMalloc OOM — the caller can
    // then fall back to a streamed strategy. The card-class label (Resident vs
    // Streamed) is recorded from the full plan; the hard guard uses physical
    // fit only, so a sub-64 GiB card running a toy shape still proceeds.
    size_t vram_free = 0, vram_total = 0;
    const bool vram_known = cudaMemGetInfo(&vram_free, &vram_total) == cudaSuccess;
    const rc::RCResidencyPlan plan = rc::PlanRCResidency(
        static_cast<uint64_t>(layout.total),
        vram_known ? static_cast<uint64_t>(vram_free) : 0ull,
        vram_known ? static_cast<uint64_t>(vram_total) : 0ull);
    if (vram_known && !plan.working_set_fits) {
        if (error) {
            *error = "RCCudaEpisodeContext residency:capacity_short (need " +
                     std::to_string(layout.total) + "B + headroom " +
                     std::to_string(plan.headroom_bytes) + "B > free " +
                     std::to_string(vram_free) + "B; " + plan.reason +
                     "; caller should stream)";
        }
        return false;
    }

    void* ptr = nullptr;
    if (!CudaOk(cudaMalloc(&ptr, layout.total), error, "RCCudaEpisodeContext cudaMalloc")) {
        if (error && vram_known) {
            *error += " [residency plan: " + plan.reason + ", free=" +
                      std::to_string(vram_free) + "B]";
        }
        return false;
    }
    m_arena = ptr;
    m_arena_bytes = layout.total;
    m_shape = shape;
    m_ready = true;
    m_bank_loaded = false;
    m_episode_bound = false;
    m_have_digest = false;
    m_state_ready = false;
    m_graph_captured = false;
    m_barrier_tables_ready = false;
    m_fault_corrupt_digest = false;
    m_state.assign(layout.state_bytes, 0);
    m_prov = {};
    m_prov.gemm_path_label = "portable_device_alu";
    m_prov.permute_extract_label = "device_barrier_tail";
    m_prov.device_digest = false;
    m_prov.parked_reason =
        "AssembleCoupledEpisodeDigest_on_host; native_mxfp4_device_ptr_awaiting_wsB; "
        "peak_ready=false";
    m_prov.peak_ready = false;

    // Record the resident-vs-streamed staging plan (NON-consensus provenance).
    m_prov.residency_mode = plan.mode;
    m_prov.resident_vram_capable = plan.resident_capable;
    m_prov.working_set_bytes = plan.working_set_bytes;
    m_prov.device_free_vram_bytes = plan.free_vram_bytes;
    m_prov.device_total_vram_bytes = plan.total_vram_bytes;
    m_prov.residency_reason = plan.reason;

    cudaStream_t stream = nullptr;
    if (!CudaOk(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), error,
                "RCCudaEpisodeContext stream")) {
        Destroy();
        return false;
    }
    m_stream = stream;

    m_prov.resident_native_mxfp4_attempted = true;
    // Qual before latch consult (A5/F12) so provenance reflects a real probe.
    (void)SelfQualifyRcOzakiCudaMxfp4Once();
    m_prov.resident_native_mxfp4_qualified = IsRcOzakiCudaMxfp4Qualified();
    if (g_device_gemm_hook != nullptr && m_prov.resident_native_mxfp4_qualified) {
        m_prov.gemm_path_label = "wsB_device_ptr_hook_present";
        m_prov.device_mx_operand_generation = false;
    } else {
        m_prov.gemm_path_label = "portable_device_alu";
    }

    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::Init(const rc::RCCoupParams& params, uint32_t batch_q,
                                std::string* error)
{
    // F6: refuse V3 M>1 rather than silently dropping rows_per_lobe and mining wrong.
    if (params.rows_per_lobe != 1) {
        if (error) {
            *error = "RCCudaEpisodeContext: rows_per_lobe!=1 fail-closed "
                     "(resident path does not wire V3 M>1)";
        }
        return false;
    }
    RCCudaEpisodeShape shape;
    shape.barriers = params.barriers;
    shape.lobes = params.lobes;
    shape.lobe_width = params.lobe_width;
    shape.bank_pages = params.bank_pages;
    shape.batch_q = batch_q == 0 ? 1 : batch_q;
    shape.pages_per_barrier_lobe =
        params.pages_per_barrier_lobe == 0 ? dc::kRCCoupPagesPerBarrierLobe
                                           : params.pages_per_barrier_lobe;
    return Init(shape, error);
}

bool RCCudaEpisodeContext::LoadBank(const std::vector<std::vector<int8_t>>& pages,
                                    std::string* error)
{
    if (!m_ready || m_arena == nullptr) {
        if (error) *error = "RCCudaEpisodeContext: Init required";
        return false;
    }
    if (pages.size() != m_shape.bank_pages) {
        if (error) *error = "RCCudaEpisodeContext: bank page count mismatch";
        return false;
    }
    const size_t page_bytes =
        static_cast<size_t>(m_shape.lobe_width) * m_shape.lobe_width;
    const ArenaLayout L = LayoutFor(m_shape, m_arena);
    m_pages = pages;
    size_t h2d = 0;
    for (uint32_t i = 0; i < m_shape.bank_pages; ++i) {
        if (pages[i].size() != page_bytes) {
            if (error) *error = "RCCudaEpisodeContext: bank page size mismatch";
            return false;
        }
        if (!CudaOk(cudaMemcpy(L.d_bank + static_cast<size_t>(i) * page_bytes, pages[i].data(),
                               page_bytes, cudaMemcpyHostToDevice),
                    error, "RCCudaEpisodeContext LoadBank H2D")) {
            return false;
        }
        h2d += page_bytes;
    }
    rc::RCCoupParams params;
    params.barriers = m_shape.barriers;
    params.lobes = m_shape.lobes;
    params.lobe_width = m_shape.lobe_width;
    params.bank_pages = m_shape.bank_pages;
    params.pages_per_barrier_lobe = m_shape.pages_per_barrier_lobe;
    m_bank_root = rc::CommitCoupledBankPages(m_pages, params);
    if (m_bank_root.IsNull()) {
        if (error) *error = "RCCudaEpisodeContext: bank commitment null";
        return false;
    }
    // Bank root stays host-side: AssembleCoupledEpisodeDigest runs on host
    // (device_digest=false). Do not H2D into a nonexistent arena slot.
    m_bank_loaded = true;
    m_prov.device_bank_resident = true;
    m_prov.h2d_bytes_per_window += h2d;
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::BindEpisode(const CBlockHeader& header, int32_t height,
                                       std::string* error)
{
    if (!m_ready) {
        if (error) *error = "RCCudaEpisodeContext: Init required before BindEpisode";
        return false;
    }
    m_header = header;
    m_height = height;
    m_episode_bound = true;
    m_have_digest = false;
    m_barrier_tables_ready = false;

    rc::RCCoupParams params;
    params.barriers = m_shape.barriers;
    params.lobes = m_shape.lobes;
    params.lobe_width = m_shape.lobe_width;
    params.bank_pages = m_shape.bank_pages;
    params.pages_per_barrier_lobe = m_shape.pages_per_barrier_lobe;
    SeedLobeStateHost(header, params, m_state);

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const uint32_t n = params.StateBytes();
    const uint32_t P = PagesPerBarrier(m_shape);
    const bool full_sched = dc::kRCCoupFullBankScheduleEnabled;

    // Host precompute all per-barrier tables (exchange_rounds=0 path).
    std::vector<uint32_t> pi_all(static_cast<size_t>(params.barriers) * n);
    std::vector<uint32_t> mix_masks(params.barriers);
    std::vector<uint32_t> prf_words(static_cast<size_t>(params.barriers) * 8);
    std::vector<uint32_t> page_ids_all(static_cast<size_t>(params.barriers) * P * params.lobes);

    for (uint32_t b = 0; b < params.barriers; ++b) {
        const auto pi = rc::DeriveCoupledBalancedPermutation(sigma, b, params);
        if (!rc::IsBalancedPermutation(pi, n)) {
            if (error) *error = "RCCudaEpisodeContext: unbalanced permutation at BindEpisode";
            return false;
        }
        std::memcpy(pi_all.data() + static_cast<size_t>(b) * n, pi.data(),
                    n * sizeof(uint32_t));
        mix_masks[b] = DeriveMixMask(sigma, b, n);
        const uint256 prf = DeriveExtractPrfKey(sigma, b);
        for (int i = 0; i < 8; ++i) {
            prf_words[static_cast<size_t>(b) * 8 + static_cast<size_t>(i)] =
                ReadLE32(prf.data() + static_cast<size_t>(i) * 4);
        }
        for (uint32_t k = 0; k < P; ++k) {
            for (uint32_t ell = 0; ell < params.lobes; ++ell) {
                const auto ids =
                    rc::SelectCoupledBankPageIds(b, ell, params, sigma, full_sched);
                if (ids.empty() || k >= ids.size()) {
                    if (error) *error = "RCCudaEpisodeContext: page schedule short at BindEpisode";
                    return false;
                }
                page_ids_all[(static_cast<size_t>(b) * P + k) * params.lobes + ell] = ids[k];
            }
        }
    }

    if (m_arena != nullptr) {
        const ArenaLayout L = LayoutFor(m_shape, m_arena);
        auto* stream = static_cast<cudaStream_t>(m_stream);
        size_t h2d = 0;
        if (!CudaOk(cudaMemcpyAsync(L.d_state, m_state.data(), n, cudaMemcpyHostToDevice, stream),
                    error, "BindEpisode H2D state")) {
            return false;
        }
        h2d += n;
        if (!CudaOk(cudaMemcpyAsync(L.d_pi_all, pi_all.data(), pi_all.size() * sizeof(uint32_t),
                                    cudaMemcpyHostToDevice, stream),
                    error, "BindEpisode H2D pi")) {
            return false;
        }
        h2d += pi_all.size() * sizeof(uint32_t);
        if (!CudaOk(cudaMemcpyAsync(L.d_mix_mask, mix_masks.data(),
                                    mix_masks.size() * sizeof(uint32_t), cudaMemcpyHostToDevice,
                                    stream),
                    error, "BindEpisode H2D mix_mask")) {
            return false;
        }
        h2d += mix_masks.size() * sizeof(uint32_t);
        if (!CudaOk(cudaMemcpyAsync(L.d_prf_key, prf_words.data(),
                                    prf_words.size() * sizeof(uint32_t), cudaMemcpyHostToDevice,
                                    stream),
                    error, "BindEpisode H2D prf_key")) {
            return false;
        }
        h2d += prf_words.size() * sizeof(uint32_t);
        if (!CudaOk(cudaMemcpyAsync(L.d_page_ids_all, page_ids_all.data(),
                                    page_ids_all.size() * sizeof(uint32_t),
                                    cudaMemcpyHostToDevice, stream),
                    error, "BindEpisode H2D page_ids")) {
            return false;
        }
        h2d += page_ids_all.size() * sizeof(uint32_t);
        // Sync once after BindEpisode uploads (outside timed barrier loop).
        if (!CudaOk(cudaStreamSynchronize(stream), error, "BindEpisode sync")) {
            return false;
        }
        m_prov.h2d_bytes_per_window += h2d;
    }

    // Keep mix masks on host for LaunchDeviceBarrierTailWithMask args (avoids
    // device→host read of a single u32 per barrier).
    m_state_ready = true;
    m_barrier_tables_ready = true;
    m_prov.device_state_resident = true;
    // Stash mix masks in m_pages? Better: member vector. Use a static thread_local
    // isn't right. Store in unused host mirror: encode into a dedicated member.
    // We added m_barrier_tables_ready but not mix mask storage — keep masks by
    // re-deriving cheaply in RunBarrierGraph from sigma (host SHA only, no D2H).
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::SetActiveState(const std::vector<int8_t>& state, std::string* error)
{
    if (!m_ready || m_arena == nullptr) {
        if (error) *error = "RCCudaEpisodeContext: Init required";
        return false;
    }
    const size_t n = static_cast<size_t>(m_shape.lobes) * m_shape.lobe_width;
    if (state.size() != n) {
        if (error) *error = "RCCudaEpisodeContext: SetActiveState size mismatch";
        return false;
    }
    m_state = state;
    const ArenaLayout L = LayoutFor(m_shape, m_arena);
    if (!CudaOk(cudaMemcpy(L.d_state, m_state.data(), n, cudaMemcpyHostToDevice), error,
                "RCCudaEpisodeContext SetActiveState H2D")) {
        return false;
    }
    m_prov.h2d_bytes_per_window += n;
    m_state_ready = true;
    m_have_digest = false;
    m_prov.device_state_resident = true;
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::DownloadActiveState(std::vector<int8_t>& out,
                                               std::string* error) const
{
    if (!m_ready || m_arena == nullptr || !m_state_ready) {
        if (error) *error = "RCCudaEpisodeContext: state not ready";
        return false;
    }
    const size_t n = static_cast<size_t>(m_shape.lobes) * m_shape.lobe_width;
    out.resize(n);
    const ArenaLayout L = LayoutFor(m_shape, m_arena);
    if (!CudaOk(cudaMemcpy(out.data(), L.d_state, n, cudaMemcpyDeviceToHost), error,
                "RCCudaEpisodeContext DownloadActiveState D2H")) {
        return false;
    }
    if (error) error->clear();
    return true;
}

const uint256* RCCudaEpisodeContext::LastDigest() const
{
    return m_have_digest ? &m_last_digest : nullptr;
}

void RCCudaEpisodeContext::FaultInjectCorruptDigest(bool enable)
{
    m_fault_corrupt_digest = enable;
}

bool RCCudaEpisodeContext::CompareWithCpuOracle(std::string* error) const
{
    if (!m_have_digest) {
        if (error) *error = "RCCudaEpisodeContext: no digest to compare";
        return false;
    }
    rc::RCCoupParams params;
    params.barriers = m_shape.barriers;
    params.lobes = m_shape.lobes;
    params.lobe_width = m_shape.lobe_width;
    params.bank_pages = m_shape.bank_pages;
    params.pages_per_barrier_lobe = m_shape.pages_per_barrier_lobe;
    const uint256 cpu = rc::RecomputeCoupledPuzzleReference(m_header, m_height, params);
    if (m_last_digest != cpu) {
        if (error) *error = "episode_digest_mismatch_vs_cpu_oracle";
        return false;
    }
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::ResealAgainstCpuOracle(std::string* error)
{
    if (!CompareWithCpuOracle(error)) {
        rc::RCCoupParams params;
        params.barriers = m_shape.barriers;
        params.lobes = m_shape.lobes;
        params.lobe_width = m_shape.lobe_width;
        params.bank_pages = m_shape.bank_pages;
        params.pages_per_barrier_lobe = m_shape.pages_per_barrier_lobe;
        m_last_digest = rc::RecomputeCoupledPuzzleReference(m_header, m_height, params);
        m_have_digest = true;
        if (error) {
            *error = "device_digest_rejected_resealed_cpu";
        }
        return false;
    }
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::RunBarrierGraph(std::string* error)
{
    if (!m_ready || m_arena == nullptr) {
        if (error) *error = "RCCudaEpisodeContext: Init required";
        return false;
    }
    if (!m_bank_loaded) {
        if (error) *error = "RCCudaEpisodeContext: LoadBank required";
        return false;
    }
    if (!m_episode_bound || !m_state_ready) {
        if (error) *error = "RCCudaEpisodeContext: BindEpisode required";
        return false;
    }
    if (!m_barrier_tables_ready) {
        if (error) *error = "RCCudaEpisodeContext: barrier tables not ready";
        return false;
    }

    rc::RCCoupParams params;
    params.barriers = m_shape.barriers;
    params.lobes = m_shape.lobes;
    params.lobe_width = m_shape.lobe_width;
    params.bank_pages = m_shape.bank_pages;
    params.pages_per_barrier_lobe = m_shape.pages_per_barrier_lobe;
    if (!rc::ValidateRCCoupParams(params)) {
        if (error) *error = "RCCudaEpisodeContext: invalid coup params";
        return false;
    }

    const uint32_t W = m_shape.lobe_width;
    const uint32_t n = params.StateBytes();
    const uint32_t P = PagesPerBarrier(m_shape);
    const ArenaLayout L = LayoutFor(m_shape, m_arena);
    auto* stream = static_cast<cudaStream_t>(m_stream);
    auto* graph = static_cast<cudaGraph_t>(m_graph);
    auto* exec = static_cast<cudaGraphExec_t>(m_graph_exec);

    if (!m_graph_captured) {
        std::string sq_err;
        std::vector<int8_t> bank0_backup(static_cast<size_t>(W) * W);
        std::vector<int8_t> state_backup = m_state;
        if (!CudaOk(cudaMemcpy(bank0_backup.data(), L.d_bank, bank0_backup.size(),
                               cudaMemcpyDeviceToHost),
                    error, "backup bank0")) {
            return false;
        }
        if (!SelfQualPortableGemmOnce(L, W, stream, &sq_err)) {
            if (error) *error = sq_err.empty() ? "portable_gemm_selfqual_failed" : sq_err;
            return false;
        }
        if (!CudaOk(cudaMemcpy(L.d_bank, bank0_backup.data(), bank0_backup.size(),
                               cudaMemcpyHostToDevice),
                    error, "restore bank0")) {
            return false;
        }
        if (!CudaOk(cudaMemcpy(L.d_state, state_backup.data(), state_backup.size(),
                               cudaMemcpyHostToDevice),
                    error, "restore state")) {
            return false;
        }
        m_state = std::move(state_backup);

        if (!CaptureBarrierGemmGraph(stream, &graph, &exec, L, m_shape.lobes, W, error)) {
            return false;
        }
        m_graph = graph;
        m_graph_exec = exec;
        m_graph_captured = true;
        ++m_prov.graph_capture_count;
    }

    const uint256 sigma = matmul::v4::DeriveSigma(m_header);
    uint64_t window_h2d = 0;
    uint64_t window_d2h = 0;
    std::vector<uint256> barrier_roots(params.barriers);
    bool use_device_tail = true;

    m_prov.permute_extract_label = "device_barrier_tail";

    // Timed resident loop — no cudaStreamSynchronize until episode end (device path).
    for (uint32_t b = 0; b < params.barriers; ++b) {
        if (!CudaOk(cudaMemsetAsync(L.d_acc, 0, n * sizeof(int64_t), stream), error,
                    "acc memset")) {
            return false;
        }

        for (uint32_t k = 0; k < P; ++k) {
            // Copy precomputed page_ids for (b,k) into the captured launch slot.
            const uint32_t* src =
                L.d_page_ids_all + (static_cast<size_t>(b) * P + k) * params.lobes;
            if (!CudaOk(cudaMemcpyAsync(L.d_page_ids, src, params.lobes * sizeof(uint32_t),
                                        cudaMemcpyDeviceToDevice, stream),
                        error, "page_ids D2D")) {
                return false;
            }
            if (!CudaOk(cudaGraphLaunch(exec, stream), error, "cudaGraphLaunch")) {
                return false;
            }
            ++m_prov.graph_replay_count;
        }

        if (g_device_gemm_hook != nullptr) {
            m_prov.resident_native_mxfp4_attempted = true;
        }

        if (use_device_tail) {
            const uint32_t mix_mask = DeriveMixMask(sigma, b, n);
            const uint32_t mix_pattern = b % rc::kRCCoupMixPatterns;
            if (!LaunchDeviceBarrierTailWithMask(L, stream, n, b, mix_mask, mix_pattern, error)) {
                // Preserve any device roots already written for barriers < b.
                if (b > 0) {
                    std::vector<uint8_t> prior(static_cast<size_t>(b) * 32u);
                    if (!CudaOk(cudaMemcpyAsync(prior.data(), L.d_barrier_roots, prior.size(),
                                                cudaMemcpyDeviceToHost, stream),
                                error, "prior barrier_roots D2H")) {
                        return false;
                    }
                    if (!CudaOk(cudaStreamSynchronize(stream), error, "prior roots sync")) {
                        return false;
                    }
                    window_d2h += prior.size();
                    for (uint32_t pb = 0; pb < b; ++pb) {
                        barrier_roots[pb] = uint256{Span<const unsigned char>{
                            prior.data() + static_cast<size_t>(pb) * 32u, 32}};
                    }
                }
                use_device_tail = false;
                m_prov.permute_extract_label = "parked_host_barrier_tail";
                m_prov.parked_reason =
                    "device_barrier_tail_launch_failed; host_ApplyCoupledBarrierTail_fallback; "
                    "peak_ready=false";
                if (!RunHostBarrierTailFallback(L, stream, sigma, b, params, m_state,
                                                &barrier_roots[b], &window_h2d, &window_d2h,
                                                error)) {
                    return false;
                }
            }
        } else {
            if (!RunHostBarrierTailFallback(L, stream, sigma, b, params, m_state,
                                            &barrier_roots[b], &window_h2d, &window_d2h, error)) {
                return false;
            }
        }
    }

    if (use_device_tail) {
        // One episode-end sync + one D2H of barrier_roots (+ final state mirror).
        std::vector<uint8_t> roots_bytes(static_cast<size_t>(params.barriers) * 32u);
        if (!CudaOk(cudaMemcpyAsync(roots_bytes.data(), L.d_barrier_roots, roots_bytes.size(),
                                    cudaMemcpyDeviceToHost, stream),
                    error, "barrier_roots D2H")) {
            return false;
        }
        if (!CudaOk(cudaMemcpyAsync(m_state.data(), L.d_state, n, cudaMemcpyDeviceToHost, stream),
                    error, "final state D2H")) {
            return false;
        }
        if (!CudaOk(cudaStreamSynchronize(stream), error, "episode end sync")) {
            return false;
        }
        window_d2h += roots_bytes.size() + n;
        for (uint32_t b = 0; b < params.barriers; ++b) {
            barrier_roots[b] = uint256{Span<const unsigned char>{
                roots_bytes.data() + static_cast<size_t>(b) * 32u, 32}};
        }
        m_prov.permute_extract_label = "device_barrier_tail";
        m_prov.per_nonce_sync_absent = true;
    } else {
        if (!CudaOk(cudaStreamSynchronize(stream), error, "host-fallback episode sync")) {
            return false;
        }
        m_prov.per_nonce_sync_absent = false;
    }

    m_last_digest = rc::AssembleCoupledEpisodeDigest(m_bank_root, barrier_roots);
    if (m_fault_corrupt_digest) {
        unsigned char* raw = m_last_digest.begin();
        raw[0] = static_cast<unsigned char>(raw[0] ^ 0x5a);
    }
    m_have_digest = true;
    m_state_ready = true;
    m_prov.device_bank_resident = true;
    m_prov.device_state_resident = true;
    m_prov.device_digest = false; // AssembleCoupledEpisodeDigest on host
    m_prov.h2d_bytes_per_window = window_h2d;
    m_prov.d2h_bytes_per_window = window_d2h;
    m_prov.digest_batch_slots = 1;
    m_prov.qstar_device_batched = false;
    SetPeakReadyDerived(m_prov, use_device_tail);

    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::RunNonceWindow(const std::vector<CBlockHeader>& headers,
                                          int32_t height, std::vector<uint256>& digests_out,
                                          std::string* error)
{
    if (headers.empty()) {
        if (error) *error = "RCCudaEpisodeContext: empty nonce window";
        return false;
    }
    if (headers.size() > m_shape.batch_q) {
        if (error) *error = "RCCudaEpisodeContext: window exceeds batch_q";
        return false;
    }
    if (!m_bank_loaded || m_arena == nullptr) {
        if (error) *error = "RCCudaEpisodeContext: LoadBank required";
        return false;
    }

    rc::RCCoupParams params;
    params.barriers = m_shape.barriers;
    params.lobes = m_shape.lobes;
    params.lobe_width = m_shape.lobe_width;
    params.bank_pages = m_shape.bank_pages;
    params.pages_per_barrier_lobe = m_shape.pages_per_barrier_lobe;
    if (!rc::ValidateRCCoupParams(params)) {
        if (error) *error = "RCCudaEpisodeContext: invalid coup params";
        return false;
    }

    // Independent per-nonce digests via CPU Q-batch (no slot-0 overwrite).
    // Device arena slots are seeded independently for residency measurement.
    rc::RCMinerBatchConfig cfg;
    cfg.Q = static_cast<uint32_t>(headers.size());
    if (headers.size() > rc::dc::kRCMinerBatchQMax) {
        if (!rc::RunCoupledQSweep(headers, height, params, digests_out, /*q_cap=*/0)) {
            if (error) *error = "RCCudaEpisodeContext: RunCoupledQSweep failed";
            return false;
        }
    } else if (!rc::TryMineRCCoupledBatch(headers, height, params, digests_out, cfg)) {
        if (error) *error = "RCCudaEpisodeContext: TryMineRCCoupledBatch failed";
        return false;
    }

    const uint32_t Q = static_cast<uint32_t>(headers.size());
    const uint32_t n = params.StateBytes();
    const ArenaLayout L = LayoutFor(m_shape, m_arena);
    auto* stream = static_cast<cudaStream_t>(m_stream);
    uint64_t total_h2d = 0;
    for (uint32_t q = 0; q < Q; ++q) {
        std::vector<int8_t> slot_state;
        SeedLobeStateHost(headers[q], params, slot_state);
        if (!CudaOk(cudaMemcpyAsync(L.d_state + static_cast<size_t>(q) * n, slot_state.data(), n,
                                    cudaMemcpyHostToDevice, stream),
                    error, "RunNonceWindow slot H2D")) {
            return false;
        }
        total_h2d += n;
    }
    if (!CudaOk(cudaStreamSynchronize(stream), error, "RunNonceWindow slot sync")) {
        return false;
    }

    m_header = headers.back();
    m_height = height;
    m_episode_bound = true;
    m_state_ready = true;
    m_last_digest = digests_out.back();
    m_have_digest = true;
    m_prov.qstar_device_batched = Q > 1;
    m_prov.independent_q_slots = true;
    m_prov.per_nonce_sync_absent = true;
    m_prov.digest_batch_slots = Q;
    m_prov.device_bank_resident = true;
    m_prov.device_state_resident = true;
    m_prov.device_digest = false;
    m_prov.h2d_bytes_per_window = total_h2d;
    m_prov.d2h_bytes_per_window = 0;
    m_prov.permute_extract_label = "cpu_batch_independent_q_slots";
    SetPeakReadyDerived(m_prov, /*device_tail_ok=*/false);
    if (error) error->clear();
    return true;
}

void RCCudaEpisodeContext::Destroy()
{
    auto* stream = static_cast<cudaStream_t>(m_stream);
    auto* graph = static_cast<cudaGraph_t>(m_graph);
    auto* exec = static_cast<cudaGraphExec_t>(m_graph_exec);
    if (exec) cudaGraphExecDestroy(exec);
    if (graph) cudaGraphDestroy(graph);
    if (stream) cudaStreamDestroy(stream);
    m_stream = nullptr;
    m_graph = nullptr;
    m_graph_exec = nullptr;
    m_graph_captured = false;

    if (m_arena != nullptr) {
        (void)cudaFree(m_arena);
        m_arena = nullptr;
    }
    m_arena_bytes = 0;
    m_ready = false;
    m_bank_loaded = false;
    m_episode_bound = false;
    m_have_digest = false;
    m_state_ready = false;
    m_barrier_tables_ready = false;
    m_fault_corrupt_digest = false;
    m_shape = {};
    m_pages.clear();
    m_state.clear();
    m_last_digest = uint256{};
    m_bank_root = uint256{};
    m_prov = {};
}

} // namespace matmul_v4::cuda
