// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_mx_ozaki_native.h>

#include <cuda/matmul_v4_lt_accel.h>
#include <cuda/matmul_v4_lt_cutlass_mxfp4.h>
#include <matmul/matmul_v4_rc_mx_ozaki.h>

#include <cuda_runtime.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <vector>

// cuBLASLt block-scaled FP4 (same toolkit gate as LT matmul_v4_lt_mx_native.cu).
#if defined(CUDART_VERSION) && (CUDART_VERSION >= 12080)
#include <cublasLt.h>
#if defined(__has_include)
#if __has_include(<cuda_fp4.h>)
#include <cuda_fp4.h>
#define BTX_RC_OZAKI_HAS_FP4_E2M1 1
#endif
#endif
#define BTX_RC_OZAKI_HAS_VEC32_UE8M0 1
#define BTX_RC_OZAKI_HAS_MX_SCALE_MODES 1
#endif

namespace matmul_v4::cuda {
namespace {

using matmul_v4::cuda::lt_cutlass_mxfp4::EncodeE2M1Nibble;
using matmul_v4::cuda::lt_cutlass_mxfp4::EncodeUe8m0FromBtXScale;
using matmul_v4::cuda::lt_cutlass_mxfp4::Fp32OutputToExactInt32;
using matmul_v4::cuda::lt_cutlass_mxfp4::kUe8m0Bias;
using matmul_v4::cuda::lt_cutlass_mxfp4::PackNibble;

/** OCP MX block length (32) — host+device visible. */
constexpr uint32_t kMxBlk = 32;

std::mutex g_ozaki_mu;

// ExactGemm IMMA panel latch (not native MXFP4).
bool g_exact_ran{false};
bool g_exact_qualified{false};

// Native MXFP4 — separate arch latches (sm_120 ≠ sm_100). Never cross-infer.
bool g_mx_ran{false};
RcOzakiMxfp4SelectedBackend g_mx_selected{RcOzakiMxfp4SelectedBackend::Unqualified};
std::string g_mx_arch_key;
std::string g_mx_backend;
std::string g_mx_deficit;
std::atomic<uint64_t> g_native_tensor_launches{0};
std::atomic<uint64_t> g_scalar_tail_launches{0};

/** Grow-only process scratch — replaces per-panel cudaMalloc/cudaFree. */
struct OzakiDeviceBuf {
    void* p{nullptr};
    size_t bytes{0};
    [[nodiscard]] bool Ensure(size_t need)
    {
        if (need == 0) return true;
        if (p != nullptr && bytes >= need) return true;
        void* np = nullptr;
        if (cudaMalloc(&np, need) != cudaSuccess) return false;
        if (p) cudaFree(p);
        p = np;
        bytes = need;
        return true;
    }
    void Release()
    {
        if (p) {
            cudaFree(p);
            p = nullptr;
            bytes = 0;
        }
    }
};

struct OzakiDeviceArena {
    OzakiDeviceBuf dA;
    OzakiDeviceBuf dB;
    OzakiDeviceBuf dSFa;
    OzakiDeviceBuf dSFb;
    OzakiDeviceBuf dD;
    OzakiDeviceBuf dWS;
    OzakiDeviceBuf dOutI64;
    OzakiDeviceBuf dHostStage; // staging for device-pointer int8 factor path
    cudaStream_t stream{nullptr};

    [[nodiscard]] bool EnsureStream()
    {
        if (stream != nullptr) return true;
        return cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking) == cudaSuccess;
    }

    [[nodiscard]] bool Ensure(size_t a, size_t b, size_t sfa, size_t sfb, size_t d_elems,
                             size_t ws = 0)
    {
        constexpr size_t kDefaultWs = 32ull * 1024ull * 1024ull;
        const size_t need_ws = ws == 0 ? kDefaultWs : ws;
        return EnsureStream() && dA.Ensure(a) && dB.Ensure(b) && dSFa.Ensure(sfa) &&
               dSFb.Ensure(sfb) && dD.Ensure(d_elems * sizeof(float)) && dWS.Ensure(need_ws);
    }
};

OzakiDeviceArena& Arena()
{
    static OzakiDeviceArena a;
    return a;
}

[[nodiscard]] bool DeviceLooksSm120(int major, int /*minor*/)
{
    return major == 12;
}

[[nodiscard]] bool DeviceLooksSm100(int major, int /*minor*/)
{
    return major == 10;
}

[[nodiscard]] std::string FormatCudaArchKey(int major, int minor)
{
    return "sm_" + std::to_string(major) + std::to_string(minor);
}

[[nodiscard]] const char* SelectedBackendName(RcOzakiMxfp4SelectedBackend b)
{
    switch (b) {
    case RcOzakiMxfp4SelectedBackend::SM120_MMA:
        return "SM120_MMA";
    case RcOzakiMxfp4SelectedBackend::SM100_CUBLASLT:
        return "SM100_CUBLASLT";
    case RcOzakiMxfp4SelectedBackend::SM100_MMA:
        return "SM100_MMA";
    case RcOzakiMxfp4SelectedBackend::Unqualified:
    default:
        return "Unqualified";
    }
}

[[nodiscard]] bool IsM11(int32_t mu)
{
    switch (mu) {
    case 0:
    case 1:
    case -1:
    case 2:
    case -2:
    case 3:
    case -3:
    case 4:
    case -4:
    case 6:
    case -6:
        return true;
    default:
        return false;
    }
}

/** Factor one K-block of int8 dequants into shared e ∈ {0..3} + M11 mantissas. */
[[nodiscard]] bool FactorBlockToMx(const int8_t* vals, uint32_t n, uint8_t& e_out,
                                   int8_t* mu_out)
{
    for (int e = 3; e >= 0; --e) {
        const int32_t scale = 1 << e;
        bool ok = true;
        for (uint32_t i = 0; i < n; ++i) {
            const int32_t v = static_cast<int32_t>(vals[i]);
            if ((v % scale) != 0) {
                ok = false;
                break;
            }
            const int32_t mu = v / scale;
            if (!IsM11(mu)) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;
        e_out = static_cast<uint8_t>(e);
        for (uint32_t i = 0; i < n; ++i) {
            mu_out[i] = static_cast<int8_t>(static_cast<int32_t>(vals[i]) / scale);
        }
        for (uint32_t i = n; i < kMxBlk; ++i) mu_out[i] = 0;
        return true;
    }
    return false;
}

/**
 * Pack MX-dequant-shaped int8 panels into E2M1 + UE8M0 (K-block scales).
 * Left: rows×K row-major. Right: K×cols row-major.
 */
[[nodiscard]] bool FactorInt8ToMxM11E8M0(const std::vector<int8_t>& left,
                                        const std::vector<int8_t>& right, uint32_t rows,
                                        uint32_t K, uint32_t cols, std::vector<uint8_t>& a_e2m1,
                                        std::vector<uint8_t>& b_e2m1,
                                        std::vector<uint8_t>& sfa_ue8m0,
                                        std::vector<uint8_t>& sfb_ue8m0, uint32_t& kblocks_out,
                                        std::string* error)
{
    if (rows == 0 || K == 0 || cols == 0) {
        if (error) *error = "FactorInt8ToMxM11E8M0: degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * K ||
        right.size() != static_cast<size_t>(K) * cols) {
        if (error) *error = "FactorInt8ToMxM11E8M0: size mismatch";
        return false;
    }
    const uint32_t kblocks = (K + kMxBlk - 1u) / kMxBlk;
    kblocks_out = kblocks;
    const size_t a_elems = static_cast<size_t>(rows) * K;
    const size_t b_elems = static_cast<size_t>(K) * cols;
    a_e2m1.assign((a_elems + 1) / 2, 0);
    b_e2m1.assign((b_elems + 1) / 2, 0);
    sfa_ue8m0.assign(static_cast<size_t>(rows) * kblocks, kUe8m0Bias);
    sfb_ue8m0.assign(static_cast<size_t>(cols) * kblocks, kUe8m0Bias);

    int8_t mu_tmp[kMxBlk];
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = left[static_cast<size_t>(r) * K + (k0 + t)];
            }
            uint8_t e = 0;
            if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                if (error) *error = "FactorInt8ToMxM11E8M0: left block not MX-factorable";
                return false;
            }
            sfa_ue8m0[static_cast<size_t>(r) * kblocks + bj] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < n; ++t) {
                const uint8_t nib = EncodeE2M1Nibble(mu_tmp[t]);
                if (nib > 0x0F) {
                    if (error) *error = "FactorInt8ToMxM11E8M0: left mu not E2M1";
                    return false;
                }
                PackNibble(a_e2m1.data(), static_cast<size_t>(r) * K + (k0 + t), nib);
            }
        }
    }

    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = right[static_cast<size_t>(k0 + t) * cols + c];
            }
            uint8_t e = 0;
            if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                if (error) *error = "FactorInt8ToMxM11E8M0: right block not MX-factorable";
                return false;
            }
            sfb_ue8m0[static_cast<size_t>(c) * kblocks + bj] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < n; ++t) {
                const uint8_t nib = EncodeE2M1Nibble(mu_tmp[t]);
                if (nib > 0x0F) {
                    if (error) *error = "FactorInt8ToMxM11E8M0: right mu not E2M1";
                    return false;
                }
                PackNibble(b_e2m1.data(), static_cast<size_t>(k0 + t) * cols + c, nib);
            }
        }
    }
    return true;
}

__device__ __forceinline__ int8_t DecodeE2M1NibbleDevice(uint8_t nib)
{
    switch (nib & 0x0Fu) {
    case 0x0: return 0;
    case 0x2: return 1;
    case 0xA: return -1;
    case 0x4: return 2;
    case 0xC: return -2;
    case 0x5: return 3;
    case 0xD: return -3;
    case 0x6: return 4;
    case 0xE: return -4;
    case 0x7: return 6;
    case 0xF: return -6;
    default: return 0;
    }
}

__device__ __forceinline__ uint8_t LoadNibble(const uint8_t* pack, size_t idx)
{
    const uint8_t byte = pack[idx >> 1];
    return (idx & 1u) ? static_cast<uint8_t>((byte >> 4) & 0x0Fu)
                      : static_cast<uint8_t>(byte & 0x0Fu);
}

/** Block-scaled E2M1 GEMM → FP32 (honest MXFP4 datatype path; not IMMA INT8). */
__global__ void rc_ozaki_mxfp4_panel_gemm(const uint8_t* a_e2m1, const uint8_t* b_e2m1,
                                          const uint8_t* sfa, const uint8_t* sfb, float* out,
                                          uint32_t rows, uint32_t K, uint32_t cols,
                                          uint32_t kblocks)
{
    const uint32_t r = blockIdx.y * blockDim.y + threadIdx.y;
    const uint32_t c = blockIdx.x * blockDim.x + threadIdx.x;
    if (r >= rows || c >= cols) return;
    float acc = 0.f;
    for (uint32_t k = 0; k < K; ++k) {
        const uint32_t bj = k / kMxBlk;
        const int ea = static_cast<int>(sfa[static_cast<size_t>(r) * kblocks + bj]) - 127;
        const int eb = static_cast<int>(sfb[static_cast<size_t>(c) * kblocks + bj]) - 127;
        const float sa = ldexpf(1.f, ea);
        const float sb = ldexpf(1.f, eb);
        const size_t a_idx = static_cast<size_t>(r) * K + k;
        const size_t b_idx = static_cast<size_t>(k) * cols + c;
        const int8_t mu_a = DecodeE2M1NibbleDevice(LoadNibble(a_e2m1, a_idx));
        const int8_t mu_b = DecodeE2M1NibbleDevice(LoadNibble(b_e2m1, b_idx));
        acc += static_cast<float>(mu_a) * sa * static_cast<float>(mu_b) * sb;
    }
    out[static_cast<size_t>(r) * cols + c] = acc;
}

/**
 * SM120a native MXFP4 TC: mma.sync kind::mxf8f6f4.block_scale m16n8k32 e2m1×e2m1.
 *
 * Block-scaled MXF8F6F4 PTX requires feature-qualified sm_120a. Plain sm_120 and
 * sm_120a both report __CUDA_ARCH__==1200, so a family range gate
 * (__CUDA_ARCH__ >= 1200 && < 1300) is too broad and fails ptxas on sm_120.
 * Do NOT use (__CUDA_ARCH__ >= 1000 && < 1100) — that can compile SM120 bodies
 * into sm_100 slices. Do NOT use __CUDA_ARCH_FAMILY_SPECIFIC__ here until an
 * sm_120f toolchain is verified locally.
 *
 * Compile IN only under:
 *   defined(__CUDA_ARCH_SPECIFIC__) && (__CUDA_ARCH_SPECIFIC__ == 1200)
 * i.e. the sm_120a device slice. Plain sm_120 (__CUDA_ARCH__==1200 without
 * SPECIFIC) and all other fatbin targets (sm_90 / sm_100 / …) compile OUT to
 * zeros — no assembler failure. SM100 stays on the separate CUBLASLT path.
 * Runtime still requires SelectedBackend==SM120_MMA after full suite.
 * Rack G: expect SASS QMMA.SF E2M1 under CUDA 13.2 + sm_120a.
 */
__device__ __forceinline__ void RcOzakiMmaMxfp4M16N8K32(float& d0, float& d1, float& d2, float& d3,
                                                         uint32_t a0, uint32_t a1, uint32_t a2,
                                                         uint32_t a3, uint32_t b0, uint32_t b1,
                                                         uint32_t sfa, uint32_t sfb)
{
#if defined(__CUDA_ARCH_SPECIFIC__) && (__CUDA_ARCH_SPECIFIC__ == 1200)
    uint16_t z = 0;
    asm volatile(
        "mma.sync.aligned.kind::mxf8f6f4.block_scale.scale_vec::1X.m16n8k32.row.col.f32.e2m1.e2m1.f32.ue8m0 "
        "{%0,%1,%2,%3},{%4,%5,%6,%7},{%8,%9},{%10,%11,%12,%13},{%14},{%15,%16},{%17},{%18,%19};\n"
        : "=f"(d0), "=f"(d1), "=f"(d2), "=f"(d3)
        : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(b0), "r"(b1), "f"(d0), "f"(d1), "f"(d2), "f"(d3),
          "r"(sfa), "h"(z), "h"(z), "r"(sfb), "h"(z), "h"(z));
#else
    (void)a0;
    (void)a1;
    (void)a2;
    (void)a3;
    (void)b0;
    (void)b1;
    (void)sfa;
    (void)sfb;
    d0 = d1 = d2 = d3 = 0.f;
#endif
}

__device__ __forceinline__ uint32_t RcOzakiPack4Bytes(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// GB202 / RTX PRO 6000 Blackwell tuning notes (sm_120a):
//   * SM12x MXFP4 uses warp-level mma.sync with A/B/D fragments in REGISTERS
//     (RMEM), NOT Tensor Memory — tcgen05/TMEM staging is an sm_100 (B200/B300)
//     concept and must NOT be added here (confirmed: Colfax NVFP4 SM12x + CUTLASS
//     blackwell_functionality). This kernel keeps operands in RMEM, correct for
//     the RTX PRO 6000's 188 SMs.
//   * This kernel is deliberately ONE warp / CTA computing a single 16x8 tile,
//     scale_vec::1X block-32 (the only mxf8f6f4 shape). It is exactness-first and
//     occupancy-limited: the grid is (N/8, M/16), so for the RC lobe shapes
//     (M small, N up to 8192) it launches thousands of CTAs and fills the 188 SMs
//     by breadth, but each CTA underuses its SM.
//   * __launch_bounds__(32): one warp/CTA. The min-blocks-per-SM hint is left
//     unset — the right value is GB202-profile-dependent (register pressure of
//     the QMMA.SF path). FLAG: set it after `ncu --set full` on real silicon.
//   * PEAK next step (profile-gated, NOT done here to preserve bit-exactness
//     without a build): a multi-warp CTA (Colfax uses 8 warps / 256 threads,
//     128x128x128 tile, ~60% of peak on RTX PRO 6000) or the cuBLASLt
//     CUDA_R_4F_E2M1 + VEC32_UE8M0 block-scaled path. Any such rewrite MUST
//     re-pass Mxfp4CompleteSuiteForLauncher bit-exactly before it may latch.
__global__ void __launch_bounds__(32)
    rc_ozaki_mxfp4_mma_gemm(const uint8_t* __restrict__ A, const uint8_t* __restrict__ B,
                            const uint8_t* __restrict__ SFa, const uint8_t* __restrict__ SFb,
                            float* __restrict__ C, int M, int N, int K, int kblocks)
{
    const int lane = static_cast<int>(threadIdx.x) & 31;
    const int bm = static_cast<int>(blockIdx.y) * 16;
    const int bn = static_cast<int>(blockIdx.x) * 8;
    const int row0 = lane / 4;
    const int ksub = lane % 4;

    float d0 = 0.f, d1 = 0.f, d2 = 0.f, d3 = 0.f;
    for (int kb = 0; kb < kblocks; ++kb) {
        const int k0 = kb * 32;
        auto loadA = [&](int row, int kbase) -> uint32_t {
            if (bm + row >= M) return 0u;
            return RcOzakiPack4Bytes(A + static_cast<size_t>(bm + row) * static_cast<size_t>(K) +
                                     static_cast<size_t>(k0 + kbase));
        };
        const uint32_t a0 = loadA(row0, ksub * 4);
        const uint32_t a1 = loadA(row0 + 8, ksub * 4);
        const uint32_t a2 = loadA(row0, 16 + ksub * 4);
        const uint32_t a3 = loadA(row0 + 8, 16 + ksub * 4);

        auto loadB = [&](int col, int kbase) -> uint32_t {
            if (bn + col >= N) return 0u;
            uint8_t tmp[4];
            for (int i = 0; i < 4; ++i) {
                tmp[i] = B[static_cast<size_t>(k0 + kbase + i) * static_cast<size_t>(N) +
                           static_cast<size_t>(bn + col)];
            }
            return RcOzakiPack4Bytes(tmp);
        };
        const uint32_t b0 = loadB(row0, ksub * 4);
        const uint32_t b1 = loadB(row0, 16 + ksub * 4);

        uint32_t sfa = 127u, sfb = 127u;
        if ((lane % 4) == 0) {
            const int r = bm + row0;
            if (r < M) sfa = SFa[static_cast<size_t>(r) * static_cast<size_t>(kblocks) + kb];
            const int c = bn + row0;
            if (c < N) sfb = SFb[static_cast<size_t>(c) * static_cast<size_t>(kblocks) + kb];
        } else if ((lane % 4) == 1) {
            const int r = bm + row0 + 8;
            if (r < M) sfa = SFa[static_cast<size_t>(r) * static_cast<size_t>(kblocks) + kb];
        }
        RcOzakiMmaMxfp4M16N8K32(d0, d1, d2, d3, a0, a1, a2, a3, b0, b1, sfa, sfb);
    }

    const int col0 = (lane % 4) * 2;
    auto store = [&](int row, int col, float v) {
        if (bm + row < M && bn + col < N) {
            C[static_cast<size_t>(bm + row) * static_cast<size_t>(N) + static_cast<size_t>(bn + col)] =
                v;
        }
    };
    store(row0, col0, d0);
    store(row0, col0 + 1, d1);
    store(row0 + 8, col0, d2);
    store(row0 + 8, col0 + 1, d3);
}

// ========================================================================== //
//  SM100 (B200 / GB200 datacenter Blackwell) native block-scaled MXFP4 via     //
//  5th-generation tensor cores (tcgen05.mma.kind::mxf8f6f4.block_scale).        //
// ========================================================================== //
//
// Unlike consumer Blackwell (sm_120, warp-synchronous mma.sync), the datacenter
// part exposes block-scaled MMA ONLY through the async, TMEM-resident tcgen05.mma
// family (PTX ISA 8.6+, compute capability 10.0). The two encodings are NOT
// interchangeable — this body is a genuinely different ISA from the sm_120a one.
//
//   * A,B operand tiles: SHARED memory, referenced by 64-bit SMEM matrix
//     descriptors (a-desc / b-desc).
//   * Block scale factors (UE8M0, one per 32 K-elements): TENSOR memory (TMEM).
//   * Accumulator D (FP32): TENSOR memory (TMEM); read back with tcgen05.ld.
//   * Completion: tcgen05.commit signals an mbarrier; the CTA waits on it.
//   * A single elected "leader" thread issues alloc / mma / commit / dealloc.
//
// Mandatory tile for .kind::mxf8f6f4.block_scale.scale_vec::1X is M=128, N=128,
// atom K=32; we step K in 128-wide groups (= 4 OCP MX blocks) per MMA.
//
// COMPILE GATING (mirror of the sm_120a body): the tcgen05 inline PTX is compiled
// IN only for the sm_100a device slice (__CUDA_ARCH_SPECIFIC__==1000). Plain
// sm_100 (__CUDA_ARCH__==1000 without SPECIFIC) and every other fatbin target
// (sm_90 / sm_120 / …) compile the body OUT to a zero-producing stub — ptxas never
// sees tcgen05 on a slice that cannot assemble it. Runtime still requires
// SelectedBackend==SM100_MMA after the complete bit-exact suite.
//
// !!! B200 OPERATOR VERIFY !!!  The exact SMEM-descriptor bitfields, the
// SF->TMEM layout, the instruction-descriptor fields, and the tcgen05.ld
// thread->element mapping are the sm_100a details that MUST be confirmed against
// the PTX ISA for the installed toolkit (they are fenced with "VERIFY" below).
// Every such detail is downstream of Fp32RowMajorToExactInt32RowMajor + the full
// self-qual suite, so ANY mismatch is FAIL-CLOSED (declines SM100_MMA and falls
// back to SM100_CUBLASLT / INT8) and can never emit a wrong digest.

#if defined(__CUDA_ARCH_SPECIFIC__) && (__CUDA_ARCH_SPECIFIC__ == 1000)

namespace sm100_tcgen05 {

/** Elect lane 0 of the CTA as the single MMA-issuing leader. */
__device__ __forceinline__ bool IsLeader()
{
    return threadIdx.x == 0;
}

/** 32-bit shared-memory address expected by tcgen05 shared::cta operands. */
__device__ __forceinline__ uint32_t SmemU32(const void* p)
{
    return static_cast<uint32_t>(__cvta_generic_to_shared(p));
}

/**
 * 64-bit SMEM matrix descriptor. VERIFY against PTX ISA "Matrix Descriptor":
 *   bits[13:0]   start address (>>4) in shared memory
 *   bits[29:16]  leading-dim byte offset (>>4)
 *   bits[45:32]  stride byte offset (>>4)
 *   bits[63:61]  swizzle mode (0 = none)
 * We stage A/B contiguously with no swizzle (mode 0); the operator may switch to
 * a 128B-swizzle atom for bandwidth once qualified.
 */
__device__ __forceinline__ uint64_t MakeSmemDesc(const void* smem_ptr, uint32_t lead_off_bytes,
                                                 uint32_t stride_off_bytes, uint32_t swizzle)
{
    const uint64_t addr = static_cast<uint64_t>(SmemU32(smem_ptr));
    uint64_t d = 0;
    d |= ((addr >> 4) & 0x3FFFull);
    d |= (static_cast<uint64_t>((lead_off_bytes >> 4) & 0x3FFFu) << 16);
    d |= (static_cast<uint64_t>((stride_off_bytes >> 4) & 0x3FFFu) << 32);
    d |= (static_cast<uint64_t>(swizzle & 0x7u) << 61);
    return d;
}

/**
 * Instruction descriptor for .kind::mxf8f6f4 with e2m1 (FP4) A and B, UE8M0
 * scales, TN layout, FP32 accumulate. VERIFY the packed bitfields (dtype = e2m1,
 * scale_type = ue8m0, transpose flags, N tile) against the PTX ISA table; the
 * value below encodes A=e2m1, B=e2m1, D=f32, no negate, N=128, scale_vec::1X.
 */
__device__ __forceinline__ uint32_t MakeInstrDescMxf8f6f4()
{
    // VERIFY: field packing is toolkit-specific. Kept as a single named constant
    // so a B200 operator can correct it in one place; wrong bits => suite fails.
    uint32_t idesc = 0;
    idesc |= (0u << 0);   // sparsity = dense
    idesc |= (1u << 2);   // A dtype = e2m1 (FP4)   [VERIFY enum]
    idesc |= (1u << 5);   // B dtype = e2m1 (FP4)   [VERIFY enum]
    idesc |= (0u << 8);   // D dtype = f32          [VERIFY enum]
    idesc |= (0u << 11);  // no A/B negate
    idesc |= (0u << 12);  // scale kind = ue8m0     [VERIFY enum]
    return idesc;
}

__device__ __forceinline__ uint32_t AllocTmem(uint32_t* smem_slot, uint32_t ncols)
{
    // tcgen05.alloc is warp-convergent (.sync.aligned): issue from warp 0 only,
    // then broadcast the TMEM base column address to the whole CTA via shared mem.
    if (threadIdx.x < 32) {
        asm volatile(
            "tcgen05.alloc.cta_group::1.sync.aligned.shared::cta.b32 [%0], %1;\n" ::"r"(
                SmemU32(smem_slot)),
            "r"(ncols));
        asm volatile("tcgen05.relinquish_alloc_permit.cta_group::1.sync.aligned;\n");
    }
    __syncthreads();
    return *reinterpret_cast<volatile uint32_t*>(smem_slot);
}

__device__ __forceinline__ void DeallocTmem(uint32_t tmem_addr, uint32_t ncols)
{
    // Warp-0-only, matching AllocTmem. Caller fences/syncs before dealloc.
    if (threadIdx.x < 32) {
        asm volatile("tcgen05.dealloc.cta_group::1.sync.aligned.b32 %0, %1;\n" ::"r"(tmem_addr),
                     "r"(ncols));
    }
}

/** Store one 32b lane of scale factors into TMEM (SF must be TMEM-resident). */
__device__ __forceinline__ void StTmem32(uint32_t tmem_addr, uint32_t v)
{
    asm volatile("tcgen05.st.sync.aligned.32x32b.x1.b32 [%0], {%1};\n" ::"r"(tmem_addr), "r"(v));
}

/** Issue one block-scaled MMA (accumulate into TMEM D). */
__device__ __forceinline__ void MmaMxf8f6f4BlockScale(uint32_t d_tmem, uint64_t a_desc,
                                                      uint64_t b_desc, uint32_t idesc,
                                                      uint32_t sfa_tmem, uint32_t sfb_tmem,
                                                      bool accumulate)
{
    const int acc = accumulate ? 1 : 0;
    asm volatile(
        "{\n"
        ".reg .pred p;\n"
        "setp.ne.b32 p, %6, 0;\n"
        "tcgen05.mma.cta_group::1.kind::mxf8f6f4.block_scale.scale_vec::1X "
        "[%0], %1, %2, %3, [%4], [%5], p;\n"
        "}\n" ::"r"(d_tmem),
        "l"(a_desc), "l"(b_desc), "r"(idesc), "r"(sfa_tmem), "r"(sfb_tmem), "r"(acc));
}

/** Commit outstanding MMAs to an mbarrier, then wait for arrival. */
__device__ __forceinline__ void CommitAndWait(uint64_t* mbar, uint32_t phase)
{
    if (IsLeader()) {
        asm volatile(
            "tcgen05.commit.cta_group::1.mbarrier::arrive::one.shared::cluster.b64 [%0];\n" ::"r"(
                SmemU32(mbar)));
    }
    __syncthreads();
    // Spin on the mbarrier phase until the async MMA group arrives.
    unsigned done = 0;
    while (done == 0) {
        asm volatile(
            "{\n"
            ".reg .pred p;\n"
            "mbarrier.try_wait.parity.shared::cta.b64 p, [%1], %2;\n"
            "selp.u32 %0, 1, 0, p;\n"
            "}\n"
            : "=r"(done)
            : "r"(SmemU32(mbar)), "r"(phase));
    }
}

/** Load a run of FP32 accumulator lanes from TMEM to registers. */
__device__ __forceinline__ void LdTmem(uint32_t tmem_addr, uint32_t* out, int n)
{
    for (int i = 0; i < n; ++i) {
        asm volatile("tcgen05.ld.sync.aligned.32x32b.x1.b32 {%0}, [%1];\n"
                     : "=r"(out[i])
                     : "r"(tmem_addr + static_cast<uint32_t>(i)));
    }
    asm volatile("tcgen05.wait::ld.sync.aligned;\n");
}

} // namespace sm100_tcgen05

#endif // __CUDA_ARCH_SPECIFIC__ == 1000

/**
 * SM100 tcgen05 block-scaled MXFP4 GEMM: A (M×K e2m1 bytes, row-major),
 * B (K×N e2m1 bytes, row-major), SFa[M×kblocks]/SFb[N×kblocks] UE8M0 → C FP32.
 * M,N padded to 128; K padded to a multiple of 128 by the caller. One CTA (128
 * threads) per 128×128 output tile.
 *
 * On the sm_100a slice this issues real tcgen05.mma.block_scale; on every other
 * slice the body is a zero-producing stub (fail-closed). The exactness/limb
 * strategy and FP32→int32 recombination are identical to the SM120 path — only
 * the tensor-core issue mechanism differs.
 */
__global__ void rc_ozaki_mxfp4_tcgen05_gemm(const uint8_t* __restrict__ A,
                                            const uint8_t* __restrict__ B,
                                            const uint8_t* __restrict__ SFa,
                                            const uint8_t* __restrict__ SFb, float* __restrict__ C,
                                            int M, int N, int K, int kblocks)
{
#if defined(__CUDA_ARCH_SPECIFIC__) && (__CUDA_ARCH_SPECIFIC__ == 1000)
    using namespace sm100_tcgen05;
    constexpr int kMN = 128;
    constexpr int kKtile = 128;      // 4 OCP MX blocks (32 each) per MMA step
    constexpr int kBlkPerTile = kKtile / 32;

    const int bm = static_cast<int>(blockIdx.y) * kMN;
    const int bn = static_cast<int>(blockIdx.x) * kMN;
    const int tid = static_cast<int>(threadIdx.x);

    extern __shared__ unsigned char smem_raw[];
    // Layout: A tile | B tile | mbarrier | tmem-alloc slot.
    uint8_t* As = smem_raw;                                  // kMN * kKtile bytes
    uint8_t* Bs = As + static_cast<size_t>(kMN) * kKtile;    // kKtile * kMN bytes
    uint64_t* mbar = reinterpret_cast<uint64_t*>(Bs + static_cast<size_t>(kKtile) * kMN);
    uint32_t* tmem_slot = reinterpret_cast<uint32_t*>(mbar + 1);

    if (IsLeader()) {
        asm volatile("mbarrier.init.shared::cta.b64 [%0], 1;\n" ::"r"(SmemU32(mbar)));
    }
    // Accumulator D: 128 columns of TMEM (128×128 FP32 tile), plus SF columns.
    // VERIFY: column budget (D + SFA + SFB) against the operator's TMEM capacity.
    const uint32_t d_tmem = AllocTmem(tmem_slot, /*ncols=*/128u + 8u);
    const uint32_t sfa_tmem = d_tmem + 128u;  // VERIFY SF sub-column placement
    const uint32_t sfb_tmem = d_tmem + 132u;
    __syncthreads();

    const int ntiles = (K + kKtile - 1) / kKtile;
    uint32_t phase = 0;
    for (int kt = 0; kt < ntiles; ++kt) {
        const int k0 = kt * kKtile;
        // Cooperative stage of the A and B e2m1 tiles into shared memory.
        for (int idx = tid; idx < kMN * kKtile; idx += blockDim.x) {
            const int r = idx / kKtile;
            const int kk = idx % kKtile;
            const int gr = bm + r;
            const int gk = k0 + kk;
            As[idx] = (gr < M && gk < K)
                          ? A[static_cast<size_t>(gr) * K + gk]
                          : uint8_t{0};
        }
        for (int idx = tid; idx < kKtile * kMN; idx += blockDim.x) {
            const int kk = idx / kMN;
            const int c = idx % kMN;
            const int gk = k0 + kk;
            const int gc = bn + c;
            Bs[idx] = (gk < K && gc < N)
                          ? B[static_cast<size_t>(gk) * N + gc]
                          : uint8_t{0};
        }
        // Stage this tile's block scales into TMEM. VERIFY the SF TMEM layout;
        // here row r's four UE8M0 bytes for this K-tile are packed into one u32.
        for (int r = tid; r < kMN; r += blockDim.x) {
            const int gr = bm + r;
            uint32_t packed = 0;
            for (int b = 0; b < kBlkPerTile; ++b) {
                const int bj = kt * kBlkPerTile + b;
                uint8_t s = 127u;
                if (gr < M && bj < kblocks) s = SFa[static_cast<size_t>(gr) * kblocks + bj];
                packed |= static_cast<uint32_t>(s) << (8 * b);
            }
            StTmem32(sfa_tmem + static_cast<uint32_t>(r), packed);
        }
        for (int c = tid; c < kMN; c += blockDim.x) {
            const int gc = bn + c;
            uint32_t packed = 0;
            for (int b = 0; b < kBlkPerTile; ++b) {
                const int bj = kt * kBlkPerTile + b;
                uint8_t s = 127u;
                if (gc < N && bj < kblocks) s = SFb[static_cast<size_t>(gc) * kblocks + bj];
                packed |= static_cast<uint32_t>(s) << (8 * b);
            }
            StTmem32(sfb_tmem + static_cast<uint32_t>(c), packed);
        }
        asm volatile("tcgen05.fence::before_thread_sync;\n");
        __syncthreads();

        if (IsLeader()) {
            const uint64_t a_desc = MakeSmemDesc(As, /*lead*/ kKtile, /*stride*/ kMN * kKtile, 0u);
            const uint64_t b_desc = MakeSmemDesc(Bs, /*lead*/ kMN, /*stride*/ kKtile * kMN, 0u);
            const uint32_t idesc = MakeInstrDescMxf8f6f4();
            MmaMxf8f6f4BlockScale(d_tmem, a_desc, b_desc, idesc, sfa_tmem, sfb_tmem,
                                  /*accumulate=*/kt != 0);
        }
        CommitAndWait(mbar, phase & 1u);
        ++phase;
    }

    // Read the 128×128 FP32 accumulator back from TMEM and store row-major.
    // !!! VERIFY (#1 layout item) !!! the thread->TMEM (lane,column) mapping.
    // Placeholder: thread `tid` owns output row `tid` and reads kMN columns whose
    // TMEM addresses start at d_tmem + tid*kTmemRowStride. The real fragment
    // layout for tcgen05.ld.32x32b is warp/lane-partitioned and MUST be corrected
    // from the PTX ISA; a wrong mapping is caught by the exact self-qual (fail-
    // closed) and never yields a wrong digest.
    constexpr uint32_t kTmemRowStride = 1u; // VERIFY: TMEM lane stride per output row
    asm volatile("tcgen05.fence::after_thread_sync;\n");
    if (tid < kMN) {
        const int gr = bm + tid;
        uint32_t regs[kMN];
        LdTmem(d_tmem + static_cast<uint32_t>(tid) * kTmemRowStride, regs, kMN);
        if (gr < M) {
            for (int c = 0; c < kMN; ++c) {
                const int gc = bn + c;
                if (gc < N) {
                    C[static_cast<size_t>(gr) * N + gc] = __int_as_float(regs[c]);
                }
            }
        }
    }
    __syncthreads();
    // DeallocTmem self-gates to warp 0 (.sync.aligned needs the full warp).
    DeallocTmem(d_tmem, 128u + 8u);
#else
    // Non-sm_100a slice: zero-producing stub. Keeps ptxas happy on plain
    // sm_100 / sm_120 / … and forces the runtime self-qual to fail-closed.
    const uint32_t r = blockIdx.y * blockDim.y + threadIdx.y;
    const uint32_t c = blockIdx.x * blockDim.x + threadIdx.x;
    (void)A;
    (void)B;
    (void)SFa;
    (void)SFb;
    (void)K;
    (void)kblocks;
    if (static_cast<int>(r) < M && static_cast<int>(c) < N) {
        C[static_cast<size_t>(r) * N + c] = 0.f;
    }
#endif
}

[[nodiscard]] bool LaunchOzakiExactPanels(const std::vector<int8_t>& left,
                                          const std::vector<int8_t>& right, uint32_t rows,
                                          uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
                                          std::string* error)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "Ozaki ExactPanels degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "Ozaki ExactPanels operand size mismatch";
        return false;
    }

    using matmul::v4::rc::kRCOzakiExactChunk;
    if (!IsMatMulLTCudaAvailable()) {
        if (error) *error = "CUDA LT GEMM unavailable (no device / self-test failed)";
        return false;
    }

    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t k0 = 0; k0 < inner; k0 += kRCOzakiExactChunk) {
        const uint32_t len = std::min(kRCOzakiExactChunk, inner - k0);
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
            out.clear();
            if (error) *error = "LaunchGemmS8S8 Ozaki ExactPanels failed";
            return false;
        }
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += static_cast<int64_t>(partial[i]);
        }
    }
    return true;
}

/** cuBLASLt 1D block-scale layout (VEC32_UE8M0) — mirrors LT native packer. */
[[nodiscard]] size_t BlockScaleTensorBytes(size_t outer, size_t K, size_t vec)
{
    const size_t rows = ((outer + 127u) / 128u) * 128u;
    const size_t kblocks = (K + vec - 1u) / vec;
    const size_t cols = ((kblocks + 3u) / 4u) * 4u;
    return rows * cols;
}

[[nodiscard]] size_t BlockScaleOffset(size_t r, size_t c, size_t K, size_t vec)
{
    const size_t kblocks = (K + vec - 1u) / vec;
    const size_t cols = ((kblocks + 3u) / 4u) * 4u;
    const size_t n_k_tiles = cols / 4u;
    return (r % 32u) * 16u + ((r % 128u) / 32u) * 4u + (c % 4u) + (c / 4u) * 512u +
           (r / 128u) * 512u * n_k_tiles;
}

[[nodiscard]] uint32_t AlignUp(uint32_t v, uint32_t a)
{
    return (v + a - 1u) / a * a;
}

/**
 * Factor int8 panels → M11 μ + BTX e∈{0..3}, then pack cuBLASLt TN:
 *   A: K×M E2M1 (ld=K), B: K×N E2M1 (ld=K), SFA/SFB: VEC32_UE8M0 swizzle.
 * Pads K/M/N to multiples of 32 so VEC32 + Blackwell heuristics admit.
 */
[[nodiscard]] bool PackOzakiPanelsCublasLtFp4(const std::vector<int8_t>& Lpanel,
                                              const std::vector<int8_t>& Rpanel, uint32_t rows,
                                              uint32_t K, uint32_t cols,
                                              std::vector<uint8_t>& A_pack,
                                              std::vector<uint8_t>& B_pack,
                                              std::vector<uint8_t>& SFa,
                                              std::vector<uint8_t>& SFb, uint32_t& Mpad,
                                              uint32_t& Npad, uint32_t& Kpad, std::string* error)
{
    if (rows == 0 || K == 0 || cols == 0) {
        if (error) *error = "PackOzakiPanelsCublasLtFp4: degenerate";
        return false;
    }
    Mpad = AlignUp(rows, kMxBlk);
    Npad = AlignUp(cols, kMxBlk);
    Kpad = AlignUp(K, kMxBlk);
    const uint32_t kblocks = Kpad / kMxBlk;

    A_pack.assign((static_cast<size_t>(Kpad) * Mpad + 1u) / 2u, 0);
    B_pack.assign((static_cast<size_t>(Kpad) * Npad + 1u) / 2u, 0);
    SFa.assign(BlockScaleTensorBytes(Mpad, Kpad, kMxBlk), kUe8m0Bias);
    SFb.assign(BlockScaleTensorBytes(Npad, Kpad, kMxBlk), kUe8m0Bias);

    int8_t mu_tmp[kMxBlk];
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = (k0 >= K) ? 0u : std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = Lpanel[static_cast<size_t>(r) * K + (k0 + t)];
            }
            uint8_t e = 0;
            if (n > 0) {
                if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                    if (error) *error = "PackOzakiPanelsCublasLtFp4: left not MX-factorable";
                    return false;
                }
            } else {
                std::memset(mu_tmp, 0, sizeof(mu_tmp));
            }
            SFa[BlockScaleOffset(r, bj, Kpad, kMxBlk)] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < kMxBlk; ++t) {
                const int8_t mu = (t < n) ? mu_tmp[t] : int8_t{0};
                const uint8_t nib = EncodeE2M1Nibble(mu);
                if (nib > 0x0F) {
                    if (error) *error = "PackOzakiPanelsCublasLtFp4: left mu not E2M1";
                    return false;
                }
                PackNibble(A_pack.data(), static_cast<size_t>(k0 + t) + static_cast<size_t>(r) * Kpad,
                           nib);
            }
        }
    }
    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = (k0 >= K) ? 0u : std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = Rpanel[static_cast<size_t>(k0 + t) * cols + c];
            }
            uint8_t e = 0;
            if (n > 0) {
                if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                    if (error) *error = "PackOzakiPanelsCublasLtFp4: right not MX-factorable";
                    return false;
                }
            } else {
                std::memset(mu_tmp, 0, sizeof(mu_tmp));
            }
            SFb[BlockScaleOffset(c, bj, Kpad, kMxBlk)] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < kMxBlk; ++t) {
                const int8_t mu = (t < n) ? mu_tmp[t] : int8_t{0};
                const uint8_t nib = EncodeE2M1Nibble(mu);
                if (nib > 0x0F) {
                    if (error) *error = "PackOzakiPanelsCublasLtFp4: right mu not E2M1";
                    return false;
                }
                PackNibble(B_pack.data(), static_cast<size_t>(k0 + t) + static_cast<size_t>(c) * Kpad,
                           nib);
            }
        }
    }
    return true;
}

[[nodiscard]] bool Fp32ColMajorToExactInt32RowMajor(const std::vector<float>& D, uint32_t M,
                                                    uint32_t N, uint32_t rows, uint32_t cols,
                                                    std::vector<int32_t>& out)
{
    if (D.size() != static_cast<size_t>(M) * N || rows > M || cols > N) return false;
    out.resize(static_cast<size_t>(rows) * cols);
    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t r = 0; r < rows; ++r) {
            const float f = D[static_cast<size_t>(c) * M + r];
            if (!std::isfinite(f)) return false;
            const float rounded = nearbyintf(f);
            if (rounded != f) return false;
            if (rounded < static_cast<float>(std::numeric_limits<int32_t>::min()) ||
                rounded > static_cast<float>(std::numeric_limits<int32_t>::max())) {
                return false;
            }
            out[static_cast<size_t>(r) * cols + c] = static_cast<int32_t>(rounded);
        }
    }
    return true;
}

#if defined(BTX_RC_OZAKI_HAS_FP4_E2M1) && defined(BTX_RC_OZAKI_HAS_MX_SCALE_MODES)

[[nodiscard]] bool RunCublasLtBlockScaledTnOzaki(const void* dA, const void* dB, const void* dSFa,
                                                 const void* dSFb, float* dD, uint32_t M,
                                                 uint32_t N, uint32_t K, void* workspace,
                                                 size_t workspace_bytes, cudaStream_t stream)
{
    cublasLtHandle_t lt = nullptr;
    cublasLtMatmulDesc_t op = nullptr;
    cublasLtMatrixLayout_t a_layout = nullptr;
    cublasLtMatrixLayout_t b_layout = nullptr;
    cublasLtMatrixLayout_t d_layout = nullptr;
    cublasLtMatmulPreference_t pref = nullptr;
    bool ok = false;

    if (cublasLtCreate(&lt) != CUBLAS_STATUS_SUCCESS) return false;

    do {
        if (cublasLtMatmulDescCreate(&op, CUBLAS_COMPUTE_32F, CUDA_R_32F) != CUBLAS_STATUS_SUCCESS) {
            break;
        }
        const cublasOperation_t op_t = CUBLAS_OP_T;
        const cublasOperation_t op_n = CUBLAS_OP_N;
        if (cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_TRANSA, &op_t, sizeof(op_t)) !=
                CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_TRANSB, &op_n, sizeof(op_n)) !=
                CUBLAS_STATUS_SUCCESS) {
            break;
        }
        const cublasLtMatmulMatrixScale_t scale_mode = CUBLASLT_MATMUL_MATRIX_SCALE_VEC32_UE8M0;
        if (cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_A_SCALE_MODE, &scale_mode,
                                           sizeof(scale_mode)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_B_SCALE_MODE, &scale_mode,
                                           sizeof(scale_mode)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_A_SCALE_POINTER, &dSFa,
                                           sizeof(dSFa)) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulDescSetAttribute(op, CUBLASLT_MATMUL_DESC_B_SCALE_POINTER, &dSFb,
                                           sizeof(dSFb)) != CUBLAS_STATUS_SUCCESS) {
            break;
        }

        if (cublasLtMatrixLayoutCreate(&a_layout, CUDA_R_4F_E2M1, K, M, K) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatrixLayoutCreate(&b_layout, CUDA_R_4F_E2M1, K, N, K) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatrixLayoutCreate(&d_layout, CUDA_R_32F, M, N, M) != CUBLAS_STATUS_SUCCESS) {
            break;
        }

        if (cublasLtMatmulPreferenceCreate(&pref) != CUBLAS_STATUS_SUCCESS ||
            cublasLtMatmulPreferenceSetAttribute(pref, CUBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES,
                                                 &workspace_bytes,
                                                 sizeof(workspace_bytes)) != CUBLAS_STATUS_SUCCESS) {
            break;
        }

        cublasLtMatmulHeuristicResult_t heuristic{};
        int returned = 0;
        if (cublasLtMatmulAlgoGetHeuristic(lt, op, a_layout, b_layout, d_layout, d_layout, pref, 1,
                                           &heuristic, &returned) != CUBLAS_STATUS_SUCCESS ||
            returned == 0) {
            break;
        }

        const float alpha = 1.0f;
        const float beta = 0.0f;
        if (cublasLtMatmul(lt, op, &alpha, dA, a_layout, dB, b_layout, &beta, dD, d_layout, dD,
                           d_layout, &heuristic.algo, workspace, workspace_bytes, stream) !=
            CUBLAS_STATUS_SUCCESS) {
            break;
        }
        ok = true;
    } while (false);

    if (pref) cublasLtMatmulPreferenceDestroy(pref);
    if (d_layout) cublasLtMatrixLayoutDestroy(d_layout);
    if (b_layout) cublasLtMatrixLayoutDestroy(b_layout);
    if (a_layout) cublasLtMatrixLayoutDestroy(a_layout);
    if (op) cublasLtMatmulDescDestroy(op);
    if (lt) cublasLtDestroy(lt);
    return ok;
}

/** Real TC: factor → cuBLASLt CUDA_R_4F_E2M1 + VEC32_UE8M0 → exact int32 (arena). */
[[nodiscard]] bool LaunchMxfp4OnePanelCublasLt(const std::vector<int8_t>& Lpanel,
                                               const std::vector<int8_t>& Rpanel, uint32_t rows,
                                               uint32_t len, uint32_t cols,
                                               std::vector<int32_t>& partial, std::string* error,
                                               cudaStream_t stream = nullptr)
{
    std::vector<uint8_t> A_pack, B_pack, SFa, SFb;
    uint32_t Mpad = 0, Npad = 0, Kpad = 0;
    if (!PackOzakiPanelsCublasLtFp4(Lpanel, Rpanel, rows, len, cols, A_pack, B_pack, SFa, SFb, Mpad,
                                    Npad, Kpad, error)) {
        return false;
    }

    auto& arena = Arena();
    constexpr size_t kWorkspace = 32ull * 1024ull * 1024ull;
    if (!arena.Ensure(A_pack.size(), B_pack.size(), SFa.size(), SFb.size(),
                      static_cast<size_t>(Mpad) * Npad, kWorkspace)) {
        if (error) *error = "rc_ozaki_mxfp4_cublaslt arena ensure failed";
        return false;
    }
    cudaStream_t s = stream != nullptr ? stream : arena.stream;

    if (cudaMemcpyAsync(arena.dA.p, A_pack.data(), A_pack.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemcpyAsync(arena.dB.p, B_pack.data(), B_pack.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemcpyAsync(arena.dSFa.p, SFa.data(), SFa.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemcpyAsync(arena.dSFb.p, SFb.data(), SFb.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemsetAsync(arena.dD.p, 0, static_cast<size_t>(Mpad) * Npad * sizeof(float), s) !=
            cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4_cublaslt H2D failed";
        return false;
    }

    if (!RunCublasLtBlockScaledTnOzaki(arena.dA.p, arena.dB.p, arena.dSFa.p, arena.dSFb.p,
                                       static_cast<float*>(arena.dD.p), Mpad, Npad, Kpad,
                                       arena.dWS.p, kWorkspace, s)) {
        if (error) *error = "rc_ozaki_mxfp4_cublaslt matmul/heuristic failed";
        return false;
    }

    std::vector<float> host_d(static_cast<size_t>(Mpad) * Npad);
    if (cudaMemcpyAsync(host_d.data(), arena.dD.p, host_d.size() * sizeof(float),
                        cudaMemcpyDeviceToHost, s) != cudaSuccess ||
        cudaStreamSynchronize(s) != cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4_cublaslt D2H failed";
        return false;
    }

    g_native_tensor_launches.fetch_add(1, std::memory_order_relaxed);

    if (!Fp32ColMajorToExactInt32RowMajor(host_d, Mpad, Npad, rows, cols, partial)) {
        if (error) *error = "rc_ozaki_mxfp4_cublaslt FP32→int32 non-exact";
        return false;
    }
    return true;
}

/**
 * Pack for SM120 QMMA.SF: one e2m1 per byte in bits 5-2 (EncodeE2M1Nibble << 2).
 * A: M×K row-major, B: K×N row-major, SFA/SFB: UE8M0 [outer × kblocks].
 */
[[nodiscard]] bool PackOzakiPanelsMmaFp4(const std::vector<int8_t>& Lpanel,
                                         const std::vector<int8_t>& Rpanel, uint32_t rows,
                                         uint32_t K, uint32_t cols, std::vector<uint8_t>& A_pack,
                                         std::vector<uint8_t>& B_pack, std::vector<uint8_t>& SFa,
                                         std::vector<uint8_t>& SFb, uint32_t& Mpad, uint32_t& Npad,
                                         uint32_t& Kpad, std::string* error)
{
    if (rows == 0 || K == 0 || cols == 0) {
        if (error) *error = "PackOzakiPanelsMmaFp4: degenerate";
        return false;
    }
    Mpad = AlignUp(rows, 16u);
    Npad = AlignUp(cols, 8u);
    Kpad = AlignUp(K, kMxBlk);
    const uint32_t kblocks = Kpad / kMxBlk;
    A_pack.assign(static_cast<size_t>(Mpad) * Kpad, 0);
    B_pack.assign(static_cast<size_t>(Kpad) * Npad, 0);
    SFa.assign(static_cast<size_t>(Mpad) * kblocks, kUe8m0Bias);
    SFb.assign(static_cast<size_t>(Npad) * kblocks, kUe8m0Bias);

    int8_t mu_tmp[kMxBlk];
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = (k0 >= K) ? 0u : std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = Lpanel[static_cast<size_t>(r) * K + (k0 + t)];
            }
            uint8_t e = 0;
            if (n > 0) {
                if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                    if (error) *error = "PackOzakiPanelsMmaFp4: left not MX-factorable";
                    return false;
                }
            } else {
                std::memset(mu_tmp, 0, sizeof(mu_tmp));
            }
            SFa[static_cast<size_t>(r) * kblocks + bj] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < kMxBlk; ++t) {
                const int8_t mu = (t < n) ? mu_tmp[t] : int8_t{0};
                const uint8_t nib = EncodeE2M1Nibble(mu);
                if (nib > 0x0F) {
                    if (error) *error = "PackOzakiPanelsMmaFp4: left mu not E2M1";
                    return false;
                }
                A_pack[static_cast<size_t>(r) * Kpad + (k0 + t)] =
                    static_cast<uint8_t>(nib << 2);
            }
        }
    }
    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t bj = 0; bj < kblocks; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = (k0 >= K) ? 0u : std::min(kMxBlk, K - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) {
                block[t] = Rpanel[static_cast<size_t>(k0 + t) * cols + c];
            }
            uint8_t e = 0;
            if (n > 0) {
                if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                    if (error) *error = "PackOzakiPanelsMmaFp4: right not MX-factorable";
                    return false;
                }
            } else {
                std::memset(mu_tmp, 0, sizeof(mu_tmp));
            }
            SFb[static_cast<size_t>(c) * kblocks + bj] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < kMxBlk; ++t) {
                const int8_t mu = (t < n) ? mu_tmp[t] : int8_t{0};
                const uint8_t nib = EncodeE2M1Nibble(mu);
                if (nib > 0x0F) {
                    if (error) *error = "PackOzakiPanelsMmaFp4: right mu not E2M1";
                    return false;
                }
                B_pack[static_cast<size_t>(k0 + t) * Npad + c] = static_cast<uint8_t>(nib << 2);
            }
        }
    }
    return true;
}

[[nodiscard]] bool Fp32RowMajorToExactInt32RowMajor(const std::vector<float>& D, uint32_t M,
                                                    uint32_t N, uint32_t rows, uint32_t cols,
                                                    std::vector<int32_t>& out)
{
    if (D.size() != static_cast<size_t>(M) * N || rows > M || cols > N) return false;
    out.resize(static_cast<size_t>(rows) * cols);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < cols; ++c) {
            const float f = D[static_cast<size_t>(r) * N + c];
            if (!std::isfinite(f)) return false;
            const float rounded = nearbyintf(f);
            if (rounded != f) return false;
            if (rounded < static_cast<float>(std::numeric_limits<int32_t>::min()) ||
                rounded > static_cast<float>(std::numeric_limits<int32_t>::max())) {
                return false;
            }
            out[static_cast<size_t>(r) * cols + c] = static_cast<int32_t>(rounded);
        }
    }
    return true;
}

/**
 * Real TC: factor → QMMA.SF m16n8k32 e2m1 block_scale → exact int32 (arena).
 * K must be a multiple of 32 — never zero-pad inside a tile. Callers hybridize
 * remainder via scalar-tail (counted separately; not MMA evidence).
 */
[[nodiscard]] bool LaunchMxfp4OnePanelMma(const std::vector<int8_t>& Lpanel,
                                          const std::vector<int8_t>& Rpanel, uint32_t rows,
                                          uint32_t len, uint32_t cols,
                                          std::vector<int32_t>& partial, std::string* error,
                                          cudaStream_t stream = nullptr)
{
    if (len == 0 || (len % kMxBlk) != 0) {
        if (error) *error = "rc_ozaki_mxfp4_mma: K not multiple of 32";
        return false;
    }
    std::vector<uint8_t> A_pack, B_pack, SFa, SFb;
    uint32_t Mpad = 0, Npad = 0, Kpad = 0;
    if (!PackOzakiPanelsMmaFp4(Lpanel, Rpanel, rows, len, cols, A_pack, B_pack, SFa, SFb, Mpad, Npad,
                               Kpad, error)) {
        return false;
    }
    if (Kpad != len) {
        if (error) *error = "rc_ozaki_mxfp4_mma: unexpected K pad";
        return false;
    }
    const uint32_t kblocks = Kpad / kMxBlk;

    auto& arena = Arena();
    if (!arena.Ensure(A_pack.size(), B_pack.size(), SFa.size(), SFb.size(),
                      static_cast<size_t>(Mpad) * Npad)) {
        if (error) *error = "rc_ozaki_mxfp4_mma arena ensure failed";
        return false;
    }
    cudaStream_t s = stream != nullptr ? stream : arena.stream;

    if (cudaMemcpyAsync(arena.dA.p, A_pack.data(), A_pack.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemcpyAsync(arena.dB.p, B_pack.data(), B_pack.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemcpyAsync(arena.dSFa.p, SFa.data(), SFa.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemcpyAsync(arena.dSFb.p, SFb.data(), SFb.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemsetAsync(arena.dD.p, 0, static_cast<size_t>(Mpad) * Npad * sizeof(float), s) !=
            cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4_mma H2D failed";
        return false;
    }

    dim3 grid(Npad / 8u, Mpad / 16u);
    rc_ozaki_mxfp4_mma_gemm<<<grid, 32, 0, s>>>(
        static_cast<const uint8_t*>(arena.dA.p), static_cast<const uint8_t*>(arena.dB.p),
        static_cast<const uint8_t*>(arena.dSFa.p), static_cast<const uint8_t*>(arena.dSFb.p),
        static_cast<float*>(arena.dD.p), static_cast<int>(Mpad), static_cast<int>(Npad),
        static_cast<int>(Kpad), static_cast<int>(kblocks));
    if (cudaGetLastError() != cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4_mma kernel launch failed";
        return false;
    }

    std::vector<float> host_d(static_cast<size_t>(Mpad) * Npad);
    if (cudaMemcpyAsync(host_d.data(), arena.dD.p, host_d.size() * sizeof(float),
                        cudaMemcpyDeviceToHost, s) != cudaSuccess ||
        cudaStreamSynchronize(s) != cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4_mma D2H failed";
        return false;
    }

    // Count only after successful launch+sync — scalar-tail never increments this.
    g_native_tensor_launches.fetch_add(1, std::memory_order_relaxed);

    if (!Fp32RowMajorToExactInt32RowMajor(host_d, Mpad, Npad, rows, cols, partial)) {
        if (error) *error = "rc_ozaki_mxfp4_mma FP32→int32 non-exact";
        return false;
    }
    return true;
}

/**
 * Real TC: factor → tcgen05.mma.kind::mxf8f6f4.block_scale (sm_100a) → exact int32.
 * K must be a multiple of 32 (never zero-pad inside a tile; the panel driver
 * hybridizes the K%32 remainder via scalar-tail, counted separately). Reuses the
 * SM120 row-major e2m1<<... no: the tcgen05 kernel consumes plain e2m1 nibble
 * bytes in bits[3:0] (NOT the SM120 QMMA <<2 layout). We therefore pack here with
 * FactorInt8ToMxM11E8M0 (nibble in low bits) unpacked to one byte per element.
 */
[[nodiscard]] bool LaunchMxfp4OnePanelSm100Mma(const std::vector<int8_t>& Lpanel,
                                               const std::vector<int8_t>& Rpanel, uint32_t rows,
                                               uint32_t len, uint32_t cols,
                                               std::vector<int32_t>& partial, std::string* error,
                                               cudaStream_t stream = nullptr)
{
    if (len == 0 || (len % kMxBlk) != 0) {
        if (error) *error = "rc_ozaki_mxfp4_tcgen05: K not multiple of 32";
        return false;
    }
    // Pack e2m1 nibbles into one byte each (low 4 bits) + UE8M0 [outer×kblocks].
    // A: rows×len row-major, B: len×cols row-major, then pad M→128k, N→128k, K→128.
    const uint32_t Mtile = AlignUp(rows, 128u);
    const uint32_t Ntile = AlignUp(cols, 128u);
    const uint32_t Ktile = AlignUp(len, 128u);
    const uint32_t kblocks = Ktile / kMxBlk;

    std::vector<uint8_t> A(static_cast<size_t>(Mtile) * Ktile, 0);
    std::vector<uint8_t> B(static_cast<size_t>(Ktile) * Ntile, 0);
    std::vector<uint8_t> SFa(static_cast<size_t>(Mtile) * kblocks, kUe8m0Bias);
    std::vector<uint8_t> SFb(static_cast<size_t>(Ntile) * kblocks, kUe8m0Bias);

    int8_t mu_tmp[kMxBlk];
    const uint32_t kblk_real = (len + kMxBlk - 1u) / kMxBlk;
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t bj = 0; bj < kblk_real; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = std::min(kMxBlk, len - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) block[t] = Lpanel[static_cast<size_t>(r) * len + (k0 + t)];
            uint8_t e = 0;
            if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                if (error) *error = "rc_ozaki_mxfp4_tcgen05: left not MX-factorable";
                return false;
            }
            SFa[static_cast<size_t>(r) * kblocks + bj] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < n; ++t) {
                const uint8_t nib = EncodeE2M1Nibble(mu_tmp[t]);
                if (nib > 0x0F) {
                    if (error) *error = "rc_ozaki_mxfp4_tcgen05: left mu not E2M1";
                    return false;
                }
                A[static_cast<size_t>(r) * Ktile + (k0 + t)] = nib;
            }
        }
    }
    for (uint32_t c = 0; c < cols; ++c) {
        for (uint32_t bj = 0; bj < kblk_real; ++bj) {
            const uint32_t k0 = bj * kMxBlk;
            const uint32_t n = std::min(kMxBlk, len - k0);
            int8_t block[kMxBlk] = {};
            for (uint32_t t = 0; t < n; ++t) block[t] = Rpanel[static_cast<size_t>(k0 + t) * cols + c];
            uint8_t e = 0;
            if (!FactorBlockToMx(block, n, e, mu_tmp)) {
                if (error) *error = "rc_ozaki_mxfp4_tcgen05: right not MX-factorable";
                return false;
            }
            SFb[static_cast<size_t>(c) * kblocks + bj] = EncodeUe8m0FromBtXScale(e);
            for (uint32_t t = 0; t < n; ++t) {
                const uint8_t nib = EncodeE2M1Nibble(mu_tmp[t]);
                if (nib > 0x0F) {
                    if (error) *error = "rc_ozaki_mxfp4_tcgen05: right mu not E2M1";
                    return false;
                }
                B[static_cast<size_t>(k0 + t) * Ntile + c] = nib;
            }
        }
    }

    auto& arena = Arena();
    if (!arena.Ensure(A.size(), B.size(), SFa.size(), SFb.size(),
                      static_cast<size_t>(Mtile) * Ntile)) {
        if (error) *error = "rc_ozaki_mxfp4_tcgen05 arena ensure failed";
        return false;
    }
    cudaStream_t s = stream != nullptr ? stream : arena.stream;

    if (cudaMemcpyAsync(arena.dA.p, A.data(), A.size(), cudaMemcpyHostToDevice, s) != cudaSuccess ||
        cudaMemcpyAsync(arena.dB.p, B.data(), B.size(), cudaMemcpyHostToDevice, s) != cudaSuccess ||
        cudaMemcpyAsync(arena.dSFa.p, SFa.data(), SFa.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemcpyAsync(arena.dSFb.p, SFb.data(), SFb.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemsetAsync(arena.dD.p, 0, static_cast<size_t>(Mtile) * Ntile * sizeof(float), s) !=
            cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4_tcgen05 H2D failed";
        return false;
    }

    // SMEM: A tile (128×128) + B tile (128×128) + mbarrier (8B) + alloc slot (4B).
    const size_t smem_bytes = 2u * 128u * 128u + sizeof(uint64_t) + sizeof(uint32_t);
    dim3 grid((Ntile + 127u) / 128u, (Mtile + 127u) / 128u);
    static std::atomic<bool> smem_attr_set{false};
    if (!smem_attr_set.exchange(true)) {
        // Best-effort opt-in; 32KB is under the 48KB default so failure is benign.
        (void)cudaFuncSetAttribute(reinterpret_cast<const void*>(&rc_ozaki_mxfp4_tcgen05_gemm),
                                   cudaFuncAttributeMaxDynamicSharedMemorySize,
                                   static_cast<int>(smem_bytes));
    }
    rc_ozaki_mxfp4_tcgen05_gemm<<<grid, 128, smem_bytes, s>>>(
        static_cast<const uint8_t*>(arena.dA.p), static_cast<const uint8_t*>(arena.dB.p),
        static_cast<const uint8_t*>(arena.dSFa.p), static_cast<const uint8_t*>(arena.dSFb.p),
        static_cast<float*>(arena.dD.p), static_cast<int>(Mtile), static_cast<int>(Ntile),
        static_cast<int>(Ktile), static_cast<int>(kblocks));
    if (cudaGetLastError() != cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4_tcgen05 kernel launch failed";
        return false;
    }

    std::vector<float> host_d(static_cast<size_t>(Mtile) * Ntile);
    if (cudaMemcpyAsync(host_d.data(), arena.dD.p, host_d.size() * sizeof(float),
                        cudaMemcpyDeviceToHost, s) != cudaSuccess ||
        cudaStreamSynchronize(s) != cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4_tcgen05 D2H failed";
        return false;
    }

    // Count only after successful launch+sync — scalar-tail never increments this.
    g_native_tensor_launches.fetch_add(1, std::memory_order_relaxed);

    if (!Fp32RowMajorToExactInt32RowMajor(host_d, Mtile, Ntile, rows, cols, partial)) {
        if (error) *error = "rc_ozaki_mxfp4_tcgen05 FP32→int32 non-exact";
        return false;
    }
    return true;
}

#else // no FP4 toolkit

[[nodiscard]] bool LaunchMxfp4OnePanelMma(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                          uint32_t, uint32_t, uint32_t, std::vector<int32_t>&,
                                          std::string* error, cudaStream_t = nullptr)
{
    if (error) *error = "rc_ozaki_mxfp4_mma: toolkit lacks FP4 helpers";
    return false;
}

[[nodiscard]] bool LaunchMxfp4OnePanelCublasLt(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                               uint32_t, uint32_t, uint32_t, std::vector<int32_t>&,
                                               std::string* error, cudaStream_t = nullptr)
{
    if (error) *error = "rc_ozaki_mxfp4_cublaslt: toolkit lacks FP4/VEC32";
    return false;
}

[[nodiscard]] bool LaunchMxfp4OnePanelSm100Mma(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                               uint32_t, uint32_t, uint32_t, std::vector<int32_t>&,
                                               std::string* error, cudaStream_t = nullptr)
{
    if (error) *error = "rc_ozaki_mxfp4_tcgen05: toolkit lacks FP4 helpers";
    return false;
}

#endif

/** Scalar-decode MXFP4 panel (E2M1 nibble decode + FP32 accumulate) — NOT native. */
[[nodiscard]] bool LaunchMxfp4OnePanelScalar(const std::vector<int8_t>& Lpanel,
                                             const std::vector<int8_t>& Rpanel, uint32_t rows,
                                             uint32_t len, uint32_t cols,
                                             std::vector<int32_t>& partial, std::string* error,
                                             cudaStream_t stream = nullptr)
{
    std::vector<uint8_t> a_e2m1, b_e2m1, sfa, sfb;
    uint32_t kblocks = 0;
    if (!FactorInt8ToMxM11E8M0(Lpanel, Rpanel, rows, len, cols, a_e2m1, b_e2m1, sfa, sfb, kblocks,
                               error)) {
        return false;
    }

    auto& arena = Arena();
    const size_t out_n = static_cast<size_t>(rows) * cols;
    if (!arena.Ensure(a_e2m1.size(), b_e2m1.size(), sfa.size(), sfb.size(), out_n)) {
        if (error) *error = "rc_ozaki_mxfp4 scalar arena ensure failed";
        return false;
    }
    cudaStream_t s = stream != nullptr ? stream : arena.stream;

    if (cudaMemcpyAsync(arena.dA.p, a_e2m1.data(), a_e2m1.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemcpyAsync(arena.dB.p, b_e2m1.data(), b_e2m1.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemcpyAsync(arena.dSFa.p, sfa.data(), sfa.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess ||
        cudaMemcpyAsync(arena.dSFb.p, sfb.data(), sfb.size(), cudaMemcpyHostToDevice, s) !=
            cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4 H2D failed";
        return false;
    }

    dim3 block(16, 16);
    dim3 grid((cols + block.x - 1) / block.x, (rows + block.y - 1) / block.y);
    rc_ozaki_mxfp4_panel_gemm<<<grid, block, 0, s>>>(
        static_cast<const uint8_t*>(arena.dA.p), static_cast<const uint8_t*>(arena.dB.p),
        static_cast<const uint8_t*>(arena.dSFa.p), static_cast<const uint8_t*>(arena.dSFb.p),
        static_cast<float*>(arena.dD.p), rows, len, cols, kblocks);
    if (cudaGetLastError() != cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4_panel_gemm launch failed";
        return false;
    }

    std::vector<float> host_fp(out_n);
    if (cudaMemcpyAsync(host_fp.data(), arena.dD.p, out_n * sizeof(float), cudaMemcpyDeviceToHost,
                        s) != cudaSuccess ||
        cudaStreamSynchronize(s) != cudaSuccess) {
        if (error) *error = "rc_ozaki_mxfp4 D2H failed";
        return false;
    }

    g_scalar_tail_launches.fetch_add(1, std::memory_order_relaxed);

    std::string conv_err;
    if (!Fp32OutputToExactInt32(host_fp.data(), out_n, partial, conv_err)) {
        if (error) *error = conv_err.empty() ? "Fp32OutputToExactInt32 failed" : conv_err;
        return false;
    }
    return true;
}


/**
 * F4 / WP-D: one-panel exact GEMM.
 * Fast path (one MMA / scalar / cuBLASLt): ONLY when |a|,|b| <= 48 AND the panel
 * FactorBlockToMx-succeeds (MX alphabet). Otherwise exact base-4: 16 limb-pair
 * products with digits in {-3..3}, recombine in int64 (weight 2^(2(i+j))).
 */
using Mxfp4OnePanelFn = bool (*)(const std::vector<int8_t>&, const std::vector<int8_t>&, uint32_t,
                                 uint32_t, uint32_t, std::vector<int32_t>&, std::string*,
                                 cudaStream_t);

[[nodiscard]] bool LaunchMxfp4OnePanelExact(const std::vector<int8_t>& Lpanel,
                                            const std::vector<int8_t>& Rpanel, uint32_t rows,
                                            uint32_t len, uint32_t cols,
                                            std::vector<int64_t>& out_panel, std::string* error,
                                            Mxfp4OnePanelFn launch_one)
{
    out_panel.assign(static_cast<size_t>(rows) * cols, 0);
    if (matmul::v4::rc::RcOzakiOperandsFitMxFastPathAbs(Lpanel, Rpanel)) {
        std::vector<int32_t> partial;
        std::string local;
        if (launch_one(Lpanel, Rpanel, rows, len, cols, partial, &local, nullptr) &&
            partial.size() == out_panel.size()) {
            for (size_t i = 0; i < out_panel.size(); ++i) {
                out_panel[i] = static_cast<int64_t>(partial[i]);
            }
            return true;
        }
    }

    std::vector<int8_t> a_planes[4];
    std::vector<int8_t> b_planes[4];
    matmul::v4::rc::DecomposeInt8Base4Planes(Lpanel.data(), Lpanel.size(), a_planes);
    matmul::v4::rc::DecomposeInt8Base4Planes(Rpanel.data(), Rpanel.size(), b_planes);

    for (uint32_t i = 0; i < 4; ++i) {
        for (uint32_t j = 0; j < 4; ++j) {
            const int64_t weight = int64_t{1} << (2u * (i + j));
            std::vector<int32_t> partial;
            if (!launch_one(a_planes[i], b_planes[j], rows, len, cols, partial, error, nullptr) ||
                partial.size() != out_panel.size()) {
                out_panel.clear();
                return false;
            }
            for (size_t t = 0; t < out_panel.size(); ++t) {
                out_panel[t] += static_cast<int64_t>(partial[t]) * weight;
            }
        }
    }
    return true;
}

/**
 * Scalar-decode MXFP4 Ozaki panels (E2M1 nibble decode + FP32 accumulate).
 * Exactness/reference accelerator only — NEVER flips native MXFP4 latches.
 * CRITICAL: must not call LaunchGemmS8S8. Backend marker includes scalar-decode.
 */
[[nodiscard]] bool LaunchOzakiMxfp4PanelsScalar(const std::vector<int8_t>& left,
                                                const std::vector<int8_t>& right, uint32_t rows,
                                                uint32_t inner, uint32_t cols,
                                                std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "Ozaki MXFP4 degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "Ozaki MXFP4 operand size mismatch";
        return false;
    }

    using matmul::v4::rc::kRCOzakiExactChunk;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t k0 = 0; k0 < inner; k0 += kRCOzakiExactChunk) {
        const uint32_t len = std::min(kRCOzakiExactChunk, inner - k0);
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

        std::vector<int64_t> partial;
        if (!LaunchMxfp4OnePanelExact(Lpanel, Rpanel, rows, len, cols, partial, error,
                                      &LaunchMxfp4OnePanelScalar) ||
            partial.size() != out.size()) {
            out.clear();
            return false;
        }
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += partial[i];
        }
    }
    return true;
}

/** Real TC Ozaki panels via cuBLASLt block-scaled E2M1 (native claim path). */
[[nodiscard]] bool LaunchOzakiMxfp4PanelsCublasLt(const std::vector<int8_t>& left,
                                                const std::vector<int8_t>& right, uint32_t rows,
                                                uint32_t inner, uint32_t cols,
                                                std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "Ozaki MXFP4 TC degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "Ozaki MXFP4 TC operand size mismatch";
        return false;
    }

    using matmul::v4::rc::kRCOzakiExactChunk;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t k0 = 0; k0 < inner; k0 += kRCOzakiExactChunk) {
        const uint32_t len = std::min(kRCOzakiExactChunk, inner - k0);
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

        std::vector<int64_t> partial;
        if (!LaunchMxfp4OnePanelExact(Lpanel, Rpanel, rows, len, cols, partial, error,
                                      &LaunchMxfp4OnePanelCublasLt) ||
            partial.size() != out.size()) {
            out.clear();
            return false;
        }
        for (size_t i = 0; i < out.size(); ++i) {
            out[i] += partial[i];
        }
    }
    return true;
}

/** Real TC Ozaki panels via SM120 QMMA.SF m16n8k32 e2m1 block_scale (native claim path).
 * Full K/32 tiles → MMA; K%32 remainder → scalar-decode (exactness). Never zero-pads
 * inside an MMA tile. */
[[nodiscard]] bool LaunchOzakiMxfp4PanelsMma(const std::vector<int8_t>& left,
                                             const std::vector<int8_t>& right, uint32_t rows,
                                             uint32_t inner, uint32_t cols,
                                             std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    {
        int device = 0;
        cudaDeviceProp prop{};
        if (cudaGetDevice(&device) == cudaSuccess &&
            cudaGetDeviceProperties(&prop, device) == cudaSuccess &&
            DeviceLooksSm100(prop.major, prop.minor)) {
            if (error) {
                *error = "SM100 refuse SM120_MMA: use SM100_CUBLASLT (no MMA dispatch)";
            }
            return false;
        }
    }
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "Ozaki MXFP4 MMA degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "Ozaki MXFP4 MMA operand size mismatch";
        return false;
    }

    out.assign(static_cast<size_t>(rows) * cols, 0);
    const uint32_t k_full = (inner / kMxBlk) * kMxBlk;
    const uint32_t k_rem = inner - k_full;

    auto add_partial64 = [&](const std::vector<int64_t>& partial) -> bool {
        if (partial.size() != out.size()) return false;
        for (size_t i = 0; i < out.size(); ++i) out[i] += partial[i];
        return true;
    };

    using matmul::v4::rc::kRCOzakiExactChunk;
    for (uint32_t k0 = 0; k0 < k_full; k0 += kRCOzakiExactChunk) {
        uint32_t len = std::min(kRCOzakiExactChunk, k_full - k0);
        len = (len / kMxBlk) * kMxBlk;
        if (len == 0) continue;
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
        std::vector<int64_t> partial;
        if (!LaunchMxfp4OnePanelExact(Lpanel, Rpanel, rows, len, cols, partial, error,
                                      &LaunchMxfp4OnePanelMma) ||
            !add_partial64(partial)) {
            out.clear();
            return false;
        }
    }

    if (k_rem > 0) {
        std::vector<int8_t> Lpanel(static_cast<size_t>(rows) * k_rem);
        std::vector<int8_t> Rpanel(static_cast<size_t>(k_rem) * cols);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t t = 0; t < k_rem; ++t) {
                Lpanel[static_cast<size_t>(r) * k_rem + t] =
                    left[static_cast<size_t>(r) * inner + (k_full + t)];
            }
        }
        for (uint32_t t = 0; t < k_rem; ++t) {
            for (uint32_t c = 0; c < cols; ++c) {
                Rpanel[static_cast<size_t>(t) * cols + c] =
                    right[static_cast<size_t>(k_full + t) * cols + c];
            }
        }
        std::vector<int64_t> partial;
        if (!LaunchMxfp4OnePanelExact(Lpanel, Rpanel, rows, k_rem, cols, partial, error,
                                      &LaunchMxfp4OnePanelScalar) ||
            !add_partial64(partial)) {
            out.clear();
            return false;
        }
    }
    return true;
}

/** Real TC Ozaki panels via SM100 tcgen05.mma.kind::mxf8f6f4.block_scale (native
 * claim path, B200). Full K/32 tiles → tcgen05 MMA; K%32 remainder → scalar-decode
 * (exactness). Never zero-pads inside an MMA tile. REFUSES any non-sm_100 device —
 * the SM120 warp MMA and the SM100 tcgen05 MMA are mutually exclusive ISAs. */
[[nodiscard]] bool LaunchOzakiMxfp4PanelsSm100Mma(const std::vector<int8_t>& left,
                                                  const std::vector<int8_t>& right, uint32_t rows,
                                                  uint32_t inner, uint32_t cols,
                                                  std::vector<int64_t>& out, std::string* error)
{
    out.clear();
    {
        int device = 0;
        cudaDeviceProp prop{};
        if (cudaGetDevice(&device) != cudaSuccess ||
            cudaGetDeviceProperties(&prop, device) != cudaSuccess ||
            !DeviceLooksSm100(prop.major, prop.minor)) {
            if (error) {
                *error = "SM100_MMA refuses non-sm_100 device (tcgen05 requires B200)";
            }
            return false;
        }
    }
    if (rows == 0 || inner == 0 || cols == 0) {
        if (error) *error = "Ozaki MXFP4 tcgen05 degenerate shape";
        return false;
    }
    if (left.size() != static_cast<size_t>(rows) * inner ||
        right.size() != static_cast<size_t>(inner) * cols) {
        if (error) *error = "Ozaki MXFP4 tcgen05 operand size mismatch";
        return false;
    }

    out.assign(static_cast<size_t>(rows) * cols, 0);
    const uint32_t k_full = (inner / kMxBlk) * kMxBlk;
    const uint32_t k_rem = inner - k_full;

    auto add_partial64 = [&](const std::vector<int64_t>& partial) -> bool {
        if (partial.size() != out.size()) return false;
        for (size_t i = 0; i < out.size(); ++i) out[i] += partial[i];
        return true;
    };

    using matmul::v4::rc::kRCOzakiExactChunk;
    for (uint32_t k0 = 0; k0 < k_full; k0 += kRCOzakiExactChunk) {
        uint32_t len = std::min(kRCOzakiExactChunk, k_full - k0);
        len = (len / kMxBlk) * kMxBlk;
        if (len == 0) continue;
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
        std::vector<int64_t> partial;
        if (!LaunchMxfp4OnePanelExact(Lpanel, Rpanel, rows, len, cols, partial, error,
                                      &LaunchMxfp4OnePanelSm100Mma) ||
            !add_partial64(partial)) {
            out.clear();
            return false;
        }
    }

    if (k_rem > 0) {
        std::vector<int8_t> Lpanel(static_cast<size_t>(rows) * k_rem);
        std::vector<int8_t> Rpanel(static_cast<size_t>(k_rem) * cols);
        for (uint32_t r = 0; r < rows; ++r) {
            for (uint32_t t = 0; t < k_rem; ++t) {
                Lpanel[static_cast<size_t>(r) * k_rem + t] =
                    left[static_cast<size_t>(r) * inner + (k_full + t)];
            }
        }
        for (uint32_t t = 0; t < k_rem; ++t) {
            for (uint32_t c = 0; c < cols; ++c) {
                Rpanel[static_cast<size_t>(t) * cols + c] =
                    right[static_cast<size_t>(k_full + t) * cols + c];
            }
        }
        std::vector<int64_t> partial;
        if (!LaunchMxfp4OnePanelExact(Lpanel, Rpanel, rows, k_rem, cols, partial, error,
                                      &LaunchMxfp4OnePanelScalar) ||
            !add_partial64(partial)) {
            out.clear();
            return false;
        }
    }
    return true;
}

void FillM11E8M0Max(std::vector<int8_t>& L, std::vector<int8_t>& R, uint32_t rows, uint32_t inner,
                    uint32_t cols, uint32_t seed, uint8_t e)
{
    L.assign(static_cast<size_t>(rows) * inner, 0);
    R.assign(static_cast<size_t>(inner) * cols, 0);
    const int32_t mag = 6 * (1 << e);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t k = 0; k < inner; ++k) {
            // Uniform e within each K-block (MX-shaped).
            const bool neg = ((r + (k / kMxBlk) + seed) & 1u) != 0;
            L[static_cast<size_t>(r) * inner + k] = static_cast<int8_t>(neg ? -mag : mag);
        }
    }
    for (uint32_t k = 0; k < inner; ++k) {
        for (uint32_t c = 0; c < cols; ++c) {
            const bool neg = (((k / kMxBlk) * 3u + c + seed) & 1u) != 0;
            R[static_cast<size_t>(k) * cols + c] = static_cast<int8_t>(neg ? -mag : mag);
        }
    }
}

void FillMxSeeded(std::vector<int8_t>& L, std::vector<int8_t>& R, uint32_t rows, uint32_t inner,
                  uint32_t cols, uint32_t seed)
{
    static constexpr int8_t kM11[] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    L.assign(static_cast<size_t>(rows) * inner, 0);
    R.assign(static_cast<size_t>(inner) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t k = 0; k < inner; ++k) {
            const uint8_t e = static_cast<uint8_t>((seed + (k / kMxBlk)) & 3u);
            const int8_t mu = kM11[(r + k + seed) % 11];
            L[static_cast<size_t>(r) * inner + k] =
                static_cast<int8_t>(static_cast<int32_t>(mu) * (1 << e));
        }
    }
    for (uint32_t k = 0; k < inner; ++k) {
        for (uint32_t c = 0; c < cols; ++c) {
            const uint8_t e = static_cast<uint8_t>((seed * 3u + (k / kMxBlk)) & 3u);
            const int8_t mu = kM11[(k * 5u + c + seed) % 11];
            R[static_cast<size_t>(k) * cols + c] =
                static_cast<int8_t>(static_cast<int32_t>(mu) * (1 << e));
        }
    }
}

/** Abrupt E8M0 scale transitions at every K-block boundary (negatives included). */
void FillScaleTransitions(std::vector<int8_t>& L, std::vector<int8_t>& R, uint32_t rows,
                          uint32_t inner, uint32_t cols, uint32_t seed)
{
    static constexpr int8_t kM11[] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 6, -6};
    L.assign(static_cast<size_t>(rows) * inner, 0);
    R.assign(static_cast<size_t>(inner) * cols, 0);
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t k = 0; k < inner; ++k) {
            const uint8_t e = static_cast<uint8_t>((k / kMxBlk) & 3u);
            const int8_t mu = kM11[(r * 7u + k + seed) % 11];
            L[static_cast<size_t>(r) * inner + k] =
                static_cast<int8_t>(static_cast<int32_t>(mu) * (1 << e));
        }
    }
    for (uint32_t k = 0; k < inner; ++k) {
        for (uint32_t c = 0; c < cols; ++c) {
            // Opposite phase so products stress scale×scale transitions.
            const uint8_t e = static_cast<uint8_t>((3u - ((k / kMxBlk) & 3u)) & 3u);
            const int8_t mu = kM11[(c * 3u + k + seed * 5u) % 11];
            R[static_cast<size_t>(k) * cols + c] =
                static_cast<int8_t>(static_cast<int32_t>(mu) * (1 << e));
        }
    }
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

[[nodiscard]] bool ExactShapeMatches(uint32_t rows, uint32_t inner, uint32_t cols, uint32_t seed,
                                     std::string* error)
{
    std::vector<int8_t> left, right;
    FillMxSeeded(left, right, rows, inner, cols, seed);
    // Also allow non-MX pseudo for ExactPanels (IMMA accepts any int8 in range).
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
    std::vector<int64_t> gpu;
    if (!LaunchOzakiExactPanels(left, right, rows, inner, cols, gpu, error)) return false;
    if (gpu != cpu) {
        if (error) *error = "CUDA ExactPanels != CPU Ozaki oracle";
        return false;
    }
    return true;
}

enum class MxFillKind : uint8_t { Seeded = 0, MaxCorner = 1, ScaleTransition = 2, HighScaleMixed = 3 };

using Mxfp4PanelLauncher = bool (*)(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                    uint32_t, uint32_t, uint32_t, std::vector<int64_t>&,
                                    std::string*);

[[nodiscard]] bool Mxfp4ShapeMatches(uint32_t rows, uint32_t inner, uint32_t cols, uint32_t seed,
                                     MxFillKind fill, uint8_t e, Mxfp4PanelLauncher launch,
                                     std::string* error)
{
    std::vector<int8_t> left, right;
    switch (fill) {
    case MxFillKind::MaxCorner:
        FillM11E8M0Max(left, right, rows, inner, cols, seed, e);
        break;
    case MxFillKind::ScaleTransition:
        FillScaleTransitions(left, right, rows, inner, cols, seed);
        break;
    case MxFillKind::HighScaleMixed:
        matmul::v4::rc::FillHighScaleMixedPanels(left, right, rows, inner, cols);
        break;
    case MxFillKind::Seeded:
    default:
        FillMxSeeded(left, right, rows, inner, cols, seed);
        break;
    }
    std::vector<int64_t> cpu;
    DenseInt64(left, right, rows, inner, cols, cpu);
    std::vector<int64_t> gpu;
    if (!launch(left, right, rows, inner, cols, gpu, error)) return false;
    if (gpu != cpu) {
        if (error) *error = "CUDA MXFP4 panels != int64 oracle";
        return false;
    }
    // Corrupted device output must fail the equality gate.
    if (!gpu.empty()) {
        auto corrupted = gpu;
        corrupted[0] += 1;
        if (corrupted == cpu) {
            if (error) *error = "corruption-equality sanity failed";
            return false;
        }
    }
    return true;
}

/**
 * COMPLETE suite for ONE launcher. Never mix MMA + cuBLASLt evidence.
 * Boundary K={1,8,31,32,33,4095,4096,4097,8192,16384}; production-ish M/N;
 * M11/E8M0 corners; scale transitions; both sides of 2^24 (via K=4096 vs 8192+).
 */
[[nodiscard]] bool Mxfp4CompleteSuiteForLauncher(Mxfp4PanelLauncher launch, std::string* error)
{
    struct Case {
        uint32_t rows, inner, cols, seed;
        MxFillKind fill;
        uint8_t e;
    };
    static constexpr Case kCases[] = {
        // Thin / remainder-K (scalar-tail for MMA hybrid; still must be exact).
        {4, 1, 4, 1, MxFillKind::Seeded, 0},
        {4, 8, 4, 2, MxFillKind::Seeded, 0},
        {4, 31, 4, 3, MxFillKind::MaxCorner, 3},
        {4, 32, 4, 5, MxFillKind::MaxCorner, 2},
        {4, 33, 4, 7, MxFillKind::Seeded, 0},
        // 2^24 neighborhood (2304·K): 4096 below, 8192/16384 above for max M11.
        {4, 4095, 4, 11, MxFillKind::MaxCorner, 3},
        {4, 4096, 4, 13, MxFillKind::MaxCorner, 3},
        {4, 4097, 4, 17, MxFillKind::MaxCorner, 2},
        {4, 8192, 4, 19, MxFillKind::Seeded, 0},
        {4, 16384, 4, 23, MxFillKind::ScaleTransition, 0},
        // Production-relevant M/N beyond 4×4 / 32×32.
        {8, 4096, 8, 29, MxFillKind::MaxCorner, 1},
        {16, 4096, 16, 31, MxFillKind::ScaleTransition, 0},
        {64, 32, 64, 37, MxFillKind::MaxCorner, 3},
        {128, 64, 16, 41, MxFillKind::Seeded, 0},
        {16, 128, 128, 43, MxFillKind::ScaleTransition, 0},
        {32, 4096, 32, 47, MxFillKind::MaxCorner, 3},
        // Negatives + e=0..3 corners.
        {8, 256, 8, 53, MxFillKind::MaxCorner, 0},
        {8, 256, 8, 59, MxFillKind::MaxCorner, 3},
        // F4 HighScaleMixed: -128 rails + odd low; requires base-4 limbs.
        {4, 64, 4, 61, MxFillKind::HighScaleMixed, 0},
        {8, 128, 8, 67, MxFillKind::HighScaleMixed, 0},
        // RTX PRO 6000 Blackwell resident-scale: a single lobe row (M=1)
        // contracting the full lobe_width K=8192 at max M11 magnitude. 2304·8192
        // ≈ 1.89e7 > 2^24, so this exercises the multi-panel exact accumulation
        // (kRCOzakiExactChunk keeps each MMA/cuBLASLt panel < 2^24) that the
        // resident 96 GB fast path depends on. HighScaleMixed variant adds the
        // -128 rail so base-4 limbs are forced at resident K.
        {1, 8192, 64, 71, MxFillKind::MaxCorner, 3},
        {1, 8192, 32, 73, MxFillKind::HighScaleMixed, 0},
    };
    for (const auto& c : kCases) {
        std::string local;
        if (!Mxfp4ShapeMatches(c.rows, c.inner, c.cols, c.seed, c.fill, c.e, launch, &local)) {
            if (error) {
                *error = "suite_fail M=" + std::to_string(c.rows) + " K=" + std::to_string(c.inner) +
                         " N=" + std::to_string(c.cols) + ": " + local;
            }
            return false;
        }
    }
    return true;
}

} // namespace

// Weak default: plain sm_120 / multi-arch builds without the sm_120a marker TU
// report false. Strong definition in matmul_v4_rc_mx_ozaki_native_sm120a.cu
// overrides when Agent B links that TU (compiled for sm_120a).
//
// F5: when BTX_CUDA_SM120_MXFP4_NATIVE is enabled, OMIT this weak-false marker
// so the strong-true object is force-extracted from the static archive (a weak
// definition in the same archive can otherwise satisfy the reference and leave
// the sm_120a marker TU unpulled).
#if !defined(BTX_CUDA_SM120_MXFP4_NATIVE) || !BTX_CUDA_SM120_MXFP4_NATIVE
__attribute__((weak)) bool RcOzakiMxfp4Sm120aKernelLinked()
{
    return false;
}
#endif

// Weak default: plain sm_100 / sm_120 / multi-arch builds without the sm_100a
// marker TU (matmul_v4_rc_mx_ozaki_native_sm100.cu) report false. Strong
// definition in that TU overrides when Agent B links it (compiled for sm_100a
// via BTX_CUDA_SM100_NATIVE, see cmake/BTXCudaSm100.cmake).
//
// F5 (mirror of the sm_120a marker): when BTX_CUDA_SM100_NATIVE is enabled, OMIT
// this weak-false marker so the strong-true object is force-extracted from the
// static archive (a weak definition in the same archive can otherwise satisfy the
// reference and leave the sm_100a marker TU unpulled).
#if !defined(BTX_CUDA_SM100_NATIVE) || !BTX_CUDA_SM100_NATIVE
__attribute__((weak)) bool RcOzakiMxfp4Sm100NativeLinked()
{
    return false;
}
#endif

bool IsRcOzakiCudaCompiled()
{
    return true;
}

bool IsRcOzakiCudaExactPanelsQualified()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    return g_exact_qualified;
}

bool SelfQualifyRcOzakiCudaExactPanelsOnce()
{
    {
        std::lock_guard<std::mutex> lock(g_ozaki_mu);
        if (g_exact_ran) return g_exact_qualified;
    }
    std::string err;
    const bool ok = ExactShapeMatches(8, 8, 8, 1u, &err) &&
                    ExactShapeMatches(32, 8192, 32, 7u, &err) &&
                    ExactShapeMatches(8, 4096, 8, 3u, &err);
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    if (!g_exact_ran) {
        g_exact_ran = true;
        g_exact_qualified = ok;
    }
    return g_exact_qualified;
}

bool TryLaunchRcOzakiExactPanelsGemmS8S8Int64(const std::vector<int8_t>& left,
                                             const std::vector<int8_t>& right, uint32_t rows,
                                             uint32_t inner, uint32_t cols,
                                             std::vector<int64_t>& out, std::string* error)
{
    return LaunchOzakiExactPanels(left, right, rows, inner, cols, out, error);
}

bool IsRcOzakiCudaMxfp4Qualified()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    if (g_mx_selected == RcOzakiMxfp4SelectedBackend::Unqualified) {
        return false;
    }
    // Belt-and-suspenders: never advertise SM120_MMA without the sm_120a object.
    if (g_mx_selected == RcOzakiMxfp4SelectedBackend::SM120_MMA &&
        !RcOzakiMxfp4Sm120aKernelLinked()) {
        return false;
    }
    // Same clamp for SM100_MMA: requires the sm_100a marker object.
    if (g_mx_selected == RcOzakiMxfp4SelectedBackend::SM100_MMA &&
        !RcOzakiMxfp4Sm100NativeLinked()) {
        return false;
    }
    return true;
}

RcOzakiMxfp4SelectedBackend RcOzakiCudaMxfp4SelectedBackend()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    if (g_mx_selected == RcOzakiMxfp4SelectedBackend::SM120_MMA &&
        !RcOzakiMxfp4Sm120aKernelLinked()) {
        return RcOzakiMxfp4SelectedBackend::Unqualified;
    }
    if (g_mx_selected == RcOzakiMxfp4SelectedBackend::SM100_MMA &&
        !RcOzakiMxfp4Sm100NativeLinked()) {
        return RcOzakiMxfp4SelectedBackend::Unqualified;
    }
    return g_mx_selected;
}

std::string RcOzakiCudaMxfp4ArchKey()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    return g_mx_arch_key;
}

std::string RcOzakiCudaMxfp4Backend()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    if ((g_mx_selected == RcOzakiMxfp4SelectedBackend::SM120_MMA &&
         !RcOzakiMxfp4Sm120aKernelLinked()) ||
        (g_mx_selected == RcOzakiMxfp4SelectedBackend::SM100_MMA &&
         !RcOzakiMxfp4Sm100NativeLinked())) {
        // Honesty: never report a hand-MMA backend without its arch object linked.
        if (g_mx_backend.find("scalar-decode") != std::string::npos) {
            return g_mx_backend;
        }
        return SelectedBackendName(RcOzakiMxfp4SelectedBackend::Unqualified);
    }
    return g_mx_backend;
}

std::string RcOzakiCudaMxfp4Deficit()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    if ((g_mx_selected == RcOzakiMxfp4SelectedBackend::SM120_MMA &&
         !RcOzakiMxfp4Sm120aKernelLinked()) ||
        (g_mx_selected == RcOzakiMxfp4SelectedBackend::SM100_MMA &&
         !RcOzakiMxfp4Sm100NativeLinked())) {
        return "not_linked";
    }
    return g_mx_deficit;
}

uint64_t RcOzakiCudaMxfp4NativeTensorLaunchCount()
{
    return g_native_tensor_launches.load(std::memory_order_relaxed);
}

uint64_t RcOzakiCudaMxfp4ScalarTailLaunchCount()
{
    return g_scalar_tail_launches.load(std::memory_order_relaxed);
}

bool SelfQualifyRcOzakiCudaMxfp4Once()
{
    {
        std::lock_guard<std::mutex> lock(g_ozaki_mu);
        if (g_mx_ran) {
            // Evaluate without re-entering IsRcOzakiCudaMxfp4Qualified (mutex).
            if (g_mx_selected == RcOzakiMxfp4SelectedBackend::Unqualified) return false;
            if (g_mx_selected == RcOzakiMxfp4SelectedBackend::SM120_MMA &&
                !RcOzakiMxfp4Sm120aKernelLinked()) {
                return false;
            }
            if (g_mx_selected == RcOzakiMxfp4SelectedBackend::SM100_MMA &&
                !RcOzakiMxfp4Sm100NativeLinked()) {
                return false;
            }
            return true;
        }
    }

    cudaDeviceProp prop{};
    std::string err;
    bool scalar_ok = false;
    RcOzakiMxfp4SelectedBackend selected = RcOzakiMxfp4SelectedBackend::Unqualified;
    std::string tc_err;
    bool device_ok = false;
    {
        int device = 0;
        if (cudaGetDevice(&device) != cudaSuccess ||
            cudaGetDeviceProperties(&prop, device) != cudaSuccess) {
            err = "device_unavailable";
        } else {
            device_ok = true;
        }
    }

    const bool is_sm120 = device_ok && DeviceLooksSm120(prop.major, prop.minor);
    const bool is_sm100 = device_ok && DeviceLooksSm100(prop.major, prop.minor);
    const bool sm120a_linked = RcOzakiMxfp4Sm120aKernelLinked();
    const bool sm100_native_linked = RcOzakiMxfp4Sm100NativeLinked();

    // Scalar-decode exactness probe — NEVER flips SelectedBackend.
    std::string scalar_err;
    if (err.empty()) {
        auto scalar = &LaunchOzakiMxfp4PanelsScalar;
        scalar_ok = Mxfp4CompleteSuiteForLauncher(scalar, &scalar_err);
    }

    // Per-backend COMPLETE suite. Never combine MMA partial with cuBLASLt.
    // Never infer SM120 from SM100 or vice versa. Independent of scalar probe.
    // SM120_MMA requires the dedicated sm_120a kernel object (Agent A/B).
    if (err.empty() && is_sm120) {
        if (!sm120a_linked) {
            // Plain sm_120 build / missing sm_120a object: fail-closed.
            tc_err = "not_linked";
        } else {
            const uint64_t native_before =
                g_native_tensor_launches.load(std::memory_order_relaxed);
            std::string mma_err;
            if (Mxfp4CompleteSuiteForLauncher(&LaunchOzakiMxfp4PanelsMma, &mma_err)) {
                const uint64_t native_after =
                    g_native_tensor_launches.load(std::memory_order_relaxed);
                // Scalar-tail alone is NOT evidence MMA executed.
                if (native_after > native_before) {
                    selected = RcOzakiMxfp4SelectedBackend::SM120_MMA;
                    tc_err.clear();
                } else {
                    tc_err = "selfqual_failed:native_tensor_launches==0 "
                             "(scalar-tail only — not MMA)";
                }
            } else {
                tc_err = mma_err.empty() ? "selfqual_failed" : ("selfqual_failed:" + mma_err);
                // Do NOT fall through to cuBLASLt and mislabel as SM120_MMA / cutlass.
            }
        }
        if (selected == RcOzakiMxfp4SelectedBackend::Unqualified && err.empty()) {
            err = tc_err;
        }
    } else if (err.empty() && is_sm100) {
        // SM100 / B200. Never call the SM120 warp MMA here (runtime refuse +
        // compile-out). Preference order, each honesty-gated on its OWN complete
        // suite with a positive native tensor-launch count:
        //   1) SM100_MMA — hand tcgen05.mma.block_scale (only if the sm_100a
        //      object is linked via BTX_CUDA_SM100_NATIVE). Peak native FP path.
        //   2) SM100_CUBLASLT — cuBLASLt block-scaled (also tcgen05 internally).
        // A failing/absent tcgen05 kernel falls back to cuBLASLt; both failing →
        // Unqualified (fail-closed). Never mislabel one as the other.
        std::string mma_err;
        if (sm100_native_linked) {
            const uint64_t native_before =
                g_native_tensor_launches.load(std::memory_order_relaxed);
            if (Mxfp4CompleteSuiteForLauncher(&LaunchOzakiMxfp4PanelsSm100Mma, &mma_err)) {
                const uint64_t native_after =
                    g_native_tensor_launches.load(std::memory_order_relaxed);
                if (native_after > native_before) {
                    selected = RcOzakiMxfp4SelectedBackend::SM100_MMA;
                    tc_err.clear();
                } else {
                    mma_err = "native_tensor_launches==0 (scalar-tail only — not tcgen05)";
                }
            }
        } else {
            mma_err = "not_linked";
        }
        if (selected == RcOzakiMxfp4SelectedBackend::Unqualified) {
            std::string lt_err;
            if (Mxfp4CompleteSuiteForLauncher(&LaunchOzakiMxfp4PanelsCublasLt, &lt_err)) {
                selected = RcOzakiMxfp4SelectedBackend::SM100_CUBLASLT;
                tc_err.clear();
            } else {
                tc_err = "selfqual_failed:sm100_mma[" +
                         (mma_err.empty() ? std::string("n/a") : mma_err) + "]; cublaslt[" +
                         (lt_err.empty() ? std::string("selfqual_failed") : lt_err) + "]";
            }
        }
        if (selected == RcOzakiMxfp4SelectedBackend::Unqualified && err.empty()) {
            err = tc_err;
        }
    } else if (err.empty()) {
        err = "unsupported_arch";
    }

    bool qualified = false;
    {
        std::lock_guard<std::mutex> lock(g_ozaki_mu);
        if (!g_mx_ran) {
            g_mx_ran = true;
            g_mx_arch_key =
                device_ok ? FormatCudaArchKey(prop.major, prop.minor) : std::string{};
            // Final honesty clamp: hand-MMA backends require their arch object.
            if (selected == RcOzakiMxfp4SelectedBackend::SM120_MMA && !sm120a_linked) {
                selected = RcOzakiMxfp4SelectedBackend::Unqualified;
                if (err.empty()) err = "not_linked";
            }
            if (selected == RcOzakiMxfp4SelectedBackend::SM100_MMA && !sm100_native_linked) {
                selected = RcOzakiMxfp4SelectedBackend::Unqualified;
                if (err.empty()) err = "not_linked";
            }
            g_mx_selected = selected;
            if (selected != RcOzakiMxfp4SelectedBackend::Unqualified) {
                g_mx_backend = SelectedBackendName(selected);
                g_mx_deficit.clear();
            } else if (scalar_ok) {
                g_mx_backend = "mxfp4_blockscaled_device_scalar-decode";
                g_mx_deficit = "scalar-decode_exact_but_not_native_tensor";
                if (!tc_err.empty()) g_mx_deficit += "; tc_failed:" + tc_err;
                else if (!err.empty()) g_mx_deficit += "; " + err;
            } else {
                g_mx_backend = SelectedBackendName(RcOzakiMxfp4SelectedBackend::Unqualified);
                if (!err.empty()) {
                    g_mx_deficit = err;
                } else if (!tc_err.empty()) {
                    g_mx_deficit = tc_err;
                } else if (!scalar_err.empty()) {
                    g_mx_deficit = "selfqual_failed:" + scalar_err;
                } else {
                    g_mx_deficit = "selfqual_failed";
                }
            }
        }
        qualified = (g_mx_selected != RcOzakiMxfp4SelectedBackend::Unqualified) &&
                    !(g_mx_selected == RcOzakiMxfp4SelectedBackend::SM120_MMA &&
                      !RcOzakiMxfp4Sm120aKernelLinked()) &&
                    !(g_mx_selected == RcOzakiMxfp4SelectedBackend::SM100_MMA &&
                      !RcOzakiMxfp4Sm100NativeLinked());
    }
    return qualified;
}

bool TryLaunchRcOzakiMxfp4GemmS8S8Int64(const std::vector<int8_t>& left,
                                       const std::vector<int8_t>& right, uint32_t rows,
                                       uint32_t inner, uint32_t cols, std::vector<int64_t>& out,
                                       std::string* error)
{
    out.clear();
    const RcOzakiMxfp4SelectedBackend sel = RcOzakiCudaMxfp4SelectedBackend();
    if (sel == RcOzakiMxfp4SelectedBackend::Unqualified) {
        if (error) {
            *error = "RC Ozaki MXFP4 native tensor path not qualified "
                     "(scalar-decode / dense INT8 are not native)";
        }
        return false;
    }
    // Fail-closed: call ONLY the backend that passed full qual — no silent switch.
    if (sel == RcOzakiMxfp4SelectedBackend::SM120_MMA) {
        if (!RcOzakiMxfp4Sm120aKernelLinked()) {
            if (error) *error = "not_linked";
            return false;
        }
        if (!LaunchOzakiMxfp4PanelsMma(left, right, rows, inner, cols, out, error)) {
            out.clear();
            if (error && error->empty()) {
                *error = "SM120_MMA launch failed (fail-closed; no cuBLASLt fallback)";
            }
            return false;
        }
        return true;
    }
    if (sel == RcOzakiMxfp4SelectedBackend::SM100_MMA) {
        if (!RcOzakiMxfp4Sm100NativeLinked()) {
            if (error) *error = "not_linked";
            return false;
        }
        if (!LaunchOzakiMxfp4PanelsSm100Mma(left, right, rows, inner, cols, out, error)) {
            out.clear();
            if (error && error->empty()) {
                *error = "SM100_MMA launch failed (fail-closed; no cuBLASLt fallback)";
            }
            return false;
        }
        return true;
    }
    if (sel == RcOzakiMxfp4SelectedBackend::SM100_CUBLASLT) {
        if (!LaunchOzakiMxfp4PanelsCublasLt(left, right, rows, inner, cols, out, error)) {
            out.clear();
            if (error && error->empty()) {
                *error = "SM100_CUBLASLT launch failed (fail-closed; no MMA fallback)";
            }
            return false;
        }
        return true;
    }
    if (error) *error = "RC Ozaki MXFP4 unknown selected backend";
    return false;
}

bool EnsureRcOzakiMxfp4DeviceArena(size_t a_bytes, size_t b_bytes, size_t sfa_bytes,
                                   size_t sfb_bytes, size_t d_elems, size_t workspace_bytes)
{
    return Arena().Ensure(a_bytes, b_bytes, sfa_bytes, sfb_bytes, d_elems, workspace_bytes);
}

bool TryLaunchRcOzakiMxfp4GemmS8S8Int64Device(const int8_t* d_left, const int8_t* d_right,
                                             int64_t* d_out, uint32_t rows, uint32_t inner,
                                             uint32_t cols, void* cuda_stream, std::string* error)
{
    // Resident entry (Workstream C): stage device int8 → host factor → arena launch
    // on caller's stream. API shape is stable; full on-device FactorBlockToMx is a
    // follow-on. Still fail-closed on SelectedBackend and never switches backends.
    if (d_left == nullptr || d_right == nullptr || d_out == nullptr || rows == 0 || inner == 0 ||
        cols == 0) {
        if (error) *error = "Ozaki MXFP4 device: null/degenerate";
        return false;
    }
    const RcOzakiMxfp4SelectedBackend sel = RcOzakiCudaMxfp4SelectedBackend();
    if (sel == RcOzakiMxfp4SelectedBackend::Unqualified) {
        if (error) *error = "Ozaki MXFP4 device: Unqualified selected backend";
        return false;
    }
    auto* stream = static_cast<cudaStream_t>(cuda_stream);
    std::vector<int8_t> left(static_cast<size_t>(rows) * inner);
    std::vector<int8_t> right(static_cast<size_t>(inner) * cols);
    if (cudaMemcpyAsync(left.data(), d_left, left.size(), cudaMemcpyDeviceToHost, stream) !=
            cudaSuccess ||
        cudaMemcpyAsync(right.data(), d_right, right.size(), cudaMemcpyDeviceToHost, stream) !=
            cudaSuccess ||
        cudaStreamSynchronize(stream) != cudaSuccess) {
        if (error) *error = "Ozaki MXFP4 device: D2H stage failed";
        return false;
    }
    std::vector<int64_t> host_out;
    std::string err;
    bool ok = false;
    if (sel == RcOzakiMxfp4SelectedBackend::SM120_MMA) {
        if (!RcOzakiMxfp4Sm120aKernelLinked()) {
            if (error) *error = "not_linked";
            return false;
        }
        ok = LaunchOzakiMxfp4PanelsMma(left, right, rows, inner, cols, host_out, &err);
    } else if (sel == RcOzakiMxfp4SelectedBackend::SM100_MMA) {
        if (!RcOzakiMxfp4Sm100NativeLinked()) {
            if (error) *error = "not_linked";
            return false;
        }
        ok = LaunchOzakiMxfp4PanelsSm100Mma(left, right, rows, inner, cols, host_out, &err);
    } else if (sel == RcOzakiMxfp4SelectedBackend::SM100_CUBLASLT) {
        ok = LaunchOzakiMxfp4PanelsCublasLt(left, right, rows, inner, cols, host_out, &err);
    }
    if (!ok) {
        if (error) *error = err.empty() ? "Ozaki MXFP4 device: selected backend declined" : err;
        return false;
    }
    if (cudaMemcpyAsync(d_out, host_out.data(), host_out.size() * sizeof(int64_t),
                        cudaMemcpyHostToDevice, stream) != cudaSuccess) {
        if (error) *error = "Ozaki MXFP4 device: H2D out failed";
        return false;
    }
    return true;
}

void ResetRcOzakiCudaQualForTest()
{
    std::lock_guard<std::mutex> lock(g_ozaki_mu);
    g_exact_ran = false;
    g_exact_qualified = false;
    g_mx_ran = false;
    g_mx_selected = RcOzakiMxfp4SelectedBackend::Unqualified;
    g_mx_arch_key.clear();
    g_mx_backend.clear();
    g_mx_deficit.clear();
    g_native_tensor_launches.store(0, std::memory_order_relaxed);
    g_scalar_tail_launches.store(0, std::memory_order_relaxed);
}

} // namespace matmul_v4::cuda
