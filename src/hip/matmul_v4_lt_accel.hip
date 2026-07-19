// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hip/matmul_v4_lt_accel.h>

#include <arith_uint256.h>
#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/int8_field.h>
#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <primitives/block.h>
#include <span.h>
#include <uint256.h>

#include <hip/hip_runtime.h>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

// ===========================================================================
// AMD ROCm/HIP backend for MatMul v4.4 ENC-DR-LT (MatExpand).
//
 // Hot path: persistent device-resident MatExpand→Extract→project→combine with
 // hipGraph replay of stable GEMM stages (structural twin of the CUDA LT
 // accel). Host ExactGemm / WindowSketchMinerLT is fail-closed fallback only.
// ===========================================================================

namespace matmul_v4::hip {

namespace {

constexpr char kMatExpandGTag[] = "BTX_MATEXPAND_G_V44LT";
constexpr char kMatExpandHTag[] = "BTX_MATEXPAND_H_V44LT";
constexpr char kMatExpandWTag[] = "BTX_MATEXPAND_W_V44LT";
constexpr char kMatExpandWATag[] = "BTX_MATEXPAND_WA_V44LT";

uint256 DeriveTaggedSeed(const char* tag, size_t taglen, const uint256& hash)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    hasher.Write(hash.data(), uint256::size());
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

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

__device__ __forceinline__ uint64_t DeviceMatExpandPrfLE64(const uint32_t key[8], int32_t raw,
                                                          uint32_t i, uint32_t j, uint32_t remix,
                                                          uint32_t lane)
{
    uint32_t x0 = 0x61707865u, x1 = 0x3320646eu, x2 = 0x79622d32u, x3 = 0x6b206574u;
    uint32_t x4 = key[0], x5 = key[1], x6 = key[2], x7 = key[3];
    uint32_t x8 = key[4], x9 = key[5], x10 = key[6], x11 = key[7];
    uint32_t x12 = remix;
    uint32_t x13 = static_cast<uint32_t>(raw) ^ lane;
    const uint64_t nonce_second = (static_cast<uint64_t>(i) << 32) | static_cast<uint64_t>(j);
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

    return static_cast<uint64_t>(x0) | (static_cast<uint64_t>(x1) << 32);
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

__device__ __forceinline__ int8_t DeviceExtractDequant(int32_t raw, uint32_t i, uint32_t j,
                                                      const uint32_t key[8])
{
    constexpr uint32_t kLaneMant = 0x4D414E54u;
    constexpr uint32_t kLaneScale = 0x53434C45u;
    uint32_t remix = 0;
    for (;;) {
        const uint64_t mixed = DeviceMatExpandPrfLE64(key, raw, i, j, remix, kLaneMant);
        for (int shift = 0; shift < 64; shift += 4) {
            bool accepted = false;
            const int8_t mu = DeviceSampleMantissaNibble(
                static_cast<uint8_t>((mixed >> shift) & 0x0F), accepted);
            if (!accepted) continue;
            const uint64_t scale_stream =
                DeviceMatExpandPrfLE64(key, raw, i, j, remix, kLaneScale);
            return static_cast<int8_t>(static_cast<int32_t>(mu) <<
                                      static_cast<uint8_t>(scale_stream & 0x3));
        }
        ++remix;
    }
}

__global__ void DeviceExtractDequantMatExpand(const int32_t* __restrict__ B32,
                                              int8_t* __restrict__ Bhat,
                                              uint32_t n, uint32_t k0, uint32_t k1, uint32_t k2,
                                              uint32_t k3, uint32_t k4, uint32_t k5, uint32_t k6,
                                              uint32_t k7)
{
    const uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    const size_t nn = static_cast<size_t>(n) * n;
    if (idx >= nn) return;
    const uint32_t key[8] = {k0, k1, k2, k3, k4, k5, k6, k7};
    Bhat[idx] = DeviceExtractDequant(B32[idx], idx / n, idx % n, key);
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

    int8_t *dG{nullptr}, *dH{nullptr}, *dU{nullptr}, *dV{nullptr}, *dAhat{nullptr};
    int32_t* dP{nullptr};
    int8_t *dW{nullptr}, *dBhat{nullptr};
    int32_t *dY{nullptr}, *dB32{nullptr}, *dQ{nullptr};
    uint64_t* dChat{nullptr};

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
        auto free_p = [](auto*& p) { if (p) { hipFree(p); p = nullptr; } };
        free_p(dG); free_p(dH); free_p(dU); free_p(dV); free_p(dAhat); free_p(dP);
        free_p(dW); free_p(dY); free_p(dB32); free_p(dBhat); free_p(dQ); free_p(dChat);
        free_p(dGemmS8L); free_p(dGemmS8R); free_p(dGemmS32L); free_p(dGemmOut);
        gemm_s8l_bytes = gemm_s8r_bytes = gemm_s32l_bytes = gemm_out_bytes = 0;
        if (stream) { hipStreamDestroy(stream); stream = nullptr; }
        template_bound = false;
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

    [[nodiscard]] bool EnsureDims(uint32_t n_in, uint32_t m_in)
    {
        const uint32_t w_in = matmul::v4::lt::kMatExpandPanelW;
        if (stream && n == n_in && m == m_in && w == w_in) return true;
        Release();
        if (hipStreamCreateWithFlags(&stream, hipStreamNonBlocking) != hipSuccess) return false;
        n = n_in; m = m_in; w = w_in;
        const size_t nn = static_cast<size_t>(n) * n;
        const size_t nw = static_cast<size_t>(n) * w;
        const size_t wn = static_cast<size_t>(w) * n;
        const size_t mn = static_cast<size_t>(m) * n;
        const size_t nm = static_cast<size_t>(n) * m;
        const size_t mm = static_cast<size_t>(m) * m;
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
            !mall(reinterpret_cast<void**>(&dChat), mm * sizeof(uint64_t))) {
            Release();
            return false;
        }
        return true;
    }

    [[nodiscard]] bool CaptureGraphs()
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

    [[nodiscard]] bool BindTemplate(const CBlockHeader& tmpl, uint32_t n_in, uint32_t m_in)
    {
        if (!EnsureDims(n_in, m_in)) return false;
        const uint256 th = matmul::v4::ComputeTemplateHash(tmpl);
        if (template_bound && template_hash == th && graphs_ready) return true;

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
        if (!CaptureGraphs()) return false;
        if (hipGraphLaunch(matexpand_exec, stream) != hipSuccess) return false;
        const uint256 prf_a = matmul::v4::lt::DeriveMatExpandPrfKey(seed_wa);
        uint32_t kw[8];
        for (int t = 0; t < 8; ++t) kw[t] = ReadLE32(prf_a.data() + static_cast<size_t>(t) * 4);
        const int et = 256;
        const int eb = static_cast<int>((nn + et - 1) / et);
        hipLaunchKernelGGL(DeviceExtractDequantMatExpand, dim3(eb), dim3(et), 0, stream,
                           dB32, dAhat, n, kw[0], kw[1], kw[2], kw[3], kw[4], kw[5], kw[6], kw[7]);
        if (hipGetLastError() != hipSuccess) return false;
        const dim3 block(16, 16, 1);
        const dim3 grid_p((n + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
        hipLaunchKernelGGL(DeviceGemmS8S8Tiled, grid_p, block, 0, stream,
                           dU, dAhat, dP, static_cast<int>(m), static_cast<int>(n), static_cast<int>(n));
        if (hipGetLastError() != hipSuccess) return false;
        if (hipStreamSynchronize(stream) != hipSuccess) return false;
        template_hash = th;
        template_bound = true;
        return true;
    }

    [[nodiscard]] bool MineOneNonce(const CBlockHeader& header,
                                    std::vector<matmul::int8_field::Fq>& chat_out)
    {
        if (!template_bound || !graphs_ready) return false;
        if (matmul::v4::ComputeTemplateHash(header) != template_hash) return false;
        const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);
        const uint256 seed_w = DeriveTaggedSeed(kMatExpandWTag, sizeof(kMatExpandWTag) - 1, header_hash);
        const std::vector<int8_t> W = matmul::v4::bmx4::ExpandProjectorBMX4C(seed_w, n, w);
        const size_t nw = static_cast<size_t>(n) * w;
        if (hipMemcpyAsync(dW, W.data(), nw, hipMemcpyHostToDevice, stream) != hipSuccess) return false;
        if (hipGraphLaunch(matexpand_exec, stream) != hipSuccess) return false;
        const uint256 prf = matmul::v4::lt::DeriveMatExpandPrfKey(seed_w);
        uint32_t kw[8];
        for (int t = 0; t < 8; ++t) kw[t] = ReadLE32(prf.data() + static_cast<size_t>(t) * 4);
        const size_t nn = static_cast<size_t>(n) * n;
        const int et = 256;
        const int eb = static_cast<int>((nn + et - 1) / et);
        hipLaunchKernelGGL(DeviceExtractDequantMatExpand, dim3(eb), dim3(et), 0, stream,
                           dB32, dBhat, n, kw[0], kw[1], kw[2], kw[3], kw[4], kw[5], kw[6], kw[7]);
        if (hipGetLastError() != hipSuccess) return false;
        if (hipGraphLaunch(project_right_exec, stream) != hipSuccess) return false;
        const dim3 block(16, 16, 1);
        const dim3 grid_c((m + block.x - 1) / block.x, (m + block.y - 1) / block.y, 1);
        hipLaunchKernelGGL(DeviceCombineModQ, grid_c, block, 0, stream,
                           dP, dQ, dChat, static_cast<int>(n), static_cast<int>(m));
        if (hipGetLastError() != hipSuccess) return false;
        chat_out.assign(static_cast<size_t>(m) * m, 0);
        if (hipMemcpyAsync(chat_out.data(), dChat, static_cast<size_t>(m) * m * sizeof(uint64_t),
                           hipMemcpyDeviceToHost, stream) != hipSuccess) {
            return false;
        }
        return hipStreamSynchronize(stream) == hipSuccess;
    }
};

LtHipResidentPool& Pool()
{
    static LtHipResidentPool pool;
    return pool;
}

[[nodiscard]] bool LaunchGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                  uint32_t rows, uint32_t k, uint32_t cols,
                                  std::vector<int32_t>& out)
{
    if (TryLaunchLtMfmaGemmS8S8(left, right, rows, k, cols, out)) {
        return true;
    }
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

[[nodiscard]] bool LaunchGemmS32S8(const std::vector<int32_t>& left, const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t k, uint32_t cols,
                                   std::vector<int32_t>& out)
{
    if (TryLaunchLtMfmaGemmS32S8(left, right, rows, k, cols, out)) {
        return true;
    }
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
        if (!LaunchGemmS8S8(left, right, kDim, kDim, kDim, gpu8) || gpu8 != cpu8) return;
        const auto cpu32 = matmul::v4::lt::ExactGemmS32S8(mid, right, kDim, kDim, kDim);
        std::vector<int32_t> gpu32;
        if (!LaunchGemmS32S8(mid, right, kDim, kDim, kDim, gpu32) || gpu32 != cpu32) return;

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
        uint256 cpu_digest;
        std::vector<unsigned char> cpu_payload;
        if (!matmul::v4::lt::ComputeDigestBMX4CLT(header, kN, cpu_digest, cpu_payload)) return;
        auto& pool = Pool();
        std::lock_guard<std::mutex> lock(pool.mu);
        if (!pool.BindTemplate(header, kN, m)) return;
        std::vector<matmul::int8_field::Fq> chat;
        if (!pool.MineOneNonce(header, chat)) return;
        if (matmul::v4::ComputeSketchDigestFromFq(matmul::v4::DeriveSigma(header), chat) != cpu_digest) {
            return;
        }
        ok = true;
    });
    return ok;
}

[[nodiscard]] bool HipDeviceAvailable()
{
    int count = 0;
    return hipGetDeviceCount(&count) == hipSuccess && count > 0;
}

thread_local bool g_lt_device_gemm_failed = false;

bool HipGemmS8S8Fn(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                   uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (LaunchGemmS8S8(L, R, rows, inner, cols, out)) return true;
    g_lt_device_gemm_failed = true;
    return false;
}

bool HipGemmS32S8Fn(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                    uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (LaunchGemmS32S8(L, R, rows, inner, cols, out)) return true;
    g_lt_device_gemm_failed = true;
    return false;
}

[[nodiscard]] bool MineDeviceResident(const CBlockHeader& tmpl, uint32_t n, uint32_t m,
                                      const uint64_t* nonces, size_t count,
                                      std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    auto& pool = Pool();
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.BindTemplate(tmpl, n, m)) return false;
    out.resize(count);
    for (size_t i = 0; i < count; ++i) {
        CBlockHeader header = tmpl;
        header.nNonce64 = nonces[i];
        header.nNonce = static_cast<uint32_t>(nonces[i]);
        std::vector<matmul::int8_field::Fq> chat;
        if (!pool.MineOneNonce(header, chat)) {
            out.clear();
            return false;
        }
        out[i].nonce = nonces[i];
        out[i].digest = matmul::v4::ComputeSketchDigestFromFq(matmul::v4::DeriveSigma(header), chat);
        out[i].target_match = false;
        out[i].backend_status = matmul::v4::bmx4::DigestOnlyBackendStatus::Ok;
    }
    return true;
}

[[nodiscard]] bool MineHostExactFallback(const CBlockHeader& tmpl, uint32_t n,
                                         const uint64_t* nonces, size_t count,
                                         bool try_device_gemms,
                                         std::vector<matmul::v4::lt::DigestOnlyResultLT>& out)
{
    matmul::v4::lt::ExactGemmBackend backend;
    if (try_device_gemms) {
        backend.gemm_s8s8 = &HipGemmS8S8Fn;
        backend.gemm_s32s8 = &HipGemmS32S8Fn;
    }
    g_lt_device_gemm_failed = false;
    matmul::v4::lt::WindowSketchMinerLT miner(tmpl, n, backend);
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

} // namespace

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

} // namespace matmul_v4::hip
