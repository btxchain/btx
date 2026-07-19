// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_tensor_gemm.h>

#include <cuda/cuda_context.h>
#include <matmul/matmul_v4_lt.h>

#include <cublasLt.h>
#include <cuda_runtime.h>

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

// CUDA IMMA path for LT ExactGemm: cuBLASLt CUBLAS_COMPUTE_32I (s8xs8->s32).
// Self-tested bit-for-bit against ExactGemmS8S8 across MatExpand shapes before
// IsLtImmaGemmAvailable returns true. Host and device-pointer launches share a
// process-persistent cuBLASLt handle + workspace + A/B/C scratch.
//
// S32S8: cuBLASLt CUBLAS_COMPUTE_32I is an s8×s8→s32 recipe only. There is no
// documented exact s32×s8→s32 IMMA/cuBLASLt/CUTLASS path we can self-qualify on
// sm_90/100/120, so TryLaunchLtImmaGemmS32S8 always declines; callers keep
// ExactGemmS32S8 / DeviceGemmS32S8Tiled and MUST NOT claim IMMA for that lane.
//
// Target arches (PR #89): sm_90 (H100/H200), sm_100 (B200), sm_120 (5090).

namespace matmul_v4::cuda {
namespace {

struct ImmaLtPool {
    std::mutex mu;
    cublasLtHandle_t lt{nullptr};
    void* workspace{nullptr};
    size_t workspace_bytes{0};
    void* dA{nullptr};
    void* dB{nullptr};
    void* dC{nullptr};
    size_t a_bytes{0};
    size_t b_bytes{0};
    size_t c_bytes{0};
    bool ready{false};

    ~ImmaLtPool() { Release(); }

    void Release()
    {
        auto free_p = [](void*& p, size_t& n) {
            if (p) {
                cudaFree(p);
                p = nullptr;
                n = 0;
            }
        };
        free_p(workspace, workspace_bytes);
        free_p(dA, a_bytes);
        free_p(dB, b_bytes);
        free_p(dC, c_bytes);
        if (lt) {
            cublasLtDestroy(lt);
            lt = nullptr;
        }
        ready = false;
    }

    [[nodiscard]] bool EnsureHandle(size_t need_workspace)
    {
        if (!ready) {
            if (cublasLtCreate(&lt) != CUBLAS_STATUS_SUCCESS) {
                lt = nullptr;
                return false;
            }
            ready = true;
        }
        if (need_workspace <= workspace_bytes) return true;
        if (workspace) {
            cudaFree(workspace);
            workspace = nullptr;
            workspace_bytes = 0;
        }
        if (need_workspace == 0) return true;
        if (cudaMalloc(&workspace, need_workspace) != cudaSuccess) return false;
        workspace_bytes = need_workspace;
        return true;
    }

    [[nodiscard]] bool EnsureScratch(size_t need_a, size_t need_b, size_t need_c)
    {
        auto grow = [](void*& p, size_t& have, size_t need) -> bool {
            if (need <= have) return true;
            if (p) {
                cudaFree(p);
                p = nullptr;
                have = 0;
            }
            if (need == 0) return true;
            if (cudaMalloc(&p, need) != cudaSuccess) return false;
            have = need;
            return true;
        };
        return grow(dA, a_bytes, need_a) && grow(dB, b_bytes, need_b) && grow(dC, c_bytes, need_c);
    }
};

ImmaLtPool& ImmaPool()
{
    static ImmaLtPool pool;
    return pool;
}

/** Caller MUST hold ImmaPool().mu. */
[[nodiscard]] bool RunCublasLtS8S8Locked(ImmaLtPool& pool, const int8_t* dA, const int8_t* dB,
                                         int32_t* dC, uint32_t M, uint32_t N, uint32_t K,
                                         cudaStream_t stream, std::string& error)
{
    constexpr size_t kDefaultWorkspace = 8ull << 20;
    if (!pool.EnsureHandle(kDefaultWorkspace)) {
        error = "cublasLtCreate / workspace alloc failed";
        return false;
    }

    cublasLtMatmulDesc_t op_desc = nullptr;
    cublasLtMatrixLayout_t a_layout = nullptr;
    cublasLtMatrixLayout_t b_layout = nullptr;
    cublasLtMatrixLayout_t c_layout = nullptr;
    cublasLtMatmulPreference_t preference = nullptr;

    auto cleanup = [&]() {
        if (preference) cublasLtMatmulPreferenceDestroy(preference);
        if (c_layout) cublasLtMatrixLayoutDestroy(c_layout);
        if (b_layout) cublasLtMatrixLayoutDestroy(b_layout);
        if (a_layout) cublasLtMatrixLayoutDestroy(a_layout);
        if (op_desc) cublasLtMatmulDescDestroy(op_desc);
    };

    if (cublasLtMatmulDescCreate(&op_desc, CUBLAS_COMPUTE_32I, CUDA_R_32I) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmulDescCreate failed";
        cleanup();
        return false;
    }
    const cublasOperation_t op_n = CUBLAS_OP_N;
    if (cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_TRANSA, &op_n, sizeof(op_n)) != CUBLAS_STATUS_SUCCESS ||
        cublasLtMatmulDescSetAttribute(op_desc, CUBLASLT_MATMUL_DESC_TRANSB, &op_n, sizeof(op_n)) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmulDescSetAttribute failed";
        cleanup();
        return false;
    }
    // Row-major ExactGemm layout: A[M×K], B[K×N], C[M×N] with leading dims K,N,N.
    if (cublasLtMatrixLayoutCreate(&a_layout, CUDA_R_8I, M, K, K) != CUBLAS_STATUS_SUCCESS ||
        cublasLtMatrixLayoutCreate(&b_layout, CUDA_R_8I, K, N, N) != CUBLAS_STATUS_SUCCESS ||
        cublasLtMatrixLayoutCreate(&c_layout, CUDA_R_32I, M, N, N) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatrixLayoutCreate failed";
        cleanup();
        return false;
    }
    const cublasLtOrder_t order = CUBLASLT_ORDER_ROW;
    cublasLtMatrixLayoutSetAttribute(a_layout, CUBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order));
    cublasLtMatrixLayoutSetAttribute(b_layout, CUBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order));
    cublasLtMatrixLayoutSetAttribute(c_layout, CUBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order));

    if (cublasLtMatmulPreferenceCreate(&preference) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmulPreferenceCreate failed";
        cleanup();
        return false;
    }
    cublasLtMatmulPreferenceSetAttribute(preference, CUBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES,
                                         &pool.workspace_bytes, sizeof(pool.workspace_bytes));

    cublasLtMatmulHeuristicResult_t heuristic{};
    int returned = 0;
    if (cublasLtMatmulAlgoGetHeuristic(pool.lt, op_desc, a_layout, b_layout, c_layout, c_layout,
                                       preference, 1, &heuristic, &returned) != CUBLAS_STATUS_SUCCESS ||
        returned < 1) {
        error = "no IMMA s8xs8->s32 heuristic";
        cleanup();
        return false;
    }
    const int32_t alpha = 1;
    const int32_t beta = 0;
    if (cublasLtMatmul(pool.lt, op_desc, &alpha, dA, a_layout, dB, b_layout, &beta, dC, c_layout, dC, c_layout,
                       &heuristic.algo, pool.workspace, pool.workspace_bytes, stream) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmul IMMA failed";
        cleanup();
        return false;
    }
    cleanup();
    return true;
}

[[nodiscard]] bool RunCublasLtS8S8(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                   uint32_t M, uint32_t N, uint32_t K,
                                   cudaStream_t stream, std::string& error)
{
    auto& pool = ImmaPool();
    std::lock_guard<std::mutex> lock(pool.mu);
    return RunCublasLtS8S8Locked(pool, dA, dB, dC, M, N, K, stream, error);
}

[[nodiscard]] bool LaunchImmaS8S8Host(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                      uint32_t rows, uint32_t k, uint32_t cols, std::vector<int32_t>& out)
{
    if (rows == 0 || k == 0 || cols == 0) {
        out.clear();
        return true;
    }
    const size_t lhs_bytes = static_cast<size_t>(rows) * k * sizeof(int8_t);
    const size_t rhs_bytes = static_cast<size_t>(k) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);

    auto& pool = ImmaPool();
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.EnsureScratch(lhs_bytes, rhs_bytes, out_bytes)) return false;
    if (cudaMemcpy(pool.dA, left.data(), lhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(pool.dB, right.data(), rhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) return false;
    std::string error;
    if (!RunCublasLtS8S8Locked(pool, static_cast<const int8_t*>(pool.dA), static_cast<const int8_t*>(pool.dB),
                               static_cast<int32_t*>(pool.dC), rows, cols, k, /*stream=*/nullptr, error)) {
        return false;
    }
    if (cudaDeviceSynchronize() != cudaSuccess) return false;
    out.assign(static_cast<size_t>(rows) * cols, 0);
    return cudaMemcpy(out.data(), pool.dC, out_bytes, cudaMemcpyDeviceToHost) == cudaSuccess;
}

[[nodiscard]] bool MatchShapeVsCpu(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                                   uint32_t rows, uint32_t inner, uint32_t cols)
{
    const auto cpu = matmul::v4::lt::ExactGemmS8S8(left, right, rows, inner, cols);
    std::vector<int32_t> gpu;
    if (!LaunchImmaS8S8Host(left, right, rows, inner, cols, gpu) || gpu != cpu) {
        return false;
    }
    // Device-pointer entry on the same persistent scratch must also match.
    auto& pool = ImmaPool();
    const size_t lhs_bytes = static_cast<size_t>(rows) * inner * sizeof(int8_t);
    const size_t rhs_bytes = static_cast<size_t>(inner) * cols * sizeof(int8_t);
    const size_t out_bytes = static_cast<size_t>(rows) * cols * sizeof(int32_t);
    std::lock_guard<std::mutex> lock(pool.mu);
    if (!pool.EnsureScratch(lhs_bytes, rhs_bytes, out_bytes)) return false;
    if (cudaMemcpy(pool.dA, left.data(), lhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) return false;
    if (cudaMemcpy(pool.dB, right.data(), rhs_bytes, cudaMemcpyHostToDevice) != cudaSuccess) return false;
    std::string error;
    if (!RunCublasLtS8S8Locked(pool, static_cast<const int8_t*>(pool.dA), static_cast<const int8_t*>(pool.dB),
                               static_cast<int32_t*>(pool.dC), rows, cols, inner, /*stream=*/nullptr, error)) {
        return false;
    }
    if (cudaDeviceSynchronize() != cudaSuccess) return false;
    std::vector<int32_t> gpu_dev(static_cast<size_t>(rows) * cols);
    if (cudaMemcpy(gpu_dev.data(), pool.dC, out_bytes, cudaMemcpyDeviceToHost) != cudaSuccess) {
        return false;
    }
    return gpu_dev == cpu;
}

[[nodiscard]] bool FillFolded(std::vector<int8_t>& v, int32_t a, int32_t b)
{
    for (size_t i = 0; i < v.size(); ++i) {
        v[i] = matmul::v4::lt::FoldInt32ToEmax48(static_cast<int32_t>(i) * a + b);
    }
    return true;
}

[[nodiscard]] bool SelfTestImmaOnce()
{
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        // (1) Square IMMA tile.
        {
            constexpr uint32_t kDim = 32;
            std::vector<int8_t> left(static_cast<size_t>(kDim) * kDim);
            std::vector<int8_t> right(static_cast<size_t>(kDim) * kDim);
            FillFolded(left, 7, -101);
            FillFolded(right, 11, 53);
            if (!MatchShapeVsCpu(left, right, kDim, kDim, kDim)) return;
        }
        // (2) Thin MatExpand-style panel (G*W with small w).
        {
            constexpr uint32_t kN = 64;
            constexpr uint32_t kW = 16;
            std::vector<int8_t> G(static_cast<size_t>(kN) * kN);
            std::vector<int8_t> W(static_cast<size_t>(kN) * kW);
            FillFolded(G, 3, -17);
            FillFolded(W, 5, 9);
            if (!MatchShapeVsCpu(G, W, kN, kN, kW)) return;
        }
        // (3) Full MatExpand panel width (G*W with kMatExpandPanelW).
        {
            constexpr uint32_t kN = 64;
            constexpr uint32_t kW = matmul::v4::lt::kMatExpandPanelW;
            std::vector<int8_t> G(static_cast<size_t>(kN) * kN);
            std::vector<int8_t> W(static_cast<size_t>(kN) * kW);
            FillFolded(G, 13, -41);
            FillFolded(W, 17, 23);
            if (!MatchShapeVsCpu(G, W, kN, kN, kW)) return;
        }
        // (4) U*Ahat style: m×n × n×n → m×n (deep tile m = n/2).
        {
            constexpr uint32_t kN = 64;
            constexpr uint32_t kM = kN / 2;
            std::vector<int8_t> U(static_cast<size_t>(kM) * kN);
            std::vector<int8_t> Ahat(static_cast<size_t>(kN) * kN);
            FillFolded(U, 19, -7);
            FillFolded(Ahat, 29, 11);
            if (!MatchShapeVsCpu(U, Ahat, kM, kN, kN)) return;
        }
        // (5) Bhat*V style: n×n × n×m → n×m.
        {
            constexpr uint32_t kN = 64;
            constexpr uint32_t kM = kN / 2;
            std::vector<int8_t> Bhat(static_cast<size_t>(kN) * kN);
            std::vector<int8_t> V(static_cast<size_t>(kN) * kM);
            FillFolded(Bhat, 31, -13);
            FillFolded(V, 37, 5);
            if (!MatchShapeVsCpu(Bhat, V, kN, kN, kM)) return;
        }
        ok = true;
    });
    return ok;
}

[[nodiscard]] LtCudaArchNameClass ClassifyArch(uint32_t major, uint32_t minor)
{
    (void)minor;
    if (major == 9) return LtCudaArchNameClass::Hopper;
    if (major == 10) return LtCudaArchNameClass::BlackwellDc;
    if (major == 12) return LtCudaArchNameClass::BlackwellConsumer;
    if (major == 0) return LtCudaArchNameClass::Unknown;
    return LtCudaArchNameClass::Other;
}

[[nodiscard]] const char* NameClassString(LtCudaArchNameClass c)
{
    switch (c) {
    case LtCudaArchNameClass::Hopper: return "hopper";
    case LtCudaArchNameClass::BlackwellDc: return "blackwell_dc";
    case LtCudaArchNameClass::BlackwellConsumer: return "blackwell_consumer";
    case LtCudaArchNameClass::Other: return "other";
    case LtCudaArchNameClass::Unknown:
    default: return "unknown";
    }
}

} // namespace

LtCudaArchProbe ProbeLtCudaArch()
{
    LtCudaArchProbe out;
    const btx::cuda::CudaRuntimeProbe runtime = btx::cuda::ProbeCudaRuntime();
    if (!runtime.compiled || !runtime.available || runtime.device_index < 0) {
        out.name_class_string = NameClassString(LtCudaArchNameClass::Unknown);
        out.sm_string = "sm_00";
        return out;
    }
    out.available = true;
    out.device_index = runtime.device_index;
    out.device_name = runtime.device_name;
    out.compute_capability_major = runtime.compute_capability_major;
    out.compute_capability_minor = runtime.compute_capability_minor;
    out.sm_string = "sm_" + std::to_string(runtime.compute_capability_major) +
                    std::to_string(runtime.compute_capability_minor);
    out.name_class = ClassifyArch(runtime.compute_capability_major, runtime.compute_capability_minor);
    out.name_class_string = NameClassString(out.name_class);
    return out;
}

LtCudaExactGemmCapabilities ProbeLtCudaExactGemmCapabilities()
{
    LtCudaExactGemmCapabilities caps;
    caps.arch = ProbeLtCudaArch();
    caps.exact_s8_s8_s32 = IsLtImmaGemmAvailable();
    // No self-qualified s32×s8→s32 IMMA recipe (cuBLASLt CUBLAS_COMPUTE_32I is s8×s8).
    caps.exact_partitioned_s32_s8 = false;
    caps.device_scalar_gemm = caps.arch.available;
    // Digest-only still Chat D2H → ComputeSketchDigestFromFq on host.
    caps.device_hashing = false;
    return caps;
}

bool IsLtImmaGemmAvailable()
{
    int device_count = 0;
    if (cudaGetDeviceCount(&device_count) != cudaSuccess || device_count <= 0) {
        return false;
    }
    return SelfTestImmaOnce();
}

bool TryLaunchLtImmaGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                             uint32_t rows, uint32_t inner, uint32_t cols, std::vector<int32_t>& out)
{
    if (!IsLtImmaGemmAvailable()) return false;
    return LaunchImmaS8S8Host(left, right, rows, inner, cols, out);
}

bool TryLaunchLtImmaGemmS8S8Device(const int8_t* dA, const int8_t* dB, int32_t* dC,
                                   uint32_t rows, uint32_t cols, uint32_t inner, void* stream)
{
    if (dA == nullptr || dB == nullptr || dC == nullptr) return false;
    if (rows == 0 || cols == 0 || inner == 0) return true;
    if (!IsLtImmaGemmAvailable()) return false;
    std::string error;
    return RunCublasLtS8S8(dA, dB, dC, rows, cols, inner,
                           static_cast<cudaStream_t>(stream), error);
}

bool TryLaunchLtImmaGemmS32S8(const std::vector<int32_t>& /*left*/, const std::vector<int8_t>& /*right*/,
                              uint32_t /*rows*/, uint32_t /*inner*/, uint32_t /*cols*/,
                              std::vector<int32_t>& /*out*/)
{
    // Honest decline: no exact s32×s8→s32 cuBLASLt/CUTLASS IMMA recipe is
    // self-qualified here. DeviceGemmS32S8Tiled / ExactGemmS32S8 remain the path.
    return false;
}

} // namespace matmul_v4::cuda
