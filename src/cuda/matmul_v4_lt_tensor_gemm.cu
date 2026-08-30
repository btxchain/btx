// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_tensor_gemm.h>

#include <cuda/cuda_context.h>
#include <matmul/matmul_v4_lt.h>

#include <cublasLt.h>
#include <cuda_runtime.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <vector>

// CUDA IMMA path for LT ExactGemm: cuBLASLt CUBLAS_COMPUTE_32I (s8xs8->s32).
// Self-tested bit-for-bit against ExactGemmS8S8 across MatExpand shapes before
// IsLtImmaGemmAvailable returns true. The selected algorithm must also declare
// CUBLASLT_NUMERICAL_IMPL_FLAGS_IMMA + INPUT_8I + ACCUMULATOR_32I, so a SIMT
// fallback that happens to be exact is never mislabeled as Tensor Core work.
// Host and device-pointer launches share a process-persistent cuBLASLt handle,
// 32 MiB workspace, per-shape descriptors/algorithms, and A/B/C scratch.
//
// S32S8: cuBLASLt CUBLAS_COMPUTE_32I is an s8×s8→s32 recipe only. There is no
// documented exact s32×s8→s32 IMMA/cuBLASLt/CUTLASS path we can self-qualify on
// sm_90/100/120, so TryLaunchLtImmaGemmS32S8 always declines; callers keep
// ExactGemmS32S8 / DeviceGemmS32S8Tiled and MUST NOT claim IMMA for that lane.
//
// Target arches (PR #89): sm_90 (H100/H200), sm_100 (B200), sm_120 (5090).
// Pre-Hopper (Ampere/Ada sm_8x, #131): native s8 IMMA is exposed only for the
// TN orientation, so GetOrCreateShapePlan falls back to a transposed-B plan
// (device-side transpose + TRANSB=OP_T) when the NN heuristic finds no native
// IMMA algorithm. The fallback is self-qualifying (SelfTestImmaOnce byte-exact
// gate) and leaves the Hopper+/Blackwell NN path bit-for-bit unchanged.

namespace matmul_v4::cuda {
namespace {

struct ImmaLtPool {
    struct ShapePlan {
        uint32_t rows{0};
        uint32_t cols{0};
        uint32_t inner{0};
        cublasLtMatmulDesc_t op_desc{nullptr};
        cublasLtMatrixLayout_t a_layout{nullptr};
        cublasLtMatrixLayout_t b_layout{nullptr};
        cublasLtMatrixLayout_t c_layout{nullptr};
        cublasLtMatmulAlgo_t algo{};
        size_t required_workspace{0};
        bool native_imma{false};
        //! Pre-Hopper native s8 IMMA is only exposed for op(B)=B^T. When set,
        //! b_layout describes B stored transposed (N×K) and the launch path
        //! materializes it with a device-side transpose (byte-exact copy).
        bool transpose_b{false};
    };

    std::mutex mu;
    cublasLtHandle_t lt{nullptr};
    void* workspace{nullptr};
    size_t workspace_bytes{0};
    void* dA{nullptr};
    void* dB{nullptr};
    void* dC{nullptr};
    void* dBt{nullptr};
    size_t a_bytes{0};
    size_t b_bytes{0};
    size_t c_bytes{0};
    size_t bt_bytes{0};
    std::vector<ShapePlan> plans;
    bool ready{false};

    ~ImmaLtPool() { Release(); }

    void Release()
    {
        for (auto& plan : plans) {
            if (plan.c_layout) cublasLtMatrixLayoutDestroy(plan.c_layout);
            if (plan.b_layout) cublasLtMatrixLayoutDestroy(plan.b_layout);
            if (plan.a_layout) cublasLtMatrixLayoutDestroy(plan.a_layout);
            if (plan.op_desc) cublasLtMatmulDescDestroy(plan.op_desc);
        }
        plans.clear();
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
        free_p(dBt, bt_bytes);
        if (lt) {
            cublasLtDestroy(lt);
            lt = nullptr;
        }
        ready = false;
    }

    [[nodiscard]] ShapePlan* FindPlan(uint32_t rows, uint32_t cols, uint32_t inner)
    {
        for (auto& plan : plans) {
            if (plan.rows == rows && plan.cols == cols && plan.inner == inner) return &plan;
        }
        return nullptr;
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

    [[nodiscard]] bool EnsureBt(size_t need_bt)
    {
        if (need_bt <= bt_bytes) return true;
        if (dBt) {
            cudaFree(dBt);
            dBt = nullptr;
            bt_bytes = 0;
        }
        if (need_bt == 0) return true;
        if (cudaMalloc(&dBt, need_bt) != cudaSuccess) return false;
        bt_bytes = need_bt;
        return true;
    }
};

ImmaLtPool& ImmaPool()
{
    static ImmaLtPool pool;
    return pool;
}

void DestroyShapePlan(ImmaLtPool::ShapePlan& plan)
{
    if (plan.c_layout) cublasLtMatrixLayoutDestroy(plan.c_layout);
    if (plan.b_layout) cublasLtMatrixLayoutDestroy(plan.b_layout);
    if (plan.a_layout) cublasLtMatrixLayoutDestroy(plan.a_layout);
    if (plan.op_desc) cublasLtMatmulDescDestroy(plan.op_desc);
    plan = {};
}

/** Transpose a row-major K×N int8 matrix B into a row-major N×K matrix Bt
 *  (Bt[n*K + k] == B[k*N + n]). Pre-Hopper cuBLASLt exposes native s8 IMMA only
 *  for the TN orientation (op(B)=B^T), so we materialize Bt and set TRANSB=OP_T.
 *  This is a pure byte copy -- no arithmetic -- so the ExactGemm result is
 *  bit-identical; the 33-wide shared tile avoids shared-memory bank conflicts. */
__global__ void TransposeS8_KN_to_NK(const int8_t* __restrict__ B,
                                     int8_t* __restrict__ Bt,
                                     uint32_t K, uint32_t N)
{
    __shared__ int8_t tile[32][33];
    const uint32_t k0 = blockIdx.y * 32u;
    const uint32_t n0 = blockIdx.x * 32u;
    const uint32_t k_in = k0 + threadIdx.y;
    const uint32_t n_in = n0 + threadIdx.x;
    if (k_in < K && n_in < N) {
        tile[threadIdx.y][threadIdx.x] =
            B[static_cast<size_t>(k_in) * N + n_in];
    }
    __syncthreads();
    const uint32_t n_out = n0 + threadIdx.y;
    const uint32_t k_out = k0 + threadIdx.x;
    if (n_out < N && k_out < K) {
        Bt[static_cast<size_t>(n_out) * K + k_out] =
            tile[threadIdx.x][threadIdx.y];
    }
}

/** Caller MUST hold ImmaPool().mu. NVIDIA recommends querying a heuristic once
 *  and reusing it. LT has only a handful of stable shapes, so cache the full
 *  descriptor/algo plan instead of rebuilding it for every nonce. */
[[nodiscard]] ImmaLtPool::ShapePlan* GetOrCreateShapePlan(ImmaLtPool& pool,
                                                          uint32_t M, uint32_t N, uint32_t K,
                                                          std::string& error)
{
    if (auto* cached = pool.FindPlan(M, N, K)) {
        if (!cached->native_imma) error = "cached shape has no native IMMA algorithm";
        return cached->native_imma ? cached : nullptr;
    }

    ImmaLtPool::ShapePlan plan;
    plan.rows = M;
    plan.cols = N;
    plan.inner = K;
    if (cublasLtMatmulDescCreate(&plan.op_desc, CUBLAS_COMPUTE_32I, CUDA_R_32I) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmulDescCreate failed";
        return nullptr;
    }
    const cublasOperation_t op_n = CUBLAS_OP_N;
    if (cublasLtMatmulDescSetAttribute(plan.op_desc, CUBLASLT_MATMUL_DESC_TRANSA, &op_n, sizeof(op_n)) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmulDescSetAttribute TRANSA failed";
        DestroyShapePlan(plan);
        return nullptr;
    }
    // A[M×K] and C[M×N] are row-major and identical for both B orientations.
    const cublasLtOrder_t order = CUBLASLT_ORDER_ROW;
    if (cublasLtMatrixLayoutCreate(&plan.a_layout, CUDA_R_8I, M, K, K) != CUBLAS_STATUS_SUCCESS ||
        cublasLtMatrixLayoutCreate(&plan.c_layout, CUDA_R_32I, M, N, N) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatrixLayoutCreate A/C failed";
        DestroyShapePlan(plan);
        return nullptr;
    }
    if (cublasLtMatrixLayoutSetAttribute(plan.a_layout, CUBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order)) != CUBLAS_STATUS_SUCCESS ||
        cublasLtMatrixLayoutSetAttribute(plan.c_layout, CUBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order)) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatrixLayoutSetAttribute A/C failed";
        DestroyShapePlan(plan);
        return nullptr;
    }

    cublasLtMatmulPreference_t preference = nullptr;
    if (cublasLtMatmulPreferenceCreate(&preference) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmulPreferenceCreate failed";
        DestroyShapePlan(plan);
        return nullptr;
    }
    if (cublasLtMatmulPreferenceSetAttribute(preference, CUBLASLT_MATMUL_PREF_MAX_WORKSPACE_BYTES,
                                             &pool.workspace_bytes, sizeof(pool.workspace_bytes)) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmulPreferenceSetAttribute failed";
        cublasLtMatmulPreferenceDestroy(preference);
        DestroyShapePlan(plan);
        return nullptr;
    }

    constexpr uint64_t kRequiredImpl =
        CUBLASLT_NUMERICAL_IMPL_FLAGS_IMMA |
        CUBLASLT_NUMERICAL_IMPL_FLAGS_ACCUMULATOR_32I |
        CUBLASLT_NUMERICAL_IMPL_FLAGS_INPUT_8I;

    // Build the B operand for a given orientation and accept only a native
    // integer Tensor Core algorithm. NN (B row-major K×N, TRANSB=OP_N) is the
    // canonical Hopper+/Blackwell path and is tried first. If no native IMMA
    // algorithm exists for NN -- the pre-Hopper (Ampere/Ada sm_8x) case, where
    // s8 IMMA is only exposed for op(B)=B^T -- retry with B stored transposed
    // (N×K, TRANSB=OP_T) plus a device-side transpose at launch (#131). The
    // choice is by actual algorithm availability, never a hard arch gate.
    // SelfTestImmaOnce byte-exact-checks representative small shapes (both
    // orientations exercise the same IMMA families), but production Rank-1 /
    // RC-ExactReplay shapes are admitted here on heuristic availability alone --
    // the ultimate byte-exact gate for those is consensus ExactReplay itself,
    // which recomputes and rejects any block whose digest a wrong algorithm
    // would produce (self-policing; a wrong build cannot split consensus, only
    // fail to sync). See adversarial finding F1.
    auto search = [&](bool transpose_b) -> bool {
        if (plan.b_layout) {
            cublasLtMatrixLayoutDestroy(plan.b_layout);
            plan.b_layout = nullptr;
        }
        const cublasOperation_t op_b = transpose_b ? CUBLAS_OP_T : CUBLAS_OP_N;
        if (cublasLtMatmulDescSetAttribute(plan.op_desc, CUBLASLT_MATMUL_DESC_TRANSB, &op_b, sizeof(op_b)) != CUBLAS_STATUS_SUCCESS) {
            return false;
        }
        // NN: B row-major K×N ld=N. TN: Bt row-major N×K ld=K, op(B)=Bt^T=B.
        const uint32_t b_rows = transpose_b ? N : K;
        const uint32_t b_cols = transpose_b ? K : N;
        if (cublasLtMatrixLayoutCreate(&plan.b_layout, CUDA_R_8I, b_rows, b_cols, b_cols) != CUBLAS_STATUS_SUCCESS) {
            return false;
        }
        if (cublasLtMatrixLayoutSetAttribute(plan.b_layout, CUBLASLT_MATRIX_LAYOUT_ORDER, &order, sizeof(order)) != CUBLAS_STATUS_SUCCESS) {
            return false;
        }
        constexpr int kMaxHeuristics = 16;
        cublasLtMatmulHeuristicResult_t heuristics[kMaxHeuristics]{};
        int returned = 0;
        if (cublasLtMatmulAlgoGetHeuristic(pool.lt, plan.op_desc, plan.a_layout, plan.b_layout,
                                           plan.c_layout, plan.c_layout, preference, kMaxHeuristics,
                                           heuristics, &returned) != CUBLAS_STATUS_SUCCESS) {
            return false;
        }
        for (int i = 0; i < returned; ++i) {
            if (heuristics[i].state != CUBLAS_STATUS_SUCCESS) continue;
            uint64_t impl_flags = 0;
            size_t written = 0;
            if (cublasLtMatmulAlgoCapGetAttribute(
                    &heuristics[i].algo, CUBLASLT_ALGO_CAP_NUMERICAL_IMPL_FLAGS,
                    &impl_flags, sizeof(impl_flags), &written) != CUBLAS_STATUS_SUCCESS ||
                written != sizeof(impl_flags) || (impl_flags & kRequiredImpl) != kRequiredImpl) {
                continue;
            }
            plan.algo = heuristics[i].algo;
            plan.required_workspace = heuristics[i].workspaceSize;
            plan.native_imma = true;
            plan.transpose_b = transpose_b;
            return true;
        }
        return false;
    };

    // BTX_LT_FORCE_TN is a validation/diagnostic override so the pre-Hopper TN
    // path can be exercised on a Hopper+/Blackwell box that would otherwise
    // always satisfy NN. It only changes which orientation is *tried*; the
    // byte-exact SelfTestImmaOnce gate still governs admission, so it can never
    // enable a non-bit-identical result.
    const bool force_tn{std::getenv("BTX_LT_FORCE_TN") != nullptr};
    if (force_tn) {
        // Loud, once: a diagnostic override that forces the pre-Hopper TN
        // orientation. If TN has no native IMMA algorithm for a shape on this
        // GPU, the negative result is cached and the whole IMMA lane disables
        // for the process (CPU/device fallback only) -- so it must never be set
        // in production, especially on Hopper+/Blackwell (audit F3).
        static std::once_flag warn_once;
        std::call_once(warn_once, [] {
            std::fprintf(stderr,
                "WARNING: BTX_LT_FORCE_TN is set -- forcing the pre-Hopper "
                "transposed-B IMMA orientation. Diagnostic/validation use only; "
                "if this GPU lacks a native TN IMMA algorithm the entire IMMA "
                "accelerator lane will be DISABLED for this process. Do NOT set "
                "this in production.\n");
        });
    }
    const bool found = force_tn
                           ? search(/*transpose_b=*/true)
                           : (search(/*transpose_b=*/false) ||
                              search(/*transpose_b=*/true));
    cublasLtMatmulPreferenceDestroy(preference);
    if (!found) {
        error = "heuristics returned no native IMMA+s32 algorithm";
        pool.plans.push_back(plan); // Cache the negative result too.
        return nullptr;
    }

    pool.plans.push_back(plan);
    return &pool.plans.back();
}

/** Caller MUST hold ImmaPool().mu. */
[[nodiscard]] bool RunCublasLtS8S8Locked(ImmaLtPool& pool, const int8_t* dA, const int8_t* dB,
                                         int32_t* dC, uint32_t M, uint32_t N, uint32_t K,
                                         cudaStream_t stream, std::string& error)
{
    // NVIDIA recommends 32 MiB for Hopper and both Blackwell families. This
    // unlocks kernels unavailable to the previous 8 MiB preference budget.
    constexpr size_t kDefaultWorkspace = 32ull << 20;
    if (!pool.EnsureHandle(kDefaultWorkspace)) {
        error = "cublasLtCreate / workspace alloc failed";
        return false;
    }
    ImmaLtPool::ShapePlan* plan = GetOrCreateShapePlan(pool, M, N, K, error);
    if (plan == nullptr) return false;

    // Pre-Hopper TN path (#131): materialize Bt = B^T (N×K) so cuBLASLt can use
    // its native s8 IMMA algorithm. Byte-exact copy on the same stream, so it
    // stays ordered before the matmul and changes no arithmetic.
    const int8_t* b_operand = dB;
    if (plan->transpose_b) {
        const size_t need_bt = static_cast<size_t>(N) * K * sizeof(int8_t);
        if (!pool.EnsureBt(need_bt)) {
            error = "Bt transpose scratch alloc failed";
            return false;
        }
        const dim3 block(32, 32);
        const dim3 grid((N + 31) / 32, (K + 31) / 32);
        TransposeS8_KN_to_NK<<<grid, block, 0, stream>>>(
            dB, static_cast<int8_t*>(pool.dBt), K, N);
        if (cudaGetLastError() != cudaSuccess) {
            error = "Bt transpose launch failed";
            return false;
        }
        b_operand = static_cast<const int8_t*>(pool.dBt);
    }

    const int32_t alpha = 1;
    const int32_t beta = 0;
    if (cublasLtMatmul(pool.lt, plan->op_desc, &alpha, dA, plan->a_layout,
                       b_operand, plan->b_layout, &beta, dC, plan->c_layout, dC, plan->c_layout,
                       &plan->algo, pool.workspace, pool.workspace_bytes, stream) != CUBLAS_STATUS_SUCCESS) {
        error = "cublasLtMatmul IMMA failed";
        return false;
    }
    if (plan->transpose_b) {
        // dBt is a pool-shared scratch and the pool mutex serializes only the
        // host-side enqueue, not GPU execution. Wait for this matmul to finish
        // reading dBt before returning (releasing the pool mutex) so a concurrent
        // TN call on another stream cannot overwrite the transpose mid-read (F2).
        // Confined to the pre-Hopper TN fallback; the NN path stays fully async.
        if (cudaStreamSynchronize(stream) != cudaSuccess) {
            error = "Bt transpose stream synchronize failed";
            return false;
        }
    }
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
        // Production-aligned sizes make it possible for cuBLASLt to select the
        // same native IMMA families used by n=4096 while keeping self-test cost
        // and memory small.
        // (1) Square IMMA tile.
        {
            constexpr uint32_t kDim = 128;
            std::vector<int8_t> left(static_cast<size_t>(kDim) * kDim);
            std::vector<int8_t> right(static_cast<size_t>(kDim) * kDim);
            FillFolded(left, 7, -101);
            FillFolded(right, 11, 53);
            if (!MatchShapeVsCpu(left, right, kDim, kDim, kDim)) return;
        }
        // (2) MatExpand panel (G*W, with the configured production width).
        {
            constexpr uint32_t kN = 256;
            constexpr uint32_t kW = matmul::v4::lt::kMatExpandPanelW;
            std::vector<int8_t> G(static_cast<size_t>(kN) * kN);
            std::vector<int8_t> W(static_cast<size_t>(kN) * kW);
            FillFolded(G, 3, -17);
            FillFolded(W, 5, 9);
            if (!MatchShapeVsCpu(G, W, kN, kN, kW)) return;
        }
        // (3) U*Ahat style: m×n × n×n → m×n (deep tile m = n/2).
        {
            constexpr uint32_t kN = 256;
            constexpr uint32_t kM = kN / 2;
            std::vector<int8_t> U(static_cast<size_t>(kM) * kN);
            std::vector<int8_t> Ahat(static_cast<size_t>(kN) * kN);
            FillFolded(U, 19, -7);
            FillFolded(Ahat, 29, 11);
            if (!MatchShapeVsCpu(U, Ahat, kM, kN, kN)) return;
        }
        // (4) Bhat*V style: n×n × n×m → n×m.
        {
            constexpr uint32_t kN = 256;
            constexpr uint32_t kM = kN / 2;
            std::vector<int8_t> Bhat(static_cast<size_t>(kN) * kN);
            std::vector<int8_t> V(static_cast<size_t>(kN) * kM);
            FillFolded(Bhat, 31, -13);
            FillFolded(V, 37, 5);
            if (!MatchShapeVsCpu(Bhat, V, kN, kN, kM)) return;
        }

        // Admission must cover the actual Rank-1 production geometry, not
        // merely a small self-test that happens to have an IMMA algorithm.
        // Heuristic planning needs no production-sized A/B/C allocation and
        // the plans are retained for the resident miner's first nonce.
        {
            constexpr uint32_t kN = 4096;
            constexpr uint32_t kM = 2048;
            constexpr uint32_t kW = matmul::v4::lt::kMatExpandPanelW;
            auto& pool = ImmaPool();
            std::lock_guard<std::mutex> lock(pool.mu);
            std::string error;
            if (!pool.EnsureHandle(32ull << 20) ||
                GetOrCreateShapePlan(pool, kN, kW, kN, error) == nullptr ||
                // Four radix-256 limbs lower resident Y*H to n×w · w×n.
                GetOrCreateShapePlan(pool, kN, kN, kW, error) == nullptr ||
                GetOrCreateShapePlan(pool, kM, kN, kN, error) == nullptr ||
                GetOrCreateShapePlan(pool, kN, kM, kN, error) == nullptr ||
                // Nine base-64 Karatsuba planes lower combine to m×n · n×m.
                GetOrCreateShapePlan(pool, kM, kM, kN, error) == nullptr) {
                return;
            }
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
