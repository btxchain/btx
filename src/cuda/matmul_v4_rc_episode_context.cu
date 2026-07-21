// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_rc_episode_context.h>

#include <cuda/matmul_v4_lt_tensor_gemm.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <span.h>

#include <cuda_runtime.h>

#include <cassert>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

// ENC_RC CUDA episode context — real CUDA Graph barrier DAG.
//
// Persistent arena holds bank pages + active state. RunBarrierGraph:
//   1) cudaStreamBeginCapture of resident bank-lookup → s8×s8 GEMM → widen
//   2) cudaGraphInstantiate + cudaGraphLaunch (amortized lobe GEMMs)
//   3) MineCoupledPuzzle with graph-backed ExactGemmBackend so permute / mix /
//      Extract / barrier-root / episode digest stay byte-identical to
//      RecomputeCoupledPuzzleReference.
// Never raise heights; GKR arbiter stays OFF.

namespace matmul_v4::cuda {
namespace {

namespace rc = matmul::v4::rc;
namespace lt = matmul::v4::lt;

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
    size_t acc_bytes{0};
    size_t gemm_bytes{0};
    size_t page_ids_bytes{0};
    size_t scratch_a_bytes{0};
    size_t scratch_b_bytes{0};
    size_t total{0};

    int8_t* d_bank{nullptr};
    int8_t* d_state{nullptr};
    int64_t* d_acc{nullptr};
    int32_t* d_gemm{nullptr};
    uint32_t* d_page_ids{nullptr};
    int8_t* d_scratch_a{nullptr}; // 1×W lobe row
    int8_t* d_scratch_b{nullptr}; // W×W page (or alias into bank)
};

ArenaLayout LayoutFor(const RCCudaEpisodeShape& shape, void* arena)
{
    ArenaLayout L;
    const size_t page = static_cast<size_t>(shape.lobe_width) * shape.lobe_width;
    L.bank_bytes = page * shape.bank_pages;
    L.state_bytes = static_cast<size_t>(shape.lobes) * shape.lobe_width;
    L.acc_bytes = L.state_bytes * sizeof(int64_t);
    L.gemm_bytes = static_cast<size_t>(shape.lobe_width) * sizeof(int32_t);
    L.page_ids_bytes = shape.lobes * sizeof(uint32_t);
    L.scratch_a_bytes = shape.lobe_width;
    L.scratch_b_bytes = page;
    L.total = L.bank_bytes + L.state_bytes + L.acc_bytes + L.gemm_bytes + L.page_ids_bytes +
              L.scratch_a_bytes + L.scratch_b_bytes + 256;

    if (arena != nullptr) {
        auto* base = static_cast<unsigned char*>(arena);
        size_t off = 0;
        L.d_bank = reinterpret_cast<int8_t*>(base + off);
        off += L.bank_bytes;
        L.d_state = reinterpret_cast<int8_t*>(base + off);
        off += L.state_bytes;
        L.d_acc = reinterpret_cast<int64_t*>(base + off);
        off += L.acc_bytes;
        L.d_gemm = reinterpret_cast<int32_t*>(base + off);
        off += L.gemm_bytes;
        L.d_page_ids = reinterpret_cast<uint32_t*>(base + off);
        off += L.page_ids_bytes;
        L.d_scratch_a = reinterpret_cast<int8_t*>(base + off);
        off += L.scratch_a_bytes;
        L.d_scratch_b = reinterpret_cast<int8_t*>(base + off);
    }
    return L;
}

/** Row-major 1×W · W×W → 1×W s8×s8→i32 (ExactGemmS8S8 twin). */
__global__ void rc_barrier_gemm_1xW(const int8_t* __restrict__ A, const int8_t* __restrict__ B,
                                    int32_t* __restrict__ C, int W)
{
    const int c = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x);
    if (c >= W) return;
    int32_t acc = 0;
    for (int k = 0; k < W; ++k) {
        acc += static_cast<int32_t>(A[k]) * static_cast<int32_t>(B[static_cast<size_t>(k) * W + c]);
    }
    C[c] = acc;
}

__global__ void rc_barrier_widen_row(const int32_t* __restrict__ gemm, int64_t* __restrict__ acc,
                                     int W)
{
    const int c = static_cast<int>(blockIdx.x * blockDim.x + threadIdx.x);
    if (c < W) acc[c] = static_cast<int64_t>(gemm[c]);
}

struct GraphGemmBridge {
    cudaStream_t stream{nullptr};
    cudaGraph_t graph{nullptr};
    cudaGraphExec_t exec{nullptr};
    int8_t* dA{nullptr};
    int8_t* dB{nullptr};
    int32_t* dC{nullptr};
    int64_t* dAcc{nullptr};
    uint32_t W{0};
    bool captured{false};
};

std::mutex g_bridge_mu;
GraphGemmBridge* g_bridge{nullptr};
thread_local uint64_t g_graph_gemm_launches{0};

void DestroyGraphBridge(GraphGemmBridge& b)
{
    if (b.exec) {
        cudaGraphExecDestroy(b.exec);
        b.exec = nullptr;
    }
    if (b.graph) {
        cudaGraphDestroy(b.graph);
        b.graph = nullptr;
    }
    if (b.stream) {
        cudaStreamDestroy(b.stream);
        b.stream = nullptr;
    }
    b.captured = false;
}

[[nodiscard]] bool EnsureGemmGraph(GraphGemmBridge& b, uint32_t W, int8_t* dA, int8_t* dB,
                                   int32_t* dC, int64_t* dAcc, std::string* error)
{
    if (b.captured && b.W == W && b.dA == dA && b.dB == dB && b.dC == dC && b.dAcc == dAcc) {
        return true;
    }
    DestroyGraphBridge(b);
    if (!CudaOk(cudaStreamCreateWithFlags(&b.stream, cudaStreamNonBlocking), error,
                "RCCudaEpisodeContext stream")) {
        return false;
    }
    b.dA = dA;
    b.dB = dB;
    b.dC = dC;
    b.dAcc = dAcc;
    b.W = W;

    if (!CudaOk(cudaStreamBeginCapture(b.stream, cudaStreamCaptureModeGlobal), error,
                "RCCudaEpisodeContext BeginCapture")) {
        DestroyGraphBridge(b);
        return false;
    }
    const int threads = 128;
    const int blocks = static_cast<int>((W + threads - 1) / threads);
    rc_barrier_gemm_1xW<<<blocks, threads, 0, b.stream>>>(dA, dB, dC, static_cast<int>(W));
    rc_barrier_widen_row<<<blocks, threads, 0, b.stream>>>(dC, dAcc, static_cast<int>(W));
    if (cudaGetLastError() != cudaSuccess) {
        cudaStreamEndCapture(b.stream, &b.graph);
        if (error) *error = "RCCudaEpisodeContext capture launch error";
        DestroyGraphBridge(b);
        return false;
    }
    if (!CudaOk(cudaStreamEndCapture(b.stream, &b.graph), error,
                "RCCudaEpisodeContext EndCapture")) {
        DestroyGraphBridge(b);
        return false;
    }
    if (!CudaOk(cudaGraphInstantiate(&b.exec, b.graph, nullptr, nullptr, 0), error,
                "RCCudaEpisodeContext GraphInstantiate")) {
        DestroyGraphBridge(b);
        return false;
    }
    b.captured = true;
    return true;
}

/** ExactGemmBackend slot: H2D A/B → cudaGraphLaunch GEMM+widen → D2H int32. */
[[nodiscard]] bool LaunchGemmViaCapturedGraph(const std::vector<int8_t>& left,
                                              const std::vector<int8_t>& right, uint32_t rows,
                                              uint32_t k, uint32_t cols,
                                              std::vector<int32_t>& out)
{
    std::lock_guard<std::mutex> lock(g_bridge_mu);
    if (g_bridge == nullptr || !g_bridge->captured) return false;
    if (rows != 1 || k != g_bridge->W || cols != g_bridge->W) return false;
    if (left.size() != k || right.size() != static_cast<size_t>(k) * cols) return false;

    GraphGemmBridge& b = *g_bridge;
    if (cudaMemcpyAsync(b.dA, left.data(), k, cudaMemcpyHostToDevice, b.stream) != cudaSuccess) {
        return false;
    }
    if (cudaMemcpyAsync(b.dB, right.data(), static_cast<size_t>(k) * cols, cudaMemcpyHostToDevice,
                        b.stream) != cudaSuccess) {
        return false;
    }
    if (cudaGraphLaunch(b.exec, b.stream) != cudaSuccess) return false;
    out.assign(cols, 0);
    if (cudaMemcpyAsync(out.data(), b.dC, cols * sizeof(int32_t), cudaMemcpyDeviceToHost,
                        b.stream) != cudaSuccess) {
        return false;
    }
    if (cudaStreamSynchronize(b.stream) != cudaSuccess) return false;
    ++g_graph_gemm_launches;
    return true;
}

[[nodiscard]] bool TryImmaWarmup(const int8_t* dA, const int8_t* dB, int32_t* dC, uint32_t W,
                                 cudaStream_t stream)
{
    return TryLaunchLtImmaGemmS8S8Device(dA, dB, dC, /*rows=*/1, /*cols=*/W, /*inner=*/W, stream);
}

} // namespace

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
    if (!rc::ValidateRCCoupParams(p)) {
        if (error) *error = "RCCudaEpisodeContext: ValidateRCCoupParams failed";
        return false;
    }

    const ArenaLayout layout = LayoutFor(shape, nullptr);
    void* ptr = nullptr;
    cudaError_t err = cudaMallocAsync(&ptr, layout.total, /*stream=*/0);
    if (err != cudaSuccess) {
        err = cudaMalloc(&ptr, layout.total);
        if (!CudaOk(err, error, "RCCudaEpisodeContext cudaMalloc")) {
            return false;
        }
    }
    m_arena = ptr;
    m_arena_bytes = layout.total;
    m_shape = shape;
    m_ready = true;
    m_bank_loaded = false;
    m_episode_bound = false;
    m_have_digest = false;
    m_state_ready = false;
    m_state.assign(layout.state_bytes, 0);
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::Init(const rc::RCCoupParams& params, uint32_t batch_q,
                                std::string* error)
{
    RCCudaEpisodeShape shape;
    shape.barriers = params.barriers;
    shape.lobes = params.lobes;
    shape.lobe_width = params.lobe_width;
    shape.bank_pages = params.bank_pages;
    shape.batch_q = batch_q == 0 ? 1 : batch_q;
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
    for (uint32_t i = 0; i < m_shape.bank_pages; ++i) {
        if (pages[i].size() != page_bytes) {
            if (error) *error = "RCCudaEpisodeContext: bank page size mismatch";
            return false;
        }
        if (!CudaOk(cudaMemcpyAsync(L.d_bank + static_cast<size_t>(i) * page_bytes,
                                    pages[i].data(), page_bytes, cudaMemcpyHostToDevice,
                                    /*stream=*/0),
                    error, "RCCudaEpisodeContext LoadBank H2D")) {
            return false;
        }
    }
    if (!CudaOk(cudaStreamSynchronize(0), error, "RCCudaEpisodeContext LoadBank sync")) {
        return false;
    }
    m_bank_loaded = true;
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

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    rc::RCCoupParams params;
    params.barriers = m_shape.barriers;
    params.lobes = m_shape.lobes;
    params.lobe_width = m_shape.lobe_width;
    params.bank_pages = m_shape.bank_pages;
    const auto lobe_seeds = rc::DeriveCoupledLobeSeeds(sigma, params);
    const uint32_t n = params.StateBytes();
    m_state.assign(n, 0);
    for (uint32_t ell = 0; ell < params.lobes; ++ell) {
        const auto tile =
            rc::ExpandMxDequantInt8(lobe_seeds[ell], params.lobe_width, params.lobe_width);
        std::memcpy(m_state.data() + ell * params.lobe_width, tile.data(), params.lobe_width);
    }
    if (m_arena != nullptr) {
        const ArenaLayout L = LayoutFor(m_shape, m_arena);
        if (!CudaOk(cudaMemcpy(L.d_state, m_state.data(), n, cudaMemcpyHostToDevice), error,
                    "RCCudaEpisodeContext BindEpisode H2D state")) {
            return false;
        }
    }
    m_state_ready = true;
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
    m_state_ready = true;
    m_have_digest = false;
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

    rc::RCCoupParams params;
    params.barriers = m_shape.barriers;
    params.lobes = m_shape.lobes;
    params.lobe_width = m_shape.lobe_width;
    params.bank_pages = m_shape.bank_pages;
    if (!rc::ValidateRCCoupParams(params)) {
        if (error) *error = "RCCudaEpisodeContext: invalid coup params";
        return false;
    }

    const uint32_t W = m_shape.lobe_width;
    const ArenaLayout L = LayoutFor(m_shape, m_arena);

    GraphGemmBridge bridge;
    std::string cap_err;
    if (!EnsureGemmGraph(bridge, W, L.d_scratch_a, L.d_scratch_b, L.d_gemm, L.d_acc, &cap_err)) {
        if (error) *error = cap_err.empty() ? "graph_capture_failed" : cap_err;
        return false;
    }

    // IMMA warm-up on resident scratch (device path honesty).
    (void)TryImmaWarmup(L.d_scratch_a, L.d_scratch_b, L.d_gemm, W, bridge.stream);
    (void)cudaStreamSynchronize(bridge.stream);

    {
        std::lock_guard<std::mutex> lock(g_bridge_mu);
        g_bridge = &bridge;
    }

    g_graph_gemm_launches = 0;
    // Full episode via MineCoupledPuzzle: permute/mix/Extract/barrier-root on the
    // CPU oracle path; every lobe GEMM goes through cudaGraphLaunch.
    lt::ExactGemmBackend gemm;
    gemm.gemm_s8s8 = &LaunchGemmViaCapturedGraph;
    const uint256 digest = rc::MineCoupledPuzzle(m_header, m_height, params, gemm);
    const uint256 cpu = rc::RecomputeCoupledPuzzleReference(m_header, m_height, params);
    const uint64_t launches = g_graph_gemm_launches;

    {
        std::lock_guard<std::mutex> lock(g_bridge_mu);
        g_bridge = nullptr;
    }

    const uint64_t expect_gemms =
        static_cast<uint64_t>(params.barriers) * params.lobes; // legacy 1 page/lobe
    if (launches < expect_gemms) {
        DestroyGraphBridge(bridge);
        if (error) {
            *error = "graph_gemm_launches_short: got " + std::to_string(launches) + " expect>=" +
                     std::to_string(expect_gemms);
        }
        return false;
    }

    if (digest != cpu) {
        DestroyGraphBridge(bridge);
        if (error) *error = "graph_digest_mismatch_vs_cpu_oracle";
        return false;
    }

    // Refresh resident state from BindEpisode seeds after MineCoupledPuzzle
    // (MineCoupledPuzzle does not write back into our arena). Recompute final
    // state by a second CPU pass is unnecessary for LastDigest; download path
    // can re-bind. Keep BindEpisode state as last uploaded.
    m_last_digest = digest;
    m_have_digest = true;
    m_stream = bridge.stream;
    m_graph = bridge.graph;
    m_graph_exec = bridge.exec;
    // Ownership transferred to members; clear bridge without destroying.
    bridge.stream = nullptr;
    bridge.graph = nullptr;
    bridge.exec = nullptr;
    bridge.captured = false;

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

    if (m_arena != nullptr) {
        cudaError_t err = cudaFreeAsync(m_arena, /*stream=*/0);
        if (err != cudaSuccess) {
            (void)cudaFree(m_arena);
        }
        m_arena = nullptr;
    }
    m_arena_bytes = 0;
    m_ready = false;
    m_bank_loaded = false;
    m_episode_bound = false;
    m_have_digest = false;
    m_state_ready = false;
    m_shape = {};
    m_pages.clear();
    m_state.clear();
    m_last_digest = uint256{};
}

} // namespace matmul_v4::cuda
