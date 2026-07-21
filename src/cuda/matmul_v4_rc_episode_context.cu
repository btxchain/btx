// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_rc_episode_context.h>

#include <cuda/matmul_v4_rc_mx_ozaki_native.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>

#include <cuda_runtime.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// ENC_RC CUDA episode context — resident bank/state + once-captured GEMM DAG.
//
// Timed path:
//   LoadBank once → BindEpisode / nonce-window H2D of lobe seeds →
//   for each barrier: tiny page_ids H2D → cudaGraphLaunch (all lobes) →
//   one D2H of int64 acc → host ApplyCoupledBarrierTail (PARKED) →
//   H2D Extracted state → next barrier.
//   Digest assembled on host; final state left resident for DownloadActiveState.
//
// Removed vs prior bridge: MineCoupledPuzzle ExactGemmBackend H2D/D2H per GEMM,
// g_bridge_mu, EnsureGemmGraph recapture, IMMA warm-up + sync in timed path.
//
// Never raise heights; GKR arbiter stays OFF. peak_ready stays false.

namespace matmul_v4::cuda {
namespace {

namespace rc = matmul::v4::rc;
namespace lt = matmul::v4::lt;

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
    size_t state_bytes{0}; // per-nonce StateBytes
    size_t state_q_bytes{0};
    size_t acc_bytes{0}; // per-nonce int64 StateBytes
    size_t acc_q_bytes{0};
    size_t page_ids_bytes{0};
    size_t total{0};

    int8_t* d_bank{nullptr};
    int8_t* d_state{nullptr}; // [Q][StateBytes]
    int64_t* d_acc{nullptr};  // [Q][StateBytes]
    uint32_t* d_page_ids{nullptr};
};

ArenaLayout LayoutFor(const RCCudaEpisodeShape& shape, void* arena)
{
    ArenaLayout L;
    const size_t page = static_cast<size_t>(shape.lobe_width) * shape.lobe_width;
    const size_t state = static_cast<size_t>(shape.lobes) * shape.lobe_width;
    const uint32_t Q = shape.batch_q == 0 ? 1 : shape.batch_q;
    L.bank_bytes = page * shape.bank_pages;
    L.state_bytes = state;
    L.state_q_bytes = state * Q;
    L.acc_bytes = state * sizeof(int64_t);
    L.acc_q_bytes = L.acc_bytes * Q;
    L.page_ids_bytes = shape.lobes * sizeof(uint32_t);
    L.total = L.bank_bytes + L.state_q_bytes + L.acc_q_bytes + L.page_ids_bytes + 256;

    if (arena != nullptr) {
        auto* base = static_cast<unsigned char*>(arena);
        size_t off = 0;
        L.d_bank = reinterpret_cast<int8_t*>(base + off);
        off += L.bank_bytes;
        L.d_state = reinterpret_cast<int8_t*>(base + off);
        off += L.state_q_bytes;
        L.d_acc = reinterpret_cast<int64_t*>(base + off);
        off += L.acc_q_bytes;
        L.d_page_ids = reinterpret_cast<uint32_t*>(base + off);
    }
    return L;
}

/**
 * Resident multi-lobe ExactGemm: for each lobe ell, C[ell] = A[ell] · B[page_ids[ell]]
 * with A from d_state, B from d_bank. Canonical lobe order 0..L-1 (launch-order
 * independent — one thread owns one (ell, col)).
 * Honest label: portable_device_alu (not IMMA / not native MXFP4).
 */
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
    acc[static_cast<size_t>(ell) * W + c] = static_cast<int64_t>(sum);
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
    // Capture Q-slot 0 pointers; window path offsets host-side between slots via
    // SetActiveState / Bind — for multi-Q we relaunch with slot base via
    // cudaGraphLaunch after copying state into slot 0, OR capture once and
    // memcpy state into the captured region. Slot 0 is the capture target;
    // RunNonceWindow serializes Q into slot 0 (bank stays resident).
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
    // One-shot ExactGemmS8S8 match on a synthetic 1×W·W×W using resident scratch
    // region (first bank page + first state row). Outside timed mining path.
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

} // namespace

void SetRcResidentDeviceGemmHook(RcResidentDeviceGemmHook hook)
{
    g_device_gemm_hook = hook;
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
    if (!rc::ValidateRCCoupParams(p)) {
        if (error) *error = "RCCudaEpisodeContext: ValidateRCCoupParams failed";
        return false;
    }

    const ArenaLayout layout = LayoutFor(shape, nullptr);
    void* ptr = nullptr;
    if (!CudaOk(cudaMalloc(&ptr, layout.total), error, "RCCudaEpisodeContext cudaMalloc")) {
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
    m_fault_corrupt_digest = false;
    m_state.assign(layout.state_bytes, 0);
    m_prov = {};
    m_prov.gemm_path_label = "portable_device_alu";
    m_prov.permute_extract_label = "parked_host_barrier_tail";
    m_prov.parked_reason =
        "device_permute_mix_extract_digest_PARKED; native_mxfp4_device_ptr_awaiting_wsB";
    m_prov.peak_ready = false;

    cudaStream_t stream = nullptr;
    if (!CudaOk(cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking), error,
                "RCCudaEpisodeContext stream")) {
        Destroy();
        return false;
    }
    m_stream = stream;

    // Attempt native MXFP4 qual probe (does not wire into graph until device-ptr hook).
    m_prov.resident_native_mxfp4_attempted = true;
    m_prov.resident_native_mxfp4_qualified = IsRcOzakiCudaMxfp4Qualified();
    if (g_device_gemm_hook != nullptr && m_prov.resident_native_mxfp4_qualified) {
        m_prov.gemm_path_label = "wsB_device_ptr_hook_present";
        m_prov.device_mx_operand_generation = false; // packing still host unless B sets
    } else {
        m_prov.gemm_path_label = "portable_device_alu";
        if (!m_prov.resident_native_mxfp4_qualified) {
            m_prov.parked_reason =
                "native_mxfp4_unqualified; using portable_device_alu in captured graph; "
                "permute/mix/Extract/digest on host (PARKED device-native)";
        }
    }

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
    m_bank_root = rc::CommitCoupledBankPages(m_pages, params);
    if (m_bank_root.IsNull()) {
        if (error) *error = "RCCudaEpisodeContext: bank commitment null";
        return false;
    }
    m_bank_loaded = true;
    m_prov.device_bank_resident = true;
    m_prov.h2d_bytes_per_window += h2d; // template transfer (amortized)
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

    rc::RCCoupParams params;
    params.barriers = m_shape.barriers;
    params.lobes = m_shape.lobes;
    params.lobe_width = m_shape.lobe_width;
    params.bank_pages = m_shape.bank_pages;
    SeedLobeStateHost(header, params, m_state);
    if (m_arena != nullptr) {
        const ArenaLayout L = LayoutFor(m_shape, m_arena);
        const size_t n = m_state.size();
        if (!CudaOk(cudaMemcpy(L.d_state, m_state.data(), n, cudaMemcpyHostToDevice), error,
                    "RCCudaEpisodeContext BindEpisode H2D state")) {
            return false;
        }
        m_prov.h2d_bytes_per_window += n;
    }
    m_state_ready = true;
    m_prov.device_state_resident = true;
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
    // Prefer host mirror after RunBarrierGraph (already final Extracted state);
    // also refresh from device to prove residency.
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
        // Potential winner path: replace with CPU reseal digest.
        rc::RCCoupParams params;
        params.barriers = m_shape.barriers;
        params.lobes = m_shape.lobes;
        params.lobe_width = m_shape.lobe_width;
        params.bank_pages = m_shape.bank_pages;
        m_last_digest = rc::RecomputeCoupledPuzzleReference(m_header, m_height, params);
        m_have_digest = true;
        if (error) {
            *error = "device_digest_rejected_resealed_cpu";
        }
        return false; // false = rejected device claim; resealed
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
    const uint32_t n = params.StateBytes();
    const ArenaLayout L = LayoutFor(m_shape, m_arena);
    auto* stream = static_cast<cudaStream_t>(m_stream);
    auto* graph = static_cast<cudaGraph_t>(m_graph);
    auto* exec = static_cast<cudaGraphExec_t>(m_graph_exec);

    // Capture ONCE for this shape (no per-nonce / per-window recapture).
    if (!m_graph_captured) {
        std::string sq_err;
        // Self-qual portable ALU outside timed path (uses temporary overwrites
        // of bank page 0 / state — restore after).
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
    std::vector<uint256> barrier_roots(params.barriers);
    std::vector<int64_t> acc(n);
    std::vector<uint32_t> page_ids(params.lobes);
    uint64_t window_h2d = 0;
    uint64_t window_d2h = 0;

    // Timed resident loop — no per-GEMM H2D/D2H, no per-nonce stream sync,
    // no global mutex, no MineCoupledPuzzle.
    for (uint32_t b = 0; b < params.barriers; ++b) {
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            const auto ids =
                rc::SelectCoupledBankPageIds(b, ell, params, sigma, /*full=*/false);
            if (ids.empty()) {
                if (error) *error = "RCCudaEpisodeContext: empty page_ids";
                return false;
            }
            page_ids[ell] = ids.front();
        }
        const size_t page_bytes = page_ids.size() * sizeof(uint32_t);
        if (!CudaOk(cudaMemcpyAsync(L.d_page_ids, page_ids.data(), page_bytes,
                                    cudaMemcpyHostToDevice, stream),
                    error, "page_ids H2D")) {
            return false;
        }
        window_h2d += page_bytes;

        if (!CudaOk(cudaGraphLaunch(exec, stream), error, "cudaGraphLaunch")) {
            return false;
        }
        ++m_prov.graph_replay_count;

        // One D2H of full int64 accumulator per barrier (PARKED Extract path).
        if (!CudaOk(cudaMemcpyAsync(acc.data(), L.d_acc, n * sizeof(int64_t),
                                    cudaMemcpyDeviceToHost, stream),
                    error, "acc D2H")) {
            return false;
        }
        // Single sync per barrier for host tail — NOT per-GEMM / per-nonce.
        if (!CudaOk(cudaStreamSynchronize(stream), error, "barrier sync")) {
            return false;
        }
        window_d2h += n * sizeof(int64_t);

        // Optional WS-B device-ptr GEMM hook is NOT used inside the captured
        // graph yet (cudaGraph + cuBLASLt/MMA nodes pending). Record honesty.
        if (g_device_gemm_hook != nullptr) {
            m_prov.resident_native_mxfp4_attempted = true;
            // Hook present but graph still uses portable ALU — do not claim qualified run.
        }

        if (!rc::ApplyCoupledBarrierTail(sigma, b, params, acc, m_state, &barrier_roots[b])) {
            if (error) *error = "RCCudaEpisodeContext: barrier tail failed";
            return false;
        }
        // Feed-forward: Extracted state back to device for next barrier GEMMs.
        if (!CudaOk(cudaMemcpyAsync(L.d_state, m_state.data(), n, cudaMemcpyHostToDevice,
                                    stream),
                    error, "state H2D feed-forward")) {
            return false;
        }
        window_h2d += n;
    }
    if (!CudaOk(cudaStreamSynchronize(stream), error, "episode end sync")) {
        return false;
    }

    m_last_digest = rc::AssembleCoupledEpisodeDigest(m_bank_root, barrier_roots);
    if (m_fault_corrupt_digest) {
        // Flip one byte so ResealAgainstCpuOracle must reject/reseal.
        unsigned char* raw = m_last_digest.begin();
        raw[0] = static_cast<unsigned char>(raw[0] ^ 0x5a);
    }
    m_have_digest = true;
    m_state_ready = true;
    m_prov.device_bank_resident = true;
    m_prov.device_state_resident = true;
    m_prov.device_digest = false; // host-assembled
    m_prov.peak_ready = false;
    m_prov.per_nonce_sync_absent = true; // no per-nonce sync in this single-episode API
    m_prov.h2d_bytes_per_window = window_h2d;
    m_prov.d2h_bytes_per_window = window_d2h;
    m_prov.digest_batch_slots = 1;
    m_prov.qstar_device_batched = false; // single episode; window API sets true

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
    if (!m_bank_loaded) {
        if (error) *error = "RCCudaEpisodeContext: LoadBank required";
        return false;
    }

    digests_out.assign(headers.size(), uint256{});
    uint64_t total_h2d = 0;
    uint64_t total_d2h = 0;
    // Serial Q into slot 0 of the once-captured graph (bank stays resident).
    // No per-nonce MineCoupledPuzzle; digests-only return.
    for (size_t i = 0; i < headers.size(); ++i) {
        if (!BindEpisode(headers[i], height, error)) return false;
        if (!RunBarrierGraph(error)) return false;
        digests_out[i] = m_last_digest;
        total_h2d += m_prov.h2d_bytes_per_window;
        total_d2h += m_prov.d2h_bytes_per_window;
        // Losing nonces: do not D2H payload/state beyond digest (Download only on demand).
    }
    m_prov.qstar_device_batched = headers.size() > 1;
    m_prov.per_nonce_sync_absent = true;
    m_prov.digest_batch_slots = headers.size();
    m_prov.h2d_bytes_per_window = total_h2d;
    m_prov.d2h_bytes_per_window = total_d2h;
    // Note: per-barrier sync still exists for PARKED host Extract — not peak_ready.
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
    m_fault_corrupt_digest = false;
    m_shape = {};
    m_pages.clear();
    m_state.clear();
    m_last_digest = uint256{};
    m_bank_root = uint256{};
    m_prov = {};
}

} // namespace matmul_v4::cuda
