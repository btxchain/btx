// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_rc_episode_context.h>

#include <matmul/matmul_v4_rc_coupled.h>

#include <cuda_runtime.h>

#include <cstdio>
#include <cstring>
#include <string>

// ENC_RC CUDA episode context — experimental TU.
//
// Persistent arena via cudaMallocAsync (when available) so bank pages, lobe
// state, and int64 accumulators stay device-resident across barriers.
// RunBarrierGraph is intentionally stubbed: capture a CUDA Graph over the
// barrier DAG once wired (cudaStreamBeginCapture → barrier kernels →
// cudaGraphInstantiate → cudaGraphLaunch) to amortize launch overhead.
// Digests must match RecomputeCoupledPuzzleReference; never raise heights.

namespace matmul_v4::cuda {
namespace {

bool CudaOk(cudaError_t err, std::string* error, const char* what)
{
    if (err == cudaSuccess) return true;
    if (error) {
        *error = std::string(what) + ": " + cudaGetErrorString(err);
    }
    return false;
}

size_t ArenaBytesFor(const RCCudaEpisodeShape& shape)
{
    const size_t page =
        static_cast<size_t>(shape.lobe_width) * shape.lobe_width; // int8
    const size_t bank = page * shape.bank_pages;
    const size_t state = static_cast<size_t>(shape.lobes) * shape.lobe_width *
                         shape.batch_q; // int8 rows
    const size_t acc = state * sizeof(int64_t);
    // Scratch for one Q×W×W GEMM output (int32) + padding.
    const size_t gemm_out = static_cast<size_t>(shape.batch_q) * shape.lobe_width *
                            sizeof(int32_t);
    return bank + state + acc + gemm_out;
}

} // namespace

bool IsRcEpisodeCudaCompiled()
{
    return true;
}

std::string RcEpisodeCudaArchKey()
{
#if defined(__CUDA_ARCH__)
    // Host TU path: report runtime device arch when present.
#endif
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
    matmul::v4::rc::RCCoupParams p;
    p.barriers = shape.barriers;
    p.lobes = shape.lobes;
    p.lobe_width = shape.lobe_width;
    p.bank_pages = shape.bank_pages;
    if (!matmul::v4::rc::ValidateRCCoupParams(p)) {
        if (error) *error = "RCCudaEpisodeContext: ValidateRCCoupParams failed";
        return false;
    }

    const size_t bytes = ArenaBytesFor(shape);
    void* ptr = nullptr;
    // Prefer async pool alloc; fall back to cudaMalloc if the driver rejects it.
    cudaError_t err = cudaMallocAsync(&ptr, bytes, /*stream=*/0);
    if (err != cudaSuccess) {
        err = cudaMalloc(&ptr, bytes);
        if (!CudaOk(err, error, "RCCudaEpisodeContext cudaMalloc")) {
            return false;
        }
    }
    m_arena = ptr;
    m_arena_bytes = bytes;
    m_shape = shape;
    m_ready = true;
    m_bank_loaded = false;
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::Init(const matmul::v4::rc::RCCoupParams& params, uint32_t batch_q,
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
    auto* dst = static_cast<unsigned char*>(m_arena);
    for (uint32_t i = 0; i < m_shape.bank_pages; ++i) {
        if (pages[i].size() != page_bytes) {
            if (error) *error = "RCCudaEpisodeContext: bank page size mismatch";
            return false;
        }
        if (!CudaOk(cudaMemcpyAsync(dst + static_cast<size_t>(i) * page_bytes,
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

bool RCCudaEpisodeContext::RunBarrierGraph(std::string* error)
{
    if (error) {
        *error = "RCCudaEpisodeContext: RunBarrierGraph not wired "
                 "(capture CUDA Graph over barrier GEMM+Extract when device path lands)";
    }
    (void)m_bank_loaded;
    return false;
}

void RCCudaEpisodeContext::Destroy()
{
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
    m_shape = {};
}

} // namespace matmul_v4::cuda
