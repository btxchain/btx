// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_rc_episode_context.h>

#include <matmul/matmul_v4_rc_coupled.h>

// Default / no-CUDA-experimental build: RC episode CUDA TU is not linked.
// Host miners keep CPU / ExactGemm backends; digests unchanged.

namespace matmul_v4::cuda {

bool IsRcEpisodeCudaCompiled()
{
    return false;
}

std::string RcEpisodeCudaArchKey()
{
    return {};
}

bool RCCudaEpisodeContext::Init(const RCCudaEpisodeShape& shape, std::string* error)
{
    Destroy();
    if (shape.barriers == 0 || shape.lobes == 0 || shape.lobe_width == 0 ||
        shape.bank_pages == 0 || shape.batch_q == 0) {
        if (error) *error = "RCCudaEpisodeContext stub: invalid shape";
        return false;
    }
    matmul::v4::rc::RCCoupParams p;
    p.barriers = shape.barriers;
    p.lobes = shape.lobes;
    p.lobe_width = shape.lobe_width;
    p.bank_pages = shape.bank_pages;
    if (!matmul::v4::rc::ValidateRCCoupParams(p)) {
        if (error) *error = "RCCudaEpisodeContext stub: ValidateRCCoupParams failed";
        return false;
    }
    m_shape = shape;
    m_ready = true;
    m_bank_loaded = false;
    m_episode_bound = false;
    m_have_digest = false;
    m_state_ready = false;
    m_arena = nullptr;
    m_arena_bytes = 0;
    m_state.assign(static_cast<size_t>(shape.lobes) * shape.lobe_width, 0);
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
    if (!m_ready) {
        if (error) *error = "RCCudaEpisodeContext stub: Init required";
        return false;
    }
    if (pages.size() != m_shape.bank_pages) {
        if (error) *error = "RCCudaEpisodeContext stub: bank page count mismatch";
        return false;
    }
    const size_t page_bytes =
        static_cast<size_t>(m_shape.lobe_width) * m_shape.lobe_width;
    for (const auto& page : pages) {
        if (page.size() != page_bytes) {
            if (error) *error = "RCCudaEpisodeContext stub: bank page size mismatch";
            return false;
        }
    }
    m_pages = pages;
    m_bank_loaded = true;
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::BindEpisode(const CBlockHeader& header, int32_t height,
                                       std::string* error)
{
    if (!m_ready) {
        if (error) *error = "RCCudaEpisodeContext stub: Init required";
        return false;
    }
    m_header = header;
    m_height = height;
    m_episode_bound = true;
    m_have_digest = false;
    m_state_ready = true;
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::SetActiveState(const std::vector<int8_t>& state, std::string* error)
{
    if (!m_ready) {
        if (error) *error = "RCCudaEpisodeContext stub: Init required";
        return false;
    }
    const size_t n = static_cast<size_t>(m_shape.lobes) * m_shape.lobe_width;
    if (state.size() != n) {
        if (error) *error = "RCCudaEpisodeContext stub: SetActiveState size mismatch";
        return false;
    }
    m_state = state;
    m_state_ready = true;
    m_have_digest = false;
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::DownloadActiveState(std::vector<int8_t>& out,
                                               std::string* error) const
{
    if (!m_ready || !m_state_ready) {
        if (error) *error = "RCCudaEpisodeContext stub: state not ready";
        return false;
    }
    out = m_state;
    if (error) error->clear();
    return true;
}

bool RCCudaEpisodeContext::RunBarrierGraph(std::string* error)
{
    if (error) {
        // Honesty tokens: graph_unavailable / not_wired — CUDA TU not linked.
        *error = "graph_unavailable:not_wired";
    }
    (void)m_bank_loaded;
    (void)m_episode_bound;
    return false;
}

const uint256* RCCudaEpisodeContext::LastDigest() const
{
    return nullptr;
}

void RCCudaEpisodeContext::Destroy()
{
    m_ready = false;
    m_bank_loaded = false;
    m_episode_bound = false;
    m_have_digest = false;
    m_state_ready = false;
    m_arena = nullptr;
    m_arena_bytes = 0;
    m_shape = {};
    m_pages.clear();
    m_state.clear();
    m_last_digest = uint256{};
    m_stream = nullptr;
    m_graph = nullptr;
    m_graph_exec = nullptr;
}

} // namespace matmul_v4::cuda
