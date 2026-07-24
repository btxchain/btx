// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <ascend/matmul_v4_rc_accel.h>

#include <ascend/matmul_v4_lt_accel.h>
#include <matmul/matmul_v4_rc_extract.h>

#include <chrono>
#include <string>
#include <vector>

namespace matmul_v4::ascend {
namespace {

bool g_ascend_attempted{false};

} // namespace

bool IsRcAscendCompiled()
{
#if defined(BTX_HAVE_CANN)
    return true;
#else
    return false;
#endif
}

bool IsRcAscendAttempted()
{
    return g_ascend_attempted;
}

std::string RcAscendDeficit()
{
    if (IsAscendRcEpisodeAvailable()) return {};
    return "requires CANN+Ascend";
}

bool HostReferenceRcAscendCoupledEpisode(const CBlockHeader& header, int32_t height,
                                         const matmul::v4::rc::RCCoupParams& params,
                                         uint256& out_digest,
                                         matmul::v4::rc::RCEpisodeTiming* timing)
{
    const auto t0 = std::chrono::steady_clock::now();
    out_digest = matmul::v4::rc::MineCoupledPuzzle(header, height, params);
    const auto t1 = std::chrono::steady_clock::now();
    if (timing) {
        timing->total_s = std::chrono::duration<double>(t1 - t0).count();
        timing->phase1_s = timing->total_s;
        timing->phase2_s = 0;
        timing->phase3_s = 0;
    }
    return true;
}

bool TryLaunchRcAscendGemmS8S8(const std::vector<int8_t>& left, const std::vector<int8_t>& right,
                               uint32_t rows, uint32_t inner, uint32_t cols,
                               std::vector<int32_t>& out, bool* used_cube_path)
{
    g_ascend_attempted = true;
    // Reuse LT Cube ExactGemm — INT8 path only; never claim native MX.
    return ExactGemmS8S8Ascend(left, right, rows, inner, cols, out, used_cube_path);
}

bool IsAscendRcEpisodeAvailable()
{
#if defined(BTX_HAVE_CANN)
    g_ascend_attempted = true;
    // Cube ExactGemm must self-qualify; native MX stays false.
    return IsAscendExactGemmAvailable();
#else
    return false;
#endif
}

bool RCAscendEpisodeContext::Init(const RCAscendEpisodeShape& shape, std::string* error)
{
    Destroy();
    if (shape.barriers == 0 || shape.lobes == 0 || shape.lobe_width == 0 ||
        shape.bank_pages == 0 || shape.batch_q == 0) {
        if (error) *error = "RCAscendEpisodeContext: invalid shape";
        return false;
    }
    matmul::v4::rc::RCCoupParams p;
    p.barriers = shape.barriers;
    p.lobes = shape.lobes;
    p.lobe_width = shape.lobe_width;
    p.bank_pages = shape.bank_pages;
    if (!matmul::v4::rc::ValidateRCCoupParams(p)) {
        if (error) *error = "RCAscendEpisodeContext: ValidateRCCoupParams failed";
        return false;
    }
    m_shape = shape;
    m_state.assign(static_cast<size_t>(shape.lobes) * shape.lobe_width, 0);
    m_ready = true;
    m_bank_loaded = false;
    if (error) error->clear();
    return true;
}

bool RCAscendEpisodeContext::Init(const matmul::v4::rc::RCCoupParams& params, uint32_t batch_q,
                                  std::string* error)
{
    RCAscendEpisodeShape shape;
    shape.barriers = params.barriers;
    shape.lobes = params.lobes;
    shape.lobe_width = params.lobe_width;
    shape.bank_pages = params.bank_pages;
    shape.batch_q = batch_q == 0 ? 1 : batch_q;
    return Init(shape, error);
}

bool RCAscendEpisodeContext::LoadBank(const std::vector<std::vector<int8_t>>& pages,
                                      std::string* error)
{
    if (!m_ready) {
        if (error) *error = "RCAscendEpisodeContext: Init required";
        return false;
    }
    if (pages.size() != m_shape.bank_pages) {
        if (error) *error = "RCAscendEpisodeContext: bank page count mismatch";
        return false;
    }
    const size_t page_bytes =
        static_cast<size_t>(m_shape.lobe_width) * m_shape.lobe_width;
    for (const auto& page : pages) {
        if (page.size() != page_bytes) {
            if (error) *error = "RCAscendEpisodeContext: bank page size mismatch";
            return false;
        }
    }
    m_bank = pages;
    m_bank_loaded = true;
    if (error) error->clear();
    return true;
}

bool RCAscendEpisodeContext::RunBarriers(std::string* error)
{
    if (!m_ready || !m_bank_loaded) {
        if (error) *error = "RCAscendEpisodeContext: Init+LoadBank required";
        return false;
    }
    if (!IsAscendRcEpisodeAvailable()) {
        if (error) *error = RcAscendDeficit();
        return false;
    }
    // Device barrier loop: Cube ExactGemm per lobe page — INT8 only.
    const auto t0 = std::chrono::steady_clock::now();
    const uint32_t W = m_shape.lobe_width;
    std::vector<int8_t> next = m_state;
    for (uint32_t b = 0; b < m_shape.barriers; ++b) {
        for (uint32_t lobe = 0; lobe < m_shape.lobes; ++lobe) {
            const uint32_t page_id = (b + lobe) % m_shape.bank_pages;
            const auto& page = m_bank[page_id];
            std::vector<int8_t> L(W);
            for (uint32_t i = 0; i < W; ++i) {
                L[i] = m_state[static_cast<size_t>(lobe) * W + i];
            }
            std::vector<int32_t> partial;
            bool used_cube = false;
            if (!TryLaunchRcAscendGemmS8S8(L, page, /*rows=*/1, W, W, partial, &used_cube) ||
                !used_cube || partial.size() != W) {
                if (error) *error = "Ascend RC Cube GEMM declined";
                return false;
            }
            for (uint32_t i = 0; i < W; ++i) {
                const int32_t v = partial[i];
                // Saturating store into active int8 state (device path only;
                // consensus still uses host MineCoupledPuzzle).
                int32_t clipped = v;
                if (clipped > 127) clipped = 127;
                if (clipped < -128) clipped = -128;
                next[static_cast<size_t>(lobe) * W + i] = static_cast<int8_t>(clipped);
            }
        }
        m_state.swap(next);
    }
    const auto t1 = std::chrono::steady_clock::now();
    m_timing.total_s = std::chrono::duration<double>(t1 - t0).count();
    m_timing.phase1_s = m_timing.total_s;
    if (error) error->clear();
    return true;
}

bool RCAscendEpisodeContext::ExtractHost(const uint256& prf_key, std::vector<int8_t>& out,
                                         std::string* error)
{
    if (!m_ready) {
        if (error) *error = "RCAscendEpisodeContext: Init required";
        return false;
    }
    std::vector<int32_t> wide(m_state.size());
    for (size_t i = 0; i < m_state.size(); ++i) wide[i] = m_state[i];
    out.resize(m_state.size());
    matmul::v4::rc::ExtractMXMatrixInt32(prf_key, wide.data(), m_shape.lobes,
                                         m_shape.lobe_width, out.data());
    if (error) error->clear();
    return true;
}

void RCAscendEpisodeContext::Destroy()
{
    m_ready = false;
    m_bank_loaded = false;
    m_bank.clear();
    m_state.clear();
    m_shape = {};
    m_timing = {};
}

} // namespace matmul_v4::ascend
