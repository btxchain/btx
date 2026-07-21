// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <tpu/matmul_v4_rc_accel.h>

#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <primitives/block.h>
#include <uint256.h>

#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace matmul_v4::tpu {
namespace {

enum class Qualification { UNTESTED, PASSED, FAILED };

struct ProviderState {
    std::mutex mutex;
    std::mutex qualification_mutex;
    TpuPjrtRcEpisodeProviderV1 provider{};
    std::string provider_name;
    bool registered{false};
    uint64_t generation{0};
    Qualification qualification{Qualification::UNTESTED};
};

ProviderState& State()
{
    static ProviderState state;
    return state;
}

} // namespace

bool RegisterTpuPjrtRcEpisodeProvider(const TpuPjrtRcEpisodeProviderV1& provider)
{
#if defined(BTX_HAVE_TPU_PJRT)
    if (provider.abi_version != kTpuPjrtRcEpisodeProviderAbiV1 ||
        provider.struct_size < sizeof(TpuPjrtRcEpisodeProviderV1) ||
        provider.run_barrier_batch == nullptr) {
        return false;
    }
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.registered) return false;
    state.provider = provider;
    state.provider_name = provider.provider_name ? provider.provider_name : "unnamed-pjrt-rc";
    state.provider.provider_name = state.provider_name.c_str();
    state.registered = true;
    ++state.generation;
    state.qualification = Qualification::UNTESTED;
    return true;
#else
    (void)provider;
    return false;
#endif
}

void ResetTpuPjrtRcEpisodeProviderForTesting()
{
    auto& state = State();
    std::lock_guard<std::mutex> q(state.qualification_mutex);
    std::lock_guard<std::mutex> lock(state.mutex);
    state.provider = {};
    state.provider_name.clear();
    state.registered = false;
    ++state.generation;
    state.qualification = Qualification::UNTESTED;
}

bool IsRcTpuCompiled()
{
#if defined(BTX_HAVE_TPU_PJRT)
    return true;
#else
    return false;
#endif
}

bool IsRcTpuAttempted()
{
    auto& state = State();
    std::lock_guard<std::mutex> lock(state.mutex);
    // Attempted only after a real self-qual invocation (not arch/getenv).
    return state.qualification != Qualification::UNTESTED;
}

std::string RcTpuDeficit()
{
    if (IsTpuPjrtRcEpisodeAvailable()) return {};
    return "requires PJRT+TPU";
}

bool HostReferenceRcTpuCoupledEpisode(const CBlockHeader& header, int32_t height,
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

bool IsTpuPjrtRcEpisodeAvailable()
{
#if defined(BTX_HAVE_TPU_PJRT)
    auto& state = State();
    std::lock_guard<std::mutex> q(state.qualification_mutex);
    TpuPjrtRcEpisodeProviderV1 provider;
    uint64_t generation{0};
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (!state.registered) return false;
        if (state.qualification == Qualification::PASSED) return true;
        if (state.qualification == Qualification::FAILED) return false;
        provider = state.provider;
        generation = state.generation;
    }
    // Minimal self-qual: toy shape must report used_exact_mxu.
    const auto params = matmul::v4::rc::MakeToyRCCoupParams();
    std::vector<int8_t> bank(static_cast<size_t>(params.bank_pages) * params.lobe_width *
                             params.lobe_width, 1);
    std::vector<int8_t> state_in(params.StateBytes(), 0);
    std::vector<int32_t> state_out(params.StateBytes(), 0);
    bool used = false;
    bool ok = false;
    try {
        ok = provider.run_barrier_batch(
            provider.context, bank.data(), bank.size(), params.barriers, params.lobes,
            params.lobe_width, params.bank_pages, /*batch_q=*/1, state_in.data(),
            state_out.data(), &used);
    } catch (...) {
        ok = false;
    }
    const bool passed = ok && used;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (!state.registered || state.generation != generation) return false;
        state.qualification = passed ? Qualification::PASSED : Qualification::FAILED;
    }
    return passed;
#else
    return false;
#endif
}

bool RCTpuEpisodeContext::Init(const RCTpuEpisodeShape& shape, std::string* error)
{
    Destroy();
    if (shape.barriers == 0 || shape.lobes == 0 || shape.lobe_width == 0 ||
        shape.bank_pages == 0 || shape.batch_q == 0) {
        if (error) *error = "RCTpuEpisodeContext: invalid shape";
        return false;
    }
    matmul::v4::rc::RCCoupParams p;
    p.barriers = shape.barriers;
    p.lobes = shape.lobes;
    p.lobe_width = shape.lobe_width;
    p.bank_pages = shape.bank_pages;
    if (!matmul::v4::rc::ValidateRCCoupParams(p)) {
        if (error) *error = "RCTpuEpisodeContext: ValidateRCCoupParams failed";
        return false;
    }
    m_shape = shape;
    m_state.assign(static_cast<size_t>(shape.lobes) * shape.lobe_width, 0);
    m_ready = true;
    m_bank_loaded = false;
    if (error) error->clear();
    return true;
}

bool RCTpuEpisodeContext::Init(const matmul::v4::rc::RCCoupParams& params, uint32_t batch_q,
                               std::string* error)
{
    RCTpuEpisodeShape shape;
    shape.barriers = params.barriers;
    shape.lobes = params.lobes;
    shape.lobe_width = params.lobe_width;
    shape.bank_pages = params.bank_pages;
    shape.batch_q = batch_q == 0 ? 1 : batch_q;
    return Init(shape, error);
}

bool RCTpuEpisodeContext::LoadBank(const std::vector<std::vector<int8_t>>& pages,
                                   std::string* error)
{
    if (!m_ready) {
        if (error) *error = "RCTpuEpisodeContext: Init required";
        return false;
    }
    if (pages.size() != m_shape.bank_pages) {
        if (error) *error = "RCTpuEpisodeContext: bank page count mismatch";
        return false;
    }
    const size_t page_bytes =
        static_cast<size_t>(m_shape.lobe_width) * m_shape.lobe_width;
    for (const auto& page : pages) {
        if (page.size() != page_bytes) {
            if (error) *error = "RCTpuEpisodeContext: bank page size mismatch";
            return false;
        }
    }
    m_bank = pages;
    m_bank_loaded = true;
    if (error) error->clear();
    return true;
}

bool RCTpuEpisodeContext::RunBarriers(std::string* error)
{
    if (!m_ready || !m_bank_loaded) {
        if (error) *error = "RCTpuEpisodeContext: Init+LoadBank required";
        return false;
    }
    if (!IsTpuPjrtRcEpisodeAvailable()) {
        if (error) *error = RcTpuDeficit();
        return false;
    }
#if defined(BTX_HAVE_TPU_PJRT)
    TpuPjrtRcEpisodeProviderV1 provider;
    {
        auto& state = State();
        std::lock_guard<std::mutex> lock(state.mutex);
        provider = state.provider;
    }
    std::vector<int8_t> flat;
    for (const auto& page : m_bank) {
        flat.insert(flat.end(), page.begin(), page.end());
    }
    std::vector<int32_t> state_out(m_state.size(), 0);
    bool used = false;
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = provider.run_barrier_batch(
        provider.context, flat.data(), flat.size(), m_shape.barriers, m_shape.lobes,
        m_shape.lobe_width, m_shape.bank_pages, m_shape.batch_q, m_state.data(),
        state_out.data(), &used);
    const auto t1 = std::chrono::steady_clock::now();
    m_timing.total_s = std::chrono::duration<double>(t1 - t0).count();
    m_timing.phase1_s = m_timing.total_s;
    if (!ok || !used) {
        if (error) *error = "TPU RC episode run_barrier_batch declined or host fallback";
        return false;
    }
    for (size_t i = 0; i < m_state.size() && i < state_out.size(); ++i) {
        const int32_t v = state_out[i];
        if (v < -128 || v > 127) {
            if (error) *error = "TPU RC episode state out of int8 range";
            return false;
        }
        m_state[i] = static_cast<int8_t>(v);
    }
    if (error) error->clear();
    return true;
#else
    if (error) *error = RcTpuDeficit();
    return false;
#endif
}

bool RCTpuEpisodeContext::ExtractHost(const uint256& prf_key, std::vector<int8_t>& out,
                                      std::string* error)
{
    if (!m_ready) {
        if (error) *error = "RCTpuEpisodeContext: Init required";
        return false;
    }
    // Host ExtractMX on int32-widened state (byte-exact consensus oracle path).
    std::vector<int32_t> wide(m_state.size());
    for (size_t i = 0; i < m_state.size(); ++i) {
        wide[i] = m_state[i];
    }
    out.resize(m_state.size());
    matmul::v4::rc::ExtractMXMatrixInt32(prf_key, wide.data(), m_shape.lobes,
                                         m_shape.lobe_width, out.data());
    if (error) error->clear();
    return true;
}

void RCTpuEpisodeContext::Destroy()
{
    m_ready = false;
    m_bank_loaded = false;
    m_bank.clear();
    m_state.clear();
    m_shape = {};
    m_timing = {};
}

} // namespace matmul_v4::tpu
