// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_infer/session.h>

#include <modelnet/swarm_infer/codes.h>

#include <string>
#include <utility>

namespace modelnet {

void SwarmInferSession::RefreshMetrics(const std::string& text)
{
    m_metrics = SwarmInferMetricsFromText(text);
    m_hold.published = false;
    m_hold.rate_stored = false;
    m_hold.tokens_per_sec = -1.0;
}

std::string SwarmInferSession::Open(const std::string& name, const fs::path& binary)
{
    std::string err;
    SwarmInferBinding binding = SwarmInferProbeAndQualify(name, binary, err);
    if (!binding.stored) {
        return SwarmInferCode::engine;
    }
    m_binding = std::move(binding);
    m_slot = SwarmInferTextSlot{};
    m_hold = SwarmInferRateHold{};
    m_metrics = SwarmInferMetrics{};
    m_closed = false;
    m_last_err = err;
    SwarmInferRuntimeRequest request;
    request.want_vllm = false;
    request.want_sglang = false;
    request.want_cuda = false;
    std::string runtime_err;
    m_runtime = SwarmInferConsiderRuntime(request, runtime_err);
    (void)runtime_err;
    return m_binding.code;
}

std::string SwarmInferSession::AcceptText(const std::string& text)
{
    if (!m_binding.stored || !m_binding.present || m_binding.status != SwarmInferCode::installed) {
        if (m_binding.stored) {
            m_last_err = SwarmInferCode::engine_absent;
            return m_last_err;
        }
        m_last_err = SwarmInferCode::engine;
        return m_last_err;
    }
    if (text.empty()) {
        RefreshMetrics(text);
        m_last_err = SwarmInferCode::text;
        return m_last_err;
    }
    if (m_closed) {
        RefreshMetrics(text);
        m_last_err = SwarmInferCode::closed;
        return m_last_err;
    }
    std::string err;
    const std::string code = SwarmInferStoreText(m_slot, text, err);
    RefreshMetrics(text);
    m_last_err = err;
    return code;
}

std::string SwarmInferSession::Publish()
{
    std::string err;
    const std::string code = SwarmInferHoldPublish(m_hold, err);
    RefreshMetrics(m_slot.value);
    m_hold.published = false;
    m_hold.rate_stored = false;
    m_hold.tokens_per_sec = -1.0;
    m_last_err = err;
    return code;
}

void SwarmInferSession::Close()
{
    m_closed = true;
}

} // namespace modelnet
