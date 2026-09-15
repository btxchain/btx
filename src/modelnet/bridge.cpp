// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/bridge.h>

namespace modelnet {

bool ModelBridge::TryEnqueuePublicHint(BoundedModelHint hint)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_hints.size() >= MAX_HINTS) return false;
    m_hints.push(std::move(hint));
    m_status.queued_hints = m_hints.size();
    return true;
}

std::optional<BoundedModelHint> ModelBridge::TryDequeueHint()
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_hints.empty()) return std::nullopt;
    auto h = std::move(m_hints.front());
    m_hints.pop();
    m_status.queued_hints = m_hints.size();
    return h;
}

ModelStatus ModelBridge::SnapshotStatus() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_status;
}

void ModelBridge::SetHelperReady(bool ready, bool pq1, const std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_status.helper_ready = ready;
    m_status.pq1_ready = pq1;
    m_status.helper_error = err;
}

ModelBridge& GetModelBridge()
{
    static ModelBridge g;
    return g;
}

} // namespace modelnet
