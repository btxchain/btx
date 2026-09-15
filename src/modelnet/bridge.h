// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_BRIDGE_H
#define BITCOIN_MODELNET_BRIDGE_H

#include <modelnet/protocol.h>

#include <atomic>
#include <mutex>
#include <optional>
#include <queue>
#include <string>

namespace modelnet {

struct BoundedModelHint {
    PublicEndpointHint hint;
    std::string from_addr;
};

struct ModelStatus {
    bool helper_ready{false};
    bool pq1_ready{false};
    std::string helper_error;
    uint32_t role_mask{0};
    size_t queued_hints{0};
};

/** Non-blocking introduction seam used by btxd. Must not hold monetary locks. */
class ModelBridge {
    mutable std::mutex m_mu;
    std::queue<BoundedModelHint> m_hints;
    ModelStatus m_status;
    static constexpr size_t MAX_HINTS = 64;

public:
    bool TryEnqueuePublicHint(BoundedModelHint hint);
    std::optional<BoundedModelHint> TryDequeueHint();
    ModelStatus SnapshotStatus() const;
    void SetHelperReady(bool ready, bool pq1, const std::string& err);
};

ModelBridge& GetModelBridge();

} // namespace modelnet

#endif // BITCOIN_MODELNET_BRIDGE_H
