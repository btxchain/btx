// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_INFER_SESSION_H
#define BTX_MODELNET_SWARM_INFER_SESSION_H

#include <modelnet/swarm_infer/engine_bind.h>
#include <modelnet/swarm_infer/metrics.h>
#include <modelnet/swarm_infer/publish.h>
#include <modelnet/swarm_infer/runtime.h>
#include <modelnet/swarm_infer/text_slot.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Local inference control plane for one session.
 *
 * Open probes a binary and qualifies it. An empty name or path returns
 * ENGINE and stores nothing. A missing file is ENGINE_ABSENT and present
 * stays false. A regular file is status INSTALLED; qualified and advertised
 * stay false and code stays UNQUALIFIED. Open does not spawn a process and
 * does not start vLLM, SGLang, or CUDA.
 *
 * AcceptText stores text only when status is INSTALLED and text is non-empty.
 * Empty text is TEXT. A second different text is CONFLICT and keeps the first.
 * The same text is REPLAY. AcceptText on an absent engine returns ENGINE_ABSENT.
 *
 * Streamed text is not a tok/s, p50, p95, or TTFT. tokens_per_sec() stays -1.
 * p50_ms(), p95_ms(), and ttft_ms() stay -1. bytes_moved() stays 0.
 * published() stays false. Publish() returns HELD and does not store a rate.
 *
 * Close() leaves the stored text readable and does not delete the binary.
 */
class SwarmInferSession {
public:
    SwarmInferSession() = default;

    std::string Open(const std::string& name, const fs::path& binary);
    std::string AcceptText(const std::string& text);
    std::string Publish();
    void Close();

    const std::string& name() const { return m_binding.name; }
    const fs::path& binary() const { return m_binding.binary; }
    const std::string& text() const { return m_slot.value; }
    const std::string& status() const { return m_binding.status; }
    const std::string& code() const { return m_binding.code; }
    const std::string& last_err() const { return m_last_err; }

    bool bound() const { return m_binding.stored; }
    bool present() const { return m_binding.present; }
    bool qualified() const { return m_binding.qualified; }
    bool advertised() const { return m_binding.advertised; }
    bool published() const { return m_hold.published; }
    bool rate_stored() const { return m_hold.rate_stored; }
    bool has_text() const { return m_slot.occupied; }
    bool closed() const { return m_closed; }
    bool runtime_started() const { return m_runtime.started; }
    bool process_spawned() const { return m_runtime.process_spawned; }

    int64_t bytes_moved() const { return m_metrics.bytes_moved; }
    double tokens_per_sec() const { return m_metrics.tokens_per_sec; }
    double p50_ms() const { return m_metrics.p50_ms; }
    double p95_ms() const { return m_metrics.p95_ms; }
    double ttft_ms() const { return m_metrics.ttft_ms; }

private:
    void RefreshMetrics(const std::string& text);

    SwarmInferBinding m_binding;
    SwarmInferTextSlot m_slot;
    SwarmInferRateHold m_hold;
    SwarmInferMetrics m_metrics;
    SwarmInferRuntime m_runtime;
    bool m_closed{false};
    std::string m_last_err;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_INFER_SESSION_H
