// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_inferlink/swarm_inferlink.h>

#include <chrono>
#include <cstdint>
#include <string>

namespace modelnet {
namespace {

int64_t MillisecondsSince(std::chrono::steady_clock::time_point start)
{
    const auto elapsed = std::chrono::steady_clock::now() - start;
    return std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
}

bool IsNamedEngine(const std::string& engine)
{
    return engine == kSwarmInferLinkVllm || engine == kSwarmInferLinkSglang || engine == kSwarmInferLinkLmcache;
}

} // namespace

bool SwarmInferLink::Open(const std::string& session, const std::string& engine, std::string& err)
{
    return m_decode.Open(session, engine, err);
}

bool SwarmInferLink::Prompt(const std::string& session, const std::string& text, bool is_private, std::string& err)
{
    return m_decode.Prompt(session, text, is_private, err);
}

bool SwarmInferLink::Pull(const std::string& session, std::string& err)
{
    return m_decode.Pull(session, err);
}

bool SwarmInferLink::Run(const std::string& session, const std::string& text, std::string& err)
{
    if (!Open(session, kSwarmInferLinkMemory, err)) {
        return false;
    }
    if (!Prompt(session, text, false, err)) {
        return false;
    }

    const auto loop_start = std::chrono::steady_clock::now();
    bool saw_success = false;
    while (Pull(session, err)) {
        if (!saw_success) {
            m_ttft_ms = MillisecondsSince(loop_start);
            saw_success = true;
        }
        m_measured_local = true;
    }
    const int64_t loop_ms = MillisecondsSince(loop_start);
    if (!saw_success) {
        m_ttft_ms = loop_ms;
    }
    m_p50_ms = loop_ms;
    m_p95_ms = loop_ms;
    return err == kSwarmInferLinkDone;
}

bool SwarmInferLink::RunNamed(const std::string& session, const std::string& engine, const std::string& text, std::string& err)
{
    if (!IsNamedEngine(engine)) {
        if (!Open(session, engine, err)) {
            return false;
        }
        err = kSwarmInferLinkEngine;
        return false;
    }
    if (!Open(session, engine, err)) {
        return false;
    }
    if (!Prompt(session, text, false, err)) {
        return false;
    }
    Pull(session, err);
    return false;
}

std::string SwarmInferLink::engine_of(const std::string& session) const
{
    return m_decode.engine_of(session);
}

const std::string& SwarmInferLink::text() const
{
    return m_decode.text();
}

int64_t SwarmInferLink::tokens() const
{
    return m_decode.tokens();
}

int64_t SwarmInferLink::ttft_ms() const
{
    return m_ttft_ms;
}

int64_t SwarmInferLink::p50_ms() const
{
    return m_p50_ms;
}

int64_t SwarmInferLink::p95_ms() const
{
    return m_p95_ms;
}

bool SwarmInferLink::measured_local() const
{
    return m_measured_local;
}

bool SwarmInferLink::measured_gpu() const
{
    return false;
}

bool SwarmInferLink::gpu() const
{
    return false;
}

bool SwarmInferLink::launched() const
{
    return false;
}

int64_t SwarmInferLink::bytes_moved() const
{
    return 0;
}

std::string SwarmInferLink::automatic_spend() const
{
    return std::string{kSwarmInferLinkAutomaticSpend};
}

bool SwarmInferLink::broadcast() const
{
    return false;
}

} // namespace modelnet
