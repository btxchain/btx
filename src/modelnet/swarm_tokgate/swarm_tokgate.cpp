// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/swarm_tokgate.h>

#include <modelnet/swarm_tokgate/bind.h>
#include <modelnet/swarm_tokgate/decode.h>
#include <modelnet/swarm_tokgate/inspect.h>
#include <modelnet/swarm_tokgate/measure.h>
#include <modelnet/swarm_tokgate/open.h>
#include <modelnet/swarm_tokgate/prompt.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmTokenGate::Open(const std::string& session, const std::string& model_id, std::string& err)
{
    return SwarmTokenGateOpenApply(m_book, session, model_id, err);
}

bool SwarmTokenGate::BindEngine(const std::string& session, const std::string& engine_name, std::string& err)
{
    return SwarmTokenGateBindApply(m_book, session, engine_name, err);
}

bool SwarmTokenGate::Prompt(const std::string& session, const std::string& text, bool is_private, std::string& err)
{
    return SwarmTokenGatePromptApply(m_book, session, text, is_private, err);
}

bool SwarmTokenGate::Decode(const std::string& session, std::string& err)
{
    return SwarmTokenGateDecodeRefuse(m_book, session, err);
}

bool SwarmTokenGate::Measure(const std::string& session, std::string& err)
{
    return SwarmTokenGateMeasureRefuse(m_book, m_latency, session, err);
}

bool SwarmTokenGate::open(const std::string& session) const
{
    return SwarmTokenGateSessionOpen(m_book, session);
}

std::string SwarmTokenGate::model_id(const std::string& session) const
{
    return SwarmTokenGateSessionModel(m_book, session);
}

std::string SwarmTokenGate::engine_name(const std::string& session) const
{
    return SwarmTokenGateSessionEngine(m_book, session);
}

bool SwarmTokenGate::prompt_stored(const std::string& session) const
{
    return SwarmTokenGateSessionPromptStored(m_book, session);
}

const std::string& SwarmTokenGate::text() const
{
    return m_output.text();
}

int64_t SwarmTokenGate::tokens() const
{
    return m_output.tokens();
}

int64_t SwarmTokenGate::ttft_ms() const
{
    return m_latency.ttft_ms();
}

int64_t SwarmTokenGate::p50_ms() const
{
    return m_latency.p50_ms();
}

int64_t SwarmTokenGate::p95_ms() const
{
    return m_latency.p95_ms();
}

bool SwarmTokenGate::measured() const
{
    return m_latency.measured();
}

bool SwarmTokenGate::running() const
{
    return m_quiet.running();
}

bool SwarmTokenGate::launched() const
{
    return m_quiet.launched();
}

bool SwarmTokenGate::gpu() const
{
    return m_quiet.gpu();
}

int64_t SwarmTokenGate::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

} // namespace modelnet
