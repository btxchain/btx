// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_toolcont.h>

namespace modelnet {

bool SwarmToolContinuation::Begin(const std::string& generation_id, std::string& err)
{
    if (generation_id.empty()) {
        m_code = "TOOL";
        err = "TOOL";
        return false;
    }
    m_state = SwarmToolState::Generating;
    m_code = "GENERATING";
    err.clear();
    return true;
}

bool SwarmToolContinuation::Interrupt(std::string& err)
{
    if (m_state != SwarmToolState::Generating) {
        m_code = "TOOL";
        err = "TOOL";
        return false;
    }
    m_state = SwarmToolState::ToolWait;
    m_code = "TOOL_WAIT";
    err.clear();
    return true;
}

bool SwarmToolContinuation::Continue(bool tool_result_present, bool context_changed, std::string& err)
{
    if (m_state != SwarmToolState::ToolWait) {
        m_code = "TOOL";
        err = "TOOL";
        return false;
    }
    if (context_changed) {
        m_state = SwarmToolState::Invalidated;
        m_code = "INVALIDATED";
        err = "INVALIDATED";
        return false;
    }
    if (!tool_result_present) {
        m_code = "TOOL_REQUIRED";
        err = "TOOL_REQUIRED";
        return false;
    }
    m_state = SwarmToolState::Continued;
    m_code = "CONTINUED";
    err.clear();
    return true;
}

} // namespace modelnet
