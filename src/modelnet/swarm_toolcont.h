// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TOOLCONT_H
#define BTX_MODELNET_SWARM_TOOLCONT_H

#include <string>

namespace modelnet {

/** Local tool-continuation record. This machine does not execute a tool and does not run a model. */
enum class SwarmToolState {
    Idle,
    Generating,
    ToolWait,
    Invalidated,
    Continued,
};

/**
 * Tool continuation. tool_executed and bytes_moved stay false: Begin,
 * Interrupt, and Continue do not execute a tool and do not run a model.
 *
 * Begin: an empty generation id is TOOL and the state stays idle. Otherwise
 * the state is generating and the code is GENERATING.
 *
 * Interrupt: only generating becomes tool_wait with TOOL_WAIT. Any other
 * state is TOOL and the state does not change.
 *
 * Continue: from tool_wait, a context change is INVALIDATED and the state
 * is invalidated. tool_wait without a tool result is TOOL_REQUIRED and the
 * state stays tool_wait. tool_wait with a tool result and no context change
 * is CONTINUED and the state is continued. Any other state is TOOL and the
 * state does not change.
 */
class SwarmToolContinuation {
public:
    bool Begin(const std::string& generation_id, std::string& err);
    bool Interrupt(std::string& err);
    bool Continue(bool tool_result_present, bool context_changed, std::string& err);

    SwarmToolState State() const { return m_state; }
    const std::string& Code() const { return m_code; }
    bool ToolExecuted() const { return false; }
    bool BytesMoved() const { return false; }

private:
    SwarmToolState m_state{SwarmToolState::Idle};
    std::string m_code;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TOOLCONT_H
