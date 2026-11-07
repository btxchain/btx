// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_RECORD_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_RECORD_H

#include <string>

namespace modelnet {

/**
 * One open decode session.
 * id and model_id are opaque strings stored by Open.
 * engine_name is the first catalog name stored by BindEngine, or empty.
 * prompt is the first public prompt stored by Prompt, or empty.
 * prompt is not generated output. engine_bound does not start a process.
 */
struct SwarmTokenGateSession {
    std::string id;
    std::string model_id;
    std::string engine_name;
    bool engine_bound{false};
    std::string prompt;
    bool prompt_stored{false};
};

/**
 * A fresh session record.
 * engine_bound stays false. prompt_stored stays false.
 * engine_name and prompt stay empty. No process is started.
 */
SwarmTokenGateSession SwarmTokenGateMakeSession(const std::string& id, const std::string& model_id);

/** True when id and model_id are both non-empty. */
bool SwarmTokenGateSessionUsable(const SwarmTokenGateSession& session);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_RECORD_H
