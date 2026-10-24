// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_OPEN_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_OPEN_H

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

/**
 * Open a decode session.
 * An empty session or an empty model_id is MODEL and stores nothing.
 * A second open of the same session is REPLAY and keeps the first model id.
 * Otherwise the session is stored, err is cleared, and the result is true.
 * running stays false. This does not start a process or bind an engine.
 */
bool SwarmTokenGateOpenApply(SwarmTokenGateBook& book,
                             const std::string& session,
                             const std::string& model_id,
                             std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_OPEN_H
