// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_INSPECT_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_INSPECT_H

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

/** True when session was stored by Open. An empty or unknown id is false. */
bool SwarmTokenGateSessionOpen(const SwarmTokenGateBook& book, const std::string& session);

/**
 * The model id stored by the first successful Open.
 * Empty when the session is not open. A replay does not change this value.
 */
std::string SwarmTokenGateSessionModel(const SwarmTokenGateBook& book, const std::string& session);

/**
 * The engine name stored by the first successful BindEngine.
 * Empty when the session is unknown or not bound.
 */
std::string SwarmTokenGateSessionEngine(const SwarmTokenGateBook& book, const std::string& session);

/**
 * True when a public prompt is stored for session.
 * A private prompt does not set this. The stored prompt is not generated text.
 */
bool SwarmTokenGateSessionPromptStored(const SwarmTokenGateBook& book, const std::string& session);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_INSPECT_H
