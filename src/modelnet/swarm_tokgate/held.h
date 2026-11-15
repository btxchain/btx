// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_HELD_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_HELD_H

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

/**
 * True when session already stores a catalog engine name and engine_name
 * is a different catalog name. The first name stays.
 * An empty or unknown name is not held. This does not start a process.
 */
bool SwarmTokenGateEngineHeld(const SwarmTokenGateBook& book,
                              const std::string& session,
                              const std::string& engine_name);

/**
 * True when session already stores a public prompt and text is a different
 * public prompt. The first prompt stays.
 * A private prompt or an empty prompt is not held.
 * The stored prompt is not generated text.
 */
bool SwarmTokenGatePromptHeld(const SwarmTokenGateBook& book,
                              const std::string& session,
                              const std::string& text,
                              bool is_private);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_HELD_H
