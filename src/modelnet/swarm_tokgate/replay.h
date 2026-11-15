// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_REPLAY_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_REPLAY_H

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

/**
 * True when session is already open.
 * An empty session or an empty model_id is not a replay.
 * The stored model id is not compared and is not replaced.
 */
bool SwarmTokenGateOpenReplay(const SwarmTokenGateBook& book,
                              const std::string& session,
                              const std::string& model_id);

/**
 * True when session is open, engine_name is a catalog name, and that same
 * name is already stored. An empty or unknown name is not a replay.
 * The stored engine name is not replaced. This does not start a process.
 */
bool SwarmTokenGateEngineReplay(const SwarmTokenGateBook& book,
                                const std::string& session,
                                const std::string& engine_name);

/**
 * True when session is open, the prompt is public and non-empty, and the
 * same prompt bytes are already stored. A private prompt is not a replay.
 * The stored prompt is not replaced and is not generated text.
 */
bool SwarmTokenGatePromptReplay(const SwarmTokenGateBook& book,
                                const std::string& session,
                                const std::string& text,
                                bool is_private);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_REPLAY_H
