// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_BIND_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_BIND_H

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

/**
 * Record an engine-name request on an open session.
 * An unknown session is SESSION. An empty name, or any name other than
 * vllm, sglang, or lmcache, is ENGINE and stores nothing.
 * A second bind of the same session and the same name is REPLAY.
 * A different catalog name keeps the first and is HELD.
 * Otherwise the name is stored, err is cleared, and the result is true.
 * running stays false. This does not start a process.
 */
bool SwarmTokenGateBindApply(SwarmTokenGateBook& book,
                             const std::string& session,
                             const std::string& engine_name,
                             std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_BIND_H
