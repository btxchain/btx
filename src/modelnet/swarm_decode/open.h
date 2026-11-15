// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_OPEN_H
#define BITCOIN_MODELNET_SWARM_DECODE_OPEN_H

#include <modelnet/swarm_decode/book.h>

#include <string>

namespace modelnet {

/**
 * Open one session on memory, vllm, sglang, or lmcache.
 * An empty session is SESSION and stores nothing.
 * Any other engine name is ENGINE and stores nothing.
 * A second open of the same session is REPLAY and keeps the first engine.
 * Success stores the session and the engine. It does not append bytes.
 */
bool SwarmDecodeOpenApply(SwarmDecodeBook& book,
                          const std::string& session,
                          const std::string& engine,
                          std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_OPEN_H
