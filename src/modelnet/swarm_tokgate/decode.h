// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_DECODE_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_DECODE_H

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

/**
 * Refuse to decode.
 * An unknown session is SESSION.
 * Every open session is ENGINE_ABSENT, including a session bound to
 * vllm, sglang, or lmcache. A stored engine name is not a running engine.
 * The caller naming an engine is not a generation.
 * tokens stay 0. Generated text stays empty. This does not exec an engine.
 */
bool SwarmTokenGateDecodeRefuse(const SwarmTokenGateBook& book,
                                const std::string& session,
                                std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_DECODE_H
