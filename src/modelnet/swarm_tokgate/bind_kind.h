// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_BIND_KIND_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_BIND_KIND_H

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

/**
 * How one BindEngine attempt relates to the book.
 * Store is the only result that may be written. The other results store nothing.
 * The book is not modified. No process is started.
 */
enum class SwarmTokenGateBindKind {
    Store,
    Session,
    Engine,
    Replay,
    Held,
};

/**
 * Classify one BindEngine attempt.
 * An unknown session is Session, including when the engine name is also empty.
 * An empty name, or a name outside vllm, sglang, and lmcache, is Engine.
 * The same catalog name already stored is Replay.
 * A different catalog name on an already bound session is Held.
 */
SwarmTokenGateBindKind SwarmTokenGateClassifyBind(const SwarmTokenGateBook& book,
                                                  const std::string& session,
                                                  const std::string& engine_name);

/** Refusal code for a non-store kind, or nullptr for Store. */
const char* SwarmTokenGateBindKindCode(SwarmTokenGateBindKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_BIND_KIND_H
