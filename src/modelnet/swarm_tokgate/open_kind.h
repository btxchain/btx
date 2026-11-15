// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_OPEN_KIND_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_OPEN_KIND_H

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

/**
 * How one Open attempt relates to the book.
 * Store is the only result that may be written. The other results store nothing.
 * The book is not modified.
 */
enum class SwarmTokenGateOpenKind {
    Store,
    Model,
    Replay,
};

/**
 * Classify one Open attempt.
 * An empty session or an empty model_id is Model, including when both are empty.
 * A session that is already open is Replay. The stored model id is not compared.
 */
SwarmTokenGateOpenKind SwarmTokenGateClassifyOpen(const SwarmTokenGateBook& book,
                                                  const std::string& session,
                                                  const std::string& model_id);

/** Refusal code for a non-store kind, or nullptr for Store. */
const char* SwarmTokenGateOpenKindCode(SwarmTokenGateOpenKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_OPEN_KIND_H
