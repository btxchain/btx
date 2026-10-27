// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_OPEN_KIND_H
#define BITCOIN_MODELNET_SWARM_DECODE_OPEN_KIND_H

#include <modelnet/swarm_decode/book.h>

#include <string>

namespace modelnet {

/**
 * How one Open attempt relates to the book.
 * Store is the only result that may be written. The other results store nothing.
 * The book is not modified.
 */
enum class SwarmDecodeOpenKind {
    Store,
    Session,
    Engine,
    Replay,
};

/**
 * Classify one Open attempt.
 * An empty session is Session.
 * An engine name other than memory, vllm, sglang, or lmcache is Engine.
 * A session that is already open is Replay. The stored engine is not replaced.
 */
SwarmDecodeOpenKind SwarmDecodeClassifyOpen(const SwarmDecodeBook& book,
                                            const std::string& session,
                                            const std::string& engine);

/** Refusal code for a non-store kind, or nullptr for Store. */
const char* SwarmDecodeOpenKindCode(SwarmDecodeOpenKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_OPEN_KIND_H
