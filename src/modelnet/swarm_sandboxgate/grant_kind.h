// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_GRANT_KIND_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_GRANT_KIND_H

#include <modelnet/swarm_sandboxgate/book.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * How one Grant attempt relates to the book.
 * Store is the only result that may be written. The other results store nothing.
 * Network is not part of the classification. The book is not modified.
 */
enum class SwarmSandboxGateGrantKind {
    Store,
    Worker,
    Path,
    Timeout,
    Capability,
    Replay,
};

/**
 * Classify one Grant attempt.
 * Empty worker is Worker, including when the prefix is also empty.
 * Empty path_prefix is Path. until_ms below 0 is Timeout.
 * An empty capabilities vector is Capability.
 * A worker and path_prefix already stored is Replay.
 */
SwarmSandboxGateGrantKind SwarmSandboxGateClassifyGrant(const SwarmSandboxGateBook& book,
                                                        const std::string& worker,
                                                        const std::string& path_prefix,
                                                        const std::vector<std::string>& capabilities,
                                                        int64_t until_ms);

/**
 * Refusal code for a non-store kind, or nullptr for Store.
 */
const char* SwarmSandboxGateGrantKindCode(SwarmSandboxGateGrantKind kind);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_GRANT_KIND_H
