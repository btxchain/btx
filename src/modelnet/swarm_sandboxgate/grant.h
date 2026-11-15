// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_GRANT_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_GRANT_H

#include <modelnet/swarm_sandboxgate/book.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Store a grant when the worker and prefix are non-empty, until_ms >= 0,
 * capabilities is non-empty, and this worker/prefix is not already stored.
 * On success err is cleared. On failure nothing is stored and err is
 * WORKER, PATH, TIMEOUT, CAPABILITY, or REPLAY.
 * A replay leaves the first capabilities, network flag, and until_ms.
 * A worker may hold more than one path prefix.
 * This does not launch a process or open a socket.
 */
bool SwarmSandboxGateGrantApply(SwarmSandboxGateBook& book,
                                const std::string& worker,
                                const std::string& path_prefix,
                                const std::vector<std::string>& capabilities,
                                bool network,
                                int64_t until_ms,
                                std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_GRANT_H
